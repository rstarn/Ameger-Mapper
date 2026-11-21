#pragma once

/*
 * Hypervisor
 * https://github.com/SamuelTulach | https://tulach.cc
 */

#include <intrin.h>
#include <Windows.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <stdint.h>
#include <vector>

#include "../Utilities/Console.hpp"

namespace Hypervisor
{

    // Compile-time flag: whether the hypervisor's NPT hide routine supports discontiguous physical pages.
    // Set to false for conservative contiguous allocation.

    inline constexpr bool kHypervisorSupportsDiscontiguousNpt = false;

    namespace Shared
    {
        constexpr ULONG64 MAGIC = 0xfeed3;
        constexpr ULONG64 COMM_CHECK = 0xdead;

        constexpr ULONG64 MAX_RW_SIZE = 0x10000;

        enum CommandId
        {
            Invalid,
            CheckPresence,
            GetProcess,
            GetDirectoryBase,
            CopyProcessMemory,
            ProtectSelf,
            FlushNpt,
            ProtectRange,
        };

        enum ErrorCodes
        {
            Success,
            ControlBlockReadFail,
            MemoryCopyTooLarge,
            MemoryCopyFailSource,
            MemoryCopyFailTarget,
            InvalidProcess,
            AccessDenied = 0xDEADBEEF,
        };

        // Data commands travel through the \\.\AmegerHv IOCTL interface. The
        // hypervisor rejects every CPL3 VMMCALL except CheckPresence, so the old
        // vmmcall transport made --hide return AccessDenied on every CPU.

        typedef struct _AMEGER_IOCTL_REQUEST
        {
            ULONG64 CommandId;
            ULONG64 Arg1;
            ULONG64 Arg2;
            ULONG64 Arg3;
        } AMEGER_IOCTL_REQUEST;

        #define IOCTL_AMEGER_HV_COMMAND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
        #define AMEGER_HV_DEVICE_NAME L"\\\\.\\\\AmegerHv"

        typedef struct _AMEGER_IOCTL_RESPONSE
        {
            ULONG64 Status;
            ULONG64 Value;
            UCHAR Payload[496];
        } AMEGER_IOCTL_RESPONSE;

        static_assert(sizeof(AMEGER_IOCTL_RESPONSE) == 512, "AMEGER_IOCTL_RESPONSE ABI mismatch");
        static_assert(offsetof(AMEGER_IOCTL_RESPONSE, Status) == 0x00, "AMEGER_IOCTL_RESPONSE.Status ABI mismatch");
        static_assert(offsetof(AMEGER_IOCTL_RESPONSE, Value) == 0x08, "AMEGER_IOCTL_RESPONSE.Value ABI mismatch");
        static_assert(offsetof(AMEGER_IOCTL_RESPONSE, Payload) == 0x10, "AMEGER_IOCTL_RESPONSE.Payload ABI mismatch");

        typedef struct _COPY_MEMORY_DATA
        {
            ULONG32 SourceProcessId;
            ULONG32 DestinationProcessId;
            ULONG64 SourceAddress;
            ULONG64 DestinationAddress;
            SIZE_T NumberOfBytes;
        } COPY_MEMORY_DATA;
        static_assert(sizeof(COPY_MEMORY_DATA) == 32, "COPY_MEMORY_DATA ABI mismatch");
    }

    namespace Data
    {
        inline bool Attached = false;
        inline PVOID Shellcode = nullptr;

        inline DWORD CurrentProcessId = 0;
        inline DWORD TargetProcessId = 0;

        inline ULONG64 CurrentEPROCESS = 0;
        inline ULONG64 CurrentDirectoryBase = 0;

        inline ULONG64 TargetEPROCESS = 0;
        inline ULONG64 TargetDirectoryBase = 0;
    }

    /*
     * Issues the vmmcall.
     *
     * trapped, when given, reports whether the instruction itself faulted: the
     * #UD a vmmcall raises on a machine where no hypervisor intercepts it. It
     * stays false when the call completed, which is what the caller needs in
     * order to say which of the two happened instead of assuming the trap.
     * Optional so every existing four argument caller is unchanged.
     */

    inline ULONG64 CallVM(ULONG64 arg1 = 0, ULONG64 arg2 = 0, ULONG64 arg3 = 0, ULONG64 arg4 = 0, bool* trapped = nullptr)
    {
        if (trapped)
            *trapped = false;

        if (!Data::Shellcode)
        {

            // vmmcall
            // ret

            const BYTE code[] = { 0x0F, 0x01, 0xD9, 0xC3 };

            Data::Shellcode = VirtualAlloc(nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!Data::Shellcode)
                throw std::runtime_error("Out of memory");

            memcpy(Data::Shellcode, code, sizeof(code));

            DWORD old_prot = 0;
            if (!VirtualProtect(Data::Shellcode, sizeof(code),
                    PAGE_EXECUTE_READ, &old_prot))
            {
                VirtualFree(Data::Shellcode, 0, MEM_RELEASE);
                Data::Shellcode = nullptr;
                throw std::runtime_error("Cannot apply execute-read protection to VMCALL stub");
            }
        }

        typedef ULONG64(__stdcall* CallFunc)(ULONG64 arg1, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);
        const CallFunc func = reinterpret_cast<CallFunc>(Data::Shellcode);

        ULONG64 output;
        try
        {
            output = func(arg1, arg2, arg3, arg4);
        }
        catch (...)
        {

            //Nothing intercepted the vmmcall, so it raised #UD. The caller
            //reports the trap; printing here as well would duplicate it in a
            //line that carries no colour and no indent.

            if (trapped)
                *trapped = true;

            output = 0xAABB;
        }

        return output;
    }

    /* Send a data command through the driver's IOCTL interface. CheckPresence
     * stays on the VMMCALL path because the hypervisor explicitly allows that
     * one from CPL3; every other command is rejected there with AccessDenied. */

    inline ULONG64 CallIoctl(ULONG64 commandId, ULONG64 arg1 = 0, ULONG64 arg2 = 0, ULONG64 arg3 = 0)
    {
        static HANDLE deviceHandle = INVALID_HANDLE_VALUE;
        if (deviceHandle == INVALID_HANDLE_VALUE) {
            deviceHandle = CreateFileW(AMEGER_HV_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (deviceHandle == INVALID_HANDLE_VALUE)
                return 0xAABB; // no hypervisor device, same sentinel as CallVM
        }

        Shared::AMEGER_IOCTL_REQUEST request = { commandId, arg1, arg2, arg3 };
        UCHAR outBuf[512] = { 0 };
        DWORD bytesReturned = 0;

        const BOOL ok = DeviceIoControl(deviceHandle, IOCTL_AMEGER_HV_COMMAND,
            &request, sizeof(request), outBuf, sizeof(outBuf), &bytesReturned, nullptr);

        const SIZE_T headerSize = offsetof(Shared::AMEGER_IOCTL_RESPONSE, Value) + sizeof(ULONG64);
        if (!ok || bytesReturned < headerSize)
            return 0xAABB;

        const auto* response = reinterpret_cast<const Shared::AMEGER_IOCTL_RESPONSE*>(outBuf);
        return response->Value;
    }

    inline bool Error(ULONG64 hvOutput)
    {
        if (hvOutput == 0xAABB)
            return true; // HV not loaded

        if (hvOutput == 0xFFFF)
            return true; // command not implemented

        if (hvOutput == static_cast<ULONG64>(Shared::ErrorCodes::AccessDenied))
            return true; // the hypervisor refused a CPL3 call

        if (hvOutput > Shared::ErrorCodes::Success &&
            hvOutput <= Shared::ErrorCodes::InvalidProcess)
            return true; // documented error codes (Success == 0 is not an error)

        return false;
    }

    //
    // Hides an arbitrary guest virtual range [base, base + size) in the NPT.
    // Pass the kernel virtual base the mapper allocated (its DriverObject
    // DriverStart) and the allocation size (DriverSize).  Call it after every
    // driver you want hidden has run DriverEntry, and run FlushAllProcessors()
    // once afterwards.
    //

    inline bool HideMemory(ULONG64 base, SIZE_T size)
    {
        const ULONG64 output = CallIoctl(Shared::CommandId::ProtectRange, base, static_cast<ULONG64>(size));
        return output == Shared::ErrorCodes::Success;
    }

    inline bool CheckPresence()
    {
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::CheckPresence);
        return output == Shared::COMM_CHECK;
    }

    //
    // Hides the mapped image in the NPT, minus [textBase, textBase + textSize).
    //
    // The driver's own executable code runs in guest mode on the NPF restore
    // path, so blanking the pages it is executing from livelocks that restore.
    // textBase is the resident VA of the executable span and textSize its
    // length; passing 0/0 hides the whole image (the legacy behaviour).
    //

    inline bool Protect(ULONG64 textBase = 0, SIZE_T textSize = 0)
    {
        const ULONG64 output = CallIoctl(Shared::CommandId::ProtectSelf, textBase, static_cast<ULONG64>(textSize));
        return output == Shared::ErrorCodes::Success;
    }

    /*
     * Forces every active processor through one #VMEXIT.
     *
     * ProtectSelf() bumps the shared NPT flush generation and sets TlbControl
     * on every published VMCB, but a vCPU that is already inside VMRUN when
     * that store lands never sees it and would only flush at its next exit.
     * Issuing FlushNpt from each CPU pins the current thread to that CPU, so
     * the VMMCALL itself is the exit that arms the flush.
     *
     * Single-threaded on purpose: the shellcode in Data::Shellcode is global
     * state, and a pinned sweep covers every CPU without racing on it.
     */

    inline bool FlushAllProcessors()
    {
        const HANDLE thread = GetCurrentThread();

        GROUP_AFFINITY original = { 0 };
        if (!GetThreadGroupAffinity(thread, &original))
            return false;

        /* Enumerate processor groups and each group's actual active mask.
         * Deriving the group as index/64 is wrong: Windows groups can hold
         * fewer than 64 logical processors and group numbering is not a simple
         * division of a global index, which could pin a nonexistent CPU or skip
         * real ones. RelationGroup reports each group's GroupMask directly. */

        DWORD bytes = 0;
        GetLogicalProcessorInformationEx(RelationGroup, nullptr, &bytes);
        if (bytes == 0)
            return false;
        std::vector<BYTE> buffer(bytes);
        auto* info = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
        if (!GetLogicalProcessorInformationEx(RelationGroup, info, &bytes))
            return false;

        bool allFlushed = true;
        for (auto* cursor = info;
             reinterpret_cast<BYTE*>(cursor) + cursor->Size <= buffer.data() + bytes;
             cursor = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(
                 reinterpret_cast<BYTE*>(cursor) + cursor->Size)) {
            if (cursor->Relationship != RelationGroup || cursor->Group.ActiveGroupCount == 0)
                continue;

            // GROUP_RELATIONSHIP holds ActiveGroupCount PROCESSOR_GROUP_INFO
            // entries in GroupInfo; each carries its group number and active mask.

            for (WORD g = 0; g < cursor->Group.ActiveGroupCount; ++g) {
                const PROCESSOR_GROUP_INFO& groupInfo = cursor->Group.GroupInfo[g];
                const WORD group = g; // GROUP_INFO entries are ordered by group number
                for (WORD bit = 0; bit < 64; ++bit) {
                    const KAFFINITY mask = static_cast<KAFFINITY>(1ULL) << bit;
                    if ((groupInfo.ActiveProcessorMask & mask) == 0)
                        continue;

                    GROUP_AFFINITY affinity = { 0 };
                    affinity.Group = group;
                    affinity.Mask = mask;

                    GROUP_AFFINITY previous = { 0 };
                    if (!SetThreadGroupAffinity(thread, &affinity, &previous))
                    {
                        printf("  [*] flush G%u:C%u: pin failed\n", group, bit);
                        allFlushed = false;
                        continue;
                    }

                    if (CallIoctl(Shared::CommandId::FlushNpt) != Shared::ErrorCodes::Success)
                    {
                        printf("  [*] flush G%u:C%u: vmmcall failed\n", group, bit);
                        allFlushed = false;
                    }
                    else
                    {
                        if (Console::ColorsDisabled())
                            printf("  [+] Flushing G%u:C%u: Success\n", group, bit);
                        else
                            printf("  \x1b[92m[+]\x1b[0m Flushing G%u:C%u: \x1b[92mSuccess\x1b[0m\n", group, bit);
                    }
                }
            }
        }

        printf("\n");

        SetThreadGroupAffinity(thread, &original, nullptr);

        return allFlushed;
    }

    inline ULONG64 GetEPROCESS(UINT32 processId)
    {
        return CallIoctl(Shared::CommandId::GetProcess, processId);
    }

    inline ULONG64 GetDirbase(UINT32 processId)
    {
        return CallIoctl(Shared::CommandId::GetDirectoryBase, processId);
    }

    inline bool AttachToProcess(UINT32 processId)
    {
        Data::CurrentProcessId = GetCurrentProcessId();
        Data::TargetProcessId = processId;

        Data::CurrentEPROCESS = GetEPROCESS(Data::CurrentProcessId);
        if (Error(Data::CurrentEPROCESS))
            return false;

        Data::TargetEPROCESS = GetEPROCESS(Data::TargetProcessId);
        if (Error(Data::TargetEPROCESS))
            return false;

        Data::CurrentDirectoryBase = GetDirbase(Data::CurrentProcessId);
        if (Error(Data::CurrentDirectoryBase))
            return false;

        Data::TargetDirectoryBase = GetDirbase(Data::TargetProcessId);
        if (Error(Data::TargetDirectoryBase))
            return false;

        Data::Attached = true;
        return true;
    }

    inline bool CopyProcessMemory(UINT32 sourceProcessId, ULONG64 sourceAddress, UINT32 targetProcessId, ULONG64 targetAddress, SIZE_T bytes)
    {

        //
        // The protocol caps one VMMCALL at Shared::MAX_RW_SIZE (the kernel
        // stages the transfer in a fixed buffer), so larger requests are
        // split here into consecutive calls.  Every chunk is validated
        // end-to-end by the driver like a standalone copy, so a chunk that
        // fails aborts the remainder and reports failure for the request.
        //

        ULONG64 source = sourceAddress;
        ULONG64 target = targetAddress;
        SIZE_T remaining = bytes;

        while (remaining)
        {
            const ULONG64 chunk = (remaining > Shared::MAX_RW_SIZE) ? static_cast<ULONG64>(Shared::MAX_RW_SIZE) : remaining;

            Shared::COPY_MEMORY_DATA data = { 0 };
            data.SourceProcessId = sourceProcessId;
            data.DestinationProcessId = targetProcessId;
            data.SourceAddress = source;
            data.DestinationAddress = target;
            data.NumberOfBytes = chunk;

            const ULONG64 value = CallIoctl(Shared::CommandId::CopyProcessMemory, reinterpret_cast<ULONG64>(&data));
            if (value != Shared::ErrorCodes::Success)
                return false;

            source += chunk;
            target += chunk;
            remaining -= static_cast<SIZE_T>(chunk);
        }

        return true;
    }

    inline bool ReadMemory(ULONG64 source, PVOID buffer, SIZE_T size)
    {
        memset(buffer, 0, size);
        return CopyProcessMemory(Data::TargetProcessId, source, Data::CurrentProcessId, reinterpret_cast<ULONG64>(buffer), size);
    }

    inline bool TryReadMemory(ULONG64 source, PVOID buffer, SIZE_T size)
    {
        return CopyProcessMemory(Data::TargetProcessId, source, Data::CurrentProcessId, reinterpret_cast<ULONG64>(buffer), size);
    }

    /*
     * The copy path resolves through physical page tables, so both the
     * source and the destination of every read/write must be RESIDENT
     * (present PTEs at every level).  A non-resident chunk fails the
     * request; the caller sees false rather than a silent partial copy.
     */

    inline bool WriteMemory(ULONG64 buffer, ULONG64 destination, SIZE_T size)
    {
        return CopyProcessMemory(Data::CurrentProcessId, buffer, Data::TargetProcessId, destination, size);
    }

    template<typename T>
    bool TryRead(ULONG64 address, T& value)
    {
        return TryReadMemory(address, &value, sizeof(T));
    }

    template<typename T>
    T Read(ULONG64 address)
    {
        T value = T();
        TryReadMemory(address, &value, sizeof(T));
        return value;
    }

    template<typename T>
    void Write(ULONG64 address, T value)
    {
        WriteMemory(reinterpret_cast<ULONG64>(&value), address, sizeof(T));
    }
}
