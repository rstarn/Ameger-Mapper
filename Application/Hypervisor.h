#pragma once

/*
 * Hypervisor
 * https://github.com/SamuelTulach | https://tulach.cc
 */

#include <Windows.h>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <vector>

#include "../Utilities/Support/Console.hpp"

namespace Hypervisor
{

    namespace Shared
    {
        constexpr ULONG64 MAGIC = 0xfeed3;
        constexpr ULONG64 COMM_CHECK = 0xdead;

        // Wire values are pinned: the hypervisor owns this protocol and may
        // insert values between those Mapper uses. See Shared.h there.
        enum CommandId
        {
            CheckPresence = 1,
            ProtectSelf   = 5,
            FlushNpt      = 6,
        };

        enum ErrorCodes
        {
            Success = 0,
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
    }

    namespace Data
    {
        inline PVOID Shellcode = nullptr;
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

}
