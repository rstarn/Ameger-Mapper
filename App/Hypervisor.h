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

namespace Hypervisor
{
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
        };

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

    inline ULONG64 CallVM(ULONG64 arg1 = 0, ULONG64 arg2 = 0, ULONG64 arg3 = 0, ULONG64 arg4 = 0)
    {
        if (!Data::Shellcode)
        {
            // vmmcall
            // ret
            const BYTE code[] = { 0x0F, 0x01, 0xD9, 0xC3 };

            Data::Shellcode = VirtualAlloc(nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!Data::Shellcode)
                throw std::runtime_error("Out of memory");

            memcpy(Data::Shellcode, code, sizeof(code));
        }

        typedef ULONG64(__stdcall* CallFunc)(ULONG64 arg1, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);
        const CallFunc func = reinterpret_cast<CallFunc>(Data::Shellcode);

        ULONG64 output;
        __try
        {
            output = func(arg1, arg2, arg3, arg4);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            printf("[!] SEH handler called\n");
            output = 0xAABB;
        }

        return output;
    }

    inline bool Error(ULONG64 hvOutput)
    {
        if (hvOutput == 0xAABB)
            return true; // HV not loaded

        if (hvOutput == 0xFFFF)
            return true; // command not implemented

        if (hvOutput <= Shared::ErrorCodes::InvalidProcess)
            return true; // documented error code

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
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::ProtectRange, base, static_cast<ULONG64>(size));
        return output == Shared::ErrorCodes::Success;
    }

    inline bool CheckPresence()
    {
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::CheckPresence);
        return output == Shared::COMM_CHECK;
    }

    inline bool Protect()
    {
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::ProtectSelf);
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
        const DWORD processorCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        if (processorCount == 0)
            return false;

        const HANDLE thread = GetCurrentThread();

        GROUP_AFFINITY original = { 0 };
        if (!GetThreadGroupAffinity(thread, &original))
            return false;

        bool allFlushed = true;
        for (DWORD index = 0; index < processorCount; index++)
        {
            GROUP_AFFINITY affinity = { 0 };
            affinity.Group = static_cast<WORD>(index / 64);
            affinity.Mask = 1ULL << (index % 64);

            GROUP_AFFINITY previous = { 0 };
            if (!SetThreadGroupAffinity(thread, &affinity, &previous))
            {
                printf("[*] flush CPU %lu: pin failed\n", index);
                allFlushed = false;
                continue;
            }

            if (CallVM(Shared::MAGIC, Shared::CommandId::FlushNpt) != Shared::ErrorCodes::Success)
            {
                printf("[*] flush CPU %lu: vmmcall failed\n", index);
                allFlushed = false;
            }
            else
            {
                printf("[*] flush CPU %lu: ok\n", index);
            }
        }

        SetThreadGroupAffinity(thread, &original, nullptr);

        return allFlushed;
    }

    inline ULONG64 GetEPROCESS(UINT32 processId)
    {
        return CallVM(Shared::MAGIC, Shared::CommandId::GetProcess, processId);
    }

    inline ULONG64 GetDirbase(UINT32 processId)
    {
        return CallVM(Shared::MAGIC, Shared::CommandId::GetDirectoryBase, processId);
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

            const ULONG64 value = CallVM(Shared::MAGIC, Shared::CommandId::CopyProcessMemory, reinterpret_cast<ULONG64>(&data));
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
