#pragma once

/*
 * The mapping engine.
 *
 * MapDriver takes the mapped image of a user mode driver, fixes it up in a
 * private user mode buffer (relocations, imports, /GS cookie), copies the
 * result into a freshly allocated kernel allocation and calls its entry point.
 *
 * It never writes to kernel memory until every user mode fixup has succeeded,
 * so a malformed or unloadable driver fails before any kernel state exists.
 */

#include <Windows.h>

namespace Mapper
{
	//Where the kernel side of the image is allocated.
	enum class AllocationMode
	{
		//Single nonpaged pool block holding the whole image. The allocation
		//stays RWX for the lifetime of the mapping: the provider cannot apply
		//per section protection to a pool block.
		AllocatePool,

		//One independent-page allocation per section, so each section can be
		//given its own protection through MmSetPageProtection after the copy.
		//Closer to how the loader maps a driver, but requires that export.
		AllocateIndependentPages
	};

	//Invoked after the image is in kernel memory but before DriverEntry runs.
	//Returning false aborts the mapping.
	//param1/param2 are forwarded as the DriverEntry arguments,
	//allocationPtr/allocationSize describe the kernel allocation.
	typedef bool (*mapCallback)(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize);

	/*
	 * Map a driver image.
	 *
	 * data         the mapped file image, treated as untrusted input
	 * data_size    length of `data`; every span the PE declares is validated
	 *              against it, so passing a short buffer is safe
	 * free         release the kernel allocation right after the entry point
	 *              returns (only safe for drivers that copy out what they need)
	 * destroyHeader  skip the PE header in the kernel copy and load the image
	 *              from the first section, which hides the "PE" signature at
	 *              the start of the allocation
	 * PassAllocationAddressAsFirstParam  pass the allocation base as the first
	 *              DriverEntry argument; param1 is ignored when set
	 * exitCode     optional, receives the DriverEntry NTSTATUS
	 *
	 * Returns the kernel base on success and 0 on failure. On failure every
	 * allocation made along the way (the user mode buffer and the kernel one)
	 * is released before returning.
	 */
	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	ULONG64 MapDriver(BYTE* data, size_t data_size, ULONG64 param1 = 0, ULONG64 param2 = 0, bool free = false, bool destroyHeader = true, AllocationMode mode = AllocationMode::AllocatePool, bool PassAllocationAddressAsFirstParam = false, mapCallback callback = nullptr, NTSTATUS* exitCode = nullptr);
}