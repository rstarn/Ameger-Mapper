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
#include <string>

#include "../PE/PE.hpp"

namespace Mapper
{
	//One import being resolved, handed to an ImportResolver.
	//name is null when the import is by ordinal rather than by name.
	struct ImportLookup {
		ULONG64 module_base;
		const std::string* name;
		uint16_t ordinal;
	};

	//Resolves one import to a kernel address, written to out_address.
	//Returns false when the named function, or the ordinal, is not present in
	//the module the descriptor named. out_address is only written on success.
	typedef bool (*ImportResolver)(const ImportLookup& request, void* context, ULONG64& out_address);
	//Where the kernel side of the image is allocated.
	enum class AllocationMode
	{
		//Single nonpaged pool block holding the whole image. The allocation
		//stays RWX for the lifetime of the mapping: the provider cannot apply
		//per section protection to a pool block.
		AllocatePool,

		//One page aligned, physically contiguous block for the whole image.
		//Same lifetime and protection properties as AllocatePool, but the base
		//is page aligned: a driver that blanks whole pages of its own image
		//(memhv's self-hide) must not touch the pool header in front of the
		//allocation or the block that follows it. This is the default.
		AllocateContiguous,

		//One independent-page allocation per section, so each section can be
		//given its own protection through MmSetPageProtection after the copy.
		//Closer to how the loader maps a driver, but requires that export.
		AllocateIndependentPages
	};

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
	 * residentSize optional, receives the number of bytes resident in the
	 *              kernel allocation (SizeOfImage minus the stripped header
	 *              span), i.e. the exact range the image occupies at the base
	 *              returned - the range a consumer like the hypervisor's NPT
	 *              self-hide must blank, not the file or SizeOfImage
	 *
	 * Returns the kernel base on success and 0 on failure. On failure every
	 * allocation made along the way (the user mode buffer and the kernel one)
	 * is released before returning.
	 */
	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	ULONG64 MapDriver(BYTE* data, size_t data_size, ULONG64 param1 = 0, ULONG64 param2 = 0, bool free = false, bool destroyHeader = true, AllocationMode mode = AllocationMode::AllocateContiguous, bool PassAllocationAddressAsFirstParam = false, NTSTATUS* exitCode = nullptr, SIZE_T* residentSize = nullptr);

	/*
	 * The three image fixups, exposed rather than kept file-local.
	 *
	 * They are the part of the mapper that decides whether an image is safe to
	 * run, and that is exactly the part worth testing against hand-built
	 * images: none of it touches the kernel, so all of it can be exercised in
	 * user mode.
	 *
	 * RelocateImageByDelta and FixSecurityCookie are pure. ResolveImports takes
	 * the resolver to use rather than calling the kernel helpers itself, so the
	 * same code path can be driven with a stub table instead of a live kernel.
	 * MapDriver supplies the real resolver; see the default in Mapper.cpp.
	 */

	//Applies DIR64 fixups by delta inside [image_base, image_base+image_size).
	//Returns false on an unsupported relocation type or a target outside the
	//image, in both cases having applied nothing further.
	bool RelocateImageByDelta(const PE::vec_relocs& relocs, ULONG64 delta, ULONG64 image_base, ULONG64 image_size);

	//Rewrites /GS security cookie so it matches the base the image runs at.
	//Returns false only when the headers themselves cannot be read; a missing
	//load config, a zero cookie and a cookie outside the image are all "nothing
	//to fix", not failures.
	bool FixSecurityCookie(void* local_image, size_t image_size, ULONG64 kernel_image_base);

	//Fills every IAT slot. Returns false on the first unresolvable import.
	bool ResolveImports(const PE::vec_imports& imports, ImportResolver resolver, void* context);
}