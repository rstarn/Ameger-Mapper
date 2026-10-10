#include "Mapper.hpp"
#include <Windows.h>
#include <iostream>

#include "../Utilities/Utilities.hpp"
#include "../Provider/Driver.hpp"
#include "../App/NT.hpp"
#include "../PE/PE.hpp"

/*
 * Apply base relocations to the local copy.
 *
 * Returns false when the image carries a relocation type this mapper does not
 * know how to apply. Silently skipping one would leave a pointer in the image
 * still aimed at the preferred base, and the first use of it is a bugcheck - so
 * an unknown type aborts the run instead.
 *
 * On x64 only two types ever appear:
 *   IMAGE_REL_BASED_ABSOLUTE  padding / no - op, skipped by design
 *   IMAGE_REL_BASED_DIR64     a 64-bit absolute address, the only one applied
 *
 * image_base/image_size bound the local copy the fixups are applied to. The
 * target of each fixup is a file controlled RVA (the block's VirtualAddress
 * plus the entry's 12-bit offset), so it has to be proved to lie inside that
 * copy before it is written: a block whose VirtualAddress is outside the image
 * would otherwise patch memory past the end of the mapper's own allocation.
 */
static bool RelocateImageByDelta(const PE::vec_relocs& relocs, const ULONG64 delta, const ULONG64 image_base, const ULONG64 image_size) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (type != IMAGE_REL_BASED_DIR64) {
								Log(L"[-] Unsupported relocation type " << type << L" at page +0x"
					<< std::hex << current_reloc.address + offset << std::dec
					<< L"; refusing to build an image with unfixed pointers" << std::endl);
				return false;
			}

			//The fixup slot has to fit inside the image, with room for the
			//8 bytes written to it. Refusing the whole image (rather than
			//skipping the entry) matches the rule above: a partially applied
			//relocation set leaves pointers aimed at the preferred base.
			const ULONG64 target = current_reloc.address + offset;
			if (target < image_base || image_size < sizeof(ULONG64) ||
				target - image_base > image_size - sizeof(ULONG64)) {
				Log(L"[-] Relocation target 0x" << std::hex << (target - image_base) << std::dec
					<< L" is outside the image; refusing to build an image with unfixed pointers" << std::endl);
				return false;
			}

			*reinterpret_cast<ULONG64*>(target) += delta;
		}
	}
	return true;
}

//Section names are 8 bytes and are not null terminated, so they must never be
//streamed as a C string: that would read past the end of the field.
static std::wstring SectionName(const PIMAGE_SECTION_HEADER section) {
	const auto* name = reinterpret_cast<const char*>(section->Name);
	const size_t length = strnlen_s(name, IMAGE_SIZEOF_SHORT_NAME);
	return std::wstring(name, name + length);
}

/*
 * Replace the image's /GS security cookie with one that matches the base it is
 * actually running at.
 *
 * MSVC's __security_check_cookie compares against a cookie the image stores
 * alongside a complement derived from the image base. A driver linked for one
 * base and loaded at another fails that check on its first call, so the cookie
 * is rewritten to a value chosen here.
 *
 * The value already in the image is only checked for being non-zero. An exact
 * match against the compiler default was used before, but that refuses to
 * map any driver linked with a custom /GS cookie, and there is no way to tell
 * "customised cookie" from "corrupt load config" by comparison alone. The
 * write is the same either way, so the strict check only cost compatibility.
 *
 * @Jerem584
 */
static bool FixSecurityCookie(void* local_image, size_t image_size, ULONG64 kernel_image_base)
{
	auto headers = PE::GetNtHeaders(local_image, image_size);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		Log(L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	//The load config directory is a file controlled RVA: it has to lie inside
	//the local image, with room for the structure the field is read from.
	if (load_config_directory >= image_size ||
		sizeof(IMAGE_LOAD_CONFIG_DIRECTORY) > image_size - load_config_directory)
	{
		Log(L"[-] Load config directory is outside the image, fix cookie skipped" << std::endl);
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		Log(L"[+] StackCookie not defined, fix cookie skipped" << std::endl);
		return true; // as I said, it is not an error and we should allow that behavior
	}

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image; //since our local image is already relocated the base returned will be kernel address

	//The rebased slot has to land inside the local image: the read and the
	//write below both dereference it, and a corrupt load config would otherwise
	//point either of them outside the buffer.
	const auto local_base = reinterpret_cast<uintptr_t>(local_image);
	const auto local_limit = local_base + image_size;
	if (stack_cookie < local_base || stack_cookie > local_limit ||
		sizeof(uintptr_t) > local_limit - stack_cookie) {
		Log(L"[-] Stack cookie slot is outside the image, fix cookie skipped" << std::endl);
		return true;
	}

	if (*(uintptr_t*)(stack_cookie) == 0) {
		Log(L"[!] StackCookie slot is zero, load config looks unwritten, fix cookie skipped" << std::endl);
		return true;
	}

	//Default of the toolchain that produced this project; a different value
	//means the author compiled with a custom /GS cookie, which is supported.
	static constexpr uintptr_t kDefaultCookie = 0x2B992DDFA232;
	if (*(uintptr_t*)(stack_cookie) != kDefaultCookie)
		Log(L"[+] Non-default stack cookie found, remapping it anyway" << std::endl);

	Log(L"[+] Fixing stack cookie" << std::endl);

	auto new_cookie = kDefaultCookie ^ GetCurrentProcessId() ^ GetCurrentThreadId(); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == kDefaultCookie)
		new_cookie = kDefaultCookie + 1;

	*(uintptr_t*)(stack_cookie) = new_cookie; // the _security_cookie_complement will be init by the driver itself if they use crt
	return true;
}

/*
 * Fill the import address table of the local copy with kernel addresses.
 *
 * Each import is looked up in the module it names; when that fails it is
 * retried against ntoskrnl, which is where most driver imports actually live
 * even when the descriptor names a different module.
 *
 * Both import forms are resolved. An import by ordinal is legal and is how a
 * driver pulls a function whose name changes between releases; skipping it
 * would leave the IAT slot at 0 and the driver would jump there on its first
 * call to that function.
 *
 * Returns false, having written nothing further, on the first unresolvable
 * import - a partially resolved image would jump to 0 on the first call.
 */
static bool ResolveImports(const PE::vec_imports& imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = Utilities::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
			Log(L"[-] Dependency " << Utilities::ToWide(current_import.module_name) << L" wasn't found" << std::endl);
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			ULONG64 function_address = current_function_data.ordinal != 0
				? Driver::GetKernelModuleExportOrdinal(Module, current_function_data.ordinal)
				: Driver::GetKernelModuleExport(Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != Driver::ntoskrnlAddr) {
					function_address = current_function_data.ordinal != 0
						? Driver::GetKernelModuleExportOrdinal(Driver::ntoskrnlAddr, current_function_data.ordinal)
						: Driver::GetKernelModuleExport(Driver::ntoskrnlAddr, current_function_data.name);

					if (!function_address) {
						if (current_function_data.ordinal != 0) {
							Log(L"[-] Failed to resolve import ordinal " << current_function_data.ordinal
								<< L" (" << Utilities::ToWide(current_import.module_name) << L")" << std::endl);
						}
						else {
							Log(L"[-] Failed to resolve import " << Utilities::ToWide(current_function_data.name)
								<< L" (" << Utilities::ToWide(current_import.module_name) << L")" << std::endl);
						}
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}

/*
 * Map a driver image into the kernel.
 *
 * Sequence, and why it is in this order:
 *   1. validate the headers against the buffer we were given
 *   2. build a complete, fixed up image in user mode
 *   3. allocate kernel memory
 *   4. copy the finished image over in one write
 *   5. optionally set per section protection
 *   6. call DriverEntry
 *
 * Every fixup happens in user mode before the single kernel write, so a driver
 * that cannot be mapped fails without having created any kernel state.
 *
 * realBase is the allocation itself. When destroyHeader is set, kernel_image_base
 * is moved forward past the header so that the image is treated as starting at
 * its first section - but everything that is written or freed uses realBase, so
 * the shifted base is only ever used to compute addresses.
 */
ULONG64 Mapper::MapDriver(BYTE* data, size_t data_size, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode) {

	if (!data || data_size == 0) {
		Log(L"[-] No image data to map" << std::endl);
		return 0;
	}

	const PIMAGE_NT_HEADERS64 nt_headers = PE::GetNtHeaders(data, data_size);

	if (!nt_headers) {
		Log(L"[-] Invalid format of PE image" << std::endl);
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Log(L"[-] Image is not 64 bit" << std::endl);
		return 0;
	}

	ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;

	//Every bound below is checked before it is used: the image is untrusted
	//input, so SizeOfHeaders/section spans are validated against the allocation
	//instead of being trusted.
	if (image_size == 0 || nt_headers->OptionalHeader.SizeOfHeaders > image_size ||
		nt_headers->OptionalHeader.SizeOfHeaders > data_size) {
		Log(L"[-] Invalid image size in PE headers" << std::endl);
		return 0;
	}

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	if (destroyHeader && TotalVirtualHeaderSize > image_size) {
		Log(L"[-] Header span exceeds the image, refusing to skip it" << std::endl);
		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	ULONG64 kernel_image_base = 0;
	if (mode == AllocationMode::AllocateIndependentPages)
	{
		kernel_image_base = Driver::MmAllocateIndependentPagesEx(image_size);
	}
	else { // AllocatePool by default
		kernel_image_base = Driver::AllocatePool(Nt::POOL_TYPE::NonPagedPool, image_size);
	}

	if (!kernel_image_base) {
		Log(L"[-] Failed to allocate remote image in kernel" << std::endl);

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do {
		Log(L"[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl);

		const ULONG64 realBase = kernel_image_base;

		// Copy image headers

		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);
		bool sections_ok = true;

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;

			const uint32_t section_va = current_image_section[i].VirtualAddress;
			const uint32_t section_raw_size = current_image_section[i].SizeOfRawData;
			const uint32_t section_raw_ptr = current_image_section[i].PointerToRawData;

			if (section_raw_size == 0)
				continue;

			//The image is untrusted input: the destination must stay inside the
			//allocation we just made and the source inside the file buffer,
			//otherwise the copy reads and writes out of bounds.
			if (section_va > nt_headers->OptionalHeader.SizeOfImage ||
				section_raw_size > nt_headers->OptionalHeader.SizeOfImage - section_va) {
				Log(L"[-] Section " << SectionName(&current_image_section[i]) << L" does not fit in the image, aborted" << std::endl);
				sections_ok = false;
				break;
			}

			if (section_raw_ptr > data_size || section_raw_size > data_size - section_raw_ptr) {
				Log(L"[-] Section " << SectionName(&current_image_section[i]) << L" is truncated in the file, aborted" << std::endl);
				sections_ok = false;
				break;
			}

			auto local_section = reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image_base) + section_va);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<ULONG64>(data) + section_raw_ptr), section_raw_size);
		}

		if (!sections_ok)
			break;

		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
			Log(L"[+] Skipped 0x" << std::hex << TotalVirtualHeaderSize << std::dec << L" bytes of PE Header" << std::endl);
		}

		// Resolve relocs and imports

		const ULONG64 relocation_delta = kernel_image_base - nt_headers->OptionalHeader.ImageBase;

		PE::vec_relocs relocations;
		if (!PE::GetRelocs(local_image_base, nt_headers->OptionalHeader.SizeOfImage, relocations)) {
			Log(L"[-] Relocation directory is malformed, refusing to map" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (!RelocateImageByDelta(relocations, relocation_delta, reinterpret_cast<ULONG64>(local_image_base), nt_headers->OptionalHeader.SizeOfImage)) {
			Log(L"[-] Failed to apply relocations" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		/*
		 * A file with no relocation directory can only run at its preferred base,
		 * which is never where the kernel allocated this image. Without a .reloc
		 * there is nothing that says which fields need rewriting, so the only safe
		 * case is an image that holds no absolute pointer into itself - and that is
		 * checkable, so it is checked rather than assumed.
		 */
		if (relocations.empty()) {
			Log(L"[!] Image has no relocation directory; it can only load at its preferred base" << std::endl);

			if (!PE::VerifyNoAbsoluteReferences(local_image_base, nt_headers->OptionalHeader.SizeOfImage)) {
				Log(L"[-] Refusing to map: the image keeps absolute pointers into itself and has no relocations to fix them" << std::endl);
				kernel_image_base = realBase;
				break;
			}

			Log(L"[+] No absolute references into the image itself; safe to load at any address" << std::endl);
		}

		if (!FixSecurityCookie(local_image_base, nt_headers->OptionalHeader.SizeOfImage, kernel_image_base))
		{
			Log(L"[-] Failed to fix cookie" << std::endl);
			//Fall into the shared cleanup instead of returning: both the local
			//image and the kernel allocation would otherwise leak.
			kernel_image_base = realBase;
			break;
		}

		PE::vec_imports imports;
		if (!PE::GetImports(local_image_base, nt_headers->OptionalHeader.SizeOfImage, imports)) {
			Log(L"[-] Import directory is malformed, refusing to map" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (!ResolveImports(imports)) {
			Log(L"[-] Failed to resolve imports" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		// Write fixed image to kernel

		if (!Driver::WriteMemory(realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
			Log(L"[-] Failed to write local image to remote image" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		//Independent pages mode only. A pool block is RWX for its whole lifetime
		//because the provider cannot change protection on it; with independent
		//pages each section gets the protection its characteristics ask for,
		//which is closer to what the loader does.
		if (mode == AllocationMode::AllocateIndependentPages)
		{
			//Used only to make the protection readable in the log below.
			auto ProtectionToString = [](ULONG prot) -> const char* {
				switch (prot)
				{
				case PAGE_NOACCESS: return "NOACCESS";
				case PAGE_READONLY: return "READONLY";
				case PAGE_READWRITE: return "READWRITE";
				case PAGE_EXECUTE: return "EXECUTE";
				case PAGE_EXECUTE_READ: return "EXECUTE_READ";
				case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
				default: return "UNKNOWN";
				}
				};

			for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
				auto sec = &IMAGE_FIRST_SECTION(nt_headers)[i];
				uintptr_t secAddr = kernel_image_base + sec->VirtualAddress;
				uint32_t secSize = sec->Misc.VirtualSize;

				if (secSize == 0) {
					Log(L"[*] Skipping empty section: " << SectionName(sec) << std::endl);
					continue;
				}

				//The section span is file controlled and has to lie inside the
				//independent-pages allocation before its protection is changed.
				if (secAddr < realBase || secSize > image_size ||
					secAddr - realBase > image_size - secSize) {
					Log(L"[-] Section " << SectionName(sec) << L" lies outside the allocation, skipping protection change" << std::endl);
					continue;
				}

				ULONG prot = PAGE_READONLY;

				if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
					prot = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ?
						PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
					prot = PAGE_READWRITE;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_READ) {
					prot = PAGE_READONLY;
				}

				Log(L"[+] Setting protection for section: "
				<< SectionName(sec)
				<< L" Base: 0x" << std::hex << secAddr
				<< L" Size: 0x" << secSize
				<< L" Prot: " << ProtectionToString(prot)
				<< std::dec << std::endl);

				if (!Driver::MmSetPageProtection(secAddr, secSize, prot)) {
					Log(L"[-] Failed to set protection for section: " << SectionName(sec) << std::endl);
				}
			}
		}

		/*
		 * Call the driver entry point.
		 *
		 * Reached by hooking NtAddAtom (see Driver::CallKernelFunction), which
		 * is why a failure here is reported rather than fatal.
		 */
		const ULONG64 address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		Log(L"[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl);

		if (callback) {
			if (!callback(&param1, &param2, realBase, image_size)) {
				Log(L"[-] Callback returns false, failed!" << std::endl);
				kernel_image_base = realBase;
				break;
			}
		}

		NTSTATUS status = 0;
		if (!Driver::CallKernelFunction(&status, address_of_entry_point, (PassAllocationAddressAsFirstParam ? realBase : param1), param2)) {
			Log(L"[-] Failed to call driver entry" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (exitCode)
			*exitCode = status;

		Log(L"[+] DriverEntry returned 0x" << std::hex << status << std::dec << std::endl);

		//Optional early release, --free. Only safe for drivers that have copied
		//out everything they need, because the image becomes invalid as soon as
		//DriverEntry returns.
		if (free) {
			Log(L"[+] Freeing memory" << std::endl);
			bool free_status = false;

			if (mode == AllocationMode::AllocateIndependentPages)
			{
				free_status = Driver::MmFreeIndependentPages(realBase, image_size);
			}
			else {
				free_status = Driver::FreePool(realBase);
			}

			if (free_status) {
				Log(L"[+] Memory has been released" << std::endl);
			}
			else {
				Log(L"[-] WARNING: Failed to free memory!" << std::endl);
			}
		}

	//Success: the driver is loaded. The user mode copy is no longer needed.
	VirtualFree(local_image_base, 0, MEM_RELEASE);
	return realBase;

} while (false);

//Every failure path above breaks out with kernel_image_base reset to realBase,
//so this release always frees the allocation itself and never the header
//shifted address.
VirtualFree(local_image_base, 0, MEM_RELEASE);

Log(L"[+] Freeing memory" << std::endl);
bool free_status = false;

if (mode == AllocationMode::AllocateIndependentPages)
{
	free_status = Driver::MmFreeIndependentPages(kernel_image_base, image_size);
}
else {
	free_status = Driver::FreePool(kernel_image_base);
}

if (free_status) {
	Log(L"[+] Memory has been released" << std::endl);
}
else {
	Log(L"[-] WARNING: Failed to free memory!" << std::endl);
}

return 0;
}
