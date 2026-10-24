#include "Mapper.hpp"
#include <Windows.h>
#include <iostream>
#include <random>

#include "../Utilities/Utilities.hpp"
#include "../Utilities/Console.hpp"
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
bool Mapper::RelocateImageByDelta(const PE::vec_relocs& relocs, const ULONG64 delta, const ULONG64 image_base, const ULONG64 image_size) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (type != IMAGE_REL_BASED_DIR64) {
				Log(L"[-] Unsupported relocation type " << Val(type) << L" at page "
					<< Val(Hex(current_reloc.address + offset))
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
				Log(L"[-] Relocation target " << Val(Hex(target - image_base))
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
 * A replacement /GS cookie for FixSecurityCookie below.
 *
 * Unpredictable rather than derived: the cookie's only job is to make
 * __security_check_cookie fail when something has written past a local buffer,
 * so a value an attacker can compute is a value an attacker writes past. See the
 * call site for what this replaced.
 */
static uintptr_t RandomSecurityCookie() {
	//Lazy, so the generator is seeded once per run rather than on every image.
	static std::mt19937_64 engine{ std::random_device{}() };

	uintptr_t value = 0;
	//Two outcomes are excluded rather than one: 0, which is the value
	//__security_check_cookie compares against, and ~0, whose complement is 0 -
	//so the pair the CRT keeps consistent can never be (0, ~0) by accident.
	do {
		value = static_cast<uintptr_t>(engine());
	} while (value == 0 || value == ~static_cast<uintptr_t>(0));

	return value;
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
bool Mapper::FixSecurityCookie(void* local_image, size_t image_size, ULONG64 kernel_image_base)
{
	auto headers = PE::GetNtHeaders(local_image, image_size);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		Log(L"[INFO] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	/*
	 * Only the bytes up to and including SecurityCookie are read, and how many
	 * those are comes from the image rather than from the SDK.
	 *
	 * The declared directory Size is what the file says the load config occupies,
	 * and most drivers emit a load config far smaller than the current
	 * IMAGE_LOAD_CONFIG_DIRECTORY - the SDK has grown members over time and old
	 * drivers never gained them. Requiring the whole SDK struct to fit therefore
	 * refused a perfectly usable image whose load config sat near the end of its
	 * section, and because that refusal returns true with a log line, the cookie
	 * was silently left unfixed. The declared Size has to cover the cookie field
	 * itself, and only that field has to be inside the buffer.
	 */
	const DWORD load_config_size = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
	const size_t cookie_field_end = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(uintptr_t);

	//The load config directory is a file controlled RVA: it has to lie inside
	//the local image, with room for the field that is read from it.
	if (load_config_size < cookie_field_end ||
		load_config_directory >= image_size ||
		cookie_field_end > image_size - load_config_directory)
	{
		Log(L"[-] Load config directory is truncated or outside the image, fix cookie skipped" << std::endl);
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		Log(L"[INFO] StackCookie not defined, fix cookie skipped" << std::endl);
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
		Log(L"[INFO] Non-default stack cookie found, remapping it anyway" << std::endl);

	Log(L"[+] Fixing stack cookie" << std::endl);

	/*
	 * The replacement value only has to be unpredictable to anything that can read
	 * the image out of memory, because the check it backs is a canary: a guessable
	 * cookie is one an attacker writes past.
	 *
	 * It used to be the toolchain default XORed with the process and thread ids.
	 * All three inputs are printed by any process enumerator on the box and the
	 * constant is in this source, so the whole expression was public - it cost a
	 * few clocks over a constant and bought nothing. Drawn from the process PRNG
	 * instead, seeded once from std::random_device.
	 */
	/*
	 * The high 16 bits stay zero: that is the invariant the toolchain's default
	 * cookie (0x2B992DDFA232) has, and everything that compares against the
	 * cookie in this image was linked for a value in that range. The image is
	 * entered through Entry, not GsDriverEntry, so __security_init_cookie never
	 * runs and the link-time cookie/complement pair is never re-derived here -
	 * a full 64-bit replacement leaves that pair inconsistent, and
	 * __security_check_cookie then fails on a cookie nothing corrupted, i.e. a
	 * 0x139 (subcode 2) inside the driver on its first protected function.
	 *
	 * Zero stays excluded as well: it is the value the check treats as "cookie
	 * not initialised".
	 */
	uintptr_t new_cookie = 0;
	do {
		new_cookie = RandomSecurityCookie() & static_cast<uintptr_t>(0x0000FFFFFFFFFFFFull);
	} while (new_cookie == 0);

	//Kept separate from the image's own .data on purpose: the CRT
	//(GsDriverEntry -> __security_init_cookie) re-derives the complement from
	//whatever it finds in the cookie slot during the driver's own startup, so it
	//must not be pre-set here to a value that disagrees with what is written
	//above. A driver that never calls the CRT initialiser keeps its link-time
	//complement, which is the same limitation this comment already described.
	*(uintptr_t*)(stack_cookie) = new_cookie;
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
/*
 * Resolves one import against the live kernel.
 *
 * This is what MapDriver passes as the ImportResolver, and the only part of
 * import handling that touches the kernel. Kept separate from ResolveImports so
 * that function stays testable without a provider.
 */
static bool ResolveImportFromKernel(const Mapper::ImportLookup& request, void*, ULONG64& out_address) {
	if (!request.module_base)
		return false;

	out_address = request.ordinal != 0
		? Driver::GetKernelModuleExportOrdinal(request.module_base, request.ordinal)
		: Driver::GetKernelModuleExport(request.module_base, *request.name);

	return out_address != 0;
}

bool Mapper::ResolveImports(const PE::vec_imports& imports, ImportResolver resolver, void* context) {
	if (!resolver)
		return false;

	for (const auto& current_import : imports) {
		const ULONG64 Module = Utilities::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
			Log(L"[-] Dependency " << Val(Utilities::ToWide(current_import.module_name)) << L" wasn't found" << std::endl);
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			ImportLookup request{};
			request.module_base = Module;
			request.name = current_function_data.ordinal ? nullptr : &current_function_data.name;
			request.ordinal = current_function_data.ordinal;

			ULONG64 resolved = 0;
			if (resolver(request, context, resolved)) {
				*current_function_data.address = resolved;
				continue;
			}

			//Lets try with ntoskrnl. Most driver imports name a module other than
			//ntoskrnl but live in it, so the first module is frequently the wrong
			//place to look. When the descriptor already named ntoskrnl there is no
			//second module left to try, so that is simply the failure.
			if (Module != Driver::ntoskrnlAddr) {
				ImportLookup fallback = request;
				fallback.module_base = Driver::ntoskrnlAddr;

				if (resolver(fallback, context, resolved)) {
					*current_function_data.address = resolved;
					continue;
				}
			}

			if (current_function_data.ordinal != 0) {
				Log(L"[-] Failed to resolve import ordinal " << Val(current_function_data.ordinal)
					<< L" (" << Val(Utilities::ToWide(current_import.module_name)) << L")" << std::endl);
			}
			else {
				Log(L"[-] Failed to resolve import " << Val(Utilities::ToWide(current_function_data.name))
					<< L" (" << Val(Utilities::ToWide(current_import.module_name)) << L")" << std::endl);
			}
			return false;
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
ULONG64 Mapper::MapDriver(BYTE* data, size_t data_size, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, NTSTATUS* exitCode) {

	if (!data || data_size == 0) {
		Log(L"[-] No image data to map" << std::endl);
		return 0;
	}

	const PIMAGE_NT_HEADERS64 nt_headers = PE::GetNtHeaders(data, data_size);

	if (!nt_headers) {
		Log(L"[-] Invalid format of PE image (not a PE32+ image, or its headers do not fit)" << std::endl);
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

	//The section table is located once, here, and every walk below uses this
	//pointer rather than recomputing IMAGE_FIRST_SECTION. Its position comes from
	//the file controlled SizeOfOptionalHeader, so the check that proves the table
	//fits inside the buffer is what the three loops below were relying on without
	//making.
	PIMAGE_SECTION_HEADER image_section = nullptr;
	uint16_t section_count = 0;
	if (!PE::GetSectionTable(data, data_size, image_section, section_count)) {
		Log(L"[-] Section table is outside the file, refusing to map" << std::endl);
		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	if (section_count == 0) {
		Log(L"[-] Image has no sections, refusing to map" << std::endl);
		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	/*
	 * How much of the image sits ahead of the first section.
	 *
	 * The header span is the lowest VirtualAddress of any section, not the first
	 * section's. Reading it off section[0] assumed the table is ordered by
	 * ascending RVA, which is a convention and not a guarantee: an unsorted table
	 * produced a header size that was wrong, and because that one value feeds the
	 * allocation size, the relocation delta and the entry point together, every
	 * one of them was wrong in the same direction and the failure surfaced later
	 * and far from its cause. The minimum is correct whatever order the table is
	 * in, and costs one pass.
	 */
	DWORD TotalVirtualHeaderSize = image_section[0].VirtualAddress;
	for (uint16_t i = 1; i < section_count; ++i) {
		if (image_section[i].VirtualAddress < TotalVirtualHeaderSize)
			TotalVirtualHeaderSize = image_section[i].VirtualAddress;
	}
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
	else if (mode == AllocationMode::AllocateContiguous)
	{
		//Page aligned, so the image occupies whole pages: a driver that hides
		//its own image page by page must not be handed a base that shares its
		//first page with a POOL_HEADER.
		kernel_image_base = Driver::AllocateContiguous(image_size);
	}
	else { // AllocatePool
		kernel_image_base = Driver::AllocatePool(Nt::POOL_TYPE::NonPagedPool, image_size);
	}

	if (!kernel_image_base) {
		Log(L"[-] Failed to allocate remote image in kernel" << std::endl);

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do {
		LogBlank();
		Log(L"[+] Image base has been allocated at " << Val(reinterpret_cast<void*>(kernel_image_base)) << std::endl);
		LogBlank();

		const ULONG64 realBase = kernel_image_base;

		// Copy image headers

		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = image_section;
		bool sections_ok = true;

		for (auto i = 0; i < section_count; ++i) {
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
				Log(L"[-] Section " << Val(SectionName(&current_image_section[i])) << L" does not fit in the image, aborted" << std::endl);
				sections_ok = false;
				break;
			}

			if (section_raw_ptr > data_size || section_raw_size > data_size - section_raw_ptr) {
				Log(L"[-] Section " << Val(SectionName(&current_image_section[i])) << L" is truncated in the file, aborted" << std::endl);
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
			Log(L"[INFO] Skipped " << Val(Hex(TotalVirtualHeaderSize)) << L" Bytes of PE Header" << std::endl);
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
			/*
			 * Say exactly what was checked.
			 *
			 * This proves one thing only: no 64-bit value inside the section data
			 * still points into the image's own preferred range, so no pointer
			 * into the image itself survives the move. It is not a general proof
			 * that the image is safe to load anywhere - it says nothing about
			 * the import table, about the IAT the resolver is about to rewrite,
			 * or about the .pdata unwind entries the unwinder reads. An image
			 * whose only hazard is its IAT is fine, because the resolver
			 * rewrites those entries before anything runs.
			 *
			 * realBase, not kernel_image_base: with the header skipped the latter
			 * is the address the relocation delta was computed from, but it is
			 * not where the image lands. Quoting it here named an address no
			 * code pointer ends up at.
			 */
			if (!PE::VerifyNoAbsoluteReferences(local_image_base, nt_headers->OptionalHeader.SizeOfImage)) {
				Log(L"[-] Refusing to map: the image keeps absolute pointers into itself and has no relocations to fix them" << std::endl);
				kernel_image_base = realBase;
				break;
			}

			Log(L"[INFO] Verified: no absolute self-pointers, safe to load at "
				<< Val(reinterpret_cast<void*>(realBase)) << std::endl);
			Log(L"[INFO] Image has no relocation directory; it can only load at its preferred base" << std::endl);
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

		if (!Mapper::ResolveImports(imports, ResolveImportFromKernel, nullptr)) {
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

			int protection_failures = 0;

			for (int i = 0; i < section_count; i++) {
				auto sec = &image_section[i];
				uintptr_t secAddr = kernel_image_base + sec->VirtualAddress;
				uint32_t secSize = sec->Misc.VirtualSize;

				if (secSize == 0) {
					Log(L"[*] Skipping empty section: " << Val(SectionName(sec)) << std::endl);
					continue;
				}

				//The section span is file controlled and has to lie inside the
				//independent-pages allocation before its protection is changed.
				if (secAddr < realBase || secSize > image_size ||
					secAddr - realBase > image_size - secSize) {
					Log(L"[-] Section " << Val(SectionName(sec)) << L" lies outside the allocation, skipping protection change" << std::endl);
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
				<< Val(SectionName(sec))
				<< L" Base: " << Val(Hex(secAddr))
				<< L" Size: " << Val(Hex(secSize))
				<< L" Prot: " << Val(ProtectionToString(prot))
				<< std::endl);

				if (!Driver::MmSetPageProtection(secAddr, secSize, prot)) {
					//Counted, not just logged. A section that should be
					//PAGE_EXECUTE_READ but stayed PAGE_READWRITE prints exactly one
					//line and is then indistinguishable from every other section in
					//the log, so a run where the protection call was unavailable
					//across the board read as a clean success. The summary below
					//says how many of them there were.
					Log(L"[-] Failed to set protection for section: " << Val(SectionName(sec)) << std::endl);
					++protection_failures;
				}
			}

			if (protection_failures) {
				Log(L"[!] " << Val(protection_failures) << L" of " << Val(static_cast<int>(section_count))
					<< L" section(s) were left with the allocation's default protection" << std::endl);
			}
		}

		/*
		 * Call the driver entry point.
		 *
		 * Reached by hooking NtAddAtom (see Driver::CallKernelFunction), which
		 * is why a failure here is reported rather than fatal.
		 */
		const ULONG64 address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		/*
		 * Build the DRIVER_OBJECT this driver is entered with.
		 *
		 * DriverEntry's first argument is a PDRIVER_OBJECT and a driver calls
		 * IoCreateDevice before it has done anything else, which dereferences
		 * DriverExtension and its back-pointer. Passing NULL there is not
		 * something a driver can ignore - it is a bugcheck on the first call -
		 * so a real object is built unless the caller explicitly asked for the
		 * raw allocation pointer instead.
		 *
		 * DriverSection is given the image base. A driver that reads it (to
		 * compare against its own image, for instance) sees a plausible
		 * address; there is no real section object, because fabricating one
		 * means walking kernel loader structures that only the load path owns.
		 *
		 * Lives until after DriverEntry returns, and on the success path it is
		 * deliberately not released: the driver holds a reference to it for as
		 * long as it is loaded, exactly like the image itself.
		 */
		ULONG64 driver_object = 0;
		if (PassAllocationAddressAsFirstParam) {
			Log(L"[INFO] Passing the allocation base as the first DriverEntry argument, as requested" << std::endl);
			param1 = realBase;
		}
		else {
			driver_object = Driver::CreateDriverObjectForEntry(realBase, image_size, realBase);
			if (!driver_object) {
				Log(L"[-] Failed to build the driver object; refusing to call DriverEntry with a null one" << std::endl);
				kernel_image_base = realBase;
				break;
			}

			/*
			 * DriverEntry must actually receive the object, otherwise the
			 * driver sees a null first argument and cannot record its range.
			 */
			param1 = driver_object;
		}

		/*
		 * Announced here rather than before the object is built: the banner said
		 * "calling DriverEntry" while a DRIVER_OBJECT still had to be created,
		 * so the setup line printed under it and made the order look wrong.
		 *
		 * The two arguments are printed as they are actually passed rather than
		 * labelled "DriverObject", because --PassAllocationPtr deliberately
		 * passes something else and a fixed label would then name a null.
		 */
		LogBlank();
		Log(L"[!] Calling DriverEntry | Entry " << Val(reinterpret_cast<void*>(address_of_entry_point))
			<< L" | DriverEntry (" << Val(param1) << L", " << Val(param2) << L")" << std::endl);

		NTSTATUS status = 0;
		if (!Driver::CallKernelFunction(&status, address_of_entry_point, param1, param2)) {
			/*
			 * The hook never went in, so DriverEntry never executed. Nothing the
			 * driver would have owned exists yet, so releasing both the image and
			 * the object it would have been given is safe here.
			 *
			 * The other direction is the one that must not happen: once
			 * CallKernelFunction returns true the driver has run and holds
			 * pointers into both, and no failure from here on may free them.
			 */
			Log(L"[-] Failed to call driver entry" << std::endl);

			if (driver_object) {
				Driver::DestroyDriverObjectForEntry(driver_object);
				driver_object = 0;
			}

			kernel_image_base = realBase;
			break;
		}

		/*
		 * DriverEntry has run, so the allocation and the driver object are now
		 * owned in part by the driver. Capture the hook outcome, which is
		 * reported separately from the call above, and carry on to the success
		 * return below regardless: a failed restore is an emergency to surface,
		 * not a reason to release memory the driver is using.
		 */
		const bool hook_restored = Driver::RestoreSucceeded();

		if (exitCode)
			*exitCode = status;

		Log(L"[+] DriverEntry returned: " << Val(Hex(status)) << std::endl);

		if (!hook_restored)
			Log(L"[!] ntoskrnl.NtAddAtom was not restored; the image is kept because the "
				"driver may still reference it. See the earlier CRITICAL line." << std::endl);

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
			else if (mode == AllocationMode::AllocateContiguous)
			{
				free_status = Driver::MmFreeContiguousMemory(realBase);
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

		/*
		 * Say plainly what is still resident.
		 *
		 * Without --free the image, and the driver object it was entered with,
		 * stay in kernel memory with no loader entry pointing at them. Nothing
		 * can reach them again and nothing reclaims them before a reboot, which
		 * is the intended outcome for a driver that is meant to stay loaded -
		 * but it used to be invisible, and a run that only prints "mapped
		 * successfully" reads like nothing was left behind.
		 */
		LogBlank();
		if (free) {
			Log(L"[+] Image released (--free); only the driver object at "
				<< Val(reinterpret_cast<void*>(driver_object))
				<< L" remains, which the loaded driver still references" << std::endl);
		}
		else {
			//Dot leaders, so the values line up under each other instead of sitting after
			//labels of different widths. Each label is padded with dots to a fixed
			//20 character field: "Image" is 5 so it takes 15, "Driver Object" is 13
			//so it takes 7. Both fields are then the same width, so the two spaces
			//that follow put both values in the same column.
			Log(L"[+] Resident In Kernel Memory:" << std::endl);
			LogBlank();
			Log(L"      Image...............  " << Val(reinterpret_cast<void*>(realBase))
				<< L"   (" << Val(Hex(image_size)) << L" Bytes)" << std::endl);
			if (driver_object)
				Log(L"      Driver Object.......  " << Val(reinterpret_cast<void*>(driver_object)) << std::endl);
		}
		LogBlank();

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
	else if (mode == AllocationMode::AllocateContiguous)
	{
		free_status = Driver::MmFreeContiguousMemory(kernel_image_base);
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
