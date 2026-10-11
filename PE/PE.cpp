/*
 * PE parsing over an untrusted buffer. See PE.hpp for the rule this file
 * follows: nothing derived from the image is dereferenced before it has been
 * shown to lie inside the buffer.
 */

#include "PE.hpp"

#include <Windows.h>
#include <string>

PIMAGE_NT_HEADERS64 PE::GetNtHeaders(void* image_base, size_t image_size) {
	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	//e_lfanew is attacker controlled, so it must point inside the buffer and
	//leave room for the full NT header.
	const auto image = reinterpret_cast<ULONG64>(image_base);
	if (dos_header->e_lfanew < 0 ||
		static_cast<size_t>(dos_header->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > image_size)
		return nullptr;

	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(image + dos_header->e_lfanew);

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	return nt_headers;
}

bool PE::GetRelocs(void* image_base, size_t image_size, vec_relocs& relocs) {
	relocs.clear();

	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base, image_size);

	if (!nt_headers)
		return false;

	const DWORD reloc_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	const DWORD reloc_size = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	//An image with no relocations can only be loaded at its preferred base.
	//Fix from @greetmark of UnknownCheats Forum.
	if (!reloc_va || !reloc_size)
		return true;

	//A directory that claims to sit outside the image is malformed, not empty.
	//The walk below would run off the end of the buffer.
	//
	//SizeOfImage and the buffer length are two different bounds and both are
	//checked: SizeOfImage is a value from the file, while image_size is the
	//length of the allocation the caller actually handed over. A caller that
	//passes a buffer shorter than the image declares must have the walk refused
	//here, because reloc_end is computed from the declared size and would
	//otherwise point past the end of the allocation the loop reads through.
	if (reloc_va >= nt_headers->OptionalHeader.SizeOfImage ||
		reloc_size > nt_headers->OptionalHeader.SizeOfImage - reloc_va ||
		reloc_va >= image_size ||
		reloc_size > image_size - reloc_va)
		return false;

	/*
	 * End of the buffer, as an address rather than a length.
	 *
	 * This used to be `image_size` on its own, which is a length, and it was
	 * compared against `block_start + SizeOfBlock` - an absolute address. On
	 * x64 image_base is always a large address, so that sum exceeded the length
	 * on the very first block and GetRelocs refused every image that carried a
	 * .reloc directory. It never showed up because the only driver ever mapped
	 * had no relocations at all; --selftest catches it.
	 */
	const ULONG64 image_end = reinterpret_cast<ULONG64>(image_base) + image_size;
	auto current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG64>(image_base) + reloc_va);
	const ULONG64 reloc_end = reinterpret_cast<ULONG64>(current_base_relocation) + reloc_size;

	while (reinterpret_cast<ULONG64>(current_base_relocation) < reloc_end && current_base_relocation->SizeOfBlock) {
		const ULONG64 block_start = reinterpret_cast<ULONG64>(current_base_relocation);

		//SizeOfBlock is file controlled: a block that claims to be larger than
		//what is left would let the relocation loop below read past the buffer.
		//The whole image is refused rather than stopping here: a partially
		//applied relocation set leaves pointers aimed at the preferred base,
		//and the first use of one is a bugcheck.
		if (current_base_relocation->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
			block_start + current_base_relocation->SizeOfBlock > image_end)
			return false;

		RelocInfo reloc_info;

		reloc_info.address = reinterpret_cast<ULONG64>(image_base) + current_base_relocation->VirtualAddress;
		reloc_info.item = reinterpret_cast<USHORT*>(block_start + sizeof(IMAGE_BASE_RELOCATION));
		reloc_info.count = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);

		relocs.push_back(reloc_info);

		current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(block_start + current_base_relocation->SizeOfBlock);
	}

	return true;
}

bool PE::GetImports(void* image_base, size_t image_size, vec_imports& imports) {
	imports.clear();

	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base, image_size);

	if (!nt_headers)
		return false;

	DWORD import_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	//No imports to resolve.
	if (!import_va)
		return true;

	const DWORD size_of_image = nt_headers->OptionalHeader.SizeOfImage;
	//A non-zero directory that points outside the image is malformed, not
	//empty: the descriptor walk below would start out of bounds.
	if (import_va >= size_of_image)
		return false;

	//The end of the buffer the image occupies. Every pointer derived from the
	//image below is checked against it before it is dereferenced.
	const auto image_limit = reinterpret_cast<ULONG64>(image_base) + size_of_image;

	auto current_import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<ULONG64>(image_base) + import_va);

	//The directory is walked until its all-zero terminator, the same way the
	//loader walks it; the declared directory size is not used to stop the walk.
	//The hard bound is the image, so a directory that never terminates is
	//refused instead of read past the end of the buffer. Stopping at that bound
	//without a terminator would silently drop imports and leave IAT slots at
	//the file's placeholder values.
	bool terminated = false;

	while (reinterpret_cast<ULONG64>(current_import_descriptor) + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= image_limit) {
		if (!current_import_descriptor->FirstThunk) {
			terminated = true;
			break;
		}

		ImportInfo import_info;

		//Every field below is file controlled and is checked against the image
		//before it is dereferenced. A field that is out of range is a broken
		//descriptor: returning an incomplete import list would map a driver
		//whose IAT still points into the file, so the whole image is refused.

		//The module name is a null terminated string: both it and its
		//terminator have to sit inside the image.
		if (current_import_descriptor->Name >= size_of_image)
			return false;

		const auto module_name_ptr = reinterpret_cast<const char*>(reinterpret_cast<ULONG64>(image_base) + current_import_descriptor->Name);
		const size_t module_name_max = static_cast<size_t>(image_limit - reinterpret_cast<ULONG64>(module_name_ptr));
		const size_t module_name_len = strnlen_s(module_name_ptr, module_name_max);
		if (module_name_len == module_name_max)
			return false;

		import_info.module_name = std::string(module_name_ptr, module_name_len);

		//FirstThunk is addressed by a file controlled RVA and has to fit inside
		//the image before the thunk loop below reads it.
		if (current_import_descriptor->FirstThunk >= size_of_image ||
			sizeof(IMAGE_THUNK_DATA64) > size_of_image - current_import_descriptor->FirstThunk)
			return false;

		auto current_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<ULONG64>(image_base) + current_import_descriptor->FirstThunk);

		//OriginalFirstThunk (the name table) is optional and is absent in some
		//linker outputs. Reading it unconditionally then walks from the DOS
		//header and resolves garbage, so fall back to FirstThunk, which the
		//loader fills in with the same names before binding. A present but out
		//of range value is a broken descriptor and refuses the image.
		PIMAGE_THUNK_DATA64 name_table = current_first_thunk;
		if (current_import_descriptor->OriginalFirstThunk) {
			if (current_import_descriptor->OriginalFirstThunk >= size_of_image ||
				sizeof(IMAGE_THUNK_DATA64) > size_of_image - current_import_descriptor->OriginalFirstThunk)
				return false;

			name_table = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<ULONG64>(image_base) + current_import_descriptor->OriginalFirstThunk);
		}

		//The thunk array is terminated by a zero entry and is required to stay
		//inside the image on both the name table and the IAT side. Running into
		//the end of the image without a terminator is a broken descriptor.
		//Ordinal imports are skipped only for the name lookup: they are
		//collected with their ordinal instead.
		while (true) {
			if (reinterpret_cast<ULONG64>(name_table) + sizeof(IMAGE_THUNK_DATA64) > image_limit ||
				reinterpret_cast<ULONG64>(current_first_thunk) + sizeof(IMAGE_THUNK_DATA64) > image_limit)
				return false;

			if (!name_table->u1.Function || !current_first_thunk->u1.Function)
				break;

			//An import is either a name/hint pair or a bare ordinal. Both are
			//legal, and both have to end up resolved: skipping one leaves the IAT
			//slot at 0, which the driver jumps to on its first call to it.
			if (!(name_table->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
				//The name/hint pair has to fit, and its name has to be null
				//terminated inside the image.
				if (name_table->u1.AddressOfData >= size_of_image ||
					sizeof(WORD) > size_of_image - name_table->u1.AddressOfData)
					return false;

				const auto thunk_data = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<ULONG64>(image_base) + name_table->u1.AddressOfData);
				const auto import_name_ptr = reinterpret_cast<const char*>(thunk_data->Name);
				const size_t import_name_max = static_cast<size_t>(image_limit - reinterpret_cast<ULONG64>(import_name_ptr));
				const size_t import_name_len = strnlen_s(import_name_ptr, import_name_max);
				if (import_name_len == import_name_max)
					return false;

				ImportFunctionInfo import_function_data;
				import_function_data.name = std::string(import_name_ptr, import_name_len);
				import_function_data.address = &current_first_thunk->u1.Function;

				import_info.function_datas.push_back(import_function_data);
			}
			else {
				ImportFunctionInfo import_function_data;
				import_function_data.ordinal = static_cast<uint16_t>(name_table->u1.Ordinal & 0xFFFF);
				import_function_data.address = &current_first_thunk->u1.Function;

				import_info.function_datas.push_back(import_function_data);
			}

			++name_table;
			++current_first_thunk;
		}

		imports.push_back(import_info);
		++current_import_descriptor;
	}

	//A descriptor walk that ran into its bound instead of the terminator means
	//the directory is truncated; see the comment on `terminated`.
	if (!terminated)
		return false;

	return true;
}

/*
 * Prove an image carries no absolute address into itself. See PE.hpp for why
 * this exists and why only section data is scanned.
 *
 * Reports through the return value only: this file has no logging of its own,
 * so the caller turns a false into the operator-facing message.
 */
bool PE::VerifyNoAbsoluteReferences(void* image_base, size_t image_size) {
	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base, image_size);

	if (!nt_headers)
		return false;

	const ULONG64 preferred_base = nt_headers->OptionalHeader.ImageBase;
	const ULONG32 image_size_declared = nt_headers->OptionalHeader.SizeOfImage;

	//A preferred base of 0 or a size of 0 means the headers are not usable, and
	//scanning against them would either match everything or nothing.
	if (preferred_base == 0 || image_size_declared == 0)
		return false;

	const auto base_address = reinterpret_cast<ULONG64>(image_base);
	const auto section = IMAGE_FIRST_SECTION(nt_headers);

	for (uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
		const ULONG32 virtual_size = section[i].Misc.VirtualSize;
		const ULONG32 raw_size = section[i].SizeOfRawData;

		//Uninitialised sections hold no file bytes, so there is nothing to scan.
		if (virtual_size == 0 || raw_size == 0)
			continue;

		//What the section actually occupies in the mapped image, and it has to
		//stay inside the buffer we were handed.
		const ULONG32 scan_length = virtual_size < raw_size ? virtual_size : raw_size;
		if (section[i].VirtualAddress > image_size ||
			scan_length > image_size - section[i].VirtualAddress)
			return false;

		const auto start = base_address + section[i].VirtualAddress;

		for (ULONG32 offset = 0; offset + sizeof(ULONG64) <= scan_length; offset += sizeof(ULONG64)) {
			const ULONG64 value = *reinterpret_cast<const ULONG64*>(start + offset);

			//A pointer back into this image is a field that was never relocated.
			if (value >= preferred_base && value < preferred_base + image_size_declared)
				return false;
		}
	}

	return true;
}
