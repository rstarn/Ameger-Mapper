/*
 * PE parsing over an untrusted buffer. See PE.hpp for the rule this file
 * follows: nothing derived from the image is dereferenced before it has been
 * shown to lie inside the buffer.
 */

#include "PE.hpp"

#include <Windows.h>
#include <string>

PIMAGE_NT_HEADERS64 PE::GetNtHeaders(void* image_base, size_t image_size) {
	//e_magic is at offset 0 and e_lfanew at 0x3C, so the DOS header has to fit
	//before either is read. Without this a four byte file was an out of bounds
	//read in the mapper's own address space rather than a refused image.
	if (image_size < sizeof(IMAGE_DOS_HEADER))
		return nullptr;

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

	//A PE32 image has the same Signature and the same DOS stub. Everything this
	//file reads afterwards - ImageBase, Subsystem, SizeOfImage, the DataDirectory
	//entries and the offset of the section table - is a different width or a
	//different offset there, so parsing one as PE32+ yields values that look
	//reasonable and are wrong. Refused here, once, rather than at each consumer.
	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return nullptr;

	return nt_headers;
}

/*
 * The section table sits at the end of the optional header, whose length is the
 * file controlled SizeOfOptionalHeader, so its position is only known after that
 * field has been read - and it has to be read before anything below can be
 * trusted. The span is then computed as a byte offset into the buffer and proved
 * to fit, rather than as a pointer comparison, so the arithmetic cannot wrap.
 */
bool PE::GetSectionTable(void* image_base, size_t image_size, PIMAGE_SECTION_HEADER& out_sections, uint16_t& out_count) {
	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base, image_size);

	if (!nt_headers)
		return false;

	//The number of entries is a file controlled WORD and each entry is 40 bytes,
	//so the table it claims is at most 2.6 MB. Widened before the multiply.
	const size_t table_bytes = static_cast<size_t>(nt_headers->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);

//IMAGE_FIRST_SECTION expands to the optional header plus SizeOfOptionalHeader,
	//so the same sum taken from the NT header base is the same address, expressed
	//as an offset into the buffer that can be range checked without any pointer
	//arithmetic.
	//
	//The NT header's offset is e_lfanew, taken from the DOS header, rather than a
	//difference of two PIMAGE_NT_HEADERS64 pointers. Those two pointers are not
	//into the same array - one points at the start of the caller's byte buffer and
	//the other 128 bytes into it - so subtracting them is undefined behaviour, and
	//MSVC resolves it by dividing the byte distance by sizeof(IMAGE_NT_HEADERS64)
	//and truncating, which turns every e_lfanew below 264 into an offset of 0.
	//e_lfanew is the field GetNtHeaders just validated and used to place the
	//headers, so reading it again says the same thing without the arithmetic.
	const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
	const size_t nt_offset = static_cast<size_t>(dos_header->e_lfanew);
	const size_t table_offset = nt_offset
		+ offsetof(IMAGE_NT_HEADERS, OptionalHeader)
		+ static_cast<size_t>(nt_headers->FileHeader.SizeOfOptionalHeader);

	//Written as a subtraction from the buffer length rather than as a sum against
	//a pointer, so an oversized SizeOfOptionalHeader cannot wrap the check.
	if (table_offset > image_size || table_bytes > image_size - table_offset)
		return false;

	out_sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(
		reinterpret_cast<BYTE*>(image_base) + table_offset);
	out_count = nt_headers->FileHeader.NumberOfSections;
	return true;
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
	 * had no relocations at all; mapping a relocatable image catches it.
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

	const DWORD declared_size = nt_headers->OptionalHeader.SizeOfImage;

	/*
	 * Two different bounds, and both are needed.
	 *
	 * SizeOfImage is a value from the file, so on its own it proves nothing about
	 * where the caller's buffer ends - it is exactly what an over-long walk would
	 * rely on. image_size is the length of the allocation that was actually handed
	 * over. Bounding the walk by whichever is smaller means a caller that passed a
	 * buffer shorter than the image declares cannot be walked off the end of, and
	 * this is the same pair GetRelocs checks; see the comment there for why the
	 * declared size alone was never enough.
	 */
	const size_t image_extent = declared_size < image_size
		? static_cast<size_t>(declared_size) : image_size;

	if (image_extent == 0)
		return true;

	//A non-zero directory that points outside the image is malformed, not
	//empty: the descriptor walk below would start out of bounds.
	if (import_va >= image_extent)
		return false;

	//The end of the buffer the image occupies. Every pointer derived from the
	//image below is checked against it before it is dereferenced. Written as a
	//subtraction from the base rather than as a sum so the end cannot wrap.
	const auto image_limit = reinterpret_cast<ULONG64>(image_base) + image_extent;

	auto current_import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<ULONG64>(image_base) + import_va);

	//The directory is walked until its all-zero terminator, the same way the
	//loader walks it; the declared directory size is not used to stop the walk.
	//The hard bound is the image, so a directory that never terminates is
	//refused instead of read past the end of the buffer. Stopping at that bound
	//without a terminator would silently drop imports and leave IAT slots at
	//the file's placeholder values.
	bool terminated = false;

	while (reinterpret_cast<ULONG64>(current_import_descriptor) + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= image_limit) {
		/*
		 * The terminator is the all-zero descriptor, the same test the loader
		 * makes. Testing FirstThunk alone was both too early and too late: a
		 * descriptor is legal with OriginalFirstThunk == 0, and a directory whose
		 * first descriptor has a zero IAT but a real module name is not the
		 * end of the list - stopping there silently dropped every import after
		 * it and left those IAT slots holding the file's placeholder values.
		 */
		if (!current_import_descriptor->OriginalFirstThunk &&
			!current_import_descriptor->TimeDateStamp &&
			!current_import_descriptor->ForwarderChain &&
			!current_import_descriptor->Name &&
			!current_import_descriptor->FirstThunk) {
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
		if (current_import_descriptor->Name >= image_extent)
			return false;

		const auto module_name_ptr = reinterpret_cast<const char*>(reinterpret_cast<ULONG64>(image_base) + current_import_descriptor->Name);
		const size_t module_name_max = static_cast<size_t>(image_limit - reinterpret_cast<ULONG64>(module_name_ptr));
		const size_t module_name_len = strnlen_s(module_name_ptr, module_name_max);
		if (module_name_len == module_name_max)
			return false;

		import_info.module_name = std::string(module_name_ptr, module_name_len);

		//FirstThunk is addressed by a file controlled RVA and has to fit inside
		//the image before the thunk loop below reads it.
		if (current_import_descriptor->FirstThunk >= image_extent ||
			sizeof(IMAGE_THUNK_DATA64) > image_extent - current_import_descriptor->FirstThunk)
			return false;

		auto current_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<ULONG64>(image_base) + current_import_descriptor->FirstThunk);

		//OriginalFirstThunk (the name table) is optional and is absent in some
		//linker outputs. Reading it unconditionally then walks from the DOS
		//header and resolves garbage, so fall back to FirstThunk, which the
		//loader fills in with the same names before binding. A present but out
		//of range value is a broken descriptor and refuses the image.
		PIMAGE_THUNK_DATA64 name_table = current_first_thunk;
		if (current_import_descriptor->OriginalFirstThunk) {
			if (current_import_descriptor->OriginalFirstThunk >= image_extent ||
				sizeof(IMAGE_THUNK_DATA64) > image_extent - current_import_descriptor->OriginalFirstThunk)
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
				if (name_table->u1.AddressOfData >= image_extent ||
					sizeof(WORD) > image_extent - name_table->u1.AddressOfData)
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

	//The section table is positioned by a file controlled field, so it is proved
	//to lie inside the buffer before the walk below indexes it.
	PIMAGE_SECTION_HEADER section = nullptr;
	uint16_t section_count = 0;
	if (!GetSectionTable(image_base, image_size, section, section_count))
		return false;

	for (uint16_t i = 0; i < section_count; ++i) {
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

			/*
			 * A pointer back into this image is a field that was never relocated.
			 *
			 * Tested as a subtraction rather than as value < base + size, because
			 * that sum is over a file controlled preferred base and a preferred
			 * base near the top of the address space wraps it to a small number -
			 * which would make the range test match almost nothing and let a real
			 * self-pointer through.
			 */
			if (value >= preferred_base && value - preferred_base < image_size_declared)
				return false;
		}
	}

	return true;
}

/*
 * Classify a driver image as a hypervisor by evidence-based indicators.
 *
 * Scans executable sections for VMX/SVM opcodes, checks imports from ntoskrnl
 * for hypervisor APIs, and searches for specific keywords in executable sections
 * and import/export name tables. Returns true only when at least two independent
 * indicator classes match.
 *
 * Section names are logged but do NOT count toward the threshold.
 *
 * out_log receives the matched indicators (internal log, not console output).
 */
bool PE::IsHypervisorImage(const std::vector<uint8_t>& image, const PIMAGE_NT_HEADERS64 nt_headers, std::wstring* out_log, int* out_class_count) {
	if (image.empty() || !nt_headers) {
		if (out_class_count)
			*out_class_count = 0;
		return false;
	}

	const size_t image_size = image.size();
	std::wstring log;
	int indicator_classes = 0;
	int opcode_count = 0;
	int import_count = 0;
	int string_count = 0;

	// Get section table for executable section filtering
	PIMAGE_SECTION_HEADER section = nullptr;
	uint16_t section_count = 0;
	if (!GetSectionTable(const_cast<uint8_t*>(image.data()), image_size, section, section_count)) {
		if (out_log)
			*out_log = L"";
		if (out_class_count)
			*out_class_count = 0;
		return false;
	}

	// Section names (informational only, does NOT count as an indicator class)
	bool found_section_names = false;
	for (uint16_t i = 0; i < section_count; ++i) {
		char name[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
		std::memcpy(name, section[i].Name, IMAGE_SIZEOF_SHORT_NAME);

		std::string section_name(name);
		for (char& c : section_name) {
			if (c >= 'A' && c <= 'Z')
				c = static_cast<char>(c - 'A' + 'a');
		}

		if (section_name.find("vmx") != std::string::npos ||
			section_name.find("svm") != std::string::npos ||
			section_name.find("hv") != std::string::npos ||
			section_name.find("vmm") != std::string::npos) {
			if (!found_section_names) {
				log += L"    [info] Section name hint: ";
				found_section_names = true;
			}
			else {
				log += L", ";
			}
			for (size_t j = 0; name[j] != '\0'; ++j)
				log += static_cast<wchar_t>(name[j]);
		}
	}
	if (found_section_names)
		log += L"\n";

	// Class 1: VMX/SVM instruction opcodes in executable sections ONLY
	// Decode ModRM for patterns that require reg field validation
	bool found_opcodes = false;
	for (uint16_t sec_idx = 0; sec_idx < section_count; ++sec_idx) {
		const auto& sec = section[sec_idx];
		
		// Skip non-executable sections
		if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
			continue;

		const ULONG32 sec_rva = sec.VirtualAddress;
		const ULONG32 sec_size = sec.Misc.VirtualSize < sec.SizeOfRawData ? sec.Misc.VirtualSize : sec.SizeOfRawData;

		// Bounds check: section must fit in image
		if (sec_rva >= image_size || sec_size > image_size - sec_rva)
			continue;

		const size_t sec_start = sec_rva;
		const size_t sec_end = sec_start + sec_size;

		// Scan this executable section
		for (size_t i = sec_start; i < sec_end; ++i) {
			// VMXON = F3 0F C7 /6 (ModRM reg field must be 6)
			if (i + 3 < sec_end && image[i] == 0xF3 && image[i+1] == 0x0F && image[i+2] == 0xC7) {
				uint8_t modrm = image[i+3];
				uint8_t reg = (modrm >> 3) & 0x07;
				if (reg == 6) {
					if (!found_opcodes) {
						log += L"    Class 1 (opcodes): ";
						found_opcodes = true;
					}
					else {
						log += L", ";
					}
					log += L"VMXON";
					++opcode_count;
				}
			}
			// VMCLEAR = 66 0F C7 /6
			else if (i + 3 < sec_end && image[i] == 0x66 && image[i+1] == 0x0F && image[i+2] == 0xC7) {
				uint8_t modrm = image[i+3];
				uint8_t reg = (modrm >> 3) & 0x07;
				if (reg == 6) {
					if (!found_opcodes) {
						log += L"    Class 1 (opcodes): ";
						found_opcodes = true;
					}
					else {
						log += L", ";
					}
					log += L"VMCLEAR";
					++opcode_count;
				}
			}
			// VMLAUNCH = 0F 01 C2
			else if (i + 2 < sec_end && image[i] == 0x0F && image[i+1] == 0x01 && image[i+2] == 0xC2) {
				if (!found_opcodes) {
					log += L"    Class 1 (opcodes): ";
					found_opcodes = true;
				}
				else {
					log += L", ";
				}
				log += L"VMLAUNCH";
				++opcode_count;
			}
			// VMRESUME = 0F 01 C3
			else if (i + 2 < sec_end && image[i] == 0x0F && image[i+1] == 0x01 && image[i+2] == 0xC3) {
				if (!found_opcodes) {
					log += L"    Class 1 (opcodes): ";
					found_opcodes = true;
				}
				else {
					log += L", ";
				}
				log += L"VMRESUME";
				++opcode_count;
			}
			// VMCALL = 0F 01 C1
			else if (i + 2 < sec_end && image[i] == 0x0F && image[i+1] == 0x01 && image[i+2] == 0xC1) {
				if (!found_opcodes) {
					log += L"    Class 1 (opcodes): ";
					found_opcodes = true;
				}
				else {
					log += L", ";
				}
				log += L"VMCALL";
				++opcode_count;
			}
			// VMRUN = 0F 01 D8
			else if (i + 2 < sec_end && image[i] == 0x0F && image[i+1] == 0x01 && image[i+2] == 0xD8) {
				if (!found_opcodes) {
					log += L"    Class 1 (opcodes): ";
					found_opcodes = true;
				}
				else {
					log += L", ";
				}
				log += L"VMRUN";
				++opcode_count;
			}
			// VMMCALL = 0F 01 D9
			else if (i + 2 < sec_end && image[i] == 0x0F && image[i+1] == 0x01 && image[i+2] == 0xD9) {
				if (!found_opcodes) {
					log += L"    Class 1 (opcodes): ";
					found_opcodes = true;
				}
				else {
					log += L", ";
				}
				log += L"VMMCALL";
				++opcode_count;
			}
			// VMLOAD = 0F 01 DA
			else if (i + 2 < sec_end && image[i] == 0x0F && image[i+1] == 0x01 && image[i+2] == 0xDA) {
				if (!found_opcodes) {
					log += L"    Class 1 (opcodes): ";
					found_opcodes = true;
				}
				else {
					log += L", ";
				}
				log += L"VMLOAD";
				++opcode_count;
			}
			// VMSAVE = 0F 01 DB
			else if (i + 2 < sec_end && image[i] == 0x0F && image[i+1] == 0x01 && image[i+2] == 0xDB) {
				if (!found_opcodes) {
					log += L"    Class 1 (opcodes): ";
					found_opcodes = true;
				}
				else {
					log += L", ";
				}
				log += L"VMSAVE";
				++opcode_count;
			}
		}
	}
	if (found_opcodes) {
		log += L" (" + std::to_wstring(opcode_count) + L" patterns)\n";
		++indicator_classes;
	}

	// Class 2: Imports from ntoskrnl matching HvCall*, HvGet*, HvSet*, HvSignal*, HvInitialize*, HvRegister*
	bool found_hv_imports = false;
	vec_imports imports;
	if (GetImports(const_cast<uint8_t*>(image.data()), image_size, imports)) {
		for (const auto& import : imports) {
			std::string module_lower = import.module_name;
			for (char& c : module_lower) {
				if (c >= 'A' && c <= 'Z')
					c = static_cast<char>(c - 'A' + 'a');
			}

			if (module_lower.find("ntoskrnl") != std::string::npos) {
				for (const auto& func : import.function_datas) {
					if (func.name.empty())
						continue;

					bool matched = false;
					if (func.name.size() >= 6 && func.name.substr(0, 6) == "HvCall")
						matched = true;
					else if (func.name.size() >= 5 && func.name.substr(0, 5) == "HvGet")
						matched = true;
					else if (func.name.size() >= 5 && func.name.substr(0, 5) == "HvSet")
						matched = true;
					else if (func.name.size() >= 8 && func.name.substr(0, 8) == "HvSignal")
						matched = true;
					else if (func.name.size() >= 12 && func.name.substr(0, 12) == "HvInitialize")
						matched = true;
					else if (func.name.size() >= 10 && func.name.substr(0, 10) == "HvRegister")
						matched = true;

					if (matched) {
						if (!found_hv_imports) {
							log += L"    Class 2 (imports): ";
							found_hv_imports = true;
						}
						else {
							log += L", ";
						}
						for (char c : func.name)
							log += static_cast<wchar_t>(c);
						++import_count;
					}
				}
			}
		}
	}
	if (found_hv_imports) {
		log += L" (" + std::to_wstring(import_count) + L" patterns)\n";
		++indicator_classes;
	}

	// Class 3: Keywords in executable sections and import/export name tables.
	// Multi-word phrases require length >= 8 and need no boundary check beyond
	// their natural word boundaries. Single mnemonics require non-identifier
	// boundaries on both sides and must occur at least twice in executable
	// sections.
	const char* kMultiWordKeywords[] = { "nested paging", "ept violation", "vmentry failure", "vmexit reason" };
	const char* kSingleMnemonicKeywords[] = { "vmcs", "vmcb", "vmread", "vmwrite", "invept", "invvpid" };
	bool found_strings = false;
	bool found_multiword = false;

	auto is_ident = [](uint8_t c) -> bool {
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
	};

	auto case_eq = [](char a, char b) -> bool {
		if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
		if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
		return a == b;
	};

	auto contains_ci = [&](const std::string& haystack, const char* needle) -> bool {
		const size_t nlen = std::strlen(needle);
		if (nlen == 0 || haystack.size() < nlen) return false;
		for (size_t i = 0; i + nlen <= haystack.size(); ++i) {
			bool match = true;
			for (size_t j = 0; j < nlen; ++j) {
				if (!case_eq(haystack[i + j], needle[j])) { match = false; break; }
			}
			if (match) return true;
		}
		return false;
	};

	std::vector<std::string> import_names;
	{
		vec_imports parsed_imports;
		if (GetImports(const_cast<uint8_t*>(image.data()), image_size, parsed_imports)) {
			for (const auto& imp : parsed_imports) {
				import_names.push_back(imp.module_name);
				for (const auto& f : imp.function_datas)
					if (!f.name.empty()) import_names.push_back(f.name);
			}
		}
	}

	std::vector<std::string> export_names;
	{
		if (nt_headers) {
			DWORD export_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			const size_t image_extent = (nt_headers->OptionalHeader.SizeOfImage < image_size)
				? nt_headers->OptionalHeader.SizeOfImage : image_size;
			if (export_va && export_va < image_extent && export_va + sizeof(IMAGE_EXPORT_DIRECTORY) <= image_extent) {
				const auto* ed = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(image.data() + export_va);
				DWORD name_count = ed->NumberOfNames;
				DWORD name_table_rva = ed->AddressOfNames;
				if (name_table_rva < image_extent && (size_t)name_count * sizeof(DWORD) <= image_extent - name_table_rva) {
					const DWORD* names = reinterpret_cast<const DWORD*>(image.data() + name_table_rva);
					for (DWORD k = 0; k < name_count; ++k) {
						DWORD nrva = names[k];
						if (nrva >= image_extent) break;
						const char* nptr = reinterpret_cast<const char*>(image.data() + nrva);
						size_t maxlen = image_extent - nrva;
						size_t len = strnlen_s(nptr, maxlen);
						if (len == maxlen) break;
						export_names.emplace_back(nptr, len);
					}
				}
			}
		}
	}

	for (const char* keyword : kMultiWordKeywords) {
		const size_t kw_len = std::strlen(keyword);
		if (kw_len < 8)
			continue;

		bool matched = false;

		for (uint16_t sec_idx = 0; sec_idx < section_count && !matched; ++sec_idx) {
			const auto& sec = section[sec_idx];
			if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
				continue;
			const ULONG32 sec_rva = sec.VirtualAddress;
			const ULONG32 sec_size = sec.Misc.VirtualSize < sec.SizeOfRawData ? sec.Misc.VirtualSize : sec.SizeOfRawData;
			if (sec_rva >= image_size || sec_size > image_size - sec_rva)
				continue;
			const size_t sec_start = sec_rva;
			const size_t sec_end = sec_start + sec_size;
			for (size_t i = sec_start; i + kw_len <= sec_end; ++i) {
				bool m = true;
				for (size_t j = 0; j < kw_len; ++j) {
					if (!case_eq(static_cast<char>(image[i + j]), keyword[j])) { m = false; break; }
				}
				if (m) { matched = true; break; }
			}
		}

		if (!matched) {
			for (const auto& nm : import_names) {
				if (contains_ci(nm, keyword)) { matched = true; break; }
			}
		}

		if (!matched) {
			for (const auto& nm : export_names) {
				if (contains_ci(nm, keyword)) { matched = true; break; }
			}
		}

		if (matched) {
			found_multiword = true;
			if (!found_strings) {
				log += L"    Class 3 (strings): ";
				found_strings = true;
			}
			else {
				log += L", ";
			}
			for (size_t j = 0; j < kw_len; ++j)
				log += static_cast<wchar_t>(keyword[j]);
			++string_count;
		}
	}

	for (const char* keyword : kSingleMnemonicKeywords) {
		const size_t kw_len = std::strlen(keyword);
		int occ = 0;
		for (uint16_t sec_idx = 0; sec_idx < section_count; ++sec_idx) {
			const auto& sec = section[sec_idx];
			if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
				continue;
			const ULONG32 sec_rva = sec.VirtualAddress;
			const ULONG32 sec_size = sec.Misc.VirtualSize < sec.SizeOfRawData ? sec.Misc.VirtualSize : sec.SizeOfRawData;
			/*
			 * Boundary window. The guard is > and not >=, so a section whose raw
			 * span ends exactly at image_size is still scanned; the loop bound
			 * i + kw_len <= sec_end then puts the last read's final byte at
			 * image_size - 1, inside the buffer. The identifier probe at
			 * i + kw_len is skipped when i + kw_len == sec_end, and the leading
			 * probe at i - 1 is skipped at sec_start, so a mnemonic flush against
			 * either section edge is matched without consulting the neighbouring
			 * byte. That can only admit a one-byte-wide false positive when the
			 * keyword is exactly the first or last bytes of a section, and no
			 * read leaves the image. Left documented rather than widened into
			 * the adjacent section, which would match across a boundary.
			 */
			if (sec_rva >= image_size || sec_size > image_size - sec_rva)
				continue;
			const size_t sec_start = sec_rva;
			const size_t sec_end = sec_start + sec_size;
			for (size_t i = sec_start; i + kw_len <= sec_end; ++i) {
				if (i > sec_start && is_ident(image[i - 1]))
					continue;
				if (i + kw_len < sec_end && is_ident(image[i + kw_len]))
					continue;
				bool m = true;
				for (size_t j = 0; j < kw_len; ++j) {
					if (!case_eq(static_cast<char>(image[i + j]), keyword[j])) { m = false; break; }
				}
				if (m) {
					++occ;
				}
			}
		}

		if (occ >= 2) {
			if (!found_strings) {
				log += L"    Class 3 (strings): ";
				found_strings = true;
			}
			else {
				log += L", ";
			}
			for (size_t j = 0; j < kw_len; ++j)
				log += static_cast<wchar_t>(keyword[j]);
			++string_count;
		}
	}
	if (found_strings) {
		log += L" (" + std::to_wstring(string_count) + L" patterns)\n";
		++indicator_classes;
	}

	if (out_log)
		*out_log += log;

	// Count of independent classes, nothing else. A multi-word phrase is already
	// class 3; adding one for it reported two classes where only one matched and
	// moved the -1 boundary one class to the left.
	if (out_class_count)
		*out_class_count = indicator_classes;

	// Require at least two independent indicator classes, unless a multi-word
	// hypervisor phrase was found (high-confidence single indicator).
	return indicator_classes >= 2 || found_multiword;
}
