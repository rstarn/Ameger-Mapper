#pragma once

/*
 * PE parsing.
 *
 * Every function here reads a PE image out of an untrusted buffer: the file the
 * user passed on the command line. None of the fields it follows (e_lfanew,
 * directory RVAs, SizeOfBlock, section spans, thunk arrays) can be trusted, so
 * each function takes the buffer length and bounds its walk against it.
 *
 * Rule for this file: never dereference a pointer derived from the image
 * without first proving it lies inside [image_base, image_base + image_size).
 * A miss here is not a clean error, it is an out of bounds access in the
 * mapper's own address space.
 */

#include <Windows.h>
#include <string>
#include <vector>

namespace PE
{
	// One IMAGE_BASE_RELOCATION block: where its fixups apply and how many
	// 2-byte entries follow. `address` is the RVA the block applies to, already
	// added to the image base, so it points straight at the patched field.
	struct RelocInfo
	{
		ULONG64 address;
		USHORT* item;
		ULONG32 count;
	};

	//One imported function. `ordinal` is non-zero when the import is by ordinal
	//rather than by name, in which case `name` is empty. Both forms are legal and
	//both have to be resolved: an unresolved IAT slot is 0 and the driver jumps
	//there on its first call to that function.
	struct ImportFunctionInfo
	{
		std::string name;
		ULONG64* address;
		uint16_t ordinal = 0;
	};

	//One imported module and everything it imports.
	struct ImportInfo
	{
		std::string module_name;
		std::vector<ImportFunctionInfo> function_datas;
	};

	using vec_relocs = std::vector<RelocInfo>;
	using vec_imports = std::vector<ImportInfo>;

	//Locate and sanity check the NT headers.
	//image_size is the length of the buffer at image_base.
	//
	//Returns nullptr when the buffer is too small to hold a DOS header, when it
	//is not a PE image, when e_lfanew points outside it, when the NT signature
	//does not match, or when the optional header is not a PE32+ one.
	//
	//The Magic test is here rather than at the call sites because every field
	//this file reads afterwards - ImageBase, Subsystem, every DataDirectory entry
	//and the position of the section table - is a different width or a different
	//offset in a PE32 optional header. Parsing a 32-bit image as PE32+ produces
	//values that are wrong in a way nothing downstream can detect.
	PIMAGE_NT_HEADERS64 GetNtHeaders(void* image_base, size_t image_size);

	//Locate the section table and prove the whole of it lies inside the buffer.
	//
	//IMAGE_FIRST_SECTION is not a fixed offset: it is the end of the optional
	//header, and SizeOfOptionalHeader is a file controlled field, so it is what
	//positions the section table. Every consumer here walks NumberOfSections
	//entries from it, and that count is a file controlled WORD, so without this
	//check a handful of header bytes decide how far out of bounds a loop walks.
	//
	//On success `out_sections` points at the first IMAGE_SECTION_HEADER and
	//`out_count` is the number of entries proven to fit. On failure both are
	//left untouched and false is returned.
	bool GetSectionTable(void* image_base, size_t image_size, PIMAGE_SECTION_HEADER& out_sections, uint16_t& out_count);

	//Collect the base relocation blocks into `relocs`.
	//Returns true with an empty `relocs` when the image has no relocation
	//directory. An image with no relocations can only run at its preferred
	//base, which is never the address the kernel allocates - so the caller has
	//to check what does need fixing.
	//Returns false when the relocation directory is malformed (a directory or
	//block that does not lie inside the image). The caller must refuse to map:
	//applying only part of a relocation set leaves pointers aimed at the
	//preferred base, and the first use of one is a bugcheck.
	bool GetRelocs(void* image_base, size_t image_size, vec_relocs& relocs);

	//Collect the import descriptors and the functions they pull in into
	//`imports`. Both by-name and by-ordinal imports are collected; an ordinal
	//import has an empty name and a non-zero ordinal.
	//Returns true with an empty `imports` when the image has no import
	//directory.
	//Returns false when a descriptor, thunk array or name is malformed. The
	//caller must refuse to map: a descriptor that is skipped leaves its IAT
	//slots holding the file's placeholder values, so the driver's first call
	//through one jumps to a file offset instead of a kernel function.
	bool GetImports(void* image_base, size_t image_size, vec_imports& imports);

	/*
	 * Prove an image carries no absolute address into itself.
	 *
	 * Returns false when the image still holds a 64-bit value pointing inside its
	 * own image. That happens when the file has no relocation directory: the
	 * kernel address an image is loaded at is never its preferred base, and with
	 * no .reloc there is nothing telling the mapper which fields need fixing - so
	 * a surviving pointer is a guaranteed jump to the wrong place.
	 *
	 * Only section data is scanned, never the PE headers: the ImageBase field of
	 * the optional header is itself a value inside the image's own range, and
	 * counting it would flag every well-formed file.
	 *
	 * Called only when GetRelocs returned an empty vector.
	 */
	bool VerifyNoAbsoluteReferences(void* image_base, size_t image_size);
}