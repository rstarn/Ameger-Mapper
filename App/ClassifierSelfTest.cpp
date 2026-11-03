/*
 * Classifier self-test.
 *
 * Moved out of Main.cpp so TestClassifier.exe can link it directly: Main.cpp
 * defines wmain and the mapper project stamps requireAdministrator into its
 * manifest, so a test that shares that translation unit cannot be run from an
 * ordinary shell.
 */

#include "ClassifierSelfTest.hpp"

#include <Windows.h>
#include <string>
#include <vector>

#include "../PE/PE.hpp"
#include "../Utilities/Console.hpp"

/*
 * Self-test for the classifier.
 * Builds synthetic PE images in memory and verifies classification results.
 * Returns 0 on success, non-zero on failure.
 */
int RunClassifierSelfTest() {
	Console::EnableAnsiColors();
	Log(L"[*] Running classifier self-test..." << std::endl);
	LogBlank();

	int failures = 0;

	auto MakeMinimalPe = [](const std::string& section_name, uint32_t section_chars,
	                       const std::vector<uint8_t>& payload_bytes,
	                       const std::string& import_module, const std::string& import_name) -> std::vector<uint8_t> {
		std::vector<uint8_t> pe;

		IMAGE_DOS_HEADER dos = {};
		dos.e_magic = IMAGE_DOS_SIGNATURE;
		dos.e_lfanew = sizeof(IMAGE_DOS_HEADER);
		pe.insert(pe.end(), reinterpret_cast<uint8_t*>(&dos), reinterpret_cast<uint8_t*>(&dos) + sizeof(dos));

		IMAGE_NT_HEADERS64 nt = {};
		nt.Signature = IMAGE_NT_SIGNATURE;
		nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
		nt.FileHeader.NumberOfSections = 1;
		nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
		nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		nt.OptionalHeader.ImageBase = 0x140000000;
		nt.OptionalHeader.SectionAlignment = 0x1000;
		nt.OptionalHeader.FileAlignment = 0x200;
		nt.OptionalHeader.SizeOfImage = 0x4000;

		const bool has_imports = !import_module.empty();
		if (has_imports) {
			nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
			nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x3000;
			nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0x1000;
		}

		pe.insert(pe.end(), reinterpret_cast<uint8_t*>(&nt), reinterpret_cast<uint8_t*>(&nt) + sizeof(nt));

		IMAGE_SECTION_HEADER hdr = {};
		strncpy_s(reinterpret_cast<char*>(hdr.Name), IMAGE_SIZEOF_SHORT_NAME, section_name.c_str(), _TRUNCATE);
		hdr.VirtualAddress = 0x400;
		hdr.Misc.VirtualSize = 0x1000;
		hdr.SizeOfRawData = 0x200;
		hdr.PointerToRawData = static_cast<DWORD>(pe.size()) + 0x200;
		hdr.Characteristics = section_chars;
		pe.insert(pe.end(), reinterpret_cast<uint8_t*>(&hdr), reinterpret_cast<uint8_t*>(&hdr) + sizeof(hdr));

		while (pe.size() < 0x400)
			pe.push_back(0);

		pe.insert(pe.end(), payload_bytes.begin(), payload_bytes.end());

		while (pe.size() < 0x600)
			pe.push_back(0);

		if (has_imports) {
			while (pe.size() < 0x3000)
				pe.push_back(0);

			IMAGE_IMPORT_DESCRIPTOR desc = {};
			desc.Name = 0x3100;
			desc.FirstThunk = 0x3200;
			desc.OriginalFirstThunk = 0x3200;
			pe.insert(pe.end(), reinterpret_cast<uint8_t*>(&desc), reinterpret_cast<uint8_t*>(&desc) + sizeof(desc));

			IMAGE_IMPORT_DESCRIPTOR null_desc = {};
			pe.insert(pe.end(), reinterpret_cast<uint8_t*>(&null_desc), reinterpret_cast<uint8_t*>(&null_desc) + sizeof(null_desc));

			while (pe.size() < 0x3100)
				pe.push_back(0);

			pe.insert(pe.end(), import_module.begin(), import_module.end());
			pe.push_back(0);

			while (pe.size() < 0x3200)
				pe.push_back(0);

			uint64_t rva = 0x3300;
			pe.insert(pe.end(), reinterpret_cast<uint8_t*>(&rva), reinterpret_cast<uint8_t*>(&rva) + sizeof(rva));

			uint64_t zero = 0;
			pe.insert(pe.end(), reinterpret_cast<uint8_t*>(&zero), reinterpret_cast<uint8_t*>(&zero) + sizeof(zero));

			while (pe.size() < 0x3300)
				pe.push_back(0);

			uint16_t hint = 0;
			pe.insert(pe.end(), reinterpret_cast<uint8_t*>(&hint), reinterpret_cast<uint8_t*>(&hint) + sizeof(hint));
			pe.insert(pe.end(), import_name.begin(), import_name.end());
			pe.push_back(0);
		}

		while (pe.size() < 0x4000)
			pe.push_back(0);

		return pe;
	};

	auto to_label = [](bool v) -> const wchar_t* { return v ? L"hypervisor" : L"non-hypervisor"; };

	// Case 1
	{
		std::vector<uint8_t> payload = { 0xF3, 0x0F, 0xC7, 0x30 };
		auto pe = MakeMinimalPe(".text", IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ, payload, "ntoskrnl.exe", "HvCallGetVpIndex");
		const PIMAGE_NT_HEADERS64 nt = PE::GetNtHeaders(pe.data(), pe.size());
		std::wstring log;
		const bool got = PE::IsHypervisorImage(pe, nt, &log);
		const bool expected = true;
		if (got == expected) {
			Log(L"CASE 1: PASS (expected=" << to_label(expected) << L" got=" << to_label(got) << L")" << std::endl);
		} else {
			Log(L"CASE 1: FAIL (expected=" << to_label(expected) << L" got=" << to_label(got) << L")" << std::endl);

			++failures;
		}
	}

	// Case 2: negative control. Bare 0F C7 /6 (VMPTRLD) is not in the scanner's
	// pattern set and "hypervisor" is not a keyword, so no class matches.
	{
		std::vector<uint8_t> payload = {
			0x0F, 0xC7, 0xF0,                                           // VMPTRLD, ModRM reg=6
			0x68, 0x79, 0x70, 0x65, 0x72, 0x76, 0x69, 0x73, 0x6F, 0x72  // "hypervisor"
		};
		auto pe = MakeMinimalPe(".text", IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ, payload, "", "");
		const PIMAGE_NT_HEADERS64 nt = PE::GetNtHeaders(pe.data(), pe.size());
		std::wstring log;
		const bool got = PE::IsHypervisorImage(pe, nt, &log);
		const bool expected = false;
		if (got == expected) {
			Log(L"CASE 2: PASS (expected=" << to_label(expected) << L" got=" << to_label(got) << L")" << std::endl);
		} else {
			Log(L"CASE 2: FAIL (expected=" << to_label(expected) << L" got=" << to_label(got) << L")" << std::endl);
			++failures;
		}
	}

	// Case 3: length-satisfying phrase in a NON-executable section. The section
	// filter must reject it before the keyword scan runs.
	{
		std::vector<uint8_t> payload = {
			0x6E, 0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x70, 0x61, 0x67, 0x69, 0x6E, 0x67  // "nested paging"
		};
		auto pe = MakeMinimalPe(".rdata", IMAGE_SCN_MEM_READ, payload, "", "");
		const PIMAGE_NT_HEADERS64 nt = PE::GetNtHeaders(pe.data(), pe.size());
		std::wstring log;
		const bool got = PE::IsHypervisorImage(pe, nt, &log);
		const bool expected = false;
		if (got == expected) {
			Log(L"CASE 3: PASS (expected=" << to_label(expected) << L" got=" << to_label(got) << L")" << std::endl);
		} else {
			Log(L"CASE 3: FAIL (expected=" << to_label(expected) << L" got=" << to_label(got) << L")" << std::endl);
			++failures;
		}
	}

	// Case 4: same 13-byte phrase in an executable section. One class matches,
	// and the multi-word override is what makes it a hypervisor.
	{
		std::vector<uint8_t> payload = {
			0x6E, 0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x70, 0x61, 0x67, 0x69, 0x6E, 0x67  // "nested paging"
		};
		auto pe = MakeMinimalPe(".text", IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ, payload, "", "");
		const PIMAGE_NT_HEADERS64 nt = PE::GetNtHeaders(pe.data(), pe.size());
		std::wstring log;
		const bool got = PE::IsHypervisorImage(pe, nt, &log);
		const bool expected = true;
		if (got == expected) {
			Log(L"CASE 4: PASS (expected=" << to_label(expected) << L" got=" << to_label(got) << L")" << std::endl);
		} else {
			Log(L"CASE 4: FAIL (expected=" << to_label(expected) << L" got=" << to_label(got) << L")" << std::endl);

			++failures;
		}
	}

	LogBlank();
	if (failures == 0) {
		Log(L"[+] All self-tests passed" << std::endl);
		return 0;
	} else {
		Log(L"[-] " << Val(failures) << L" self-test(s) failed" << std::endl);
		return 1;
	}
}
