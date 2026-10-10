//SymbolTool - resolves kernel offsets and structure field offsets for the
//running Windows build from the matching Microsoft PDBs and writes them to
//Offsets.ini for Mapper.exe.
//
// The whole file is built in memory first and only written once every module
//has resolved, so a symbol download or lookup failure exits before the
//existing Offsets.ini is touched and the mapper keeps working with the last
//known good values.
//
// Note that the final write itself is not atomic: it truncates the destination
//and then writes. If the process dies between those two steps the file is left
//truncated. Everything that can fail is checked before this point, so the
//remaining window is a write failure or a hard kill.

#include <Windows.h>

#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "Engine/SymbolEngine.hpp"

namespace
{
	//Duplicated from Utilities on purpose: SymbolTool links neither that
	//project nor anything that depends on it, and pulling one more translation
	//unit in for a single function is not worth the build coupling.
	std::wstring GetCurrentAppFolder() {
		wchar_t buffer[1024] = { 0 };
		if (!GetModuleFileNameW(NULL, buffer, static_cast<UINT>(std::size(buffer))))
			return L"";
		std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
		if (pos == std::wstring::npos)
			return L"";
		return std::wstring(buffer).substr(0, pos);
	}
}

//Modules to resolve. ci.dll only matters when Defender is present, so its
//entries end up in an empty [ci.dll.fields] section when it is not.
int wmain()
{
	//ANSI escape processing has to be enabled before any colour sequence is
	//written, otherwise the escape bytes print literally.
	EnableAnsiColors();

	std::vector<std::wstring> targetBinaries = {
		L"C:\\Windows\\System32\\ntoskrnl.exe",
		L"C:\\Windows\\System32\\ci.dll"
	};

	//Symbols that must resolve: the mapper cannot run without them.
	std::vector<SymbolRequest> symbolsToRetrieve{
		{ L"ntoskrnl.exe", L"MmAllocateIndependentPagesEx" },
		{ L"ntoskrnl.exe", L"MmFreeIndependentPages" },
		{ L"ntoskrnl.exe", L"PiDDBLock" },
		{ L"ntoskrnl.exe", L"PiDDBCacheTable" },
		{ L"ntoskrnl.exe", L"MmSetPageProtection" },
		{
		// Base of the page table self-map window. Resolved rather than hardcoded because the
		// value is build dependent, and a wrong constant is an unmapped address.
		// Symbols\Handler\SymbolsHandler.cpp reads it, Driver.cpp uses it.
		L"ntoskrnl.exe", L"MmPteBase" },
		{ L"ci.dll", L"g_KernelHashBucketList" },
		{ L"ci.dll", L"g_HashCacheLock" },
	};

	//Structure field offsets. Each one replaces a hardcoded numeric offset that
	//could silently change between Windows builds.
	//
	//The optional=true entries are the internal types Microsoft does not publish
	//in the PDB type stream. They cannot be resolved here by design and are
	//reported as a single dimmed summary instead of one warning each; the mapper
	//derives their offsets at runtime by content matching.
	std::vector<FieldRequest> fieldsToRetrieve{
		{ L"ntoskrnl.exe", L"_FILE_OBJECT",               L"DeviceObject" },
		{ L"ntoskrnl.exe", L"_DEVICE_OBJECT",             L"DriverObject" },
		{ L"ntoskrnl.exe", L"_DRIVER_OBJECT",             L"DriverSection" },
		{ L"ntoskrnl.exe", L"_KLDR_DATA_TABLE_ENTRY",     L"BaseDllName" },
		{ L"ntoskrnl.exe", L"_RTL_AVL_TABLE",             L"DeleteCount" },
		{ L"ntoskrnl.exe", L"_PiDDBCacheEntry",           L"List",           true },
		{ L"ntoskrnl.exe", L"_PiDDBCacheEntry",           L"DriverName",     true },
		{ L"ntoskrnl.exe", L"_PiDDBCacheEntry",           L"TimeDateStamp",  true },
		{ L"ntoskrnl.exe", L"_RTL_PROCESS_MODULE_INFORMATION", L"OffsetToFileName", true },
		{ L"ci.dll",       L"HashBucketEntry",            L"DriverName",     true },
	};

	const std::wstring wdFilterPath = L"C:\\Windows\\System32\\drivers\\wd\\WdFilter.sys";
	//WdFilter only exists when Defender is installed, and the mapper treats
	//its absence as "nothing to clean up" rather than as an error.
	if (std::filesystem::exists(wdFilterPath)) {
		targetBinaries.push_back(wdFilterPath);
		symbolsToRetrieve.push_back({ L"WdFilter.sys", L"MpBmDocOpenRules" });
		symbolsToRetrieve.push_back({ L"WdFilter.sys", L"MpFreeDriverInfoEx" });
	}

	SymbolEngine engine(GetCurrentAppFolder() + L"\\Symbols");

	std::wostringstream content;
	//Optional fields are allowed to fail: the mapper validates those objects
	//at runtime instead of trusting a compiled-in offset.
	bool allResolved = true;

	for (const auto& binary : targetBinaries) {
		const bool isWdFilter = binary.find(L"WdFilter") != std::wstring::npos;

		const auto pdbPath = engine.GetPDB(binary);
		if (pdbPath.empty()) {
			if (isWdFilter) {
				//WdFilter's PDB is not always published, and the mapper treats a
				//missing WdFilter cleanup as "nothing to remove", so skip it
				//rather than failing the whole run over an optional module.
				std::wcout << kColorDim << L"[i] No symbols available for " << binary
					<< L", skipping" << kColorReset << std::endl;
				continue;
			}
			std::wcout << L"[-] No symbols available for " << binary << std::endl;
			return -1;
		}

		std::vector<std::wstring> symbols;
		std::vector<FieldRequest> fields;

		for (const auto& request : symbolsToRetrieve) {
			if (binary.find(request.binaryName) != std::wstring::npos)
				symbols.push_back(request.symbolName);
		}
		for (const auto& request : fieldsToRetrieve) {
			if (binary.find(request.binaryName) != std::wstring::npos)
				fields.push_back(request);
		}

		const auto offsets = engine.GetOffset(pdbPath, symbols);
		if (offsets.size() != symbols.size()) {
			std::wcout << kColorRed << L"[-] Could not resolve every symbol of " << binary << kColorReset << std::endl;
			return -1;
		}

		const auto fieldOffsets = engine.GetStructFieldOffsets(pdbPath, fields);
		//GetStructFieldOffsets returns one value per requested field, or an
		//empty vector when the PDB could not be loaded. The loop below indexes
		//it by fields.size(), so the two have to agree or the read runs off the
		//end of the vector.
		if (fieldOffsets.size() != fields.size()) {
			std::wcout << kColorRed << L"[-] Could not resolve the structure fields of " << binary << kColorReset << std::endl;
			return -1;
		}

		const auto name = std::filesystem::path(binary).filename().wstring();

		content << L"[" << name << L"]" << std::endl;
		for (size_t i = 0; i < symbols.size(); i++)
			content << symbols[i] << L"=" << std::dec << offsets[i] << std::endl;

		content << L"[" << name << L".fields]" << std::endl;
		for (size_t i = 0; i < fields.size(); i++) {
			//Only publish what actually resolved: a zero entry would look like a
			//legitimate offset of zero. Missing fields fall back to the compiled
			//default plus runtime validation in the mapper.
			if (fieldOffsets[i] == 0) {
				allResolved = false;
				continue;
			}
			content << fields[i].structName << L"." << fields[i].fieldName << L"=" << std::dec << fieldOffsets[i] << std::endl;
		}

		content << std::endl;
	}

	//Written next to Mapper.exe, which is also where the mapper looks for it.
	const auto outputPath = GetCurrentAppFolder() + L"\\Offsets.ini";

	std::wofstream out(outputPath, std::ios::trunc);
	if (!out.is_open()) {
		std::wcout << L"[-] Could not write " << outputPath << std::endl;
		return -1;
	}
	out << content.str();
	out.close();
	if (out.fail()) {
		std::wcout << kColorRed << L"[-] Failed to write " << outputPath << kColorReset << std::endl;
		return -1;
	}

	std::wcout << kColorGreen << L"[+] Wrote " << outputPath
		<< (allResolved ? L"" : L" (with unresolved optional fields)") << kColorReset << std::endl;
	return 0;
}
