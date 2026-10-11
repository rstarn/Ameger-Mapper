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

#include <algorithm>
#include <vector>
#include <string>
#include <utility>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "Engine/SymbolEngine.hpp"
#include "../Utilities/Console.hpp"

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

	//A symbol resolved from a module's PDB, held until the whole report can be
	//printed in one fixed order instead of in resolution order.
	struct ResolvedSymbol {
		std::wstring name;
		uint64_t offset = 0;
	};

	//A structure field resolved from a module's PDB type stream. optional
	//mirrors the request: a non-optional miss is reported as a warning, an
	//optional miss stays silent.
	//
	//Resolved is separate from offset because a field can legitimately resolve
	//to offset 0, and treating that as a miss silently dropped
	//_DRIVER_EXTENSION.DriverObject from the generated file.
	struct ResolvedField {
		std::wstring structName;
		std::wstring fieldName;
		std::wstring matchedName;
		uint64_t offset = 0;
		bool optional = false;

		bool Resolved() const { return !matchedName.empty(); }
	};
}

//Modules to resolve. ci.dll only matters when Defender is present, so its
//entries end up in an empty [ci.dll.fields] section when it is not.
int wmain()
{
	//ANSI escape processing has to be enabled before any colour sequence is
	//written, otherwise the escape bytes print literally.
	Console::EnableAnsiColors();

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
	//in the PDB type stream. They cannot be resolved here by design, so they are
	//omitted from the report; the mapper derives their offsets at runtime by
	//content matching.
	std::vector<FieldRequest> fieldsToRetrieve{
		{ L"ntoskrnl.exe", L"_FILE_OBJECT",               L"DeviceObject" },
		{ L"ntoskrnl.exe", L"_DEVICE_OBJECT",             L"DriverObject" },
		{ L"ntoskrnl.exe", L"_DRIVER_OBJECT",             L"DriverSection" },
		{ L"ntoskrnl.exe", L"_KLDR_DATA_TABLE_ENTRY",     L"BaseDllName" },
		{ L"ntoskrnl.exe", L"_RTL_AVL_TABLE",             L"DeleteCount" },

		/*
		 * Fields the mapper writes when it builds the DRIVER_OBJECT it hands to a
		 * driver's DriverEntry. A driver reaches IoCreateDevice before it has
		 * registered anything, and IoCreateDevice reads DriverExtension and the
		 * extension's own back-reference - so all of these have to be this
		 * build's real offsets, not a guess.
		 *
		 * Optional: a build that does not publish one of them falls back to the
		 * compiled default, and Driver::CreateDriverObjectForEntry validates what
		 * it wrote rather than trusting the layout blindly.
		 *
		 * _DRIVER_EXTENSION has no Size member in the PDB type stream - its
		 * first member is DriverObject, the back-pointer - so nothing is
		 * requested for Size and nothing is written there.
		 */
		{ L"ntoskrnl.exe", L"_DRIVER_OBJECT",             L"Size",           true },
		{ L"ntoskrnl.exe", L"_DRIVER_OBJECT",             L"DriverStart",    true },
		{ L"ntoskrnl.exe", L"_DRIVER_OBJECT",             L"DriverSize",     true },
		{ L"ntoskrnl.exe", L"_DRIVER_OBJECT",             L"DriverExtension",true },
		{ L"ntoskrnl.exe", L"_DRIVER_OBJECT",             L"Flags",          true },
		{ L"ntoskrnl.exe", L"_DRIVER_OBJECT",             L"DriverUnload",   true },
		{ L"ntoskrnl.exe", L"_DRIVER_EXTENSION",          L"DriverObject",   true },
		{ L"ntoskrnl.exe", L"_DRIVER_EXTENSION",          L"AddDevice",      true },

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

	/*
	 * The flat PDB cache lives at Build\Symbols, one level above the release
	 * folder this tool is staged into. Keeping it outside the release root is
	 * what lets Build\Executors\Create.bat wipe the release on every rebuild
	 * without discarding the cache - see the stage notes there.
	 */
	SymbolEngine engine(std::filesystem::path(GetCurrentAppFolder()).parent_path().wstring() + L"\\Symbols");

	std::wostringstream content;
	//Optional fields are allowed to fail: the mapper validates those objects
	//at runtime instead of trusting a compiled-in offset.

	//Results are collected while resolving and printed afterwards in a fixed
	//order, so the report is not grouped by the PDB each value came from.
	std::vector<ResolvedSymbol> resolvedSymbols;
	std::vector<ResolvedField> resolvedFields;
	std::vector<std::wstring> loadingPaths;

	for (const auto& binary : targetBinaries) {
		const bool isWdFilter = binary.find(L"WdFilter") != std::wstring::npos;

		const auto pdbPath = engine.GetPDB(binary);
		if (pdbPath.empty()) {
			if (isWdFilter) {
				//WdFilter's PDB is not always published, and the mapper treats a
				//missing WdFilter cleanup as "nothing to remove", so skip it
				//rather than failing the whole run over an optional module.
				Log(L"[INFO] No symbols available for " << Val(binary) << L", skipping" << std::endl);
				continue;
			}
			Log(L"[-] No symbols available for " << Val(binary) << std::endl);
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
			Log(L"[-] Could not resolve every symbol of " << Val(binary) << std::endl);
			return -1;
		}

		const auto fieldResults = engine.GetStructFieldOffsets(pdbPath, fields);
		//GetStructFieldOffsets returns one result per requested field, or an
		//empty vector when the PDB could not be loaded. The loop below indexes
		//it by fields.size(), so the two have to agree or the read runs off the
		//end of the vector.
		if (fieldResults.size() != fields.size()) {
			Log(L"[-] Could not resolve the structure fields of " << Val(binary) << std::endl);
			return -1;
		}

		const auto name = std::filesystem::path(binary).filename().wstring();

		content << L"[" << name << L"]" << std::endl;
		for (size_t i = 0; i < symbols.size(); i++)
			content << symbols[i] << L"=" << std::dec << offsets[i] << std::endl;

		content << L"[" << name << L".fields]" << std::endl;
		for (size_t i = 0; i < fields.size(); i++) {
			/*
			 * Publish anything that resolved, including one at offset 0.
			 *
			 * The previous test was offset != 0, which dropped
			 * _DRIVER_EXTENSION.DriverObject: it really is the first member, so
			 * its resolved offset is 0, and writing "=0" was mistaken for a
			 * missing entry. The mapper then used its compiled default without
			 * saying so - which happened to be the same number, so the bug was
			 * invisible until a build where the two differ.
			 *
			 * A genuine miss has an empty matchedName and is still skipped, so
			 * the file never carries an entry that means nothing.
			 */
			if (!fieldResults[i].Resolved()) {
				continue;
			}
			content << fields[i].structName << L"." << fields[i].fieldName << L"=" << std::dec << fieldResults[i].offset << std::endl;
		}

		content << std::endl;

		//Held for the report pass below rather than printed here, so the
		//console output follows the fixed order and not this loop's.
		loadingPaths.push_back(pdbPath);
		for (size_t i = 0; i < symbols.size(); i++)
			resolvedSymbols.push_back({ symbols[i], offsets[i] });
		for (size_t i = 0; i < fields.size(); i++)
			resolvedFields.push_back({
				fields[i].structName, fields[i].fieldName,
				fieldResults[i].matchedName, fieldResults[i].offset, fields[i].optional });
	}

	/*
	 * Console report, emitted in one fixed order once every module has resolved
	 * so the two PDBs do not split the symbol block and the fields do not land
	 * in the middle of it. The lists below only decide the order; the values
	 * come from the resolution pass above.
	 *
	 * Field order groups what a reader is looking at, not what the request list
	 * happened to be in:
	 *
	 *   - the offsets the cleanup walks dereference to reach an object come
	 *     first, because a wrong one is a write into the wrong kernel structure
	 *   - then the DRIVER_OBJECT members the mapper writes when it builds the
	 *     object it hands to DriverEntry
	 *   - then the extension members, whose layout is what makes a real
	 *     IoCreateDevice work
	 *
	 * Anything the list does not name keeps its resolution order and is still
	 * reported, so a newly requested field can never silently disappear from
	 * the report by being absent here.
	 */
	const std::vector<std::wstring> symbolReportOrder{
		L"MmAllocateIndependentPagesEx",
		L"MmFreeIndependentPages",
		L"g_KernelHashBucketList",
		L"MmSetPageProtection",
		L"PiDDBCacheTable",
		L"g_HashCacheLock",
		L"PiDDBLock",
		L"MmPteBase",
	};
	const std::vector<std::pair<std::wstring, std::wstring>> fieldReportOrder{
		{ L"_KLDR_DATA_TABLE_ENTRY",    L"BaseDllName" },
		{ L"_DRIVER_OBJECT",            L"DriverExtension" },
		{ L"_DRIVER_EXTENSION",         L"DriverObject" },
		{ L"_DRIVER_OBJECT",            L"DriverSection" },
		{ L"_DRIVER_OBJECT",            L"DriverUnload" },
		{ L"_DRIVER_OBJECT",            L"DriverStart" },
		{ L"_DEVICE_OBJECT",            L"DriverObject" },
		{ L"_RTL_AVL_TABLE",            L"DeleteCount" },
		{ L"_DRIVER_EXTENSION",         L"AddDevice" },
		{ L"_DRIVER_OBJECT",            L"DriverSize" },
		{ L"_FILE_OBJECT",              L"DeviceObject" },
		{ L"_DRIVER_OBJECT",            L"Flags" },
		{ L"_DRIVER_OBJECT",            L"Size" },
	};

	//Rank by position in the fixed order. An entry the list does not name - a
	//conditional WdFilter symbol - ranks last and keeps its resolution order,
	//so nothing is silently dropped from the report.
	auto symbolRank = [&symbolReportOrder](const std::wstring& name) {
		for (size_t i = 0; i < symbolReportOrder.size(); i++)
			if (symbolReportOrder[i] == name)
				return i;
		return symbolReportOrder.size();
	};
	std::stable_sort(resolvedSymbols.begin(), resolvedSymbols.end(),
		[&](const ResolvedSymbol& a, const ResolvedSymbol& b) {
			return symbolRank(a.name) < symbolRank(b.name);
		});

	auto fieldRank = [&fieldReportOrder](const std::wstring& structName, const std::wstring& fieldName) {
		for (size_t i = 0; i < fieldReportOrder.size(); i++)
			if (fieldReportOrder[i].first == structName && fieldReportOrder[i].second == fieldName)
				return i;
		return fieldReportOrder.size();
	};
	std::stable_sort(resolvedFields.begin(), resolvedFields.end(),
		[&](const ResolvedField& a, const ResolvedField& b) {
			return fieldRank(a.structName, a.fieldName) < fieldRank(b.structName, b.fieldName);
		});

	//Group A: symbols.
	for (const auto& symbol : resolvedSymbols) {
		Log(L"[+] Symbol " << Val(symbol.name) << L" Offset: " << Val(Hex(symbol.offset)) << std::endl);
	}
	LogBlank();

	//Group B: structure fields.
	for (const auto& field : resolvedFields) {
		if (field.Resolved()) {
			//Field | Offset = 0x.., so the name and the value are separated by a
			//delimiter that is not part of either and that stays readable when the
			//name is long. The alternate-spelling note goes before the delimiter,
			//because it qualifies the name rather than the value.
			if (!field.matchedName.empty() && field.matchedName != field.structName)
				Log(L"[+] Field " << Val(field.structName) << L"." << Val(field.fieldName)
					<< L" (as " << Val(field.matchedName) << L") | Offset = " << Val(Hex(field.offset)) << std::endl);
			else
				Log(L"[+] Field " << Val(field.structName) << L"." << Val(field.fieldName)
					<< L" | Offset = " << Val(Hex(field.offset)) << std::endl);
		}
		else if (!field.optional) {
			//An optional field is expected to miss: it is not in the public PDB
			//type stream, so the mapper derives its offset at runtime instead.
			Log(L"[-] Field " << Val(field.structName) << L"." << Val(field.fieldName) << L" unresolved" << std::endl);
		}
	}
	LogBlank();

	//Group C: the PDBs the offsets were resolved from.
	for (const auto& pdbPath : loadingPaths) {
		Log(L"[+] Loading Symbols From " << Val(pdbPath) << std::endl);
	}
	LogBlank();

	//Written next to Mapper.exe, which is also where the mapper looks for it.
	const auto outputPath = GetCurrentAppFolder() + L"\\Offsets.ini";

	std::wofstream out(outputPath, std::ios::trunc);
	if (!out.is_open()) {
		Log(L"[-] Could not write " << Val(outputPath) << std::endl);
		return -1;
	}
	out << content.str();
	out.close();
	if (out.fail()) {
		Log(L"[-] Failed to write " << Val(outputPath) << std::endl);
		return -1;
	}

	//The "Wrote" line is emitted by the reader that consumes this file, inside
	//its symbol report, so that it lands between MmPteBase and g_HashCacheLock
	//rather than at the head of the mapper's symbol list. Printing it here as
	//well would show it once for each of the two programs.
	return 0;
}
