#include "SymbolEngine.hpp"

#include <windows.h>
#include <string>
#include <memory>
#include <filesystem>
#include <iostream>
#include <dbghelp.h>
#pragma comment( lib, "dbghelp.lib" )


SymbolEngine::SymbolEngine(std::wstring cachePath) {
	process = (unsigned long long)GetCurrentProcess();
	SymInitializeW((HANDLE)process, (L"cache*" + cachePath + L";SRV*http://msdl.microsoft.com/download/symbols").c_str(), FALSE);
	SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_DEBUG);
}

SymbolEngine::~SymbolEngine() {
	SymCleanup((HANDLE)process);
}

std::wstring SymbolEngine::GetPDB(const std::wstring binaryPath) {

	SYMSRV_INDEX_INFOW info{};
	info.sizeofstruct = sizeof(SYMSRV_INDEX_INFOW);
	bool result = SymSrvGetFileIndexInfoW(binaryPath.c_str(), &info, 0);
	if (!result)
	{
		std::wcout << "[-] Failed to find binary info. Error: " << GetLastError() << std::endl;
		return {};
	}

	void* id;
	DWORD idType;
	if (info.guid == GUID{}) { // GUID is zeroed
		id = &info.sig;
		idType = SSRVOPT_DWORDPTR;
	}
	else {
		id = &info.guid;
		idType = SSRVOPT_GUIDPTR;
	}

	auto pdbPath = std::make_unique<wchar_t[]>(4096);
	bool found = SymFindFileInPathW(
		(HANDLE)process,
		NULL,
		info.pdbfile,
		id,
		info.age,
		0,
		idType,
		pdbPath.get(),
		NULL,
		NULL
	);

	auto resultPath = std::wstring(pdbPath.get());
	// Windows don't provide symsrv.dll and dbghelp loads it from his current path, if its not loaded after those calls means that symsrv/dbghelp are invalid
	if (resultPath.empty() && GetModuleHandleA("symsrv.dll") == nullptr) {
		std::wcout << "[-] Please provide proper dbghelp.dll and symsrv.dll!" << std::endl;
	}

	return resultPath;
}

std::vector<ULONG64> SymbolEngine::GetOffset(std::wstring pdbPath, std::vector<std::wstring> symbolName) {

	DWORD64 BaseAddr = 0x40000;
	DWORD FileSize = (DWORD)std::filesystem::file_size(pdbPath);

	// Load symbols for the module 
	std::wcout << "[+] Loading Symbols From " << pdbPath << std::endl;
	DWORD64 ModBase = SymLoadModuleExW(
		(HANDLE)process, // Process handle of the current process 
		NULL,                // Handle to the module's image file (not needed)
		pdbPath.c_str(),           // Path/name of the file 
		NULL,                // User-defined short name of the module (it can be NULL) 
		BaseAddr,            // Base address of the module (cannot be NULL if .PDB file is used, otherwise it can be NULL) 
		FileSize,            // Size of the file (cannot be NULL if .PDB file is used, otherwise it can be NULL) 
		NULL,
		NULL
	);

	if (ModBase == 0)
	{
		std::wcout << "[-] Error: SymLoadModule64() failed. Error code: " << GetLastError() << std::endl;
		return {};
	}


	SYMBOL_INFO_PACKAGEW SymInfoPackage{};
	SymInfoPackage.si.SizeOfStruct = sizeof(SYMBOL_INFOW);
	SymInfoPackage.si.MaxNameLen = sizeof(SymInfoPackage.name);//MAX_SYM_NAME + 1;

	std::vector<ULONG64> offsets{};

	for (const auto& sym : symbolName) {
		BOOL bRet = SymFromNameW(
			(HANDLE)process,
			sym.c_str(),
			&SymInfoPackage.si
		);
		if (!bRet || !SymInfoPackage.si.Address)
		{
			std::wcout << "[-] Error: SymFromName() failed. Sym: " << sym << " || Error code: " << GetLastError() << std::endl;
			SymUnloadModule64(GetCurrentProcess(), ModBase);
			return {};
		}

		// Display information about the symbol 
		std::wcout << "[+] Symbol " << sym << " Offset: " << (DWORD)(SymInfoPackage.si.Address - ModBase) << std::endl;
		offsets.push_back((DWORD)(SymInfoPackage.si.Address - ModBase));
	}

	SymUnloadModule64(GetCurrentProcess(), ModBase);

	return offsets;
}

/*
* Resolve the offset of a structure field using the PDB type information.
* Some internal types are present under more than one name, so a list of
* candidates is tried.
*/
static bool GetFieldOffsetInternal(HANDLE hProcess, ULONG64 ModBase, const std::wstring& structName, const std::wstring& fieldName, ULONG64& outOffset) {
	static const std::vector<std::wstring> alternateNames = {
		L"_PiDDBCacheEntry", L"PiDDBCacheEntry", L"_PIDDBCACHE_ENTRY", L"_PIDDB_CACHE_ENTRY",
		L"_HashBucketEntry", L"HashBucketEntry", L"_HASHBUCKET_ENTRY",
		L"_RTL_PROCESS_MODULE_INFORMATION", L"RTL_PROCESS_MODULE_INFORMATION",
		L"_RTL_PROCESS_MODULES", L"RTL_PROCESS_MODULES",
	};

	std::vector<std::wstring> candidates = { structName };
	for (const auto& alternate : alternateNames) {
		if (alternate != structName)
			candidates.push_back(alternate);
	}

	for (const auto& candidate : candidates) {
		SYMBOL_INFO_PACKAGEW package{};
		package.si.SizeOfStruct = sizeof(SYMBOL_INFOW);
		package.si.MaxNameLen = sizeof(package.name);

		if (!SymGetTypeFromNameW(hProcess, ModBase, candidate.c_str(), &package.si) || !package.si.TypeIndex)
			continue;

		const ULONG typeIndex = package.si.TypeIndex;

		DWORD childrenCount = 0;
		if (!SymGetTypeInfo(hProcess, ModBase, typeIndex, TI_GET_CHILDRENCOUNT, &childrenCount) || !childrenCount)
			continue;

		const size_t bufferSize = sizeof(TI_FINDCHILDREN_PARAMS) + (size_t)childrenCount * sizeof(ULONG);
		auto children = std::make_unique<BYTE[]>(bufferSize);
		auto* findChildren = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(children.get());
		findChildren->Count = childrenCount;
		findChildren->Start = 0;

		if (!SymGetTypeInfo(hProcess, ModBase, typeIndex, TI_FINDCHILDREN, findChildren))
			continue;

		for (DWORD i = 0; i < childrenCount; ++i) {
			const ULONG childId = findChildren->ChildId[i];

			WCHAR* name = nullptr;
			if (!SymGetTypeInfo(hProcess, ModBase, childId, TI_GET_SYMNAME, &name) || !name)
				continue;

			const bool matches = (fieldName == name);
			LocalFree(name);

			if (!matches)
				continue;

			if (!SymGetTypeInfo(hProcess, ModBase, childId, TI_GET_OFFSET, &outOffset))
				return false;

			std::wcout << L"[+] Field " << candidate << L"." << fieldName << L" offset: 0x" << std::hex << outOffset << std::dec << std::endl;
			return true;
		}
	}

	std::wcout << L"[-] Field " << structName << L"." << fieldName << L" not found" << std::endl;
	return false;
}

std::vector<ULONG64> SymbolEngine::GetStructFieldOffsets(std::wstring pdbPath, std::vector<std::pair<std::wstring, std::wstring>> structAndField) {
	DWORD64 BaseAddr = 0x40000;
	DWORD FileSize = (DWORD)std::filesystem::file_size(pdbPath);

	DWORD64 ModBase = SymLoadModuleExW(
		(HANDLE)process,
		NULL,
		pdbPath.c_str(),
		NULL,
		BaseAddr,
		FileSize,
		NULL,
		NULL
	);

	if (ModBase == 0) {
		std::wcout << L"[-] Error: SymLoadModule64() failed. Error code: " << GetLastError() << std::endl;
		return {};
	}

	std::vector<ULONG64> offsets{};
	offsets.reserve(structAndField.size());

	for (const auto& [structName, fieldName] : structAndField) {
		ULONG64 offset = 0;
		if (GetFieldOffsetInternal((HANDLE)process, ModBase, structName, fieldName, offset)) {
			std::wcout << L"[+] Field " << structName << L"." << fieldName << L" offset: 0x" << std::hex << offset << std::dec << std::endl;
		}
		else {
			std::wcout << L"[!] Field " << structName << L"." << fieldName << L" unresolved" << std::endl;
		}
		offsets.push_back(offset);
	}

	SymUnloadModule64(GetCurrentProcess(), ModBase);

	return offsets;
}