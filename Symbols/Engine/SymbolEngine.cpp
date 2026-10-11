/*
 * dbghelp based PDB reader. See SymbolEngine.hpp for the contract.
 *
 * Two kinds of lookup are used:
 *   - symbols, through SymFromName
 *   - structure field offsets, through the PDB type information
 *
 * The second exists because field offsets cannot be found by name alone, and
 * some of the structures this project needs are not public UDTs at all and so
 * are not in the type stream either.
 *
 * dbghelp is loaded explicitly from the DLLs subfolder instead of being linked
 * statically. A static import is resolved before main() runs, using the
 * application directory, then the system directories, then PATH - and
 * %SystemRoot%\System32 already contains its own dbghelp.dll, so a copy sitting
 * in a subfolder can never win and the wrong build is used. Loading it by full
 * path with LOAD_WITH_ALTERED_SEARCH_PATH also makes dbghelp pick up symsrv.dll
 * from that same folder, which is what actually makes the layout work.
 */

#include "SymbolEngine.hpp"
#include "../../Utilities/Console.hpp"

#include <Windows.h>
#include <string>
#include <memory>
#include <filesystem>
#include <iostream>
#include <cstdio>
#include <dbghelp.h>

namespace
{
	/*
	 * The dbghelp entry points this file uses, resolved once at first use.
	 *
	 * Types mirror dbghelp.h exactly; the header is still included for the
	 * structures (SYMBOL_INFO_PACKAGEW, SYMSRV_INDEX_INFOW, IMAGE_DEBUG_TYPE)
	 * that are passed across the boundary, only the calls go through pointers.
	 */
	struct DbgHelp
	{
		HMODULE module = nullptr;
		std::wstring path;

		BOOL(WINAPI* SymInitializeW)(HANDLE, PCWSTR, BOOL) = nullptr;
		BOOL(WINAPI* SymCleanup)(HANDLE) = nullptr;
		DWORD64(WINAPI* SymSetOptions)(DWORD) = nullptr;
		BOOL(WINAPI* SymSrvGetFileIndexInfoW)(PCWSTR, PSYMSRV_INDEX_INFOW, DWORD) = nullptr;
		BOOL(WINAPI* SymFindFileInPathW)(HANDLE, PCWSTR, PCWSTR, void*, DWORD, DWORD, DWORD, PWSTR, PSTR, PSTR) = nullptr;
		BOOL(WINAPI* SymFromNameW)(HANDLE, PCWSTR, PSYMBOL_INFOW) = nullptr;
		BOOL(WINAPI* SymGetTypeFromNameW)(HANDLE, DWORD64, PCWSTR, PSYMBOL_INFOW) = nullptr;
		//IMAGE_DEBUG_TYPE and PMODLOAD_EXTRA_DATA are spelled as int / void*
		//rather than by name: they are declared inside dbghelp.h's own guard
		//and are not visible here, and a failed declaration collapses the whole
		//prototype into a short one. Both are ABI-compatible (4 byte enum, and
		//pointer) and every argument the call sites pass converts implicitly.
		BOOL(WINAPI* SymGetTypeInfo)(HANDLE, DWORD64, ULONG, int, void*) = nullptr;
		DWORD64(WINAPI* SymLoadModuleExW)(HANDLE, HMODULE, PCWSTR, PCWSTR, DWORD64, DWORD, void*, void*) = nullptr;
		BOOL(WINAPI* SymUnloadModule64)(HANDLE, DWORD64) = nullptr;

		template<typename T>
		bool Bind(const char* name, T& slot) {
			slot = reinterpret_cast<T>(GetProcAddress(module, name));
			if (!slot) {
				Log(L"[-] dbghelp.dll is missing export " << Val(name) << std::endl);
				return false;
			}
			return true;
		}

		bool BindAll() {
			return Bind("SymInitializeW", SymInitializeW)
				&& Bind("SymCleanup", SymCleanup)
				&& Bind("SymSetOptions", SymSetOptions)
				&& Bind("SymSrvGetFileIndexInfoW", SymSrvGetFileIndexInfoW)
				&& Bind("SymFindFileInPathW", SymFindFileInPathW)
				&& Bind("SymFromNameW", SymFromNameW)
				&& Bind("SymGetTypeFromNameW", SymGetTypeFromNameW)
				&& Bind("SymGetTypeInfo", SymGetTypeInfo)
				&& Bind("SymLoadModuleExW", SymLoadModuleExW)
				&& Bind("SymUnloadModule64", SymUnloadModule64);
		}

		//Locate the running executable's folder without pulling in Utilities,
		//which this tool does not link.
		static std::wstring ExeFolder() {
			wchar_t buffer[MAX_PATH] = { 0 };
			if (!GetModuleFileNameW(nullptr, buffer, MAX_PATH))
				return {};
			std::wstring path(buffer);
			const auto pos = path.find_last_of(L"\\/");
			return pos == std::wstring::npos ? std::wstring() : path.substr(0, pos);
		}

		bool Load() {
			const std::wstring folder = ExeFolder();
			if (folder.empty())
				return false;

			//Preferred: the DLLs subfolder, which is where the release ships them.
			path = folder + L"\\" + kSymbolDllFolder + L"\\dbghelp.dll";
			module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);

			//Fallback: next to the executable, for a developer layout that has
			//not adopted the DLLs folder yet.
			if (!module) {
				path = folder + L"\\dbghelp.dll";
				module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
			}

			if (!module) {
				Log(L"[-] Could not load dbghelp.dll from " << Val(folder) << std::endl);
				return false;
			}

			if (!BindAll()) {
				FreeLibrary(module);
				module = nullptr;
				return false;
			}

			return true;
		}
	};

	const DbgHelp& Dbg() {
		static DbgHelp instance;
		static bool attempted = false;
		if (!attempted) {
			attempted = true;
			instance.Load();
		}
		return instance;
	}
}

namespace
{
	/*
	 * The identity a debug file is indexed by on the symbol server: a GUID and
	 * age when the file carries a GUID, otherwise the timestamp signature and
	 * age. The same rule is applied to the binary and to a cached PDB so their
	 * identities can be compared directly.
	 */
	struct DebugIdentity {
		bool hasGuid = false;
		GUID guid{};
		DWORD sig = 0;
		DWORD age = 0;
	};

	DebugIdentity IdentityOf(const SYMSRV_INDEX_INFOW& info) {
		DebugIdentity identity;
		if (info.guid == GUID{}) { // GUID is zeroed
			identity.hasGuid = false;
			identity.sig = info.sig;
			identity.age = info.age;
		}
		else {
			identity.hasGuid = true;
			identity.guid = info.guid;
			identity.age = info.age;
		}
		return identity;
	}

	bool SameIdentity(const DebugIdentity& a, const DebugIdentity& b) {
		if (a.hasGuid != b.hasGuid || a.age != b.age)
			return false;
		return a.hasGuid ? a.guid == b.guid : a.sig == b.sig;
	}

	/*
	 * A unique empty folder under %TEMP% for symsrv to write its symstore layout
	 * into. The caller removes it once the PDB has been moved out; it exists
	 * only so the flat cache folder is never turned back into a symstore tree.
	 */
	std::wstring MakeTempSymbolStore() {
		wchar_t tempRoot[MAX_PATH + 1] = { 0 };
		if (!GetTempPathW(MAX_PATH, tempRoot))
			return {};

		for (int attempt = 0; attempt < 16; ++attempt) {
			const std::wstring candidate = std::wstring(tempRoot)
				+ L"amager_sym_" + std::to_wstring(GetCurrentProcessId())
				+ L"_" + std::to_wstring(GetTickCount64())
				+ L"_" + std::to_wstring(attempt);
			if (CreateDirectoryW(candidate.c_str(), nullptr))
				return candidate;
		}
		return {};
	}
}

/*
 * Resolve the PDB path for a binary, downloading it if it is not cached yet.
 *
 * The cache is a flat folder: <cachePath>\<pdbfile>. SymSrvGetFileIndexInfoW
 * reads the debug directory of the binary to get its signature or GUID and age,
 * which is also what identifies the matching PDB. A cached PDB is reused only
 * when its own index matches the binary's; a stale PDB from an earlier Windows
 * build is treated as a miss, never loaded silently.
 *
 * A miss is fetched through SymFindFileInPathW - the msdl URL layout is left to
 * symsrv - but its downstream store is pointed at a throwaway temporary folder,
 * because symsrv would otherwise rebuild the nested <name>\<GUID>\ layout (and
 * a pingme.txt) under the cache folder. The downloaded PDB is then moved into
 * the flat cache path and the temporary store is removed.
 *
 * An empty result means no symbols are available, which the caller treats as a
 * hard failure rather than continuing with a missing offset.
 */
SymbolEngine::SymbolEngine(const std::wstring& cachePath) : cachePath(cachePath) {
	process = (unsigned long long)GetCurrentProcess();

	const auto& dbg = Dbg();
	if (!dbg.module)
		return;

	//No downstream store is given here on purpose: every download goes through
	//GetPDB, which points SymFindFileInPathW at a temporary store so the flat
	//cache folder is never rebuilt into a symstore tree.
	const std::wstring searchPath = L"SRV*http://msdl.microsoft.com/download/symbols";
	if (!dbg.SymInitializeW((HANDLE)process, searchPath.c_str(), FALSE))
		Log(L"[-] SymInitializeW failed, error " << Val(GetLastError()) << std::endl);
	dbg.SymSetOptions(SYMOPT_EXACT_SYMBOLS);
}

SymbolEngine::~SymbolEngine() {
	const auto& dbg = Dbg();
	if (process && dbg.module)
		dbg.SymCleanup((HANDLE)process);
}

std::wstring SymbolEngine::GetPDB(const std::wstring& binaryPath) {

	//Resolved once; every call below goes through these pointers.
	const auto& dbg = Dbg();
	if (!dbg.module)
		return {};

	SYMSRV_INDEX_INFOW binaryInfo{};
	binaryInfo.sizeofstruct = sizeof(SYMSRV_INDEX_INFOW);
	if (!dbg.SymSrvGetFileIndexInfoW(binaryPath.c_str(), &binaryInfo, 0))
	{
		Log(L"[-] Failed to find binary info. Error: " << Val(GetLastError()) << std::endl);
		return {};
	}

	if (binaryInfo.pdbfile[0] == L'\0') {
		Log(L"[-] No PDB name in the debug directory of " << Val(binaryPath) << std::endl);
		return {};
	}

	//The flat cache path this binary's PDB belongs at.
	const std::wstring flatPath = cachePath + L"\\" + binaryInfo.pdbfile;
	const DebugIdentity binaryIdentity = IdentityOf(binaryInfo);

	//Cache hit: the flat PDB exists and its index belongs to this exact binary.
	//A PDB whose index does not match is a miss, not a silent load.
	if (std::filesystem::exists(flatPath)) {
		SYMSRV_INDEX_INFOW cachedInfo{};
		cachedInfo.sizeofstruct = sizeof(SYMSRV_INDEX_INFOW);
		if (dbg.SymSrvGetFileIndexInfoW(flatPath.c_str(), &cachedInfo, 0)
			&& SameIdentity(binaryIdentity, IdentityOf(cachedInfo))) {
			return flatPath;
		}
		Log(L"[INFO] Cached " << Val(binaryInfo.pdbfile) << L" does not match the running build; refreshing" << std::endl);
	}

	void* id;
	DWORD idType;
	//A binary with no GUID is identified by its signature and timestamp
	//instead, which is what the classic PDB layout uses.
	if (binaryInfo.guid == GUID{}) { // GUID is zeroed
		id = &binaryInfo.sig;
		idType = SSRVOPT_DWORDPTR;
	}
	else {
		id = &binaryInfo.guid;
		idType = SSRVOPT_GUIDPTR;
	}

	//A private, throwaway store: symsrv writes the nested <name>\<GUID>\ layout
	//and a pingme.txt there instead of under the flat cache folder.
	const std::wstring tempStore = MakeTempSymbolStore();
	if (tempStore.empty()) {
		Log(L"[-] Could not create a temporary symbol store" << std::endl);
		return {};
	}
	const std::wstring tempSearch = L"cache*" + tempStore + L";SRV*http://msdl.microsoft.com/download/symbols";

	auto pdbPath = std::make_unique<wchar_t[]>(4096);
	dbg.SymFindFileInPathW(
		(HANDLE)process,
		tempSearch.c_str(),
		binaryInfo.pdbfile,
		id,
		binaryInfo.age,
		0,
		idType,
		pdbPath.get(),
		NULL,
		NULL
	);

	const std::wstring downloadedPath = pdbPath.get();
	// Windows don't provide symsrv.dll and dbghelp loads it from his current path, if its not loaded after those calls means that symsrv/dbghelp are invalid
	if (downloadedPath.empty() && GetModuleHandleA("symsrv.dll") == nullptr) {
		Log(L"[-] Please provide proper dbghelp.dll and symsrv.dll!" << std::endl);
	}

	std::wstring result;
	if (!downloadedPath.empty()) {
		//The flat cache folder may not exist yet on a first run.
		std::error_code dirError;
		std::filesystem::create_directories(cachePath, dirError);

		//MOVEFILE_COPY_ALLOWED because %TEMP% and the cache folder can be on
		//different volumes, where a plain rename cannot work.
		if (MoveFileExW(downloadedPath.c_str(), flatPath.c_str(),
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
			Log(L"[+] Downloaded " << Val(binaryInfo.pdbfile) << L" to " << Val(flatPath) << std::endl);
			result = flatPath;
		}
		else {
			Log(L"[-] Could not move the downloaded PDB to " << Val(flatPath)
				<< L", error " << Val(GetLastError()) << std::endl);
		}
	}

	//Remove the temporary store whatever happened: nothing of it may survive,
	//least of all a pingme.txt or a GUID subfolder.
	std::error_code removeError;
	std::filesystem::remove_all(tempStore, removeError);

	return result;
}

std::vector<uint64_t> SymbolEngine::GetOffset(const std::wstring& pdbPath, const std::vector<std::wstring>& symbolName) {

	//Resolved once; every call below goes through these pointers.
	const auto& dbg = Dbg();
	if (!dbg.module)
		return {};

	DWORD64 BaseAddr = 0x40000;

	//std::filesystem::file_size throws when the path does not exist, which
	//would take the whole tool down instead of reporting the problem.
	std::error_code fileSizeError;
	const auto fileSize = std::filesystem::file_size(pdbPath, fileSizeError);
	if (fileSizeError) {
		Log(L"[-] Cannot read " << Val(pdbPath) << L": " << Val(fileSizeError.message().c_str()) << std::endl);
		return {};
	}
	const DWORD FileSize = (DWORD)fileSize;

	// Load symbols for the module.
	//The module is loaded at a fixed base with the PDB as the image, so the
	//addresses dbghelp returns are offsets from that base and can be written
	//straight into Offsets.ini. The loading line is printed by the caller, which
	//reports every module together at the end instead of in resolution order.
	DWORD64 ModBase = dbg.SymLoadModuleExW(
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
		Log(L"[-] Error: SymLoadModule64() failed. Error code: " << Val(GetLastError()) << std::endl);
		return {};
	}


	SYMBOL_INFO_PACKAGEW SymInfoPackage{};
	SymInfoPackage.si.SizeOfStruct = sizeof(SYMBOL_INFOW);
	SymInfoPackage.si.MaxNameLen = sizeof(SymInfoPackage.name);//MAX_SYM_NAME + 1;

	std::vector<ULONG64> offsets{};

	for (const auto& sym : symbolName) {
		BOOL bRet = dbg.SymFromNameW(
			(HANDLE)process,
			sym.c_str(),
			&SymInfoPackage.si
		);
		if (!bRet || !SymInfoPackage.si.Address)
		{
			Log(L"[-] Error: SymFromName() failed. Sym: " << Val(sym) << L" || Error code: " << Val(GetLastError()) << std::endl);
			dbg.SymUnloadModule64(GetCurrentProcess(), ModBase);
			return {};
		}

		//Symbol offsets are relative to the module base, which can exceed 32
		//bits, so they are kept at full width. The caller prints them, in a
		//fixed order, once every module has resolved.
		const uint64_t offset = SymInfoPackage.si.Address - ModBase;
		offsets.push_back(offset);
	}

	dbg.SymUnloadModule64(GetCurrentProcess(), ModBase);

	return offsets;
}

//Resolve one field offset.
//
// The offset of a field cannot be looked up by name directly, so the type is
// located first and then walked:
//   SymGetTypeFromNameW   find the type
//   TI_GET_CHILDRENCOUNT  how many members it has
//   TI_FINDCHILDREN       get their type indices in one call
//   TI_GET_SYMNAME        the name of each member
//   TI_GET_OFFSET         the byte offset of the one that matched
//
// Internal types appear in the PDB under several spellings depending on the
// build, so a list of alternates is tried. matchedName reports which one
// actually matched, because it can differ from the requested one.
//
// Silent on failure: the caller reports it, so this stays usable as a predicate.
static bool GetFieldOffsetInternal(HANDLE hProcess, ULONG64 ModBase, const std::wstring& structName, const std::wstring& fieldName, ULONG64& outOffset, std::wstring& matchedName) {

	//Resolved once; every call below goes through these pointers.
	const auto& dbg = Dbg();
	if (!dbg.module)
		return {};
	//Fallback spellings for the types this project cares about.
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

		if (!dbg.SymGetTypeFromNameW(hProcess, ModBase, candidate.c_str(), &package.si) || !package.si.TypeIndex)
			continue;

		const ULONG typeIndex = package.si.TypeIndex;

			//Members have to be enumerated before their offsets can be read;
			//SymGetTypeInfo has no "find a member by name" call.
			DWORD childrenCount = 0;
		if (!dbg.SymGetTypeInfo(hProcess, ModBase, typeIndex, TI_GET_CHILDRENCOUNT, &childrenCount) || !childrenCount)
			continue;

		const size_t bufferSize = sizeof(TI_FINDCHILDREN_PARAMS) + (size_t)childrenCount * sizeof(ULONG);
		auto children = std::make_unique<BYTE[]>(bufferSize);
		auto* findChildren = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(children.get());
		findChildren->Count = childrenCount;
		findChildren->Start = 0;

		if (!dbg.SymGetTypeInfo(hProcess, ModBase, typeIndex, TI_FINDCHILDREN, findChildren))
			continue;

		for (DWORD i = 0; i < childrenCount; ++i) {
			const ULONG childId = findChildren->ChildId[i];

			WCHAR* name = nullptr;
			if (!dbg.SymGetTypeInfo(hProcess, ModBase, childId, TI_GET_SYMNAME, &name) || !name)
				continue;

			const bool matches = (fieldName == name);
			LocalFree(name);

			if (!matches)
				continue;

			if (!dbg.SymGetTypeInfo(hProcess, ModBase, childId, TI_GET_OFFSET, &outOffset))
				return false;

			matchedName = candidate;
			return true;
		}
	}

	return false;
}

std::vector<SymbolEngine::FieldResult> SymbolEngine::GetStructFieldOffsets(const std::wstring& pdbPath, const std::vector<FieldRequest>& fields) {

	//Resolved once; every call below goes through these pointers.
	const auto& dbg = Dbg();
	if (!dbg.module)
		return {};
	DWORD64 BaseAddr = 0x40000;

	std::error_code fileSizeError;
	const auto fileSize = std::filesystem::file_size(pdbPath, fileSizeError);
	if (fileSizeError) {
		Log(L"[-] Cannot read " << Val(pdbPath) << L": " << Val(fileSizeError.message().c_str()) << std::endl);
		return {};
	}
	const DWORD FileSize = (DWORD)fileSize;

	DWORD64 ModBase = dbg.SymLoadModuleExW(
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
		Log(L"[-] Error: SymLoadModule64() failed. Error code: " << Val(GetLastError()) << std::endl);
		return {};
	}

	std::vector<FieldResult> results{};
	results.reserve(fields.size());

	for (const auto& request : fields) {
		const std::wstring& structName = request.structName;
		const std::wstring& fieldName = request.fieldName;

		//A miss leaves offset at 0 and matchedName empty; the caller decides
		//how to report it, based on the request's optional flag. Reporting used
		//to happen here, which is why the field block landed in the middle of
		//the console report.
		FieldResult result{};
		std::wstring matchedName;
		if (GetFieldOffsetInternal((HANDLE)process, ModBase, structName, fieldName, result.offset, matchedName)) {
			//Set even when the offset is 0: that is how the caller tells a field
			//that legitimately sits at the start of the struct from one that was
			//not found.
			result.matchedName = matchedName;
		}

		results.push_back(result);
	}

	dbg.SymUnloadModule64(GetCurrentProcess(), ModBase);

	return results;
}
