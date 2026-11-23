/*
 * dbghelp based PDB reader. See Symbol.hpp for the contract.
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

#include "Symbol.hpp"
#include "../../Utilities/Support/Console.hpp"

#include <Windows.h>
#include <algorithm>
#include <string>
#include <memory>
#include <random>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <limits>
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
			/* GetModuleFileNameW returns nSize when the buffer was too small.
			 * Refusing every path >= MAX_PATH disabled all symbol loading for a
			 * valid long install path, so grow the buffer until the whole path
			 * fits instead. The cap bounds a pathological return value. */

			std::wstring path;
			for (DWORD capacity = MAX_PATH;;) {
				path.assign(capacity, L'\0');
				const DWORD length = GetModuleFileNameW(nullptr, path.data(), capacity);
				if (length == 0u)
					return {};
				if (length < capacity) {
					path.resize(length);
					break;
				}
				if (capacity > (1u << 15))
					return {};
				capacity *= 2;
			}
			const auto pos = path.find_last_of(L"\\/");
			return pos == std::wstring::npos ? std::wstring() : path.substr(0, pos);
		}

		bool Load() {
			const std::wstring folder = ExeFolder();
			if (folder.empty())
				return false;

			//Preferred: the DLLs subfolder, which is where the release ships them.

			std::wstring dll_path = folder + L"\\" + kSymbolDllFolder + L"\\dbghelp.dll";
			module = LoadLibraryExW(dll_path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);

			//Fallback: next to the executable, for a developer layout that has
			//not adopted the DLLs folder yet.

			if (!module) {
				dll_path = folder + L"\\dbghelp.dll";
				module = LoadLibraryExW(dll_path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
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
 *
 * The name carries a per-process random component, not just the pid and the
 * tick count. %TEMP% is writable by every process on the box, so a name an
 * attacker can predict is a name they can pre-create: CreateDirectoryW then
 * fails for a path that already exists and is theirs, and after the attempts run
 * out symbol resolution aborts for the whole run. The random component does not
 * make the path unguessable, it makes a pre-created one impossible to land.
 */

std::wstring MakeTempSymbolStore() {
	/* GetTempPathW returns the required size when the buffer is too small. The
	 * old fixed buffer ignored that nonzero truncation result and built every
	 * candidate path from a truncated root, so a long TEMP broke symbol
	 * resolution. Grow until the value fits, with a sanity cap. */

	std::wstring tempRoot;
	for (DWORD capacity = MAX_PATH;;) {
		std::wstring buffer(capacity, L'\0');
		const DWORD length = GetTempPathW(capacity, buffer.data());
		if (length == 0u)
			return {};
		if (length < capacity) {
			buffer.resize(length);
			tempRoot = std::move(buffer);
			break;
		}
		if (capacity > (1u << 15))
			return {};
		capacity *= 2;
	}

	//Seeded once, like every other generator in this project. 64 bits of it; the
	//whole value is rendered as hex so nothing here is short either.

	static std::mt19937_64 engine{ std::random_device{}() };

	for (int attempt = 0; attempt < 16; ++attempt) {
		std::wostringstream name;
		name << L"amager_sym_" << GetCurrentProcessId()
			<< L"_" << GetTickCount64()
			<< L"_" << std::hex << std::setw(16) << std::setfill(L'0') << engine()
			<< L"_" << attempt;

		const std::wstring candidate = std::wstring(tempRoot) + name.str();
		if (CreateDirectoryW(candidate.c_str(), nullptr))
			return candidate;
	}
	return {};
}

/*
 * Download one PDB straight from the public symbol server as a fallback for
 * SymFindFileInPathW.
 *
 * msdl now answers symbol requests with a 302 to an Azure blob URL. Some
 * symsrv builds do not follow that redirect and report a plain
 * ERROR_FILE_NOT_FOUND for a PDB that is in fact published, which used to fail
 * the whole offsets run. URLDownloadToFileW follows the redirect chain, so the
 * same file is fetched here instead.
 *
 * The URL is built from the binary's own debug identity, and the downloaded
 * file is checked against that identity before it is accepted. A 404 body, a
 * truncated transfer or a wrong build therefore never reaches the flat cache.
 */

bool DownloadPdbDirect(const SYMSRV_INDEX_INFOW& info, const std::wstring& destPath, const DbgHelp& dbg) {
	std::wstring identity;
	wchar_t buffer[48];

	if (info.guid == GUID{}) {
		//Classic signature + age layout.
		swprintf(buffer, std::size(buffer), L"%08lx%lx", info.sig, info.age);
	}
	else {
		//GUID + age, lowercase with no separators, as the server expects.
		swprintf(buffer, std::size(buffer),
			L"%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%lx",
			info.guid.Data1, info.guid.Data2, info.guid.Data3,
			info.guid.Data4[0], info.guid.Data4[1], info.guid.Data4[2], info.guid.Data4[3],
			info.guid.Data4[4], info.guid.Data4[5], info.guid.Data4[6], info.guid.Data4[7],
			info.age);
	}
	identity = buffer;

	const std::wstring url = L"https://msdl.microsoft.com/download/symbols/"
		+ std::wstring(info.pdbfile) + L"/" + identity + L"/" + info.pdbfile;

	//Loaded on demand: this fallback is rare, and adding a hard import just for
	//it would couple the release to urlmon.dll even when symbols resolve normally.

	HMODULE urlmon = LoadLibraryW(L"urlmon.dll");
	if (!urlmon) {
		Log(L"[-] Could not load urlmon.dll for a direct symbol download" << std::endl);
		return false;
	}

	using DownloadFn = HRESULT(WINAPI*)(void*, const wchar_t*, const wchar_t*, DWORD, void*);
	const auto download = reinterpret_cast<DownloadFn>(GetProcAddress(urlmon, "URLDownloadToFileW"));
	if (!download) {
		FreeLibrary(urlmon);
		Log(L"[-] urlmon.dll is missing URLDownloadToFileW" << std::endl);
		return false;
	}

	const HRESULT hr = download(nullptr, url.c_str(), destPath.c_str(), 0, nullptr);
	FreeLibrary(urlmon);
	if (FAILED(hr)) {
		Log(L"[-] Direct download of " << Val(info.pdbfile) << L" failed, HRESULT "
			<< Val(Hex(static_cast<unsigned long>(hr))) << std::endl);
		return false;
	}

	//A success code with a missing or wrong file is still a miss. Verify the
	//downloaded PDB carries the identity the binary asked for before moving it
	//into the flat cache, exactly as the cache-hit path does.

	SYMSRV_INDEX_INFOW downloadedInfo{};
	downloadedInfo.sizeofstruct = sizeof(downloadedInfo);
	if (!dbg.SymSrvGetFileIndexInfoW(destPath.c_str(), &downloadedInfo, 0)
		|| !SameIdentity(IdentityOf(info), IdentityOf(downloadedInfo))) {
		Log(L"[-] Downloaded " << Val(info.pdbfile) << L" does not match the running build" << std::endl);
		DeleteFileW(destPath.c_str());
		return false;
	}

	return true;
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
 * A miss is fetched through SymFindFileInPathW, whose downstream store is
 * pointed at a throwaway temporary folder because symsrv would otherwise
 * rebuild the nested <name>\<GUID>\ layout (and a pingme.txt) under the cache
 * folder. If symsrv cannot follow msdl's redirect to blob storage, the same
 * PDB is fetched directly over HTTPS instead. Either way the download is then
 * moved into the flat cache path and the temporary store is removed.
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

	/* RAII: an allocation failure in the strings below used to unwind past the
	 * plain remove_all at the end of this function and leave the temporary
	 * symstore (pingme.txt and GUID subfolders) on disk. */

	struct TempStoreCleanup {
		std::wstring path;
		~TempStoreCleanup() {
			std::error_code ec;
			std::filesystem::remove_all(path, ec);
		}
	} cleanup{ tempStore };

	const std::wstring tempSearch = L"cache*" + tempStore + L";SRV*http://msdl.microsoft.com/download/symbols";

	auto pdbPath = std::make_unique<wchar_t[]>(4096);
	const BOOL found = dbg.SymFindFileInPathW(
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

	//Capture before any logging: argument evaluation order is unspecified, so
	//reading GetLastError() inside the stream below could observe a later call.

	const DWORD findError = GetLastError();
	std::wstring downloadedPath = pdbPath.get();

	//The return value was discarded, so a failure was inferred from an empty
	//output buffer - and the only diagnostic that could fire checked whether
	//symsrv.dll was loaded at all. A network outage, a 404 for a PDB Microsoft
	//has not published, or a cache ACL problem all produced silence: no message
	//and no file, and the caller reported only "no symbols available".

	if (!found) {
		Log(L"[INFO] symsrv could not retrieve " << Val(binaryInfo.pdbfile)
			<< L", error " << Val(static_cast<unsigned long>(findError))
			<< L"; trying a direct download" << std::endl);
	}

	//Windows does not ship symsrv.dll and dbghelp loads it from its own folder.
	//If it is not loaded after those calls, the DLLs folder is wrong or the file
	//is not the one that was meant to be there - a different problem from the
	//lookup failing, and worth saying so.
	else if (downloadedPath.empty() && GetModuleHandleA("symsrv.dll") == nullptr) {
		Log(L"[-] Please provide proper dbghelp.dll and symsrv.dll!" << std::endl);
	}

	/* msdl answers symbol requests with a 302 to Azure blob storage, and some
	 * symsrv builds fail to follow it - which is exactly the ERROR_FILE_NOT_FOUND
	 * above for a PDB that is really published. Fetch the same identity directly
	 * into the temp store; the move below then treats it like any other hit, and
	 * the RAII guard still removes the store on every path. */
	if (downloadedPath.empty()) {
		const std::wstring directPath = tempStore + L"\\" + binaryInfo.pdbfile;
		if (DownloadPdbDirect(binaryInfo, directPath, dbg)) {
			Log(L"[+] Downloaded " << Val(binaryInfo.pdbfile)
				<< L" directly from the symbol server" << std::endl);
			downloadedPath = directPath;
		}
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

	//The cleanup guard above removes the temporary store on every exit,
	//including an exception, so no pingme.txt or GUID subfolder survives.

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
	//SymLoadModuleExW takes a DWORD size. A wider file would be passed with a
	//truncated length, so refuse it rather than load a corrupt module.
	if (fileSize > (std::numeric_limits<DWORD>::max)()) {
		Log(L"[-] PDB too large to load: " << Val(pdbPath) << std::endl);
		return {};
	}
	const DWORD FileSize = static_cast<DWORD>(fileSize);

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
		Log(L"[-] Error: SymLoadModuleExW() failed. Error code: " << Val(GetLastError()) << std::endl);
		return {};
	}


	SYMBOL_INFO_PACKAGEW SymInfoPackage{};
	SymInfoPackage.si.SizeOfStruct = sizeof(SYMBOL_INFOW);
	//MaxNameLen is in CHARACTERS, not bytes. sizeof(name) is twice the
	//character count for this WCHAR array and would let dbghelp overrun it.
	SymInfoPackage.si.MaxNameLen = MAX_SYM_NAME + 1;

	std::vector<ULONG64> offsets{};

	for (const auto& sym : symbolName) {
		BOOL bRet = dbg.SymFromNameW(
			(HANDLE)process,
			sym.c_str(),
			&SymInfoPackage.si
		);
		if (!bRet || !SymInfoPackage.si.Address)
		{
			Log(L"[-] Error: SymFromNameW() failed. Sym: " << Val(sym) << L" || Error code: " << Val(GetLastError()) << std::endl);
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

namespace
{

	/*
	 * Upper bound on the members a type may declare before this file stops
	 * enumerating it. Used where the count comes out of the PDB and sizes an
	 * allocation directly; see the use below.
	 */

	constexpr DWORD kMaxTypeChildren = 0x10000;
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
		return false;

	/* Fallback spellings are scoped to ONE struct family. A single global list
	 * let HashBucketEntry.DriverName resolve against _PiDDBCacheEntry, which has
	 * a same-named member but a different layout; the caller then published that
	 * offset under the HashBucketEntry key. Only alternate spellings of the same
	 * type may be substituted. */

	static const std::vector<std::vector<std::wstring>> nameFamilies = {
		{ L"_PiDDBCacheEntry", L"PiDDBCacheEntry", L"_PIDDBCACHE_ENTRY", L"_PIDDB_CACHE_ENTRY" },
		{ L"_HashBucketEntry", L"HashBucketEntry", L"_HASHBUCKET_ENTRY" },
		{ L"_RTL_PROCESS_MODULE_INFORMATION", L"RTL_PROCESS_MODULE_INFORMATION" },
		{ L"_RTL_PROCESS_MODULES", L"RTL_PROCESS_MODULES" },
	};

	std::vector<std::wstring> candidates = { structName };
	for (const auto& family : nameFamilies) {
		if (std::find(family.begin(), family.end(), structName) == family.end())
			continue;
		for (const auto& alternate : family) {
			if (alternate != structName)
				candidates.push_back(alternate);
		}
		break;
	}

	for (const auto& candidate : candidates) {
		SYMBOL_INFO_PACKAGEW package{};
		package.si.SizeOfStruct = sizeof(SYMBOL_INFOW);
		package.si.MaxNameLen = MAX_SYM_NAME + 1;

		if (!dbg.SymGetTypeFromNameW(hProcess, ModBase, candidate.c_str(), &package.si) || !package.si.TypeIndex)
			continue;

		const ULONG typeIndex = package.si.TypeIndex;

//Members have to be enumerated before their offsets can be read;
		//SymGetTypeInfo has no "find a member by name" call.

		DWORD childrenCount = 0;
		if (!dbg.SymGetTypeInfo(hProcess, ModBase, typeIndex, TI_GET_CHILDRENCOUNT, &childrenCount) || !childrenCount)
			continue;

		/*
		 * Capped before it is multiplied.
		 *
		 * childrenCount is a 32-bit value out of the PDB and it sizes the
		 * allocation directly, so a malformed or hostile one asks for up to
		 * 256 GB and the failure is an uncaught bad_alloc that takes the whole
		 * tool down. A UDT with more members than this is not one this project
		 * resolves against; treating it as a miss costs the field, and refusing
		 * to allocate costs nothing.
		 */

		if (childrenCount > kMaxTypeChildren) {
			Log(L"[!] " << Val(structName) << L" reports " << Val(childrenCount)
				<< L" members, above the supported maximum; skipping it" << std::endl);
			continue;
		}

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
	//SymLoadModuleExW takes a DWORD size. A wider file would be passed with a
	//truncated length, so refuse it rather than load a corrupt module.
	if (fileSize > (std::numeric_limits<DWORD>::max)()) {
		Log(L"[-] PDB too large to load: " << Val(pdbPath) << std::endl);
		return {};
	}
	const DWORD FileSize = static_cast<DWORD>(fileSize);

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
		Log(L"[-] Error: SymLoadModuleExW() failed. Error code: " << Val(GetLastError()) << std::endl);
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
