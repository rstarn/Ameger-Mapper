/*
 * Entry point and command line handling for Mapper.exe.
 *
 * Order of operations, which matters:
 *   1. install the crash handler, so a failure still unloads the provider
 *   2. parse arguments
 *   3. resolve Offsets.ini (running SymbolTool.exe unless told not to)
 *   4. verify the driver file exists
 *   5. load the provider and prepare offsets
 *   6. map the driver and call its entry point
 *   7. unload the provider
 *
 * Steps 5 and 6 are the only ones that touch the kernel, and they only run once
 * the file has been fully validated, so a bad path never gets as far as
 * loading anything.
 */

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <TlHelp32.h>

#include "../Mapper/Mapper.hpp"
#include "../Utilities/Utilities.hpp"
#include "../Provider/Driver.hpp"

#ifdef PDB_OFFSETS
#include "../Symbols/Handler/SymbolsHandler.hpp"
#endif

/*
 * Unhandled exception handler.
 *
 * A crash here usually means the kernel side went wrong, and leaving the
 * provider loaded would keep whatever state it created alive, so the handler
 * unloads before letting the process die.
 */
LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
	{
		const auto* rec = ExceptionInfo->ExceptionRecord;
		Log(L"[!!] Crash at addr 0x" << std::hex << (uint64_t)rec->ExceptionAddress
			<< L" by 0x" << rec->ExceptionCode << std::dec << std::endl);
	}
	else
		Log(L"[!!] Crash" << std::endl);

	if (Driver::hDevice)
		Driver::Unload();

	return EXCEPTION_EXECUTE_HANDLER;
}

//Index of a command line flag, -1 when absent.
//Accepts both /flag and --flag, case insensitively, so the two styles in the
//help text both work.
int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}

/*
 * Example callback, runs once the image is in kernel memory but before
 * DriverEntry. This is the point where the final mapping address is known and
 * can still be modified.
 */
bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	Log("[+] Callback example called" << std::endl);

	/*
	This callback occurs before call driver entry and
	can be useful to pass more customized params in
	the last step of the mapping procedure since you
	know now the mapping address and other things
	*/
	return true;
}

//Parent process id, 0 when it cannot be determined.
//Walks the process snapshot; the handle is closed in the finally block either
//way.
DWORD getParentProcess()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == 0) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot != 0) CloseHandle(hSnapshot);
	}
	return ppid;
}

//Help people that don't understand how to open a console.
//Only pauses when launched from explorer, so a run from a terminal or a script
//is not left waiting for a keypress.
void PauseIfParentIsExplorer() {
	DWORD explorerPid = 0;
	GetWindowThreadProcessId(GetShellWindow(), &explorerPid);
	DWORD parentPid = getParentProcess();
	if (parentPid == explorerPid) {
		Log(L"[+] Pausing to allow for debugging" << std::endl);
		Log(L"[+] Press enter to close" << std::endl);
		std::cin.get();
	}
}

void help() {
	Log(L"\r\n\r\n[!] Incorrect Usage!" << std::endl);
	Log(L"[+] Usage: Mapper.exe [--free][--indPages][--PassAllocationPtr][--copy-header][--no-forensics]");

#ifdef PDB_OFFSETS
	Log(L"[--dontUpdateOffsets [--offsetsPath \"FilePath\"]]");
#endif

	Log(L" driver" << std::endl);

	PauseIfParentIsExplorer();
}

int wmain(const int argc, wchar_t** argv) {
	//Installed first so an access violation anywhere below still unloads the
	//provider rather than leaving it loaded in a half configured state.
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	bool free = paramExists(argc, argv, L"free") > 0;
	bool indPagesMode = paramExists(argc, argv, L"indPages") > 0;
	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;
	bool copyHeader = paramExists(argc, argv, L"copy-header") > 0;

	if (free) {
		Log(L"[+] Free memory after driver execution enabled" << std::endl);
	}

	if (indPagesMode) {
		Log(L"[+] Allocate Independent Pages mode enabled" << std::endl);
	}

	if (passAllocationPtr) {
		Log(L"[+] Pass Allocation Ptr as first param enabled" << std::endl);
	}

	if (copyHeader) {
		Log(L"[+] Copying driver header enabled" << std::endl);
	}

#ifdef PDB_OFFSETS
	bool UpdateOffset = !(paramExists(argc, argv, L"dontUpdateOffsets") > 0);
	int FilePathParamIdx = paramExists(argc, argv, L"offsetsPath");
	std::wstring offsetFilePath = Utilities::GetCurrentAppFolder() + L"\\Offsets.ini";

	if (UpdateOffset && FilePathParamIdx > 0) {
		Log("[-] Can't set --offsetsPath without set --dontUpdateOffsets" << std::endl);
		help();
		return -1;
	}

	if (FilePathParamIdx > 0) {
		//The value is the next argument. When the flag is the last one there is
		//none, and argv[argc] is NULL, which would be read as a wide string.
		if (FilePathParamIdx + 1 >= argc) {
			Log(L"[-] --offsetsPath requires a file path argument" << std::endl);
			help();
			return -1;
		}
		offsetFilePath = argv[FilePathParamIdx + 1];
		Log("[+] Setting Offsets File Path To: " << offsetFilePath << std::endl);
	}
#endif

	//Warn on any argument that looks like a flag but was not recognized. A typo
	//in an option name would otherwise be silently ignored, and the run would
	//proceed with the default behaviour instead of what was asked for.
	static const wchar_t* knownFlags[] = {
		L"free", L"indPages", L"PassAllocationPtr", L"copy-header",
		L"no-forensics", L"dontUpdateOffsets", L"offsetsPath"
	};
	for (int i = 1; i < argc; i++) {
		const wchar_t* arg = argv[i];
		if (arg[0] != L'-')
			continue;
		//The argument after --offsetsPath is its value, not a flag.
		if (i > 1 && (_wcsicmp(argv[i - 1], L"--offsetsPath") == 0 || _wcsicmp(argv[i - 1], L"/offsetsPath") == 0))
			continue;
		const wchar_t* name = (arg[1] == L'-') ? arg + 2 : arg + 1;
		bool known = false;
		for (const wchar_t* flag : knownFlags) {
			if (_wcsicmp(name, flag) == 0) {
				known = true;
				break;
			}
		}
		if (!known)
			Log(L"[!] Unrecognized option: " << arg << std::endl);
	}

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (_wcsicmp(std::filesystem::path(argv[i]).extension().c_str(), L".sys") == 0) {
			drvIndex = i;
			break;
		}
	}

	//Skip the anti-forensic structure walks (PiDDB, hash bucket cache, unloaded
	//driver list, WdFilter). Everything is validated and fails cleanly, but
	//every one of them is another write into a kernel data structure, so this
	//flag reduces the number of chances the run has to destabilize the system.
	if (paramExists(argc, argv, L"no-forensics") > 0) {
		Driver::g_skipForensicCleanup = true;
		Log(L"[+] Forensic cleanup disabled (--no-forensics)" << std::endl);
	}

	if (drvIndex <= 0) {
		help();
		return -1;
	}

	const std::wstring driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path)) {
		Log(L"[-] File " << driver_path << L" doesn't exist" << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}

#ifdef PDB_OFFSETS
	if (!SymbolsHandler::GetInstance()->ReloadFile(offsetFilePath, UpdateOffset ? Utilities::GetCurrentAppFolder() + L"\\" + SYMBOL_TOOL_EXE : L"")) {
		Log(L"[-] Error: Failed To Get Symbols Info." << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}
#endif

	if (!NT_SUCCESS(Driver::Load())) {
		PauseIfParentIsExplorer();
		return -1;
	}

	std::vector<uint8_t> raw_image = { 0 };
	if (!Utilities::ReadFileToMemory(driver_path, &raw_image)) {
		Log(L"[-] Failed to read image to memory" << std::endl);
		Driver::Unload();
		PauseIfParentIsExplorer();
		return -1;
	}

	Mapper::AllocationMode mode = Mapper::AllocationMode::AllocatePool;

	if (indPagesMode) {
		mode = Mapper::AllocationMode::AllocateIndependentPages;
	}

	NTSTATUS exitCode = 0;
	if (!Mapper::MapDriver(raw_image.data(), raw_image.size(), 0, 0, free, !copyHeader, mode, passAllocationPtr, callbackExample, &exitCode)) {
		Log(L"[-] Failed to map " << driver_path << std::endl);
		Driver::Unload();
		PauseIfParentIsExplorer();
		return -1;
	}

	if (!NT_SUCCESS(Driver::Unload())) {
		Log(L"[-] Warning failed to fully unload vulnerable driver " << std::endl);
		PauseIfParentIsExplorer();
	}
	Log(L"[+] success" << std::endl);

}
