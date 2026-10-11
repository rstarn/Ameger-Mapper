/*
 * Entry point and command line handling for Mapper.exe.
 *
 * Order of operations, which matters:
 *   1. install the crash handler, so a failure still unloads the provider
 *   2. parse arguments, then prompt for a driver path when none was given
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
#include <sstream>
#include <iomanip>
#include <cstring>

//bcrypt backs the SHA-256 in the driver summary and wintrust the Authenticode
//check. Both are system libraries, so their import libraries are pulled in here
//rather than through the project file.
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")

#include "../Mapper/Mapper.hpp"
#include "../PE/PE.hpp"
#include "../Utilities/Utilities.hpp"
#include "../Utilities/Console.hpp"
#include "../Provider/Driver.hpp"

#ifdef PDB_OFFSETS
#include "../Symbols/Handler/SymbolsHandler.hpp"
#endif

/*
 * Console colour and layout come from Console.hpp, which is shared with
 * SymbolTool so both programs print the same way: two-space indent, coloured
 * leading tags and green values, all inert under AMEGER_NO_COLOR=1.
 */
namespace
{
	//Trim ASCII whitespace from both ends of a string.
	std::wstring TrimWhitespace(const std::wstring& text) {
		static const wchar_t* whitespace = L" \t\r\n\f\v";
		const size_t first = text.find_first_not_of(whitespace);
		if (first == std::wstring::npos)
			return L"";
		const size_t last = text.find_last_not_of(whitespace);
		return text.substr(first, last - first + 1);
	}

	//Normalise typed or pasted input: trim whitespace, drop the surrounding
	//quotes Windows drag-and-drop inserts, and resolve to an absolute path.
	std::wstring SanitizeDriverPath(std::wstring line) {
		line = TrimWhitespace(line);
		if (line.size() >= 2 && line.front() == L'"' && line.back() == L'"')
			line = line.substr(1, line.size() - 2);
		line = TrimWhitespace(line);
		if (line.empty())
			return line;

		std::error_code ec;
		const std::filesystem::path absolute = std::filesystem::absolute(line, ec);
		if (ec)
			return line;
		return absolute.lexically_normal().wstring();
	}

	//Group a byte count with thousands separators: 3072 -> "3,072". Built by
	//hand rather than with a locale facet so the summary reads the same on every
	//machine the mapper runs on.
	std::wstring GroupThousands(uint64_t value) {
		const std::wstring digits = std::to_wstring(value);
		std::wstring grouped;
		grouped.reserve(digits.size() + digits.size() / 3);
		for (size_t i = 0; i < digits.size(); ++i) {
			if (i > 0 && (digits.size() - i) % 3 == 0)
				grouped.push_back(L',');
			grouped.push_back(digits[i]);
		}
		return grouped;
	}

	//Human readable size for the summary, always in KB or MB so it lines up
	//next to the exact byte count.
	std::wstring HumanReadableSize(uint64_t bytes) {
		std::wostringstream stream;
		stream << std::fixed << std::setprecision(2);
		if (bytes >= 1024ull * 1024ull)
			stream << static_cast<double>(bytes) / (1024.0 * 1024.0) << L" MB";
		else
			stream << static_cast<double>(bytes) / 1024.0 << L" KB";
		return stream.str();
	}

	//Lowercase hex SHA-256 of a byte buffer, via CNG. Returns "unavailable"
	//rather than failing the run when the provider cannot be opened, which only
	//happens on a system with no CNG at all.
	std::wstring Sha256Hex(const std::vector<BYTE>& data) {
		BCRYPT_ALG_HANDLE algorithm = nullptr;
		if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
			return L"unavailable";

		DWORD object_length = 0;
		DWORD bytes_written = 0;
		if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &bytes_written, 0) < 0) {
			BCryptCloseAlgorithmProvider(algorithm, 0);
			return L"unavailable";
		}

		std::vector<BYTE> object(object_length);
		BCRYPT_HASH_HANDLE hash = nullptr;
		if (BCryptCreateHash(algorithm, &hash, object.data(), object_length, nullptr, 0, 0) < 0) {
			BCryptCloseAlgorithmProvider(algorithm, 0);
			return L"unavailable";
		}

		std::vector<BYTE> digest(32);
		NTSTATUS status = BCryptHashData(hash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
		if (status >= 0)
			status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);

		BCryptDestroyHash(hash);
		BCryptCloseAlgorithmProvider(algorithm, 0);

		if (status < 0)
			return L"unavailable";

		static const wchar_t* hex = L"0123456789abcdef";
		std::wstring text;
		text.reserve(digest.size() * 2);
		for (const BYTE byte : digest) {
			text.push_back(hex[byte >> 4]);
			text.push_back(hex[byte & 0x0F]);
		}
		return text;
	}

	//Authenticode status through WinVerifyTrust. A present but untrusted or
	//expired chain is reported with its status code rather than as "signed", so
	//the summary never claims more than the trust engine verified.
	std::wstring SignatureStatus(const std::wstring& path) {
		WINTRUST_FILE_INFO file_info = {};
		file_info.cbStruct = sizeof(file_info);
		file_info.pcwszFilePath = path.c_str();

		WINTRUST_DATA trust_data = {};
		trust_data.cbStruct = sizeof(trust_data);
		trust_data.dwUIChoice = WTD_UI_NONE;
		trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
		trust_data.dwUnionChoice = WTD_CHOICE_FILE;
		trust_data.pFile = &file_info;
		trust_data.dwStateAction = WTD_STATEACTION_VERIFY;

		GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		const LONG status = WinVerifyTrust(nullptr, &policy, &trust_data);

		//Release the state WinVerifyTrust allocated for this check.
		trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(nullptr, &policy, &trust_data);

		if (status == ERROR_SUCCESS)
			return L"signed";
		if (status == static_cast<LONG>(TRUST_E_NOSIGNATURE))
			return L"unsigned";

		std::wostringstream stream;
		stream << L"unsigned (trust error 0x" << std::hex << std::uppercase
			<< std::setw(8) << std::setfill(L'0') << static_cast<unsigned long>(status) << L")";
		return stream.str();
	}

	/*
	 * Print a short summary of the driver file at `path` and report whether it
	 * is a usable PE image.
	 *
	 * Returns false, after printing a red reason, when the file cannot be read
	 * or has no parseable PE headers. A file that is not a PE image could never
	 * be mapped, so the caller refuses it rather than handing it to the mapper.
	 * Everything here runs in user mode, before the provider is loaded.
	 */
	bool DescribeDriverImage(const std::wstring& path) {
		std::vector<BYTE> image;
		if (!Utilities::ReadFileToMemory(path, &image) || image.empty()) {
			Log(L"[-] Failed to read \"" << Val(path) << L"\"" << std::endl);
			return false;
		}

		const PIMAGE_NT_HEADERS64 nt_headers = PE::GetNtHeaders(image.data(), image.size());
		if (!nt_headers) {
			Log(L"[-] \"" << Val(path) << L"\" is not a valid PE image" << std::endl);
			return false;
		}

		//The section table sits at IMAGE_FIRST_SECTION, whose position comes from
		//the file controlled SizeOfOptionalHeader, so it is bounds checked before
		//any section name below is read.
		const size_t section_offset = reinterpret_cast<const BYTE*>(IMAGE_FIRST_SECTION(nt_headers)) - image.data();
		const size_t section_bytes = static_cast<size_t>(nt_headers->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
		if (section_offset > image.size() || section_bytes > image.size() - section_offset) {
			Log(L"[-] \"" << Val(path) << L"\" is not a valid PE image" << std::endl);
			return false;
		}

		const std::wstring file_name = std::filesystem::path(path).filename().wstring();
		std::error_code ec;
		const std::wstring absolute = std::filesystem::absolute(path, ec).lexically_normal().wstring();

		Log(L"[+] File:         " << Val(file_name) << std::endl);
		if (!ec && absolute != file_name)
			Log(L"[+] Path:         " << Val(absolute) << std::endl);
		LogBlank();

		const uint64_t size = static_cast<uint64_t>(image.size());
		const std::wstring size_text = GroupThousands(size) + L" bytes (" + HumanReadableSize(size) + L")";
		Log(L"[+] Size:         " << Val(size_text) << std::endl);

		Log(L"[+] SHA-256:      " << Val(Sha256Hex(image)) << std::endl);
		LogBlank();

		const wchar_t* architecture = L"unknown";
		switch (nt_headers->FileHeader.Machine) {
		case IMAGE_FILE_MACHINE_AMD64: architecture = L"x64"; break;
		case IMAGE_FILE_MACHINE_I386:  architecture = L"x86"; break;
		case IMAGE_FILE_MACHINE_ARM64: architecture = L"ARM64"; break;
		case IMAGE_FILE_MACHINE_ARM:   architecture = L"ARM"; break;
		}
		Log(L"[+] Architecture: " << Val(architecture) << std::endl);

		const wchar_t* subsystem = L"unknown";
		switch (nt_headers->OptionalHeader.Subsystem) {
		case IMAGE_SUBSYSTEM_NATIVE:             subsystem = L"Native"; break;
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:        subsystem = L"Windows GUI"; break;
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:        subsystem = L"Windows CUI"; break;
		case IMAGE_SUBSYSTEM_EFI_APPLICATION:    subsystem = L"EFI application"; break;
		case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: subsystem = L"EFI runtime driver"; break;
		}
		Log(L"[+] Subsystem:    " << Val(subsystem) << std::endl);

		std::wostringstream address;
		address << L"0x" << std::hex << std::setw(16) << std::setfill(L'0')
			<< static_cast<unsigned long long>(nt_headers->OptionalHeader.ImageBase);
		Log(L"[+] Image base:   " << Val(address.str()) << std::endl);
		LogBlank();

		std::wostringstream entry;
		entry << L"0x" << std::hex << static_cast<unsigned int>(nt_headers->OptionalHeader.AddressOfEntryPoint);
		Log(L"[+] Entry point:  " << Val(entry.str()) << std::endl);

		std::wstring sections;
		const PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
		for (uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			//The name is an 8 byte field that is not null terminated when it uses
			//all eight bytes, so it is copied into a wider buffer first.
			char name[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
			std::memcpy(name, section[i].Name, IMAGE_SIZEOF_SHORT_NAME);
			if (!sections.empty())
				sections.push_back(L' ');
			sections += Utilities::ToWide(name);
		}
		Log(L"[+] Sections:     " << Val(sections.empty() ? L"(none)" : sections) << std::endl);
		LogBlank();

		const auto& reloc = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		Log(L"[+] Relocations:  " << Val(reloc.VirtualAddress && reloc.Size ? L"present" : L"absent") << std::endl);

		Log(L"[+] Signature:    " << Val(SignatureStatus(path)) << std::endl);
		LogBlank();

		return true;
	}

	/*
	 * Prompt until a path naming an existing regular file that parses as a PE
	 * image is entered.
	 *
	 * Empty input re-prompts silently; a bad path reports and re-prompts. A path
	 * without a .sys extension is warned about but accepted, because the PE
	 * validation is the real gate: a file that is not a PE image could never be
	 * mapped, so it is rejected here and the prompt comes back. Returns an empty
	 * string when the console input ends (closed or redirected to nothing),
	 * which the caller treats as "no path was given".
	 */
	std::wstring PromptForDriverPath() {
		for (;;) {
			LogRaw(L"Driver path: ");

			std::wstring line;
			if (!std::getline(std::wcin, line)) {
				LogBlank();
				return L"";
			}

			const std::wstring path = SanitizeDriverPath(line);
			if (path.empty())
				continue;

			//Separate the echoed input from the summary that follows it.
			LogBlank();

			std::error_code ec;
			if (!std::filesystem::exists(path, ec)) {
				Log(L"[-] File \"" << Val(path) << L"\" doesn't exist" << std::endl);
				continue;
			}
			if (!std::filesystem::is_regular_file(path, ec)) {
				Log(L"[-] \"" << Val(path) << L"\" is not a file" << std::endl);
				continue;
			}
			if (_wcsicmp(std::filesystem::path(path).extension().c_str(), L".sys") != 0) {
				Log(L"[INFO] Warning: \"" << Val(path) << L"\" does not have a .sys extension" << std::endl);
			}
			//The file is readable and is a regular file: summarise it. A file
			//that is not a PE image can never be mapped, so that re-prompts too.
			if (!DescribeDriverImage(path))
				continue;
			return path;
		}
	}
}

/*
 * Wait for the user before the process exits, so a double-clicked run does not
 * close its console window before the result can be read.
 *
 * The prompt is printed on every exit path. The read only blocks when stdin is
 * a real console; a pipe, a redirected file or a closed stdin returns from it
 * at once, so a script or CI run is never left hanging.
 */
void PauseBeforeExit() {
	LogBlank();
	Log(L"Press Enter to exit..." << std::endl);

	HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode = 0;
	if (input == INVALID_HANDLE_VALUE || input == nullptr || !GetConsoleMode(input, &mode))
		return;

	std::wcin.get();
}

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
		Log(L"[!!] Crash at addr " << Val(reinterpret_cast<void*>(rec->ExceptionAddress))
			<< L" by " << Val(Hex(rec->ExceptionCode)) << std::endl);
	}
	else
		Log(L"[!!] Crash" << std::endl);

	if (Driver::hDevice)
		Driver::Unload();

	//Returning EXCEPTION_EXECUTE_HANDLER terminates the process instead of
	//resuming the faulting code, so the wait has to happen here rather than on
	//the wmain exit path.
	PauseBeforeExit();

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

void help() {
	LogBlank();
	LogRaw(L"[+] Usage: Mapper.exe [--free][--indPages][--PassAllocationPtr][--copy-header][--no-forensics]");

#ifdef PDB_OFFSETS
	LogRaw(L"[--dontUpdateOffsets [--offsetsPath \"FilePath\"]]");
#endif

	LogRaw(L" [driver.sys]" << std::endl);
	LogRaw(L"[+] Run with no driver path to be prompted for one interactively." << std::endl);
}

int wmain(const int argc, wchar_t** argv) {
	//Installed first so an access violation anywhere below still unloads the
	//provider rather than leaving it loaded in a half configured state.
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	//Enabled before anything is printed so the interactive errors and warnings
	//below render as intended.
	Console::EnableAnsiColors();

	//Explicit help request. Handled before the flags so it never starts a run.
	if (paramExists(argc, argv, L"help") > 0) {
		help();
		PauseBeforeExit();
		return 0;
	}

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
		PauseBeforeExit();
		return -1;
	}

	if (FilePathParamIdx > 0) {
		//The value is the next argument. When the flag is the last one there is
		//none, and argv[argc] is NULL, which would be read as a wide string.
		if (FilePathParamIdx + 1 >= argc) {
			Log(L"[-] --offsetsPath requires a file path argument" << std::endl);
			help();
			PauseBeforeExit();
			return -1;
		}
		offsetFilePath = argv[FilePathParamIdx + 1];
		Log(L"[+] Setting Offsets File Path To: " << Val(offsetFilePath) << std::endl);
	}
#endif

	//Warn on any argument that looks like a flag but was not recognized. A typo
	//in an option name would otherwise be silently ignored, and the run would
	//proceed with the default behaviour instead of what was asked for.
	static const wchar_t* knownFlags[] = {
		L"free", L"indPages", L"PassAllocationPtr", L"copy-header",
		L"no-forensics", L"dontUpdateOffsets", L"offsetsPath", L"help"
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
			Log(L"[-] Unrecognized option: " << Val(arg) << std::endl);
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

	std::wstring driver_path;
	if (drvIndex > 0) {
		//A path was given on the command line: skip the prompt and behave
		//exactly as before, so existing scripts are unaffected.
		driver_path = argv[drvIndex];

		if (!std::filesystem::exists(driver_path)) {
			Log(L"[-] File " << Val(driver_path) << L" doesn't exist" << std::endl);
			PauseBeforeExit();
			return -1;
		}

		//Summarise the file and refuse a non PE image, the same gate the
		//interactive prompt applies.
		if (!DescribeDriverImage(driver_path)) {
			PauseBeforeExit();
			return -1;
		}
	}
	else {
		//No path argument: ask for one interactively.
		driver_path = PromptForDriverPath();
		if (driver_path.empty()) {
			//Input ended before a usable path was entered.
			help();
			PauseBeforeExit();
			return -1;
		}
	}

#ifdef PDB_OFFSETS
	if (!SymbolsHandler::GetInstance()->ReloadFile(offsetFilePath, UpdateOffset ? Utilities::GetCurrentAppFolder() + L"\\" + SYMBOL_TOOL_EXE : L"")) {
		Log(L"[-] Error: Failed To Get Symbols Info." << std::endl);
		PauseBeforeExit();
		return -1;
	}
#endif

	if (!NT_SUCCESS(Driver::Load())) {
		PauseBeforeExit();
		return -1;
	}

	std::vector<uint8_t> raw_image = { 0 };
	if (!Utilities::ReadFileToMemory(driver_path, &raw_image)) {
		Log(L"[-] Failed to read image to memory" << std::endl);
		Driver::Unload();
		PauseBeforeExit();
		return -1;
	}

	Mapper::AllocationMode mode = Mapper::AllocationMode::AllocatePool;

	if (indPagesMode) {
		mode = Mapper::AllocationMode::AllocateIndependentPages;
	}

	NTSTATUS exitCode = 0;
	if (!Mapper::MapDriver(raw_image.data(), raw_image.size(), 0, 0, free, !copyHeader, mode, passAllocationPtr, nullptr, &exitCode)) {
		Log(L"[-] Failed to map " << Val(driver_path) << std::endl);
		Driver::Unload();
		PauseBeforeExit();
		return -1;
	}

	if (!NT_SUCCESS(Driver::Unload())) {
		Log(L"[-] Warning failed to fully unload vulnerable driver " << std::endl);
	}
	Log(L"[+] \"" << Val(std::filesystem::path(driver_path).filename().wstring())
		<< L"\" has been mapped successfully." << std::endl);

	PauseBeforeExit();
	return 0;
}
