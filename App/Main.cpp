/*
 * Entry point and command line handling for Mapper.exe.
 *
 * Order of operations, which matters:
 *   1. install the crash handler, so a failure still unloads the provider
 *   2. parse arguments, then prompt for a driver path when none was given
 *   3. read and validate the driver file, keeping the validated bytes
 *   4. resolve Offsets.ini (running SymbolTool.exe unless told not to)
 *   5. load the provider and prepare offsets
 *   6. map the driver and call its entry point
 *   7. unload the provider
 *
 * Steps 5 and 6 are the only ones that touch the kernel, and they only run once
 * the file has been fully validated, so a bad path never gets as far as
 * loading anything. Step 3 also keeps the bytes it validated: the image that is
 * mapped is the one that was summarised, not a later re-read of the same path.
 */

#include <Windows.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <intrin.h>
#include <fstream>
#include <ctime>

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
#include "../Symbols/Handler/SymbolsHandler.hpp"
#include "Probing/Probe.h"

//Hypervisor client header (Hypervisor.h): --hide issues the nested-page-table hide
//commands from the very process that did the mapping, so the resident base
//never has to be typed into a shell or written to a file the way a separate
//tool would require.
#include "Hypervisor.h"


/*
 * Build number of the running kernel.
 *
 * Taken from ntdll rather than GetVersionEx, whose answer depends on the
 * process manifest: a manifest claiming compatibility with an older release
 * makes GetVersionEx report that release's version regardless of the build
 * actually running. The value gates a kernel call whose prototype changed in
 * 24H2, so it has to be the real build.
 */
extern "C" NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW version_information);

/*
 * Console colour and layout come from Console.hpp, which is shared with
 * SymbolTool so both programs print the same way: two-space indent, coloured
 * leading tags and green values, all inert under AMEGER_NO_COLOR=1.
 */
namespace
{
	/*
	 * Symbolic name for the NTSTATUS values a DriverEntry is likely to return,
	 * so a failed run reads as something other than a bare number. Codes not
	 * listed here still print their hex value; only the name is generic.
	 */
	const wchar_t* StatusName(NTSTATUS status) {
		switch (status) {
		case STATUS_SUCCESS:                  return L"STATUS_SUCCESS";
		case STATUS_UNSUCCESSFUL:             return L"STATUS_UNSUCCESSFUL";
		case STATUS_INVALID_PARAMETER:        return L"STATUS_INVALID_PARAMETER";
		case STATUS_ACCESS_DENIED:            return L"STATUS_ACCESS_DENIED";
		case STATUS_INSUFFICIENT_RESOURCES:   return L"STATUS_INSUFFICIENT_RESOURCES";
		case STATUS_NOT_SUPPORTED:            return L"STATUS_NOT_SUPPORTED";
		case STATUS_NOT_IMPLEMENTED:          return L"STATUS_NOT_IMPLEMENTED";
		case STATUS_INVALID_DEVICE_REQUEST:   return L"STATUS_INVALID_DEVICE_REQUEST";
		case STATUS_OBJECT_NAME_COLLISION:    return L"STATUS_OBJECT_NAME_COLLISION";
		case STATUS_INVALID_IMAGE_FORMAT:     return L"STATUS_INVALID_IMAGE_FORMAT";
		case STATUS_PRIVILEGE_NOT_HELD:       return L"STATUS_PRIVILEGE_NOT_HELD";
		//0xC0000096 is a privileged instruction executed in user mode
		//(RDMSR/WRMSR/HLT/CLI/IN/OUT), not a stack overrun. The stack overrun
		//is 0xC0000409; conflating the two is what made a ring-3 RDMSR look
		//like a /GS canary failure.
		case STATUS_PRIVILEGED_INSTRUCTION:   return L"STATUS_PRIVILEGED_INSTRUCTION";
		case STATUS_STACK_BUFFER_OVERRUN:     return L"STATUS_STACK_BUFFER_OVERRUN";
		//The hypervisor's CheckSupport() refuses to launch and reports this
		//custom code instead of a standard NTSTATUS. It means the AMD SVM
		//support gate failed - most often a stale resident hypervisor
		//(EFER.SVME left set by a prior run), not an Intel CPU, or a CPU
		//lacking the SVM/NP feature bits.
		case (NTSTATUS)0xc0350057:           return L"STATUS_HV_SUPPORT_CHECK_FAILED";
		default:                              return L"unknown status";
		}
	}

	//Build number of the running Windows kernel, or 0 when ntdll cannot report
	//it. The --indPages guard treats 0 as "unknown" and refuses rather than
	//running a kernel routine whose prototype it cannot confirm for this build.
	//noinline: this function's 276-byte RTL_OSVERSIONINFOW local used to be
	//inlined into wmain, inflating its stack frame. Keep it as its own
	//function so the buffer lives in this function's small frame instead of
	//wmain's. The 0xC0000096 this split was blamed for is
	//STATUS_PRIVILEGED_INSTRUCTION (a ring-3 RDMSR), not a /GS stack overrun;
	//the split is kept because it still keeps wmain's frame small.
	__declspec(noinline)
	DWORD RunningBuildNumber() {
		RTL_OSVERSIONINFOW version = {};
		version.dwOSVersionInfoSize = sizeof(version);
		if (!NT_SUCCESS(RtlGetVersion(&version)))
			return 0;
		return version.dwBuildNumber;
	}

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

	/*
	 * Global silent mode flag.
	 *
	 * Set when no console is attached or when --silent is passed. In silent
	 * mode, suppress the classification summary and the prompt. Only emit
	 * warnings that indicate safety-critical degradation.
	 */
	bool g_silentAutomatic = false;

	/*
	 * Classification report path. When non-empty, write a UTF-8 file on exit
	 * containing classification evidence and decisions.
	 */
	std::wstring g_classificationReportPath;

	/*
	 * Classification report data, accumulated during the run.
	 */
	struct ClassificationReport {
		std::wstring timestamp;
		std::wstring input_file;
		std::wstring evidence_log;
		int detect_result = -1;
		bool hide = false;
		bool free = false;
		bool forceFree = false;
		bool copyHeader = false;
		bool indPagesMode = false;
	} g_classificationReport;

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
			return L"Signed";
		if (status == static_cast<LONG>(TRUST_E_NOSIGNATURE))
			return L"Unsigned";

		std::wostringstream stream;
		stream << L"Unsigned (trust error 0x" << std::hex << std::uppercase
			<< std::setw(8) << std::setfill(L'0') << static_cast<unsigned long>(status) << L")";
		return stream.str();
	}

	/*
	 * Print a short summary of the driver file at `path` and report whether it
	 * is a usable PE image.
	 *
	 * On success out_image holds the exact bytes that were read and summarised.
	 * Those same bytes are what the mapper is given later, which is what keeps
	 * the file from being a second one between validation and use: a summary
	 * taken from one copy and an image loaded from a later re-read is a window
	 * where the two can differ.
	 *
	 * Returns false, after printing a red reason, when the file cannot be read
	 * or has no parseable PE headers. A file that is not a PE image could never
	 * be mapped, so the caller refuses it rather than handing it to the mapper.
	 * Everything here runs in user mode, before the provider is loaded.
	 */
	bool DescribeDriverImage(const std::wstring& path, std::vector<BYTE>* out_image) {
		std::vector<BYTE> image;
		if (!Utilities::ReadFileToMemory(path, &image) || image.empty()) {
			Log(L"[-] Failed to read \"" << Val(path) << L"\"" << std::endl);
			return false;
		}

		const PIMAGE_NT_HEADERS64 nt_headers = PE::GetNtHeaders(image.data(), image.size());
		if (!nt_headers) {
			Log(L"[-] \"" << Val(path) << L"\" is not a valid PE32+ image" << std::endl);
			return false;
		}

		//The section table sits at IMAGE_FIRST_SECTION, whose position comes from
		//the file controlled SizeOfOptionalHeader, so it is bounds checked before
		//any section below is read. This is the same check the mapper makes
		//through PE::GetSectionTable, so a file that summarises cleanly here is
		//also a file the mapper can walk.
		PIMAGE_SECTION_HEADER section = nullptr;
		uint16_t section_count = 0;
		if (!PE::GetSectionTable(image.data(), image.size(), section, section_count)) {
			Log(L"[-] \"" << Val(path) << L"\" has a section table that lies outside the file" << std::endl);
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
		const std::wstring size_text = GroupThousands(size) + L" Bytes (" + HumanReadableSize(size) + L")";
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
		for (uint16_t i = 0; i < section_count; ++i) {
			//The name is an 8 byte field that is not null terminated when it uses
			//all eight bytes, so it is copied into a wider buffer first.
			char name[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
			std::memcpy(name, section[i].Name, IMAGE_SIZEOF_SHORT_NAME);
			if (!sections.empty())
				sections.push_back(L' ');
			sections += Utilities::ToWide(name);
		}
		Log(L"[+] Sections:     " << Val(sections.empty() ? L"(None)" : sections) << std::endl);
		LogBlank();

		const auto& reloc = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		Log(L"[+] Relocations:  " << Val(reloc.VirtualAddress && reloc.Size ? L"Present" : L"Absent") << std::endl);

		Log(L"[+] Signature:    " << Val(SignatureStatus(path)) << std::endl);
		LogBlank();

		//Hand back the bytes that were just summarised. The mapper maps these,
		//never a later re-read of the same path.
		if (out_image)
			*out_image = std::move(image);

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
	 *
	 * out_image receives the validated bytes, the same ones DescribeDriverImage
	 * summarised.
	 */
	std::wstring PromptForDriverPath(std::vector<BYTE>* out_image) {
		for (;;) {
			//Separates the diagnostic block above from the prompt, so the
			//prompt reads as the question it is rather than as one more line
			//of the probe output.
			LogBlank();
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
			if (!DescribeDriverImage(path, out_image))
				continue;
			return path;
		}
	}

	/*
	 * Inspect a driver image for callback/device registration imports.
	 *
	 * Before forceFree is allowed, check whether the driver imports any routines
	 * that register callbacks or create devices. A driver that does so keeps
	 * running after DriverEntry returns, so freeing its image is unsafe.
	 *
	 * Returns true when the image is safe to free (no dangerous imports found),
	 * false otherwise.
	 */
	bool CheckCallbackSafetyGate(const std::vector<uint8_t>& image) {
		PE::vec_imports imports;
		if (!PE::GetImports(const_cast<uint8_t*>(image.data()), image.size(), imports))
			return true; // No imports to check; assume safe

		const char* dangerous_imports[] = {
			"IoCreateDevice",
			"IoRegisterDriverReinitialization",
			"IoRegisterBootDriverReinitialization",
			"PsSetCreateProcessNotifyRoutine",
			"PsSetCreateProcessNotifyRoutineEx",
			"PsSetCreateThreadNotifyRoutine",
			"PsSetLoadImageNotifyRoutine",
			"CmRegisterCallback",
			"CmRegisterCallbackEx",
			"ObRegisterCallbacks"
		};

		for (const auto& import : imports) {
			// Check if module is ntoskrnl (case insensitive)
			std::string module_lower = import.module_name;
			for (char& c : module_lower) {
				if (c >= 'A' && c <= 'Z')
					c = static_cast<char>(c - 'A' + 'a');
			}

			if (module_lower.find("ntoskrnl") != std::string::npos) {
				for (const auto& func : import.function_datas) {
					if (func.name.empty())
						continue;

					for (const char* dangerous : dangerous_imports) {
						if (func.name == dangerous) {
							if (!g_silentAutomatic) {
								Log(L"[!] Driver imports " << Val(Utilities::ToWide(func.name))
									<< L"; refusing to free its image" << std::endl);
								Log(L"[!] This function registers callbacks or creates devices, so the driver keeps running after DriverEntry." << std::endl);
							}
							return false;
						}
					}
				}
			}
		}

		return true;
	}

	/*
	 * Write the classification report to the specified path.
	 * Called on normal exit or via the teardown path.
	 */
	void WriteClassificationReport() {
		if (g_classificationReportPath.empty())
			return;

		/*
		 * Assembled as one wide string, converted once, written as bytes.
		 *
		 * This used to stream through std::wofstream with a std::codecvt_utf8
		 * facet. <codecvt> is deprecated in C++17 and removed in C++26, and it
		 * was the only user in this file. WideCharToMultiByte does the same job
		 * without a facet: UTF-8, no BOM, which is what the facet wrote too -
		 * the old "Write UTF-8 BOM" comment described a header that was never
		 * emitted.
		 */
		std::wostringstream text;
		text << L"Classification Report\n";
		text << L"====================\n\n";
		text << L"Timestamp:     " << g_classificationReport.timestamp << L"\n";
		text << L"Input File:    " << g_classificationReport.input_file << L"\n\n";
		text << L"Detection Result: " << g_classificationReport.detect_result << L" (";
		switch (g_classificationReport.detect_result) {
		case 1:  text << L"hypervisor"; break;
		case 0:  text << L"non-hypervisor"; break;
		case -1: text << L"indeterminate"; break;
		default: text << L"unknown"; break;
		}
		text << L")\n\n";

		if (!g_classificationReport.evidence_log.empty()) {
			text << L"Evidence:\n";
			text << g_classificationReport.evidence_log;
			text << L"\n";
		}

		text << L"Applied Settings:\n";
		text << L"  hide:        " << (g_classificationReport.hide ? L"true" : L"false") << L"\n";
		text << L"  free:        " << (g_classificationReport.free ? L"true" : L"false") << L"\n";
		text << L"  forceFree:   " << (g_classificationReport.forceFree ? L"true" : L"false") << L"\n";
		text << L"  copyHeader:  " << (g_classificationReport.copyHeader ? L"true" : L"false") << L"\n";
		text << L"  indPagesMode:" << (g_classificationReport.indPagesMode ? L"true" : L"false") << L"\n";

		const std::wstring wide = text.str();
		const int wide_length = static_cast<int>(wide.size());

		const int utf8_length = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), wide_length,
		                                              nullptr, 0, nullptr, nullptr);
		if (utf8_length <= 0) {
			Log(L"[-] Failed to convert the classification report to UTF-8" << std::endl);
			return;
		}

		std::string utf8(static_cast<size_t>(utf8_length), '\0');
		::WideCharToMultiByte(CP_UTF8, 0, wide.data(), wide_length,
		                      utf8.data(), utf8_length, nullptr, nullptr);

		std::ofstream report(g_classificationReportPath, std::ios::out | std::ios::trunc | std::ios::binary);
		if (!report.is_open()) {
			Log(L"[-] Failed to write classification report to " << Val(g_classificationReportPath) << std::endl);
			return;
		}

		report.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
		report.close();
	}

	/*
	 * Classify a driver image as hypervisor, non-hypervisor, or indeterminate.
	 *
	 * Returns:
	 *   1  - hypervisor (hide it in NPT)
	 *   0  - non-hypervisor (can be freed if callback-safe)
	 *  -1  - indeterminate (keep resident, safe default)
	 *
	 * Logs the classification evidence when not in silent mode.
	 * Also saves evidence to g_classificationReport for --classification-report.
	 */
	int DetectDriverType(const std::vector<uint8_t>& image) {
		const PIMAGE_NT_HEADERS64 nt_headers = PE::GetNtHeaders(
			const_cast<uint8_t*>(image.data()), image.size());

		if (!nt_headers) {
			g_classificationReport.detect_result = -1;
			g_classificationReport.evidence_log += L"Failed to parse NT headers\n";
			return -1;
		}

		std::wstring log;
		int class_count = 0;
		const bool is_hypervisor = PE::IsHypervisorImage(image, nt_headers, &log, &class_count);

		// Append evidence to report (unconditional)
		g_classificationReport.evidence_log += log;

		if (is_hypervisor) {
			g_classificationReport.detect_result = 1;
			if (!g_silentAutomatic) {
				LogBlank();
				Log(L"[+] Automatic classification: Hypervisor driver detected" << std::endl);
				if (!log.empty()) {
					Log(L"[+] Evidence:" << std::endl);
					LogRaw(log);
				}
			}
			return 1;
		}

		if (class_count == 0) {
			g_classificationReport.detect_result = 0;
			if (!g_silentAutomatic) {
				LogBlank();
				Log(L"[+] Automatic classification: Non-hypervisor driver (no hypervisor indicators found)" << std::endl);
			}
			return 0;
		}

		/*
		 * The one-class case, and the only case left: two classes set
		 * is_hypervisor and returned above, and zero returned above that. The
		 * test that used to sit here and the return after it were both
		 * unreachable, so this is the tail of the function now.
		 */
		g_classificationReport.detect_result = -1;
		if (!g_silentAutomatic) {
			LogBlank();
			Log(L"[!] Automatic classification: Indeterminate (insufficient evidence)" << std::endl);
		}
		return -1;
	}

	/*
	 * Ask whether the driver being mapped is a hypervisor, and return the
	 * decision: 1 for a hypervisor (hide it in the nested page table), 0 for a
	 * non hypervisor (free its image after DriverEntry), and -1 when stdin
	 * already ended and there is no console to ask, in which case the caller
	 * keeps whatever the command line set (the image stays resident, the safe
	 * default).
	 *
	 * A hypervisor's code runs out of its own image on every VMEXIT, so freeing
	 * that image would hang the machine; blanking its pages in the nested page
	 * table is the safe alternative. A driver that is not a hypervisor may still
	 * keep running, so freeing its image is only safe for one that will not
	 * execute in guest mode again.
	 */
	int PromptIsHypervisor() {
		LogRaw(L"Is the driver a Hypervisor? [Y/N]: ");

		for (;;) {
			std::wstring line;
			if (!std::getline(std::wcin, line)) {
				//No console: a pipe or closed stdin, so nothing can be asked.
				LogBlank();
				return -1;
			}

			const wchar_t* p = line.c_str();
			while (*p == L' ' || *p == L'\t')
				++p;

			//Anything other than y or n (including an empty answer) re-prompts.
			if (*p != L'y' && *p != L'Y' && *p != L'n' && *p != L'N') {
				Log(L"[-] Answer with y or n" << std::endl);
				continue;
			}

			return (*p == L'y' || *p == L'Y') ? 1 : 0;
		}
	}

	/*
	 * Whether MmAllocateIndependentPagesEx can be called with the pre-24H2
	 * signature this mapper uses: only on a known build below 26100. A build
	 * that cannot be determined, or one of 26100+, returns false and the
	 * contiguous allocation path is used instead.
	 */
	bool IndPagesAvailable() {
		const DWORD build = RunningBuildNumber();
		return build != 0 && build < 26100;
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

//What the crash-time module walk found. Plain data, so the walk that fills it
//can run inside __try.
struct FaultingModule
{
	uint64_t base;
	uint64_t size;
	uint64_t rva;
	wchar_t name[MAX_PATH];
};

/*
 * Locate the module that contains `address` and report its base, SizeOfImage,
 * RVA and file name.
 *
 * The headers are read from the image already mapped into this process, never
 * from the module's file. The previous version re-read the file from disk
 * inside the exception filter, and a failed open made tellg() return -1, which
 * became std::vector<BYTE>((size_t)-1) - a std::bad_alloc thrown from inside
 * the filter, which suppresses the very report it exists to print.
 *
 * This lives in its own function because a __try cannot appear in a function
 * that needs C++ object unwinding (C2712), and the handler streams its report
 * through std::wstring and iostreams. Everything inside the guarded block is
 * POD and allocation free, so a corrupt module header makes this report
 * nothing instead of faulting the filter.
 *
 * Returns false when no module contains the address.
 */
bool FindFaultingModule(const void* address, FaultingModule* out_module)
{
	out_module->base = 0;
	out_module->size = 0;
	out_module->rva = 0;
	out_module->name[0] = L'\0';

	bool found = false;
	__try
	{
		const uint64_t fault = reinterpret_cast<uint64_t>(address);
		HMODULE modules[512];
		DWORD needed = 0;
		if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed))
		{
			for (DWORD i = 0; i < needed / sizeof(HMODULE) && !found; ++i)
			{
				const uint64_t base = reinterpret_cast<uint64_t>(modules[i]);
				const auto* dos = reinterpret_cast<const PIMAGE_DOS_HEADER>(base);
				if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
					continue;

				//e_lfanew is read out of the mapped image and is the only field
				//that can point this walk outside it. A loaded image keeps its
				//NT headers in the first page.
				if (static_cast<uint64_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > 0x1000)
					continue;

				const auto* nt = reinterpret_cast<const PIMAGE_NT_HEADERS64>(base + static_cast<uint64_t>(dos->e_lfanew));
				if (nt->Signature != IMAGE_NT_SIGNATURE)
					continue;

				const uint64_t image_size = nt->OptionalHeader.SizeOfImage;
				if (image_size == 0 || fault < base || fault >= base + image_size)
					continue;

				out_module->base = base;
				out_module->size = image_size;
				out_module->rva = fault - base;
				found = GetModuleFileNameW(modules[i], out_module->name, MAX_PATH) != 0;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		found = false;
	}

	return found;
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

		//0xC0000096 is the one code this tool has actually hit, and the number
		//alone does not say what it means: it is a privileged instruction
		//(RDMSR/WRMSR/HLT/CLI/IN/OUT) executed in user mode, which a ring-3
		//binary raises the moment it touches one.
		if (rec->ExceptionCode == 0xC0000096)
			Log(L"[!!] STATUS_PRIVILEGED_INSTRUCTION: a ring 0 instruction (RDMSR/WRMSR/HLT/CLI/IN/OUT) ran in user mode" << std::endl);

		//Name the module that contains the faulting address from its mapped
		//headers, so the crash resolves to a function in that module's PDB
		//instead of an anonymous address.
		FaultingModule module = {};
		if (FindFaultingModule(rec->ExceptionAddress, &module)) {
			//Derive the module name from the path rather than a second
			//module-name API (the SDK's GetModuleBaseNameA maps to a 4-arg
			//k32 variant here).
			const std::wstring modName = std::filesystem::path(module.name).filename().wstring();
			Log(L"[!!] Faulting module: " << Val(modName)
				<< L" | base " << Val(Hex(module.base))
				<< L" | size " << Val(Hex(module.size))
				<< L" | RVA " << Val(Hex(module.rva)) << std::endl);
		}
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
//help text both work. A single leading dash is deliberately not one of them:
//Windows convention reserves -flag for a POSIX tool, which this is not, and
//accepting it silently would make a mistyped -free run with the flag ignored.
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

//True when argv[i] is a value some option consumed rather than an option or the
//driver path. Only --offsetsPath takes a separate value today, but this is a
//property of the argument list and is asked here rather than duplicated at each
//place that walks it.
static bool IsOptionValue(const int argc, wchar_t** argv, int i) {
	if (i < 1)
		return false;
	return paramExists(argc, argv, L"offsetsPath") == i - 1
		|| paramExists(argc, argv, L"probe-context") == i - 1
		|| paramExists(argc, argv, L"classification-report") == i - 1;
}



void help() {
	LogBlank();
	LogRaw(L"[+] Usage: Mapper.exe [--free [--force-free]][--indPages][--PassAllocationPtr][--copy-header][--hide [--require-hide]]" << std::endl);
	LogRaw(L"         [--no-forensics][--silent][--assume-hypervisor|--assume-driver]" << std::endl);
	LogRaw(L"         [--classification-report <path>][--dontUpdateOffsets [--offsetsPath \"FilePath\"]] [driver.sys]" << std::endl);
	LogBlank();
	LogRaw(L"[+] Run with no driver path to be prompted for one interactively." << std::endl);
	LogBlank();
	LogRaw(L"[+] Automatic Classification Flags:" << std::endl);
	LogRaw(L"      --assume-hypervisor       Force hypervisor mode (--hide, keep header)" << std::endl);
	LogRaw(L"      --assume-driver           Force non-hypervisor mode (keep resident)" << std::endl);
	LogRaw(L"      --silent                  Suppress automatic classification output" << std::endl);
	LogRaw(L"      --classification-report   Write classification evidence and decisions to file" << std::endl);
	LogBlank();
	LogRaw(L"[+] Stealth and Safety Flags:" << std::endl);
	LogRaw(L"      --hide                    Hide image in NPT (hypervisors)" << std::endl);
	LogRaw(L"      --require-hide            Abort if --hide requested but no hypervisor present" << std::endl);
	LogRaw(L"      --free                    Request image release after DriverEntry" << std::endl);
	LogRaw(L"      --force-free              Confirm image release (bypasses safety prompt)" << std::endl);
	LogRaw(L"      --copy-header             Keep PE header in mapped image" << std::endl);
	LogBlank();
}

/*
 * The --hide work the caller requested: confirm the hypervisor is present,
 * hide the mapped image minus its executable span, and publish the NPT flush
 * to every processor.
 *
 * Lived inline in wmain. The 0xC0000096 it was hoisted out of is
 * STATUS_PRIVILEGED_INSTRUCTION - a ring 3 RDMSR - not the /GS stack overrun
 * it was read as, so the split did not fix that crash; it is kept because it
 * keeps wmain's frame smaller.
 *
 * Returns hide_ok, which folds into the exit code only when --hide was
 * requested. A requested hide that did not fully happen - no hypervisor, or
 * any operation that failed - reads as a failure to a script keying on the
 * exit code.
 *
 * If hide is requested but no hypervisor is present, returns false and logs
 * a warning. The image is left resident (safe default) unless the caller
 * passed requireHide, in which case the mapping should be aborted before
 * this function is called.
 */
//noinline: keep this helper's frame separate from wmain's. The 0xC0000096 it
//was split out for is STATUS_PRIVILEGED_INSTRUCTION, not a stack overrun.
__declspec(noinline)
bool ApplyHypervisorHide(bool hide, ULONG64 text_base, SIZE_T text_size) {
	bool hide_ok = !hide;

	if (hide) {
		LogBlank();
		Log(L"[!] NPT Hide = Enabled" << std::endl);

		if (!Hypervisor::CheckPresence()) {
			Log(L"[-] No hypervisor present; hide requested but cannot be applied" << std::endl);
			Log(L"[!] Image is left resident in memory (safe default)" << std::endl);
			hide_ok = false;
		}
		else {
			Log(L"[+] Hypervisor Presence = Confirmed" << std::endl);

			/*
			 * Hide the image this run mapped, minus its executable span.
			 *
			 * ProtectSelf rewrites the NPT for the mapped image but leaves
			 * [text_base, text_base + text_size) mapped: that is the code the
			 * driver executes on the NPF restore path, so hiding it would
			 * livelock the restore. The range was computed from the raw image
			 * above; with 0/0 the driver hides the whole image, the legacy
			 * behaviour, and that path is logged when it is taken.
			 *
			 * There is deliberately no HideMemory() fallback here. It covers
			 * the whole resident range, executable span included, which is the
			 * exact livelock ProtectSelf is being given the span to avoid.
			 */
			if (!Hypervisor::Protect(text_base, text_size)) {
				Log(L"[-] Hypervisor self-hide failed" << std::endl);
				hide_ok = false;
			}
			else if (text_size) {
				Log(L"[+] Hypervisor image hidden except its executable span: "
					<< Val(reinterpret_cast<void*>(text_base)) << L" (" << Val(Hex(text_size))
					<< L" bytes)" << std::endl);
			}
			else {
				Log(L"[+] Hypervisor image hidden (whole image)" << std::endl);
			}

			// Publish the NPT rewrites to every CPU.
			LogBlank();
			if (!Hypervisor::FlushAllProcessors()) {
				Log(L"[!] Not every processor confirmed the NPT flush" << std::endl);
				hide_ok = false;
			}
			else {
				Log(L"[+] NPT Flush = Confirmed (Every Processor)" << std::endl);
			}
		}
	}

	return hide_ok;
}

/*
 * The whole map + executable-span + --hide work the Y path needs, kept in one
 * frame of its own rather than in wmain's. The 0xC0000096 it was split out for
 * is STATUS_PRIVILEGED_INSTRUCTION (a ring 3 RDMSR), not a /GS stack overrun,
 * so the split is not what fixed that crash.
 *
 * Chooses the allocation mode, calls Mapper::MapDriver, computes the
 * executable span, and runs ApplyHypervisorHide. Returns false (after
 * unloading the provider) when mapping failed, so wmain pauses and returns -1.
 */
//Forward declaration: ComputeExecutableSpan is defined later in this file,
//after wmain, so RunMapAndHide needs it declared before use.
__declspec(noinline)
void ComputeExecutableSpan(BYTE* image, size_t image_size, bool copyHeader,
                           ULONG64 resident_base, SIZE_T resident_size,
                           ULONG64* text_base, SIZE_T* text_size);

__declspec(noinline)
bool RunMapAndHide(std::vector<BYTE>& raw_image, const std::wstring& driver_path,
                    bool hide, bool free, bool copyHeader, bool indPagesMode, bool passAllocationPtr,
                    NTSTATUS& driver_status, SIZE_T& resident_size,
                    ULONG64& resident_base, ULONG64& text_base, SIZE_T& text_size,
                    bool& hide_ok) {
	Mapper::AllocationMode mode = Mapper::AllocationMode::AllocateContiguous;
	if (indPagesMode)
		mode = Mapper::AllocationMode::AllocateIndependentPages;

	driver_status = STATUS_SUCCESS;
	resident_size = 0;

	resident_base = Mapper::MapDriver(
		raw_image.data(), raw_image.size(), 0, 0, free, !copyHeader, mode, passAllocationPtr,
		&driver_status, &resident_size);

	if (!resident_base) {
		Log(L"[-] Failed to map " << Val(driver_path) << std::endl);
		Driver::Unload();
		return false;
	}

	text_base = 0;
	text_size = 0;
	ComputeExecutableSpan(raw_image.data(), raw_image.size(), copyHeader,
		resident_base, resident_size, &text_base, &text_size);

	hide_ok = ApplyHypervisorHide(hide, text_base, text_size);
	return true;
}

/*
 * Decide the stealth mode using automatic classification or operator input.
 *
 * When the command line already specified --hide, --free, or --force-free,
 * those explicit flags take precedence and classification is skipped.
 *
 * Otherwise, the driver image is automatically classified as hypervisor,
 * non-hypervisor, or indeterminate. The decision table:
 *
 *   Hypervisor (1)     -> hide = true, copyHeader = true, free = false
 *                         Enable indPages only if build < 26100
 *   Non-hypervisor (0) -> hide = false, free = false by default
 *                         Only set forceFree if --force-free was explicit
 *                         Enable indPages if build allows
 *   Indeterminate (-1) -> Prompt if console attached; otherwise keep resident
 *
 * Lived inline in wmain. The 0xC0000096 it was hoisted out of is
 * STATUS_PRIVILEGED_INSTRUCTION (a ring 3 RDMSR), not a /GS stack overrun, so
 * the split is not what fixed that crash; it is kept because it keeps wmain's
 * frame smaller.
 */
//noinline: keep this helper's frame separate from wmain's. The 0xC0000096 it
//was split out for is STATUS_PRIVILEGED_INSTRUCTION, not a stack overrun.
__declspec(noinline)
void ChooseStealthMode(bool& hide, bool& copyHeader, bool& free, bool& forceFree, bool& indPagesMode,
                        const std::vector<uint8_t>& image, bool assumeHypervisor, bool assumeDriver, bool forceFreeAllowed) {
	// If explicit flags were given, honor them and skip classification
	if (hide || free || forceFree)
		return;

	// If explicit assumption flags were given, use them
	if (assumeHypervisor || assumeDriver) {
		if (assumeHypervisor) {
			if (!g_silentAutomatic) {
				LogBlank();
				Log(L"[+] --assume-hypervisor: treating as hypervisor driver" << std::endl);
			}
			hide = true;
			copyHeader = true;
			// Allocation shape follows the NPT hide routine's range support, not the driver.
			indPagesMode = Hypervisor::kHypervisorSupportsDiscontiguousNpt ? IndPagesAvailable() : false;
			if (!g_silentAutomatic) {
				// Not a ternary inside Log(): Log is a macro, so `Log(c ? a : b)`
				// expands to `Console::Line() << c ? a : b` and tests the stream.
				if (indPagesMode)
					Log(L"[+] Hypervisor: scattered allocation enabled (NPT hide supports discontiguous ranges)");
				else
					Log(L"[+] Hypervisor: contiguous allocation (NPT hide requires contiguous physical pages)");
				Log(L"[+] NPT hide enabled: the mapped driver's image will be hidden in the nested page table, except its executable span" << std::endl);
				LogBlank();
			}
			return;
		}
		else { // assumeDriver
			if (!g_silentAutomatic) {
				LogBlank();
				Log(L"[+] --assume-driver: treating as non-hypervisor driver" << std::endl);
				Log(L"[+] Image will be kept resident (use --force-free explicitly to override)" << std::endl);
			}
			// Non-hypervisor stays resident by default
			hide = false;
			free = false;
			if (IndPagesAvailable() && !g_silentAutomatic) {
				Log(L"[+] Scattered independent-page allocation enabled" << std::endl);
				indPagesMode = true;
			}
			if (!g_silentAutomatic)
				LogBlank();
			return;
		}
	}

	//Scatter the allocation across independent pages whenever this build
	//allows it: a discontiguous physical run is harder to fingerprint than
	//a contiguous blob. This is auto-applied, not requested, so on a build
	//where MmAllocateIndependentPagesEx changed (26100+) it falls back to
	//contiguous with a note instead of aborting.
	auto enableIndPages = []() {
		if (IndPagesAvailable()) {
			if (!g_silentAutomatic)
				Log(L"[+] Scattered independent-page allocation enabled" << std::endl);
			return true;
		}
		if (!g_silentAutomatic)
			Log(L"[!] Scattered independent pages unavailable on this build; using contiguous allocation" << std::endl);
		return false;
	};

	// Run the automatic classifier
	const int classification = DetectDriverType(image);

	switch (classification) {
	case 1: // Hypervisor detected
		hide = true;
		copyHeader = true;
		free = false;
		forceFree = false;
		// Allocation shape follows the NPT hide routine's range support, not the driver.
		indPagesMode = Hypervisor::kHypervisorSupportsDiscontiguousNpt ? IndPagesAvailable() : false;

		if (!g_silentAutomatic) {
			LogBlank();
			Log(L"[+] NPT hide enabled: the mapped driver's image will be hidden in the nested page table, except its executable span" << std::endl);
			if (indPagesMode)
				Log(L"[+] Hypervisor: scattered allocation enabled (NPT hide supports discontiguous ranges)");
			else
				Log(L"[+] Hypervisor: contiguous allocation (NPT hide requires contiguous physical pages)");
			LogBlank();
		}
		break;

	case 0: // Non-hypervisor detected
		hide = false;
		free = false;
		forceFree = false;

		if (!g_silentAutomatic) {
			LogBlank();
			Log(L"[+] Non-hypervisor driver: image will be kept resident" << std::endl);
			Log(L"[+] Use --force-free explicitly to release the image after DriverEntry (unsafe for drivers with callbacks)" << std::endl);
		}

		// For non-hypervisors, enable independent pages if available
		if (enableIndPages())
			indPagesMode = true;

		if (!g_silentAutomatic)
			LogBlank();
		break;

	default: // Indeterminate (-1)
		// Check if console is attached
		HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
		DWORD mode = 0;
		const bool console_attached = (input != INVALID_HANDLE_VALUE && input != nullptr && GetConsoleMode(input, &mode));

		if (console_attached) {
			// Console attached: ask the operator
			if (!g_silentAutomatic) {
				LogBlank();
				Log(L"[!] Automatic classification inconclusive; asking operator" << std::endl);
			}

			switch (PromptIsHypervisor()) {
			case 1: // Operator says hypervisor
				hide = true;
				copyHeader = true;
				// Allocation shape follows the NPT hide routine's range support, not the driver.
				indPagesMode = Hypervisor::kHypervisorSupportsDiscontiguousNpt ? IndPagesAvailable() : false;
				if (!g_silentAutomatic) {
					LogBlank();
					Log(L"[+] NPT hide enabled: the mapped driver's image will be hidden in the nested page table, except its executable span" << std::endl);
					if (indPagesMode)
						Log(L"[+] Hypervisor: scattered allocation enabled (NPT hide supports discontiguous ranges)");
					else
						Log(L"[+] Hypervisor: contiguous allocation (NPT hide requires contiguous physical pages)");
					LogBlank();
				}
				break;
			case 0: // Operator says non-hypervisor
				// The same gate the top-level --free path uses: with callbacks or a
				// device object present, free stays false and the log below is true.
				free = forceFreeAllowed;
				if (forceFreeAllowed) {
					forceFree = true;
					if (!g_silentAutomatic) {
						LogBlank();
						Log(L"[+] Free memory after driver execution enabled" << std::endl);
						LogBlank();
						Log(L"[!] The image is only safe to free for a driver that will not run in guest mode again." << std::endl);
					}
				} else {
					forceFree = false;
					if (!g_silentAutomatic) {
						LogBlank();
						Log(L"[-] Driver registers callbacks or creates devices; refusing to free its image" << std::endl);
						Log(L"[-] Image will be kept resident (safe default)." << std::endl);
					}
				}
				if (enableIndPages())
					indPagesMode = true;
				break;
			default: // Operator input ended
				if (!g_silentAutomatic)
					Log(L"[!] No operator input: the image is kept resident (safe default)" << std::endl);
				break;
			}
		}
		else {
			// No console: keep resident, log warning
			if (!g_silentAutomatic) {
				LogBlank();
				Log(L"[!] WARNING: Automatic classification inconclusive and no console attached" << std::endl);
				Log(L"[!] Image will be kept resident (safe default for unknown driver type)" << std::endl);
				Log(L"[!] Use --assume-hypervisor or --assume-driver to override, or --hide/--force-free for explicit control" << std::endl);
				LogBlank();
			}
			hide = false;
			free = false;
			forceFree = false;
		}
		break;
	}

	// Save final settings to classification report
	g_classificationReport.hide = hide;
	g_classificationReport.free = free;
	g_classificationReport.forceFree = forceFree;
	g_classificationReport.copyHeader = copyHeader;
	g_classificationReport.indPagesMode = indPagesMode;
}

/*
 * The executable span of the mapped image, for --hide.
 *
 * ProtectSelf blanks the mapped image in the nested page table but has to
 * leave the driver's executable code mapped: the NPF restore path runs out of
 * that image in guest mode, so hiding the pages it executes from livelocks the
 * handler that would bring them back. This process is the only one holding both
 * the raw image and the resident base, so the span is computed here and passed
 * to the driver, which hides everything else.
 *
 * The resident image is the raw image shifted down by the header span MapDriver
 * strips when !copyHeader (the default): image RVA r lives at
 * resident_base + r - header_skip. With --copy-header nothing is stripped and
 * the image keeps its RVAs from resident_base, so header_skip is 0.
 *
 * header_size is the lowest section VirtualAddress - the same value MapDriver
 * strips - not section[0]'s, because the table is not guaranteed to be sorted
 * by RVA.
 *
 * Lived inline in wmain. The 0xC0000096 it was hoisted out of is
 * STATUS_PRIVILEGED_INSTRUCTION (a ring 3 RDMSR), not a /GS stack overrun, so
 * the split is not what fixed that crash; it is kept because it keeps wmain's
 * frame smaller.
 */
//noinline: keep this helper's frame separate from wmain's. The 0xC0000096 it
//was split out for is STATUS_PRIVILEGED_INSTRUCTION, not a stack overrun.
__declspec(noinline)
void ComputeExecutableSpan(BYTE* image, size_t image_size, bool copyHeader,
                           ULONG64 resident_base, SIZE_T resident_size,
                           ULONG64* text_base, SIZE_T* text_size) {
	*text_base = 0;
	*text_size = 0;

	PIMAGE_SECTION_HEADER image_section = nullptr;
	uint16_t image_section_count = 0;
	if (PE::GetSectionTable(image, image_size, image_section, image_section_count) && image_section_count > 0) {
		ULONG32 header_size = image_section[0].VirtualAddress;
		ULONG32 text_rva = 0;
		ULONG64 text_end = 0;
		bool text_found = false;

		for (uint16_t i = 0; i < image_section_count; ++i) {
			const PIMAGE_SECTION_HEADER section = &image_section[i];

			if (section->VirtualAddress < header_size)
				header_size = section->VirtualAddress;

			if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
				continue;

			//Widened before the add: both fields are file controlled 32-bit
			//values whose sum can wrap in 32 bits.
			const ULONG64 section_end = static_cast<ULONG64>(section->VirtualAddress) + section->Misc.VirtualSize;

			if (!text_found || section->VirtualAddress < text_rva)
				text_rva = section->VirtualAddress;
			if (!text_found || section_end > text_end)
				text_end = section_end;
			text_found = true;
		}

		const ULONG64 header_skip = copyHeader ? 0 : header_size;

		if (!text_found || text_end <= text_rva) {
			Log(L"[!] No executable section found; the whole image will be hidden" << std::endl);
		}
		else {
			const ULONG64 offset = (text_rva >= header_skip) ? text_rva - header_skip : 0;
			const ULONG64 span = text_end - text_rva;

			if (offset >= resident_size) {
				Log(L"[!] Executable span starts outside the resident image; the whole image will be hidden" << std::endl);
			}
			else {
				//Clamped to what was allocated: the span comes from the file
				//and the size from the headers, and the range handed to the
				//driver has to stay inside the resident image.
				const ULONG64 available = resident_size - offset;
				*text_base = resident_base + offset;
				*text_size = static_cast<SIZE_T>(span < available ? span : available);

				Log(L"[+] Executable span kept mapped: RVA " << Val(Hex(text_rva))
					<< L", size " << Val(Hex(span)) << L", resident "
					<< Val(reinterpret_cast<void*>(*text_base)) << std::endl);
			}
		}
	}
	else {
		Log(L"[!] Section table unreadable; the whole image will be hidden" << std::endl);
	}
}

/*
 * Report the final verdict (driver_ok / provider_clean / driver_status) and the
 * provider-left-resident warning, in a frame of its own rather than in wmain's.
 * The 0xC0000096 it was split out for is STATUS_PRIVILEGED_INSTRUCTION (a ring 3
 * RDMSR), not a /GS stack overrun, so the split is not what fixed that crash.
 */
__declspec(noinline)
void ReportRunResult(bool driver_ok, bool provider_clean, const std::wstring& driver_path,
                      NTSTATUS driver_status) {
	LogBlank();
	if (driver_ok) {
		Log(L"[+] \"" << Val(std::filesystem::path(driver_path).filename().wstring())
			<< L"\" has been mapped successfully." << std::endl);
	}
	else {
		Log(L"[-] \"" << Val(std::filesystem::path(driver_path).filename().wstring())
			<< L"\" was mapped, but DriverEntry returned "
			<< Val(Hex(static_cast<unsigned long>(driver_status)))
			<< L" (" << Val(StatusName(driver_status)) << L")." << std::endl);
		Log(L"[-] The image is left resident, but the driver reported failure and may not be usable." << std::endl);
	}

	if (!provider_clean) {
		//Unmissable on purpose: this is the state the whole tool exists to avoid
		//leaving behind, and it is the one condition where the machine is no safer
		//than before the run started - in fact it is less safe, because the run
		//also removed the provider's traces from PiDDB, the hash cache and
		//MmUnloadedDrivers while leaving the driver itself loaded.
		LogBlank();
		Log(L"[!!] The provider driver was NOT unloaded and is still resident in kernel memory." << std::endl);
		LogBlank();
		Log(L"      This machine is left exposed. Until the provider unloads, it can be" << std::endl);
		Log(L"      reached by anything holding that driver, and its service key has" << std::endl);
		Log(L"      already been deleted, so the service manager cannot be used to stop it." << std::endl);
		LogBlank();
		Log(L"      Rebooting is the only reliable way to clear it." << std::endl);
		LogBlank();
	}
}

/*
 * Self-test for the classifier.
 * Builds three synthetic PE images in memory and verifies classification results.
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


int wmain(const int argc, wchar_t** argv) {
	/*
	 * The report is flushed on every exit path, not only the success one. The
	 * early returns below - --require-hide, elevation, symbols, provider load,
	 * a failed map - each used to leave no report behind, which made a failed
	 * run indistinguishable from a run that was never classified.
	 *
	 * WriteClassificationReport() is a no-op while no path was given, so
	 * constructing this before the flags are parsed is safe.
	 */
	struct ClassificationReportFlusher { ~ClassificationReportFlusher() { WriteClassificationReport(); } } g_report_flusher;

	//Installed first so an access violation anywhere below still unloads the
	//provider rather than leaving it loaded in a half configured state.
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	//Enabled before anything is printed so the interactive errors and warnings
	//below render as intended.
	Console::EnableAnsiColors();

	//Self-test for classifier - runs before everything else and exits
	if (paramExists(argc, argv, L"self-test-classifier") > 0) {
		return RunClassifierSelfTest();
	}

	//Explicit help request. Handled before the flags so it never starts a run.
	if (paramExists(argc, argv, L"help") > 0) {
		help();
		PauseBeforeExit();
		return 0;
	}

	//The --probe-context switch runs the param2 propagation probe and returns
	//immediately, without entering the normal map flow.
	int probeContextIdx = paramExists(argc, argv, L"probe-context");
	if (probeContextIdx > 0)
		return RunProbeContext(argc, argv, probeContextIdx);

	bool free = paramExists(argc, argv, L"free") > 0;
	bool forceFree = paramExists(argc, argv, L"force-free") > 0;
	bool indPagesMode = paramExists(argc, argv, L"indPages") > 0;
	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;
	bool copyHeader = paramExists(argc, argv, L"copy-header") > 0;
	bool hide = paramExists(argc, argv, L"hide") > 0;
	bool requireHide = paramExists(argc, argv, L"require-hide") > 0;
	bool assumeHypervisor = paramExists(argc, argv, L"assume-hypervisor") > 0;
	bool assumeDriver = paramExists(argc, argv, L"assume-driver") > 0;
	bool silent = paramExists(argc, argv, L"silent") > 0;

	// Parse --classification-report flag
	int classificationReportIdx = paramExists(argc, argv, L"classification-report");
	if (classificationReportIdx > 0) {
		if (classificationReportIdx + 1 >= argc) {
			Log(L"[-] --classification-report requires a file path argument" << std::endl);
			help();
			PauseBeforeExit();
			return -1;
		}
		g_classificationReportPath = argv[classificationReportIdx + 1];
		Log(L"[+] Classification report will be written to: " << Val(g_classificationReportPath) << std::endl);
	}

	// Capture timestamp for classification report
	{
		std::time_t now = std::time(nullptr);
		wchar_t buf[100];
		std::tm tm_buf;
		localtime_s(&tm_buf, &now);
		std::wcsftime(buf, sizeof(buf) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &tm_buf);
		g_classificationReport.timestamp = buf;
	}

	// Set global silent mode flag
	HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode = 0;
	const bool console_attached = (input != INVALID_HANDLE_VALUE && input != nullptr && GetConsoleMode(input, &mode));
	g_silentAutomatic = silent || !console_attached;

	// Validate flag combinations
	if (assumeHypervisor && assumeDriver) {
		Log(L"[-] Cannot specify both --assume-hypervisor and --assume-driver" << std::endl);
		help();
		PauseBeforeExit();
		return -1;
	}

	if (requireHide && !hide) {
		Log(L"[-] --require-hide requires --hide to be specified" << std::endl);
		help();
		PauseBeforeExit();
		return -1;
	}

	/*
	 * --free releases the kernel image as soon as DriverEntry returns. That is
	 * only safe for a driver that copied everything it needs out of the image
	 * first; a driver that keeps running - a system thread, a registered
	 * callback, a device object - still executes code out of that allocation,
	 * and freeing it under the running thread is an immediate bugcheck.
	 *
	 * The mapper cannot tell the two apart, so --free is ignored unless the
	 * caller confirms with --force-free. Ignoring it keeps the image, which is
	 * the default behaviour and the safe one.
	 */
	if (free) {
		if (!forceFree) {
			Log(L"[!] --free ignored: the image would be released while the driver may still be running." << std::endl);
			Log(L"[!] Freeing the image under a driver that keeps running after DriverEntry returns is an instant bugcheck." << std::endl);
			Log(L"[!] The image is kept, which is the default. Add --force-free only for a driver that never touches its image again." << std::endl);
			free = false;
		}
		else {
			Log(L"[!] WARNING: --free is unsafe for drivers that keep running after DriverEntry returns." << std::endl);
			Log(L"[!] Freeing as requested because --force-free was given." << std::endl);
			Log(L"[+] Free memory after driver execution enabled" << std::endl);
		}
	}

	/*
	 * MmAllocateIndependentPagesEx changed signature in 24H2 (build 26100).
	 * Driver.cpp still calls it with the pre-24H2 shape (size, -1, 0, 0),
	 * which is correct only for earlier builds. The signature cannot be
	 * verified from here, so this refuses on 26100 and later rather than
	 * calling a routine with arguments it may not accept. The default pool
	 * mode is unaffected and is the verified path.
	 *
	 * This runs before the driver file is read and before Driver::Load, so a
	 * refused run has not touched the kernel.
	 */
	if (indPagesMode) {
		const DWORD build = RunningBuildNumber();
		if (build == 0) {
			Log(L"[-] --indPages: could not determine the running Windows build; refusing to use it." << std::endl);
			Log(L"[-] Use the default pool mode on this build: drop --indPages." << std::endl);
			PauseBeforeExit();
			return -1;
		}
		if (build >= 26100) {
			Log(L"[-] --indPages is not supported on Windows build " << Val(build) << L"." << std::endl);
			Log(L"[-] MmAllocateIndependentPagesEx changed signature in 24H2 (build 26100); the call this mapper uses is only valid before that." << std::endl);
			Log(L"[-] Use the default pool mode on this build: drop --indPages." << std::endl);
			PauseBeforeExit();
			return -1;
		}
		Log(L"[+] Allocate Independent Pages mode enabled" << std::endl);
	}

	if (passAllocationPtr) {
		Log(L"[+] Pass Allocation Ptr as first param enabled" << std::endl);
	}

	if (copyHeader) {
		Log(L"[+] Copying driver header enabled" << std::endl);
	}

	if (hide) {
		Log(L"[+] NPT hide enabled: the hypervisor will blank the mapped driver's" << std::endl);
		Log(L"[+] resident pages and its own image in the nested page table" << std::endl);
	}

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

	//Warn on any argument that looks like a flag but was not recognized. A typo
	//in an option name would otherwise be silently ignored, and the run would
	//proceed with the default behaviour instead of what was asked for.
	static const wchar_t* knownFlags[] = {
		L"free", L"force-free", L"indPages", L"PassAllocationPtr", L"copy-header",
		L"hide", L"no-forensics", L"dontUpdateOffsets", L"offsetsPath", L"help", L"probe-context",
		L"require-hide", L"assume-hypervisor", L"assume-driver", L"silent", L"classification-report",
		L"self-test-classifier"
	};
	for (int i = 1; i < argc; i++) {
		const wchar_t* arg = argv[i];
		if (arg[0] != L'-')
			continue;
		//The argument after --offsetsPath is its value, not a flag.
		if (IsOptionValue(argc, argv, i))
			continue;

		if (arg[1] != L'-') {
			//A single dash, which paramExists does not accept. It used to be
			//stripped down to the flag name and compared against the known list,
			//so -free came out as "free" - a known flag - and produced no
			//warning, while paramExists never matched it. The run then went
			//ahead with the memory free silently disabled. Say which form is
			//accepted instead.
			Log(L"[-] Unrecognized option: " << Val(arg)
				<< L" (flags are written as --name or /name, not -name)" << std::endl);
			continue;
		}

		const wchar_t* name = arg + 2;
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

	/*
	 * The driver path, taken as the first argument that names a .sys file and is
	 * not some other option's value.
	 *
	 * Skipping option values matters: --offsetsPath takes one, and an offsets
	 * file is called Offsets.ini rather than anything .sys, but the check used to
	 * be "first argument whose extension is .sys" over every argument. Give
	 * --offsetsPath a path that ends in .sys and it was taken as the driver, the
	 * offsets file was never read from where it was asked for, and the run went
	 *on with the previous Offsets.ini.
	 */
	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (IsOptionValue(argc, argv, i))
			continue;
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

	/*
	 * The image bytes, filled in by whichever branch below validated the file.
	 * These are the bytes that were summarised, and they are the bytes that get
	 * mapped: nothing re-reads the path in between.
	 */
	//
	// Primary idempotency check: ask CPUID whether a hypervisor is already
	// present (CPUID.1:ECX[31]) and whether this CPU implements AMD SVM
	//(CPUID.80000001h:ECX[2]). This used to read IA32_EFER (MSR 0xC0000080)
	//and test SVME directly, but RDMSR is ring 0 only: executing it here
	//raised #GP -> 0xC0000096 (STATUS_PRIVILEGED_INSTRUCTION) and the process
	//died before it had read a driver path. CPUID is ring 3 legal and answers
	//the same question less precisely, so it only warns: VBS, Hyper-V and
	//Credential Guard all set the hypervisor-present bit on machines where
	//this mapper runs perfectly well.
	//
	{
		int registers[4] = { 0 };

		__cpuid(registers, 1);
		const bool hypervisor_present = (static_cast<unsigned int>(registers[2]) & (1u << 31)) != 0;

		bool svm_supported = false;
		__cpuid(registers, static_cast<int>(0x80000000u));
		if (static_cast<unsigned int>(registers[0]) >= 0x8000000Au) {
			__cpuid(registers, static_cast<int>(0x80000001u));
			svm_supported = (static_cast<unsigned int>(registers[2]) & (1u << 2)) != 0;
		}

		//The colour carries the verdict, so the line does not have to say it in
		//words: a resident hypervisor is informational - VBS, Hyper-V and
		//Credential Guard all set the bit on machines this mapper runs on - and
		//a CPU without SVM cannot run the SVM path at all.
		const wchar_t* const hypervisor_color = hypervisor_present ? Console::kYellow : Console::kGreen;
		const wchar_t* const svm_color = svm_supported ? Console::kGreen : Console::kRed;

		Log(L"[!] CPUID: Hypervisor Present = " << Tint(hypervisor_color, static_cast<int>(hypervisor_present))
			<< L", SVM Supported = " << Tint(svm_color, static_cast<int>(svm_supported)) << std::endl);
		if (hypervisor_present)
			Log(L"[!] A hypervisor is already resident; the vmmcall probe below decides whether it is this one" << std::endl);

		//Separates the CPUID verdict from the vmmcall probe below, so the two
		//read as the two separate tests they are rather than as one block.
		LogBlank();
	}

	//
	// Secondary idempotency check: vmmcall probe. This is the authoritative
	// test for *this* hypervisor - CPUID above cannot tell it apart from VBS
	// or Hyper-V, and a resident one of those is no reason to refuse to map.
	// CallVM catches the #UD internally and answers 0xAABB when nothing
	// intercepts the vmmcall, 0xdead when the hypervisor is present. That
	// 0xAABB is a sentinel for "nothing ran", not a result, so it is never
	// printed as one below.
	//
	{
		//CallVM issues the vmmcall and catches the #UD internally: trapped says
		//whether the instruction faulted (nothing intercepted it) or completed.
		//A nested __try is illegal here (C2712) because main() holds locals
		//that need unwinding, so we rely on CallVM's own handler.
		bool trapped = false;
		const ULONG64 probeResult = Hypervisor::CallVM(
			Hypervisor::Shared::MAGIC, Hypervisor::Shared::CommandId::CheckPresence, 0, 0, &trapped);

		if (trapped)
			Log(L"[!] VMMCALL trapped (no hypervisor intercepted it)" << std::endl);
		else
			Log(L"[+] VMMCALL executed without fault" << std::endl);

		//Both values come from where they are decided: the return value from
		//the call, the expectation from the shared header. The verdict is the
		//comparison between them, never a claim written into the format.
		const bool probe_matched = probeResult == Hypervisor::Shared::COMM_CHECK;

		if (trapped) {
			//Nothing returned: the vmmcall faulted before any hypervisor saw
			//it, and 0xAABB is only CallVM's sentinel for that. Printing it
			//would present a sentinel as a probe result and colour it red,
			//which reads as a failure when a bare metal machine is the normal
			//case. Amber, and no value at all.
			Log(L"[!] " << Tint(Console::kYellow, L"Probe skipped: nothing returned (expected COMM_CHECK="
				+ Hex(Hypervisor::Shared::COMM_CHECK) + L")") << std::endl);
		}
		else {
			const wchar_t* const probe_color = probe_matched ? Console::kGreen : Console::kRed;
			const std::wstring expectation = L"COMM_CHECK=" + Hex(Hypervisor::Shared::COMM_CHECK)
				+ (probe_matched ? L", match" : L", no match");

			Log((probe_matched ? L"[+] Probe returned " : L"[!] Probe returned ")
				<< Tint(probe_color, Hex(probeResult))
				<< L" (" << Tint(probe_color, expectation) << L")" << std::endl);
		}

		if (probe_matched) {
			Log(L"[!] Probe matched COMM_CHECK; treating as active; skipping map" << std::endl);
			PauseBeforeExit();
			return -1;
		}
	}

	std::vector<BYTE> raw_image;
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
		if (!DescribeDriverImage(driver_path, &raw_image)) {
			PauseBeforeExit();
			return -1;
		}
	}
	else {
		//No path argument: ask for one interactively.
		driver_path = PromptForDriverPath(&raw_image);
		if (driver_path.empty()) {
			//Input ended before a usable path was entered.
			help();
			PauseBeforeExit();
			return -1;
		}
	}

	if (raw_image.empty()) {
		//Both branches above only return a path once DescribeDriverImage has
		//handed back a non empty buffer, so this cannot normally fire. It is
		//checked anyway because it is the one condition that would otherwise let
		//an empty buffer reach the mapper.
		Log(L"[-] Driver image is empty" << std::endl);
		PauseBeforeExit();
		return -1;
	}

	// Save input file path to classification report
	g_classificationReport.input_file = driver_path;

	// Safety gate runs immediately after the image is read and before stealth
	// mode selection: it decides whether forceFree is allowed.
	bool forceFreeAllowed = CheckCallbackSafetyGate(raw_image);
	if (forceFree && !forceFreeAllowed) {
		if (!g_silentAutomatic) {
			Log(L"[-] Driver registers callbacks or creates devices; refusing to free its image." << std::endl);
			Log(L"[-] Image will be kept resident (safe default)." << std::endl);
		}
		free = false;
		forceFree = false;
	}

	//The stealth-mode decision runs in a helper frame of its own rather than in
	//wmain's. The 0xC0000096 it was split out for is
	//STATUS_PRIVILEGED_INSTRUCTION, not a /GS stack overrun.
	ChooseStealthMode(hide, copyHeader, free, forceFree, indPagesMode, raw_image, assumeHypervisor, assumeDriver, forceFreeAllowed);

	// If --require-hide was specified, check hypervisor presence before mapping
	if (requireHide && hide) {
		if (!Hypervisor::CheckPresence()) {
			Log(L"[-] --require-hide: Hide requested but no hypervisor present" << std::endl);
			Log(L"[-] Aborting before mapping (--require-hide demands successful hide)" << std::endl);
			PauseBeforeExit();
			return -1;
		}
	}

	if (!IsElevated()) {
		Log(L"[-] Mapper.exe has to run elevated." << std::endl);
		Log(L"[-] Start it from an administrator terminal, or run it again and accept the UAC prompt." << std::endl);
		PauseBeforeExit();
		return -1;
	}

	if (!SymbolsHandler::GetInstance()->ReloadFile(offsetFilePath, UpdateOffset ? Utilities::GetCurrentAppFolder() + L"\\" + SYMBOL_TOOL_EXE : L"")) {
		Log(L"[-] Error: Failed To Get Symbols Info." << std::endl);
		PauseBeforeExit();
		return -1;
	}

	/*
	 * The provider is loaded only now that the image has been read and
	 * validated. Loading it before the file was known to be readable left a
	 * dropped driver, a service key and a loaded driver to unwind for a file
	 * read that was going to fail anyway.
	 */
	if (!NT_SUCCESS(Driver::Load())) {
		PauseBeforeExit();
		return -1;
	}

	//The map + span + --hide work the Y path needs runs in RunMapAndHide, a
	//helper frame of its own rather than wmain's. The 0xC0000096 it was split
	//out for is STATUS_PRIVILEGED_INSTRUCTION, not a /GS stack overrun.
	NTSTATUS driver_status = STATUS_SUCCESS;
	SIZE_T resident_size = 0;
	ULONG64 resident_base = 0;
	ULONG64 text_base = 0;
	SIZE_T text_size = 0;
	bool hide_ok = !hide;

	if (!RunMapAndHide(raw_image, driver_path, hide, free, copyHeader, indPagesMode, passAllocationPtr,
		driver_status, resident_size, resident_base, text_base, text_size, hide_ok)) {
		PauseBeforeExit();
		return -1;
	}

	/*
	 * The final verdict on the run.
	 *
	 * Three independent facts are reported: whether DriverEntry succeeded,
	 * whether the image was mapped, and whether the provider unloaded. A
	 * DriverEntry that returns an error used to be reported as success because
	 * MapDriver returned the allocation base regardless of the entry status, so
	 * the tool printed "mapped successfully" for a driver that had failed to
	 * initialise. That is the case this now distinguishes.
	 *
	 * Unload failing and the mapping succeeding are independent facts, and only
	 * one of them was ever reported. A run that loaded the provider, could not
	 * unload it, and therefore left a vulnerable signed driver resident in the
	 * kernel with its complete binary still on disk printed "has been mapped
	 * successfully" and exited 0 - which is the one thing an operator scanning a
	 * log should never be able to take away from a run that left that behind.
	 *
	 * The facts are reported separately and the exit code follows the worse of
	 * them, because the exit code is what a script or a wrapper keys on and it
	 * has to mean the same thing as the log.
	 */
	const bool driver_ok = NT_SUCCESS(driver_status);
	const bool provider_clean = NT_SUCCESS(Driver::Unload());

	//The verdict + provider-clean report runs in ReportRunResult, a helper
	//frame of its own rather than wmain's. The 0xC0000096 it was split out for
	//is STATUS_PRIVILEGED_INSTRUCTION, not a /GS stack overrun.
	ReportRunResult(driver_ok, provider_clean, driver_path, driver_status);

	//The classification report is written by g_report_flusher on scope exit.

	PauseBeforeExit();

	//A DriverEntry that returned an error, a provider left loaded, or a
	//requested hide that did not happen, is a failure of the task as a whole
	//and the caller has to be able to act on it.
	return (driver_ok && provider_clean && hide_ok) ? 0 : -1;
}
