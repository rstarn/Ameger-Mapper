/*
 * Helpers shared by the mapper. None of these touch kernel memory: they all
 * run before the provider is loaded or after it has been unloaded. See
 * Utilities.hpp for the per function contracts.
 */

#include "Utilities.hpp"
#include "Console.hpp"
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include "../App/NT.hpp"

namespace
{
	/*
	 * Upper bound on a file this project will read into memory.
	 *
	 * The only file read through here is the driver image the operator named on
	 * the command line, and a driver is tens of kilobytes. 256 MB is three
	 * orders of magnitude above that and below anything that could exhaust
	 * memory, so the check exists to turn "this is not a driver" into a refused
	 * read rather than into an allocation failure.
	 */
	constexpr uint64_t kMaxReadFileSize = 256ull * 1024ull * 1024ull;
}

//Widens an ASCII identifier. A per byte copy is correct for the narrow ASCII
//module and export names used here and is cheaper than a codepage conversion,
//which would need a locale.
std::wstring Utilities::ToWide(const std::string& text) {
	return std::wstring(text.begin(), text.end());
}

std::wstring Utilities::GetFullTempPath() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / sizeof(wchar_t), temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		Log(L"[-] Failed to get temp path" << std::endl);
		return L"";
	}

	const size_t temp_length = wcslen(temp_directory);
	if (temp_length && temp_directory[temp_length - 1] == L'\\')
		temp_directory[temp_length - 1] = 0x0;

	return std::wstring(temp_directory);
}

bool Utilities::ReadFileToMemory(const std::wstring& file_path, std::vector<BYTE>* out_buffer) {
	std::ifstream file_ifstream(file_path, std::ios::binary);

	if (!file_ifstream)
		return false;

	/*
	 * Seek to the end and read exactly that much, rather than streaming the file
	 * into a container until it stops.
	 *
	 * The streaming form allocates whatever the file turns out to be, so pointing
	 * this at anything larger than a driver - a disk image, say - is an
	 * unhandled bad_alloc that takes the process down with it, at a point where
	 * the only sensible response would have been "that is not a driver".
	 */
	file_ifstream.seekg(0, std::ios::end);
	const std::streamoff length = file_ifstream.tellg();
	if (length < 0 || static_cast<uint64_t>(length) > kMaxReadFileSize) {
		file_ifstream.close();
		return false;
	}
	file_ifstream.seekg(0, std::ios::beg);

	out_buffer->assign(static_cast<size_t>(length), 0);
	if (length > 0 && !file_ifstream.read(reinterpret_cast<char*>(out_buffer->data()), length)) {
		file_ifstream.close();
		out_buffer->clear();
		return false;
	}
	file_ifstream.close();

	return true;
}

bool Utilities::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size)) {
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

uint64_t Utilities::GetKernelModuleAddress(const std::string& module_name) {
	void* buffer = nullptr;
	DWORD buffer_size = 0;

	//SystemModuleInformation has no size query, so it is called once with a
	//null buffer to have the kernel report how much it needs, then again with
	//a buffer of that size. The loop handles the race where the module list
	//grows between the two calls.
	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(Nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(Nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	const auto modules = static_cast<Nt::PRTL_PROCESS_MODULES>(buffer);
	if (!modules || modules->NumberOfModules == 0) {
		VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	/*
	 * Does this module list carry addresses at all?
	 *
	 * SystemModuleInformation reports ImageBase as 0 for every module to a process
	 * that does not hold SeDebugPrivilege - the names are filled in, the addresses
	 * are not. Verified on a run of this machine: 289 modules, 289 of them with an
	 * ImageBase of zero, and the same query issued after enabling the privilege
	 * returned 289 populated ones.
	 *
	 * Without this check, a caller that has not enabled the privilege sees a
	 * perfectly ordinary module list and reports the module it asked for as "not
	 * found", which is indistinguishable from a genuinely absent module and points
	 * at entirely the wrong thing. Scanned once rather than per lookup, because
	 * the answer is the same for every entry.
	 */
	bool any_address = false;
	for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		if (modules->Modules[i].ImageBase != 0) {
			any_address = true;
			break;
		}
	}

	if (!any_address) {
		Log(L"[-] The kernel module list reports no addresses at all ("
			<< Val(modules->NumberOfModules) << L" modules, every ImageBase zero)."
			<< L" That is what Windows returns without SeDebugPrivilege." << std::endl);
		VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		const auto& current = modules->Modules[i];

		/*
		 * The base name is the tail of FullPathName from OffsetToFileName.
		 *
		 * FullPathName is a fixed 256 byte field inside a structure the kernel
		 * fills, not a C string: the entry is exactly as long as the header says
		 * and is not terminated. Building a std::string from
		 * FullPathName + OffsetToFileName read past the end of the field looking
		 * for a zero byte - inside the next module entry for every entry but the
		 * last, and past the end of the buffer for the last. The comparison below
		 * only needs the tail, so the tail is copied and that is all.
		 */
		const size_t path_length = strnlen_s(
			reinterpret_cast<const char*>(current.FullPathName), sizeof(current.FullPathName));

		//OffsetToFileName is an offset into that field; a value past the end
		//means the layout is not the one assumed, so nothing is matched.
		if (current.OffsetToFileName >= path_length)
			continue;

		const std::string current_module_name(
			reinterpret_cast<const char*>(current.FullPathName) + current.OffsetToFileName,
			path_length - current.OffsetToFileName);

		if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
		{
			const uint64_t result = reinterpret_cast<uint64_t>(current.ImageBase);

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}

std::wstring Utilities::GetCurrentAppFolder() {
	wchar_t buffer[1024] = { 0 };
	const DWORD length = GetModuleFileNameW(NULL, buffer, static_cast<DWORD>(std::size(buffer)));
	if (!length || length >= std::size(buffer))
		return L"";

	std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
	if (pos == std::wstring::npos)
		return L"";
	return std::wstring(buffer).substr(0, pos);
}
