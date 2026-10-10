/*
 * Helpers shared by the mapper. None of these touch kernel memory: they all
 * run before the provider is loaded or after it has been unloaded. See
 * Utilities.hpp for the per function contracts.
 */

#include "Utilities.hpp"
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include "../App/NT.hpp"

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

	out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
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

	for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		//FullPathName holds the whole path; OffsetToFileName is where the base
		//name starts inside it.
		const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

		if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
		{
			const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

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
