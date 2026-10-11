#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/*
 * Helpers shared by the rest of the project. Nothing here touches kernel
 * memory: these all run before the provider is loaded or after it has been
 * unloaded.
 */
namespace Utilities
{
	//Widens an ASCII identifier. Kernel module names and export names are narrow
	//ASCII, so a per byte copy is correct and cheaper than a codepage conversion,
	//which would need a locale.
	std::wstring ToWide(const std::string& text);

	//%TEMP% with the trailing backslash removed, or an empty string on failure.
	std::wstring GetFullTempPath();

	//Slurp a file into out_buffer, replacing any previous contents.
	//Returns false when the file cannot be opened.
	bool ReadFileToMemory(const std::wstring& file_path, std::vector<BYTE>* out_buffer);

	//Write size bytes at address to desired_file_path, truncating it.
	//Returns false when the write fails.
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);

	//Base address of a loaded kernel module, matched case-insensitively on the
	//file name (e.g. "ntoskrnl.exe"). 0 when the module is not loaded.
	//Runs NtQuerySystemInformation(SystemModuleInformation), which needs no
	//special privilege.
	uint64_t GetKernelModuleAddress(const std::string& module_name);

	//Folder containing the running executable, without a trailing separator.
	//Used to locate Offsets.ini and SymbolTool.exe next to Mapper.exe.
	std::wstring GetCurrentAppFolder();
}
