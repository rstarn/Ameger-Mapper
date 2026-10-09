//TheCruZ Remake

#include <windows.h>

#include <vector>
#include <string>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <utility>

#include "SymbolEngine.hpp"


std::wstring GetCurrentAppFolder() {
	wchar_t buffer[1024];
	GetModuleFileNameW(NULL, buffer, 1024);
	std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
	return std::wstring(buffer).substr(0, pos);
}

int main()
{
	std::vector<std::wstring> targetBinaries = {
		L"C:\\Windows\\System32\\ntoskrnl.exe",
		L"C:\\Windows\\System32\\ci.dll"
	};

	std::vector<SymbolRequest> symbolsToRetrieve{
		{ L"ntoskrnl.exe", L"MmAllocateIndependentPagesEx" },
		{ L"ntoskrnl.exe", L"MmFreeIndependentPages" },
		{ L"ntoskrnl.exe", L"PiDDBLock" },
		{ L"ntoskrnl.exe", L"PiDDBCacheTable" },
		{ L"ntoskrnl.exe", L"MmSetPageProtection" },
		{ L"ci.dll", L"g_KernelHashBucketList" },
		{ L"ci.dll", L"g_HashCacheLock" },
	};

	//Structure field offsets. Every one of these replaces a hardcoded numeric
	//offset that can silently change between Windows builds.
	std::vector<FieldRequest> fieldsToRetrieve{
		{ L"ntoskrnl.exe", L"_FILE_OBJECT",     L"DeviceObject" },
		{ L"ntoskrnl.exe", L"_DEVICE_OBJECT",   L"DriverObject" },
		{ L"ntoskrnl.exe", L"_DRIVER_OBJECT",   L"DriverSection" },
		{ L"ntoskrnl.exe", L"_KLDR_DATA_TABLE_ENTRY", L"BaseDllName" },
		{ L"ntoskrnl.exe", L"_RTL_AVL_TABLE",   L"DeleteCount" },
		{ L"ntoskrnl.exe", L"_PiDDBCacheEntry", L"List" },
		{ L"ntoskrnl.exe", L"_PiDDBCacheEntry", L"DriverName" },
		{ L"ntoskrnl.exe", L"_PiDDBCacheEntry", L"TimeDateStamp" },
		{ L"ntoskrnl.exe", L"_RTL_PROCESS_MODULE_INFORMATION", L"OffsetToFileName" },
		{ L"ntoskrnl.exe", L"_RTL_SPLAY_LINKS", L"LeftChild" },
		{ L"ci.dll",       L"HashBucketEntry",  L"DriverName" },
	};

	std::wstring WdFltrPath = L"C:\\Windows\\System32\\drivers\\wd\\WdFilter.sys";
	if (std::filesystem::exists(WdFltrPath))
	{
		targetBinaries.push_back(WdFltrPath);
		symbolsToRetrieve.push_back({ L"WdFilter.sys", L"MpBmDocOpenRules" });
		symbolsToRetrieve.push_back({ L"WdFilter.sys", L"MpFreeDriverInfoEx" });
	}

	SymbolEngine handler(GetCurrentAppFolder() + L"\\Symbols");

	for (const auto& binPath : targetBinaries) {
		auto pdbPath = handler.GetPDB(binPath);
		if (pdbPath.empty()) {
			std::wcout << L"[-] Failed to get symbol for " << binPath << std::endl;
			return -1;
		}

		std::vector<std::wstring> symbolsForThisFile{};
		for (const auto& sym : symbolsToRetrieve) {
			if (binPath.find(sym.binaryName) == std::wstring::npos) {
				continue;
			}
			symbolsForThisFile.push_back(sym.symbolName);
		}

		std::vector<std::pair<std::wstring, std::wstring>> fieldsForThisFile{};
		for (const auto& fld : fieldsToRetrieve) {
			if (binPath.find(fld.binaryName) == std::wstring::npos) {
				continue;
			}
			fieldsForThisFile.emplace_back(fld.structName, fld.fieldName);
		}

		auto offsets = handler.GetOffset(pdbPath, symbolsForThisFile);
		if (offsets.size() != symbolsForThisFile.size()) {
			std::wcout << L"[-] Failed to get offsets for " << binPath << std::endl;
			return -1;
		}

		auto fieldOffsets = handler.GetStructFieldOffsets(pdbPath, fieldsForThisFile);
		if (fieldOffsets.size() != fieldsForThisFile.size()) {
			std::wcout << L"[-] Failed to get field offsets for " << binPath << std::endl;
			return -1;
		}

		//Save as ini format in offsets.ini
		std::wofstream ofs(GetCurrentAppFolder() + L"\\offsets.ini", std::ofstream::out | std::ofstream::app);
		if (!ofs.is_open()) {
			std::wcout << L"[-] Failed to open offsets.ini" << std::endl;
			return -1;
		}

		auto filename = std::filesystem::path(binPath).filename().wstring();

		ofs << L"[" << filename << L"]" << std::endl;
		for (size_t i = 0; i < symbolsForThisFile.size(); i++) {
			ofs << symbolsForThisFile[i] << L"=" << std::dec << offsets[i] << std::endl;
		}

		ofs << L"[" << filename << L".fields]" << std::endl;
		for (size_t i = 0; i < fieldsForThisFile.size(); i++) {
			ofs << fieldsForThisFile[i].first << L"." << fieldsForThisFile[i].second << L"=" << std::dec << fieldOffsets[i] << std::endl;
		}
		ofs << std::endl;
	}
	return 0;
}
