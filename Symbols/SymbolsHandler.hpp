//TheCruZ Remake

#pragma once

#ifdef PDB_OFFSETS

#include <string>
#include <vector>

#define SYM_FROM_PDB_EXE L"SymbolsFromPDB.exe"

struct SymbolOffset {
	unsigned long long offset{};
	std::wstring name{};
};

class SymbolsHandler
{

public:
	SymbolsHandler() {
	};

	static SymbolsHandler* GetInstance()
	{
		static SymbolsHandler instance{};
		return &instance;
	}

	bool ReloadFile(std::wstring path, std::wstring updater);
	unsigned long long GetOffset(std::wstring name);
	unsigned long long GetFieldOffset(std::wstring structAndField);

	//Static layouts of internal types are not part of any public ABI. When a
	//field offset could not be resolved from the PDB, callers fall back to the
	//compiled default and must additionally validate the structure before
	//writing to it.
	static constexpr unsigned long long kFieldUnresolved = 0;

private:
	std::vector<SymbolOffset> symbols{};
};

#endif