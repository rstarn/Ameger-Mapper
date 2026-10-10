//TheCruZ Remake

#pragma once

#ifdef PDB_OFFSETS

#include <string>
#include <vector>

//Name of the offset generator built by Template\SymbolTool.vcxproj. It is
//deployed next to Mapper.exe and is what --dontUpdateOffsets turns off.
//Keep in sync with <TargetName> in Template\SymbolTool.vcxproj.
#define SYMBOL_TOOL_EXE L"SymbolTool.exe"

//Folder next to Mapper.exe and SymbolTool.exe holding dbghelp.dll and
//symsrv.dll.
//This is NOT a default DLL search location: SymbolTool.exe imports dbghelp.dll
//(so the loader must find it before main runs) and dbghelp then loads symsrv.dll
//itself. Both therefore resolve through the application directory, the system
//directories and PATH - so every process that starts SymbolTool has to put this
//folder on PATH. ReloadFile does that for the process it spawns, and
//Build\Executors\Create.bat does it for its own invocation.
#define SYMBOL_DLL_FOLDER L"DLLs"

//One entry of Offsets.ini: a symbol name and its offset from the module base.
struct SymbolOffset {
	unsigned long long offset{};
	std::wstring name{};
};

/*
 * Reader for Offsets.ini, the file SymbolTool.exe writes.
 *
 * Offsets.ini holds every kernel address and structure field offset the mapper
 * uses, resolved from the PDBs of the machine it runs on. Nothing here is
 * hardcoded or cached across builds, so a wrong or missing entry is the
 * difference between finding a structure and corrupting one.
 *
 * Singleton because it is read from all over the mapper during Load().
 */
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

	/*
	 * Replace the loaded symbol set.
	 *
	 * path     Offsets.ini to read. Ignored when `updater` is not empty,
	 *          because the updater always writes to the default location.
	 * updater  path to SymbolTool.exe, or empty to read `path` as is.
	 *
	 * The previous Offsets.ini is deliberately left in place while the updater
	 * runs: a failed update then leaves the mapper with the last known good
	 * offsets instead of with nothing.
	 *
	 * Returns false when the file is missing, the updater fails, or the file
	 * cannot be parsed; in every case the symbol set is left empty.
	 */
	bool ReloadFile(const std::wstring& path, const std::wstring& updater);

	//Offset of a symbol, 0 when it is not present. A real offset is never 0,
	//so 0 doubles as "not found" here.
	unsigned long long GetOffset(const std::wstring& name);

	//Offset of a structure field, stored as "<Struct>.<Field>".
	//Returns kFieldUnresolved when the field could not be resolved from the
	//PDB, which is a normal outcome for types that are not public UDTs.
	unsigned long long GetFieldOffset(const std::wstring& structAndField);

	//Static layouts of internal types are not part of any public ABI. When a
	//field offset could not be resolved from the PDB, callers fall back to the
	//compiled default and must additionally validate the structure before
	//writing to it.
	static constexpr unsigned long long kFieldUnresolved = 0;

private:
	std::vector<SymbolOffset> symbols{};
};

#endif