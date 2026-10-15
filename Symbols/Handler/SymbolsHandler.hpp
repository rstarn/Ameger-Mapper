//TheCruZ Remake

#pragma once

#include <string>
#include <unordered_map>

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
	 *
	 * Also returns false when the file parses but is not usable: no entries at
	 * all, or missing one of the offsets the run cannot proceed without. That
	 * case used to return true, which reported success and then walked kernel
	 * structures on the compiled-in defaults - the opposite of what a successful
	 * load is supposed to mean for a file whose whole purpose is to describe this
	 * build.
	 */
	bool ReloadFile(const std::wstring& path, const std::wstring& updater);

	//Offset of a symbol, 0 when it is not present. A real offset is never 0,
	//so 0 doubles as "not found" here.
	unsigned long long GetOffset(const std::wstring& name);

	//Offset of a structure field, stored as "<Struct>.<Field>".
	//Returns kFieldUnresolved when the field could not be resolved from the
	//PDB, which is a normal outcome for types that are not public UDTs.
	//
	//The sentinel is deliberately not 0: a field can legitimately resolve to
	//offset 0, and reusing the "not found" value of GetOffset for it meant a
	//caller could not tell "this field is at the start of the struct" from
	//"this field is not in the PDB". Callers compare against the sentinel
	//itself, so the two are now distinguishable.
	unsigned long long GetFieldOffset(const std::wstring& structAndField);

	//Returned by GetFieldOffset when no offset could be resolved. Deliberately
	//outside the range of any real member offset.
	static constexpr unsigned long long kFieldUnresolved = ~0ULL;

private:
	/*
	 * Every entry, keyed by name.
	 *
	 * A map rather than the list this used to hold. GetOffset and
	 * GetFieldOffset are called from the kernel structure walks, where the
	 * WdFilter discovery in particular looks a field up once per candidate
	 * offset, so a linear scan turned a bounded search into a quadratic one.
	 */
	std::unordered_map<std::wstring, unsigned long long> symbols{};
};