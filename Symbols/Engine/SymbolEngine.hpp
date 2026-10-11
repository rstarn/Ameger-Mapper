#pragma once

#include <cstdint>
#include <string>
#include <vector>

//Folder next to the executable holding dbghelp.dll and symsrv.dll.
//Kept in step with SYMBOL_DLL_FOLDER in Symbols\Handler\SymbolsHandler.hpp, which
//is the mapper side of the same layout; the two programs do not share a header,
//so both spell it out here.
inline constexpr const wchar_t* kSymbolDllFolder = L"DLLs";

//One symbol to look up in a module's PDB.
struct SymbolRequest {
	std::wstring binaryName;
	std::wstring symbolName;
};

//A structure field: module, structure name, field name.
struct FieldRequest {
	std::wstring binaryName;
	std::wstring structName;
	std::wstring fieldName;

	//Set when the field is known not to exist in the public PDB type stream and
	//is therefore derived at runtime by content matching. An unresolved
	//optional field is an expected outcome, so the caller does not report it as
	//a failure.
	bool optional = false;
};

/*
 * dbghelp wrapper used by SymbolTool.exe to resolve kernel addresses and
 * structure field offsets from Microsoft's public PDBs.
 *
 * Loads dbghelp.dll and symsrv.dll from the DLLs subfolder next to the
 * executable; see SymbolEngine.cpp for why that is done explicitly rather than
 * through the import table.
 *
 * Every function reports failure by returning an empty container instead of
 * throwing, so a partially downloaded or missing PDB degrades to "that offset
 * could not be resolved" rather than taking the tool down.
 */
class SymbolEngine {
public:

	//cachePath is the flat folder the PDBs are stored in: one <name>.pdb per
	//binary, directly in that folder.
	explicit SymbolEngine(const std::wstring& cachePath);

	~SymbolEngine();

	//Reuse the flat <cachePath>\<name>.pdb for a binary, or download it there
	//when it is missing or belongs to a different build, and return its path.
	//Empty when no PDB is available for it.
	std::wstring GetPDB(const std::wstring& binaryPath);

	//Resolve symbol addresses, returned as offsets from the module base.
	//Returns an empty vector if any symbol fails, so a partial result is never
	//mistaken for a complete one.
	std::vector<uint64_t> GetOffset(const std::wstring& pdbPath, const std::vector<std::wstring>& symbolName);

	//One resolved structure field. offset is 0 when the field could not be
	//resolved. matchedName is the spelling the type was found under, which can
	//differ from the requested struct name for the internal types that appear
	//under several names in the PDB; empty on a miss.
	struct FieldResult {
		uint64_t offset = 0;
		std::wstring matchedName{};
	};

	//Resolve field offsets inside a structure using the PDB type information.
	//Returns one result per entry, offset 0 when the field could not be
	//resolved. Reporting is left to the caller, which knows the request's
	//optional flag.
	std::vector<FieldResult> GetStructFieldOffsets(const std::wstring& pdbPath, const std::vector<FieldRequest>& fields);

private:
	uint64_t process = 0; //HANDLE but we don't want to share the windows.h include
	std::wstring cachePath{}; //flat folder holding the downloaded PDBs
};