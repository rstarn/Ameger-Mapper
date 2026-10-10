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
	//is therefore derived at runtime by content matching. Such a field is
	//reported once, dimmed, instead of as a per-field warning, because an
	//unresolved optional field is an expected outcome and not a failure.
	bool optional = false;
};

/*
 * Console colour sequences, honoured once EnableAnsiColors() has run. They are
 * inert if the console does not interpret ANSI escapes, so redirected output
 * still reads correctly.
 */
inline constexpr const wchar_t* kColorReset = L"\x1b[0m";
inline constexpr const wchar_t* kColorGreen = L"\x1b[92m";
inline constexpr const wchar_t* kColorRed = L"\x1b[91m";
inline constexpr const wchar_t* kColorDim = L"\x1b[90m";

/*
 * Enables ANSI escape processing on this console so the sequences above are
 * drawn rather than printed literally. Honours AMEGER_NO_COLOR=1, the same
 * opt-out the build script uses.
 */
void EnableAnsiColors();

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

	//Resolve field offsets inside a structure using the PDB type information.
	//Returns one value per entry, 0 when the field could not be resolved. Each
	//entry's optional flag decides whether a miss is reported as a dimmed
	//expected outcome or as a real warning.
	std::vector<uint64_t> GetStructFieldOffsets(const std::wstring& pdbPath, const std::vector<FieldRequest>& fields);

private:
	uint64_t process = 0; //HANDLE but we don't want to share the windows.h include
	std::wstring cachePath{}; //flat folder holding the downloaded PDBs
};