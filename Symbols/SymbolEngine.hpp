#pragma once

#include <string>
#include <vector>
#include <utility>

struct SymbolRequest {
	std::wstring binaryName;
	std::wstring symbolName;
};

//A structure field: module, structure name, field name.
struct FieldRequest {
	std::wstring binaryName;
	std::wstring structName;
	std::wstring fieldName;
};

//Require dbghelp.dll and symsrv.dll
class SymbolEngine {
public:

	SymbolEngine(std::wstring cachePath);

	~SymbolEngine();

	std::wstring GetPDB(const std::wstring binaryPath);

	std::vector<unsigned long long> GetOffset(std::wstring pdbPath, std::vector<std::wstring> symbolName);

	//Resolve field offsets inside a structure using the PDB type information.
	//Returns one value per entry, 0 when the field could not be resolved.
	std::vector<unsigned long long> GetStructFieldOffsets(std::wstring pdbPath, std::vector<std::pair<std::wstring, std::wstring>> structAndField);

private:
	unsigned long long process; //HANDLE but we don't want to share the windows.h include
};
