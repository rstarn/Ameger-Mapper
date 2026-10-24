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
* The defaults are values that have been stable across Windows builds, but every
* one of them is replaced at runtime by the offset of the real type in the
* running kernel (the symbol tool writes them into Offsets.ini as
* "[<module>.fields] Struct.Field=<offset>").
*
* Anything that cannot be resolved from symbols is not trusted on its own: the
* caller must structurally validate the object before writing to it.
*
* PDB_OFFSETS is not optional. The build that ships defines it, and the kernel
* walks read SymbolsHandler unconditionally from Driver.cpp, so a configuration
* without it does not fall back to compiled-in offsets - it does not compile.
* The guards that used to suggest otherwise have been removed rather than left
* to mislead the next reader.
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

	/*
	 * Upper bound on a plausible member offset for any of the types above.
	 *
	 * The largest is _KLDR_DATA_TABLE_ENTRY, which is a few hundred bytes; a
	 * kilobyte is far past anything real and below the first page, so a resolved
	 * value at or above it means the entry in Offsets.ini does not describe the
	 * field that was asked for. Used to reject a bad resolution loudly rather
	 * than quietly keep the compiled default.
	 */
	static constexpr uint64_t kMaxFieldOffset = 0x1000;

	bool ResolvedFromSymbols = false;

	//Count of the public UDT fields above that were replaced with this build's
	//own offset. Reported alongside ResolvedFromSymbols so a partial resolution
	//is visible rather than hidden behind a single boolean.
	uint32_t ResolvedFieldCount = 0;

	//Total number of fields that have a public UDT to resolve against. The
	//internal types further down deliberately have none, so they are not counted.
	static constexpr uint32_t kResolvableFieldCount = 5;

	/*
	 * Offsets inside _DRIVER_OBJECT and _DRIVER_EXTENSION.
	 *
	 * Separate from the block above because these are only needed to build the
	 * DRIVER_OBJECT handed to DriverEntry, and because a miss here is expected
	 * on builds that do not publish one of them - the constructor validates what
	 * it wrote instead of assuming the layout.
	 *
	 * Defaults are the x64 values. _DRIVER_EXTENSION has no Size member in the
	 * PDB type stream, so nothing is written there: the back-pointer below is
	 * the only field the constructor touches, because it is the one
	 * IoCreateDevice dereferences.
	 */
	uint32_t DriverObject_Size = 0x02;
	uint32_t DriverObject_DriverStart = 0x18;
	uint32_t DriverObject_DriverSize = 0x20;
	uint32_t DriverObject_DriverExtension = 0x30;
	uint32_t DriverObject_Flags = 0x10;
	uint32_t DriverObject_DriverUnload = 0x68;
	uint32_t DriverExtension_DriverObject = 0x00;

	//How many of the seven fields above were replaced with this build's own.
	uint32_t DriverObjectResolvedCount = 0;
	static constexpr uint32_t kDriverObjectResolvableFieldCount = 7;

	void LoadFromSymbols() {
		const auto lookup = [](const wchar_t* name, uint32_t& target) {
			const auto value = SymbolsHandler::GetInstance()->GetFieldOffset(name);
			//A field that resolves to something past this bound cannot be a
			//member offset of any of the types involved, so it is treated as a
			//resolution failure rather than silently written over the compiled
			//default. Previously such a value was dropped without a line of log
			//and the run continued on the default, which is the one failure mode
			//this file exists to prevent.
			if (value == SymbolsHandler::kFieldUnresolved || value >= kMaxFieldOffset) {
				if (value != SymbolsHandler::kFieldUnresolved)
					Log(L"[!] Field " << Val(name) << L" resolved to " << Val(Hex(value))
						<< L", outside the plausible offset range; keeping the compiled default" << std::endl);
				return false;
			}
			target = static_cast<uint32_t>(value);
			return true;
		};

		uint32_t resolved = 0;
		resolved += lookup(L"_FILE_OBJECT.DeviceObject", FileObject_DeviceObject) ? 1u : 0u;
		resolved += lookup(L"_DEVICE_OBJECT.DriverObject", DeviceObject_DriverObject) ? 1u : 0u;
		resolved += lookup(L"_DRIVER_OBJECT.DriverSection", DriverObject_DriverSection) ? 1u : 0u;
		resolved += lookup(L"_KLDR_DATA_TABLE_ENTRY.BaseDllName", LdrEntry_BaseDllName) ? 1u : 0u;
		resolved += lookup(L"_RTL_AVL_TABLE.DeleteCount", AvlTable_DeleteCount) ? 1u : 0u;

		ResolvedFieldCount = resolved;
		//All or nothing, matching how every other resolver in this project
		//treats a partial answer. A single resolved field used to set this flag
		//and the caller then reported "offsets resolved from symbols for this
		//build" while four fields were still compiled-in guesses.
		ResolvedFromSymbols = (resolved == kResolvableFieldCount);

		/*
		 * Same treatment for the DRIVER_OBJECT layout. Counted separately from
		 * the five above because a miss here is normal on some builds and only
		 * degrades the DRIVER_OBJECT the mapper builds; it does not invalidate
		 * the offsets the kernel structure walks use.
		 */
		uint32_t object_fields = 0;
		object_fields += lookup(L"_DRIVER_OBJECT.Size", DriverObject_Size) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverStart", DriverObject_DriverStart) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverSize", DriverObject_DriverSize) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverExtension", DriverObject_DriverExtension) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.Flags", DriverObject_Flags) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverUnload", DriverObject_DriverUnload) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_EXTENSION.DriverObject", DriverExtension_DriverObject) ? 1u : 0u;
		DriverObjectResolvedCount = object_fields;
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

	//Page aligned, physically contiguous allocation for the image. Needed
	//because a pool block's first and last page are shared with pool metadata.
	uint64_t AllocateContiguous(uint64_t size);
	bool MmFreeContiguousMemory(uint64_t address);

	/*
	 * Build the DRIVER_OBJECT handed to a mapped driver's DriverEntry.
	 *
	 * DriverEntry's contract is DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING).
	 * A driver calls IoCreateDevice before it has registered anything else, and
	 * that call dereferences DriverObject->DriverExtension and the extension's
	 * own back-pointer, so a NULL DriverObject is a guaranteed bugcheck rather
	 * than something a driver can ignore.
	 *
	 * Returns the address of the object, 0 on failure. Two nonpaged blocks are
	 * taken: the extension and the object itself, both zeroed before a single
	 * field is written, so a member the PDB did not describe is zero rather than
	 * whatever was in the pool.
	 *
	 * driver_start/driver_size describe the mapped image and land in DriverStart
	 * and DriverSize; driver_section is what belongs in DriverSection, and the
	 * caller passes the image base for a driver that has no real section.
	 *
	 * Every field is written through a helper that bounds the write inside the
	 * allocation, and every pointer written is checked to be one this process
	 * holds. The object is not registered anywhere: it is owned by the caller
	 * and must outlive DriverEntry, because a driver keeps a reference to it
	 * for as long as it is loaded.
	 */
	uint64_t CreateDriverObjectForEntry(uint64_t driver_start, uint64_t driver_size, uint64_t driver_section);

	//Releases both blocks CreateDriverObjectForEntry took. Only valid before
	//DriverEntry has been entered - see MapDriver for the lifetime rule.
	bool DestroyDriverObjectForEntry(uint64_t driver_object);

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
	 * Outcome of the most recent CallKernelFunction, as set by that call.
	 *
	 * Read it immediately after the call returns and before doing anything else,
	 * because the next call overwrites it. It exists for the one caller that
	 * owns memory the target may have adopted: CallKernelFunction returning true
	 * says the target ran, and this says whether ntoskrnl was left clean.
	 *
	 * A file scope inline variable rather than a local static, so the one piece of
	 * state it names is visible as such at the point it is read. It is still a
	 * plain bool with no synchronisation, which is correct for the single
	 * threaded flow this runs in and is not correct for two threads calling
	 * CallKernelFunction at once - see CallKernelFunction's own note for why that
	 * is not something a flag could fix anyway.
	 */
	inline bool g_restore_succeeded = false;

	inline bool& RestoreSucceeded() {
		return g_restore_succeeded;
	}

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
	 * Every argument must be trivially copyable and there can be at most 4 of
	 * them, since the hook passes everything through registers.
	 *
	 * T is the return type; T = void means no result is stored.
	 *
	 * Return value: whether the TARGET was invoked - that is, whether the hook
	 * was installed and the call was made. It deliberately does not report the
	 * restore, because the two must not be conflated:
	 *
	 *   - a false return means the target never ran, so nothing the caller
	 *     passed in has been touched and the caller is free to clean up
	 *   - a true return means the target ran and may have taken ownership of,
	 *     or written through, whatever the caller owns. Releasing that state
	 *     now would corrupt memory a running kernel object is using.
	 *
	 * That distinction is why the restore does not decide this return value.
	 * LastCallHookRestored() reports the restore separately; a caller that owns
	 * state the target may have adopted has to check it.
	 */
	template<typename T, typename ...A>
	bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		//Only up to 4 arguments can be forwarded through the syscall jump.
		static_assert(sizeof...(A) <= 4, "CallKernelFunction: too many arguments");

		//Every return below leaves this false, so the caller's flag is only ever
		//set once the restore has actually been confirmed.
		RestoreSucceeded() = false;

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

		//Cached once resolved: the export is the same for the whole run, and
		//resolving it walks the kernel export directory.
		//
		//Retry-on-zero, not one-shot static initialisation. A one-shot
		//initialiser runs on the first call only, so a first call made before
		//ntoskrnlAddr was resolved cached 0 forever and every later call
		//reported the same failure without retrying. Same shape as the export
		//resolvers in Driver.cpp.
		//
		//One copy per instantiation, not one per process: each distinct argument
		//list A... gets its own variable, so each signature resolves NtAddAtom
		//once rather than sharing a single lookup. That is a redundant export
		//walk per signature on first use, which is not worth a template-level
		//cache with its own lifetime rules in exchange for.
		static uint64_t kernel_NtAddAtom = 0;
		if (!kernel_NtAddAtom) {
			kernel_NtAddAtom = GetKernelModuleExport(Driver::ntoskrnlAddr, "NtAddAtom");
			if (!kernel_NtAddAtom) {
				Log(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
				return false;
			}
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

		/*
		 * From here the target runs. Everything above could fail without the
		 * kernel having executed anything; everything below must be treated as
		 * cleanup of state that may already have been modified.
		 */
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

		/*
		 * Restore the original bytes.
		 *
		 * Attempted twice. The second attempt exists because the failure mode
		 * is a transient fault in the provider's copy (the same stale-TLB window
		 * WriteToReadOnlyMemory documents), not a refused write - which a
		 * second attempt pastes into.
		 *
		 * Whatever the outcome, the target has already run, so this function
		 * returns true: the caller must learn that the kernel state it passed in
		 * may have been taken over. A failure to restore is reported through
		 * hook_restored instead, because folding it into the return value is
		 * what previously let a caller release memory a running kernel object
		 * was using.
		 */
		bool restored = WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));

		if (!restored) {
			Log(L"[!] NtAddAtom restore failed, retrying" << std::endl);
			restored = WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
		}

		if (!restored) {
			//ntoskrnl is still patched. Say so plainly: the process must not exit
			//believing the hook is gone, because NtAddAtom will jump into the
			//last target until something else restores it.
			Log(L"[!!] CRITICAL: ntoskrnl.NtAddAtom is still hooked after a "
				"failed restore. Do not terminate this process: every NtAddAtom "
				"call on this machine now jumps to the last target until the page "
				"is repaired." << std::endl);
		}
		else {
			RestoreSucceeded() = true;
		}

		return true;
	}
}
