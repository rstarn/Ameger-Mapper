#include <Windows.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>

#include "../../Mapper/Mapper.hpp"
#include "../../Utilities/Utilities.hpp"
#include "../../Utilities/Console.hpp"
#include "../../Provider/Driver.hpp"
#include "../../Symbols/Handler/SymbolsHandler.hpp"
#include "../../../../Injector/Ameger/Bridge.h"
#include "Probe.h"

//IsElevated uses advapi32: CheckTokenMembership and the SID helpers live there.
#pragma comment(lib, "advapi32.lib")

static_assert(sizeof(AMEGER_KERNEL_CONTEXT) == 96, "AMEGER_KERNEL_CONTEXT must be 96 bytes");

namespace
{
	//The same byte-reading and console helpers the probe needs, pulled in from
	//the shared Utilities and Console layers rather than duplicated here.
	using Console::Val;
	using Console::Hex;
}

/*
 * Is this process running with the administrator token enabled?
 *
 * The manifest asks for requireAdministrator, so on the supported launch paths
 * this is always true. It is checked anyway because the tool can also be started
 * from a shell that ignores the manifest - a debugger, or a host that creates
 * the process itself - and the failure that produces is the least legible one in
 * the project: SE_LOAD_DRIVER_PRIVILEGE cannot be acquired, Service.cpp reports
 * "make sure you are running as administrator" after the provider has already
 * been written to %TEMP%, and nothing has been mapped.
 */
bool IsElevated() {
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
	PSID administrators = nullptr;

	if (!AllocateAndInitializeSid(&nt_authority, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&administrators))
		return false;

	BOOL member = FALSE;
	const BOOL checked = CheckTokenMembership(nullptr, administrators, &member);
	FreeSid(administrators);

	//A failed check is reported as "not elevated" rather than as elevated: the
	//caller's response to each is the same, and guessing wrong in the other
	//direction would only produce the failure this is meant to explain early.
	return checked && member != FALSE;
}

/*
 * --probe-context <path>: read the driver bytes, allocate an AMEGER_KERNEL_CONTEXT
 * with VirtualAlloc, pass it as param2 to Mapper::MapDriver so the driver's
 * DriverEntry treats it as its second argument, then report whether the driver
 * wrote back its success fields. Prints PROBE_RESULT=PASS or PROBE_RESULT=FAIL
 * with every context field and an 80-byte hex dump of the context.
 */
int RunProbeContext(const int argc, wchar_t** argv, int probeContextIdx) {
	if (probeContextIdx + 1 >= argc) {
		Log(L"[-] --probe-context requires a file path argument" << std::endl);
		return -1;
	}
	const std::wstring probePath = argv[probeContextIdx + 1];

	//1. Read the driver bytes (the same bytes get mapped, never a later re-read).
	std::vector<BYTE> image;
	if (!Utilities::ReadFileToMemory(probePath, &image) || image.empty()) {
		Log(L"[-] Failed to read driver bytes from \"" << Val(probePath) << L"\"" << std::endl);
		return -1;
	}

	//2. Allocate the context struct in caller-process memory (readable/writable).
	AMEGER_KERNEL_CONTEXT* ctx = static_cast<AMEGER_KERNEL_CONTEXT*>(
		VirtualAlloc(nullptr, sizeof(AMEGER_KERNEL_CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!ctx) {
		Log(L"[-] Failed to allocate the probe context" << std::endl);
		return -1;
	}
	std::memset(ctx, 0, sizeof(*ctx));
	ctx->magic = AMEGER_KERNEL_CONTEXT_MAGIC;
	ctx->version = AMEGER_KERNEL_ABI_VERSION;

	//T4: reserve the user-mode ring buffer the driver will MDL-lock in DriverEntry.
	AMEGER_KERNEL_COMMAND* ring_buffer = static_cast<AMEGER_KERNEL_COMMAND*>(
		VirtualAlloc(nullptr, AMEGER_RING_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!ring_buffer) {
		Log(L"[-] Failed to allocate the ring buffer" << std::endl);
		VirtualFree(ctx, 0, MEM_RELEASE);
		return -1;
	}
	std::memset(ring_buffer, 0, AMEGER_RING_SIZE);
	ctx->ring_buffer_user_va = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ring_buffer));
	ctx->ring_buffer_size = AMEGER_RING_SIZE;

	//The probe runs the real mapping path, so it needs the provider loaded.
	const bool elevated = IsElevated();
	if (!elevated) {
		Log(L"[-] The probe needs to run elevated to load the kernel provider." << std::endl);
		return -1;
	}

	//1. Initialize symbols FIRST: load (or regenerate) Offsets.ini exactly as the
	//normal path does, so the tracing lines and MmPteBase resolve before any
	//kernel call. Without this, GetOffset(L"MmPteBase") returns 0 and the probe
	//fails at Driver::Load.
	const std::wstring offsetFilePath = Utilities::GetCurrentAppFolder() + L"\\Offsets.ini";
	const std::wstring updater = Utilities::GetCurrentAppFolder() + L"\\" + SYMBOL_TOOL_EXE;
	if (!SymbolsHandler::GetInstance()->ReloadFile(offsetFilePath, updater)) {
		Log(L"[-] Failed to load Offsets.ini; the probe cannot run." << std::endl);
		return -1;
	}

	//2. Then load the driver.
	NTSTATUS load_status = Driver::Load();
	if (!(load_status >= 0)) {
		Log(L"[-] Failed to load the kernel provider; the probe cannot run." << std::endl);
		return -1;
	}

	//3. Pass the context as param2 to MapDriver.
	NTSTATUS driver_status = (NTSTATUS)0x8000ffff;
	SIZE_T resident_size = 0;
	const ULONG64 base = Mapper::MapDriver(
		image.data(), image.size(), 0,
		static_cast<ULONG64>(reinterpret_cast<uintptr_t>(ctx)),
		/*free=*/false, /*destroyHeader=*/true,
		Mapper::AllocationMode::AllocateContiguous,
		/*passAllocationPtr=*/false,
		&driver_status, &resident_size);

	const bool provider_clean = (Driver::Unload() >= 0);

	//4. Check the fields the driver is expected to write back.
	const bool mapped = (base != 0);
	const bool entry_ok = (driver_status >= 0);
	const bool fields_ok =
		ctx->driver_started == 1 &&
		ctx->driver_load_mode == 1 &&
		ctx->driver_ntstatus == (uint64_t)0 &&
		ctx->probe_echo == 0xDEADBEEFCAFEBABEull;

	if (mapped && entry_ok && fields_ok)
		Log(L"PROBE_RESULT=PASS" << std::endl);
	else
		Log(L"PROBE_RESULT=FAIL" << std::endl);

	//Report every context field so the result is auditable.
	Log(L"driver_started  = " << Val(ctx->driver_started) << std::endl);
	Log(L"driver_load_mode= " << Val(ctx->driver_load_mode) << std::endl);
	Log(L"driver_ntstatus= " << Val(Hex(ctx->driver_ntstatus)) << std::endl);
	Log(L"driver_image_base= " << Val(Hex(ctx->driver_image_base)) << std::endl);
	Log(L"probe_echo    = " << Val(Hex(ctx->probe_echo)) << std::endl);

	//T4 additions, reported too.
	Log(L"ring_buffer_user_va= " << Val(Hex(ctx->ring_buffer_user_va)) << std::endl);
	Log(L"ring_buffer_size  = " << Val(Hex(ctx->ring_buffer_size)) << std::endl);
	Log(L"shutdown_flag    = " << Val(ctx->shutdown_flag) << std::endl);
	Log(L"driver_heartbeat = " << Val(ctx->driver_heartbeat) << std::endl);
	Log(L"driver_error   = " << Val(Hex(ctx->driver_error)) << std::endl);

	//T4 communication test: write a Ping command into the user-mode ring buffer,
	//give the driver a few timer ticks, then read the heartbeat and the command
	//status back through the same buffer the driver wrote via its MDL-mapped VA.
	AMEGER_KERNEL_COMMAND* cmd = ring_buffer;
	cmd->type = AmegerCmdPing;
	Sleep(200);
	const bool comm_ok = (ctx->driver_heartbeat > 0) && (cmd->type == AmegerCmdNone) && (cmd->status == 0);
	if (comm_ok)
		Log(L"COMM_TEST=SUCCESS heartbeat=" << Val(ctx->driver_heartbeat) << std::endl);
	else
		Log(L"COMM_TEST=FAIL heartbeat=" << Val(ctx->driver_heartbeat) << std::endl);

	//Safe shutdown: request shutdown, then wait for the driver to confirm it is
	//safe to free memory (shutdown_complete) before the user releases the buffers.
	ctx->shutdown_flag = 1;
	for (int i = 0; i < 50; i++) {
		if (ctx->shutdown_complete == 1) break;
		Sleep(10);
	}
	Log(L"cmd_status     = " << Val(Hex(cmd->status)) << std::endl);
	if (ctx->shutdown_complete != 1) {
		Log(L"[-] Driver did not complete shutdown in time." << std::endl);
	}

	VirtualFree(ring_buffer, 0, MEM_RELEASE);

	//Hex dump of the whole 88-byte context, as it exists after MapDriver returned.
	LogBlank();
	LogRaw(L"Context hex dump (96 bytes):");
	const unsigned char* bytes = reinterpret_cast<const unsigned char*>(ctx);
	std::wostringstream hex;
	for (size_t i = 0; i < sizeof(*ctx); ++i) {
		hex << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<unsigned>(bytes[i]);
		if (i + 1 < sizeof(*ctx))
			hex << L' ';
	}
	LogRaw(hex.str());

	VirtualFree(ctx, 0, MEM_RELEASE);

	return (mapped && entry_ok && fields_ok && provider_clean) ? 0 : -1;
}
