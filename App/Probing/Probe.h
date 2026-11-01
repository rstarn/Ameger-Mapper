#pragma once

#include <stdint.h>

/*
 * The user/kernel ABI shared with the Ameger driver.
 *
 * These declarations used to come from the driver repository through
 * "../../../../Injector/Ameger/Bridge.h". That header no longer exists, so the
 * subset the probe actually uses is declared here instead of reaching across
 * repositories. Field order and types have to stay byte-identical to the
 * driver's own view of AMEGER_KERNEL_CONTEXT: DriverEntry writes these fields
 * straight into the user-mode allocation passed as param2, and Probe.cpp
 * asserts the resulting size.
 */
#define AMEGER_KERNEL_ABI_VERSION   1u
#define AMEGER_KERNEL_CONTEXT_MAGIC 0x4B414D47u  /* "KAMG" */

#define AMEGER_RING_SIZE 0x1000

typedef enum _AMEGER_COMMAND_TYPE {
	AmegerCmdNone = 0,
	AmegerCmdPing = 1,
	AmegerCmdShutdown = 2
} AMEGER_COMMAND_TYPE;

typedef struct _AMEGER_KERNEL_COMMAND {
	uint32_t type;
	uint32_t status;
	uint64_t arg1;
	uint64_t arg2;
} AMEGER_KERNEL_COMMAND;

typedef struct _AMEGER_KERNEL_CONTEXT {
	uint32_t magic;
	uint32_t version;
	uint64_t reserved[2];

	uint32_t driver_started;
	uint32_t driver_load_mode;
	uint64_t driver_ntstatus;
	uint64_t driver_image_base;
	uint64_t probe_echo;

	/* T4 additions */
	uint64_t ring_buffer_user_va;
	uint64_t ring_buffer_size;
	uint32_t shutdown_flag;        /* User sets to 1 to request shutdown */
	uint32_t shutdown_complete;    /* Driver sets to 1 when it is safe for user to free memory */
	uint32_t driver_heartbeat;
	uint32_t driver_error;         /* Non-zero if MDL lock fails */
	uint64_t mm_set_page_protection_addr;
} AMEGER_KERNEL_CONTEXT;

//Runs the --probe-context flow: read the driver image, allocate an
//AMEGER_KERNEL_CONTEXT with VirtualAlloc, pass it to Mapper::MapDriver as
//param2 so the driver's DriverEntry treats it as its second argument, then
//report whether the driver wrote back its success fields. Prints
//PROBE_RESULT=PASS or PROBE_RESULT=FAIL with every context field and an
//80-byte hex dump of the context.
int RunProbeContext(const int argc, wchar_t** argv, int probeContextIdx);

//True when the process runs under the administrator token. The manifest asks
//for requireAdministrator, but the tool can also be started from a shell that
//ignores the manifest - a debugger, or a host that creates the process itself.
//Checked before touching the kernel, so the elevation failure is reported early.
bool IsElevated();
