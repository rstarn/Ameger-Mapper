#pragma once

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
