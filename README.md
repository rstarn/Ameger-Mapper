# Ameger Mapper

User-mode manual-mapper for `Driver.sys`. It maps the driver image into kernel
memory, builds a synthetic driver object, enters `DriverEntry`, and performs
anti-forensic cleanup before handing control over.

## Kernel-call primitive

`Driver::CallKernelFunction` is the mechanism for executing arbitrary kernel
functions from user mode. The provider (`PdFwKrnl`, CVE-2023-20598) exposes only
an unchecked read/write IOCTL — it has no "call function" facility — so a
transient kernel-mode execution gadget is structurally required.

### Current design

The gadget is a 12-byte patch of `ntoskrnl!NtAddAtom`:

```
mov rax, <target>    ; 48 b8 <8-byte address>
jmp rax              ; ff e0
```

Calling `NtAddAtom` from user mode therefore jumps to the requested kernel
function in kernel context. The original bytes are captured first and restored
as soon as the call returns, so the hook exists only for the duration of one
call (roughly ten instructions).

Hardening in place (`Harden in-kernel call primitive against residual hooks`):

- **Fail-closed startup check** — `VerifyNtAddAtomNotHooked()` runs in `Load()`
  before any kernel write. If `NtAddAtom` already carries our hook shape (the
  residue a process would leave if killed or bugchecked between install and
  restore), the whole run aborts rather than stacking a second stub over bytes
  we cannot prove clean.
- **Byte-exact restore verification** — after each call the 12 bytes are read
  back and compared with the saved original, up to three attempts. Only an
  exact match sets `RestoreSucceeded()`.
- **Poison flag** — once a restore cannot be verified, all further kernel calls
  refuse to patch, so a damaged page can never get a second hook on top of it.

### Residual risk (accepted)

This is hardening in place, not elimination. PatchGuard (Kernel Patch
Protection) can in principle detect the transient `ntoskrnl` code modification,
and there are two failure windows that cannot be designed away with an
R/W-only provider:

- If the process is killed or the machine crashes between install and restore,
  `NtAddAtom` is left pointing at the last target until a reboot.
- Another process calling `NtAddAtom` during the hook window races the call to
  the target function.

A full elimination requires replacing the code patch with a function-pointer
hijack into a writable, non-PatchGuard-guarded structure (a dispatch table or a
controlled syscall stub). That is a larger, riskier rewrite of the execution
layer and is intentionally deferred. If the fail-closed startup check ever
aborts on a clean reboot with no prior run, treat it as a real detection event.

### Resolved: 0x109 from a stale scratch alias (2026-11-20)

A `0x109 CRITICAL_STRUCTURE_CORRUPTION` (Arg4=1, bucket `nt!NtSetUuidSeed`) was
traced with `!chkimg -d nt` to a single corrupted byte at `NtAddAtom`'s page
base: `0x85` had become `0x00`. The hook itself was correctly restored; the
stray byte came from `WriteToReadOnlyMemory`, which faulted in its scratch page
by **writing** zero at offset 0. After a call restored the alias PTE, the TLB
could still map the scratch VA onto the kernel page; the next `VirtualAlloc`
reused that VA and the fault-in write landed in kernel code, which PatchGuard
later flagged. Fix: fault in with a **read**, and hand every call a distinct,
never-freed scratch VA from a rotating pool so a stale alias is never reused.

## Build

Use the full release builder; it stages the symbol tooling and `Offsets.ini`
that `Mapper.exe` expects next to itself:

```
Build\Executors\Create.bat
```

Building the vcxproj directly produces `Mapper.exe` but its post-build step
copies `dbghelp.dll`/`symsrv.dll` from a path that does not exist in every
checkout; that is a staging-path issue, not a source defect.
