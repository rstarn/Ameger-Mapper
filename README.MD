# Ameger Mapper

A manual kernel driver mapper for Windows that exploits a signed vulnerable driver to map non-signed drivers into kernel memory.

Originally based on [KDMapper](https://github.com/TheCruZ/kdmapper) by TheCruZ and the extended kdmapper lineage, this fork has been restructured into a clean, modular C++ codebase under the **Ameger** project.

Tested from **Windows 10 1607** to **Windows 11 26H2** :heavy_check_mark:

---

## Features

- **Modular architecture** — code split into focused namespaces: `Mapper`, `PE`, `Provider`, `Service`, `Symbols`, `Utilities`, and `App`.
- **Multi-provider support** — selectable signed vulnerable-driver providers (Intel NAL / AMD PDFW) via `Provider.hpp`.
- **Automatic PDB offset resolution** — parses Symbol Server PDBs to resolve kernel offsets for any Windows build, eliminating the need for hardcoded offset tables.
- **Relocation** — fixes image relocations when the driver cannot be loaded at its preferred base address.
- **Import resolution** — resolves kernel imports so mapped drivers can call exported kernel routines.
- **Security cookie fix** — patches the `/GS` stack cookie so drivers compiled with stack-protection work correctly.
- **Anti-forensics** — clears `MmUnloadedDrivers`, `PiDDBCacheTable`, `g_KernelHashBucketList`, and related artifacts to reduce detection.
- **Header section skipping** — strips the PE header before copying to reduce footprint.
- **`/GS-` compatibility** — works with drivers compiled with stack protection disabled.

## Parameters

| Parameter | Description |
|---|---|
| `--copy-header` | Enable the copy driver header option by command line. |
| `--free` | Automatically unmap the allocated memory after the driver entry returns. |
| `--indPages` | Map the driver in allocated independent pages. |
| `--PassAllocationPtr` | Pass the allocation pointer as the first argument to the driver entry. |
| `--offsetsPath "FilePath"` | **(PDB builds only)** Include your own offsets file path (default: `.\offsets.ini`). Quote the path if it contains spaces. |
| `--dontUpdateOffsets` | **(PDB builds only)** Execute without updating the offsets file. Ensure offsets are current for your Windows build to avoid a BSOD. |

## Building

1. Install [Visual Studio](https://visualstudio.microsoft.com/downloads/) (2019 or later).
2. Install the [Windows SDK](https://developer.microsoft.com/windows/downloads/windows-sdk/).
3. Install the [Windows WDK](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk).
4. Clone this repository and open `Template\Mapper.sln` in Visual Studio.
5. Select a build configuration, e.g. `Release` or `Release_Pdb_Offset`.
6. Build the solution.

> **Note:** Add the definition `DISABLE_OUTPUT` to suppress all console output.

## Requirements

- The mapped driver entry must return as quickly as possible to avoid PatchGuard / unexpected calls. Do not use infinite loops in `DriverEntry`; spawn a thread or deferred routine instead.
- Disable the Windows vulnerable driver blocklist if needed: open `regedit.exe`, navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Config`, and set `VulnerableDriverBlocklistEnable` to `0`, then restart.

## Project Structure

```
Mapper/
├── App/          # Application entry point, CLI parsing and NT type definitions
├── Mapper/       # Core driver mapping logic (relocations, imports, cookie fix)
├── PE/           # Minimal PE parser for in-memory image manipulation
├── Provider/     # Vulnerable driver provider abstraction (Intel NAL / AMD PDFW)
├── Service/      # Kernel driver service install / start / stop utilities
├── Symbols/      # PDB symbol engine and offset handler
├── Template/     # Visual Studio solution and project files
└── Utilities/    # Logging, general utilities and the dbghelp/symsrv DLLs
```

## Common Issues

### BSOD with a simple driver

In `DriverEntry`, `DriverObject` and `RegistryPath` are `NULL` unless explicitly set. This is a manually mapped driver — it is **not** loaded through the normal Windows loader.

### Error \Device\Nal is already in use

A provider driver is already loaded, another mapper instance is running, or a previous crash left the driver loaded. Restart your computer, or manually unload the provider driver if needed.

### Errors 0xC0000022 / 0xC000009A

These are typically caused by FACEIT AC or another antivirus / anti-cheat product blocking the provider driver.

### Error 0xC0000603

The certificate has been revoked as part of the vulnerable driver blocklist. See the [Microsoft KB5020779](https://support.microsoft.com/en-us/topic/kb5020779) article for details.

## Credits

- **Original creator** — [z175](https://github.com/z175)
- **kdmapper maintainer** — [TheCruZ](https://github.com/TheCruZ)
- **Initial PDB offsets parser** — [Mohi-eddine](https://github.com/Mohi-eddine)
- **Code cleanup** — [tihomirocrew](https://github.com/tihomirocrew)
- **Stack cookie fix** — [Jerem594](https://github.com/Jerem594)
- **Ameger Mapper fork maintainer** — [rstarn](https://github.com/rstarn)

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
