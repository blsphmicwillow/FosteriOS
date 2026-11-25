# NT compatibility — sources and analysis log

Every fact used for the NT work is recorded here with where it came from and how
it was checked. Add a row when a new source is mined; do not cite from memory.

## Reference material

| Source | What it is for | Status |
|--------|----------------|--------|
| [Windows 11 download](https://www.microsoft.com/en-us/software-download/windows11) | Legal Windows 11 26H2 media for extracting real binaries and drivers | Fetched 2026-11-25; form flow, no direct ISO URL |
| [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) | COFF/PE headers, sections, imports, exports, relocations | Canonical; mined in M1 |
| [WDK documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/) | Driver model, IRPs, device objects, `DriverEntry` | Canonical; mined in M6 |
| [Kernel-mode programming guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/) | Object/memory/I-O manager semantics | Canonical; mined in M4–M7 |
| [Microsoft public symbols](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols) | PDBs for `ntoskrnl.exe`, `ntdll.dll`, drivers | Verified 2026-11-25: `srv*<cache>*msdl.microsoft.com/download/symbols` |
| [Symbol path syntax](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-path) | `.sympath` / `_NT_SYMBOL_PATH` | Verified 2026-11-25 |
| [ReactOS](https://github.com/reactos/reactos) | From-scratch NT implementation: dispatch, object manager, registry, loader | Reference only; GPL/LGPL — read behaviour, do not copy |
| [Wine](https://gitlab.winehq.org/wine/wine) | PE loader, `ntdll` stubs, userland NT semantics | Reference only; LGPL |
| [phnt headers](https://github.com/winsiderss/systeminformer/tree/develop/phnt) | Prototypes/layouts for undocumented `Nt*` calls | Reference; MIT |
| [Windows syscall tables](https://github.com/j00ru/windows-syscalls) | Per-build syscall numbers for the SSDT coverage table | Reference; check licence before reuse |
| [Windows driver samples](https://github.com/microsoft/Windows-driver-samples) | Real `DriverEntry`/dispatch patterns to test against | Reference; MIT |
| *Windows Internals, 7th ed.* | Process/thread/object/memory manager chapters | Book; cite chapter in notes |

## Microsoft licence boundary

The Windows 11 ISO is downloadable from Microsoft for installation and testing.
It is not redistributable. Extracted binaries stay on the developer's machine
and are never committed; fixtures in this repo are mingw-built or generated.
ReactOS and Wine are read for behaviour, not copied: a kernel that reuses GPL
code inherits GPL.

## Windows 11 ISO: manual steps

The page is a form flow; there is no stable direct URL, and generated links
expire after 24 hours. Do this on your own machine:

1. Open <https://www.microsoft.com/en-us/software-download/windows11>.
2. Scroll to **Download Windows 11 Disk Image (ISO) for x64 devices**.
3. Select **Windows 11 (multi-edition ISO for x64 devices)** → **Download**.
4. Choose the product language → **Confirm**.
5. Click **64-bit Download** and save the ISO (valid 24 hours).
6. Verify the SHA-256 against the table on the page.

Keep it on your machine, e.g. `~/isos/win11-26h2-x64.iso`. Do **not** upload the
~7 GB ISO to this chat: the workspace checkpoint limit is 4 GiB and this VM has
no KVM, so a Windows guest cannot be tested here. When a binary is needed, copy
it out of a mounted ISO or an installed Windows and attach that file:

```
sources/win11/Windows/System32/ntdll.dll
sources/win11/Windows/System32/kernel32.dll
sources/win11/Windows/System32/kernelbase.dll
sources/win11/Windows/System32/win32u.dll
sources/win11/Windows/System32/drivers/<driver>.sys
```

`sources/` is git-ignored.

## REA evaluation

**What it is.** REA (`rea.tools`, `npx rea-agents@latest setup`) is an
agent-oriented reverse-engineering layer. It registers an MCP server and a skill
with a coding agent, then exposes workflows over native executables,
JavaScript/Electron apps, browser pages, managed assemblies, APKs and firmware.
For native code it returns assembly, pseudocode, calls and constants.

**Fit.** A front end, not an engine:

* Deep native analysis requires a provider — Hopper, Ghidra or IDA. REA
  orchestrates one; it does not replace it.
* It is driven through an MCP-capable agent. This chat cannot mount a new MCP
  server, so REA cannot run here. It can run on your machine with Claude Code,
  Codex, Cursor or VS Code, pointed at a PE.
* Examples are userland Windows binaries and JavaScript, not kernel drivers.

**Recommendation.** Ghidra (free, headless, PE/driver support) as the primary
engine, radare2/rizin for scripted checks. Add REA on your machine if you want
an agent-driven investigation loop.

## Analysis log

| Date | What was done | Finding |
|------|---------------|---------|
| 2026-11-25 | Searched the Forsteri tree for NT/kernel symbols | It is a Linux distribution; no kernel, no C/asm, no PE loader |
| 2026-11-25 | Fetched the Windows 11 download page | 26H2; form flow; links expire in 24 h; SHA-256 table on page |
| 2026-11-25 | Verified Microsoft symbol-server docs | `srv*<cache>*msdl.microsoft.com/download/symbols`, https required |
| 2026-11-25 | Evaluated REA | MCP front end; needs Hopper/Ghidra/IDA; not usable from this chat |
| 2026-11-25 | Built and booted the M0 module on 7.3.5-arch1-1 | Module loads, `/proc` works, binfmt handler invoked, synthetic PE recognised, `execve` returns `ENOEXEC` |
| 2026-11-25 | Checked `BINPRM_BUF_SIZE` and binfmt ABI in 7.3.5 headers | 256-byte buffer; `register_binfmt` returns void; `struct linux_binfmt` fields as used |
| 2026-11-25 | Tested `execve` permission path | `execve` requires the execute bit; the harness sets 0755 on the stub |

## Open questions

1. Reference Windows build: 26H2 for now; record it in every coverage table.
2. Registry placement: kernel service or userland broker? Decide in M5, but
   design the object-manager interface in M4 so either fits.
3. Driver model order: WDM first (M6), KMDF subset after; confirm against the
   first real driver we test.
4. In-tree patch budget: how large a diff can we carry across kernel bumps?
   Target: entry-path flag + dispatcher call only.
