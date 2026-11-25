# Roadmap

The order is deliberate: every stage ends with a test that fails today and
passes when the stage is done. A stage is not "in progress" without a test.

Reference build: Windows 11 26H2 (x64). Syscall numbers and structure layouts
are build-specific; record the build number in every coverage table.

## M0 — module skeleton and binfmt hook ✅ (2026-11-25)

- Out-of-tree `ntpersonality` module, `/proc/forsteri_nt`, PE magic detection
  at `execve()`, QEMU serial boot gate.
- Exit test: `scripts/run-m0.sh` prints `BOOT-TEST: PASS` on the distribution
  kernel. Passing.

## M1 — PE/COFF parser (next)

Parse DOS/COFF/optional headers, section table, data directories, imports,
exports, base relocations and TLS. Bounds-check everything; treat the image as
hostile.

- Exit test: parse a mingw-built hello-world and a table of malformed images;
  every field matches `objdump -x`; malformed inputs are rejected, never crash.
- Keep it reusable in kernel context: no libc, fixed-width types, explicit
  integer overflow checks.

## M2 — image mapping, PEB/TEB, first PE execution

Map sections, apply relocations, build the loader structures, enter a static
hello-world. No imports yet beyond a loader-provided thunk page; the program
writes through a direct `NtWriteFile` stub or a syscall gate.

- Exit test: a static PE prints one line and exits with a known status; the
  kernel reports the status.
- Realistically requires the first `Nt*` entry point; if the syscall patch is
  not ready, use a temporary `int 0x2e` gate for the test only.

## M3 — NT syscall ABI (in-tree patch)

Per-task NT flag in the kernel; `syscall` entry routes PE tasks to an NT
dispatcher; NT numbers per reference build; SSDT coverage table generated from
`j00ru/windows-syscalls` and verified against the reference build.

- Exit test: unmodified mingw hello-world that calls `NtWriteFile` via `ntdll`
  prints through the NT path; Linux binaries are unaffected.
- Coverage table: implemented / stubbed (`STATUS_NOT_IMPLEMENTED`) / missing,
  per syscall, checked into `docs/nt-compat/coverage.md`.

## M4 — object manager, handles, tokens

Namespace (`\??\`, `\Device\`, `\BaseNamedObjects\`), object types, handle
tables, reference counts, NT access masks; token/SID/ACL checks backed by Linux
credentials where possible.

- Exit test: `NtCreateFile`/`NtOpenFile`/`NtClose` on a real file through a
  handle; `NtDuplicateHandle`; a token check that denies a write it should deny.

## M5 — registry

Hive parser, key/value tree, notifications; decide early whether the registry
is a kernel service or a userland broker with a kernel RPC surface.

- Exit test: load a real `SYSTEM`/`SOFTWARE` hive read-only and answer
  `NtOpenKey`/`NtQueryValueKey` for known keys.

## M6 — I/O manager and WDM

IRPs, device objects, `DriverEntry`, dispatch routines, I/O stacks; kernel-side
PE loader for `.sys`; export shim beginning with the imports of a trivial WDM
driver.

- Exit test: a WDM sample driver loads, creates a device, and completes a
  create/read/close IRP sequence.
- KMDF subset follows WDM, not before.

## M7 — memory manager semantics

Section objects, protection constants, MDLs, nonpaged pool, paging behaviour
that drivers can observe.

- Exit test: shared section between two processes; MDL read/write of a user
  buffer from a driver; protection violations return the NT status Windows does.

## M8 — export surface for drivers

Grow `ntoskrnl`/`hal` exports from real driver imports, not from a wish list.
Track IRQL/locking semantics per export.

- Exit test: the M6 driver sample plus a second, independent driver.

## M9 — userland graphics/audio

Win32 windowing and D3D translation (DXVK/VKD3D approach) once processes run.

## M10 — anticheat requirements (documentation only)

For each product (Vanguard, BattlEye, EAC): required exports, callbacks,
attestation, signed-driver chain. Report gaps. No spoofing, no evasion, no
hiding. Hardware-rooted attestation is expected to be a hard gap; say so.

## Next three tasks

1. M1: write `kernel/nt/pe.c` + `pe.h` with bounds-checked header parsing and a
   host test harness (`tests/pe/`) covering valid and malformed images.
2. M1: compare parsed output against `objdump -x` for a mingw hello-world and
   add the malformed-image table to the test gate.
3. M2 design: pin the PEB/TEB layout and loader data for the reference build,
   from public symbols and `phnt`; write it in `docs/nt-compat/PEB.md` before
   writing mapping code.

## Risks

- **Scope**: the NT kernel is decades of work. Prioritise what real binaries and
  real drivers import; do not aim for completeness.
- **In-tree patches**: carrying a patch series means rebasing on every kernel
  bump. Keep the diff minimal and test Linux userland after each rebase.
- **Driver signing**: a `.sys` signed for Windows will not validate against a
  FosteriOS chain. Test with test-signed builds; document the production gap.
- **Anticheat**: attestation cannot be legitimately reproduced. Expect products
  that require it to refuse to run; that is the honest outcome.
