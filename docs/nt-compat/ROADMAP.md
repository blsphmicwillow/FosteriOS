# Frost roadmap

The order is deliberate: every stage ends with a test that fails today and
passes when the stage is done. A stage is not "in progress" without a test.

Reference build: Windows 11 26H2 (x64). Syscall numbers and structure layouts
are build-specific; record the build number in every coverage table.

## M0 — module skeleton and binfmt hook ✅ (2026-11-25)

- Out-of-tree `ntpersonality` module, `/proc/forsteri_nt`, PE magic detection
  at `execve()`, QEMU serial boot gate.
- Exit test: `scripts/run-m0.sh` prints `BOOT-TEST: PASS`. Passing.
- Live image: module loads through systemd and the real-image serial test
  prints `FORSTERI-NT-TEST: PASS`.

## M1 — PE/COFF parser ✅ (2026-11-25)

- `kernel/nt/pe.c` + `pe.h`: allocation-free, bounds-checked parsing of headers,
  sections, imports, exports, base relocations and TLS, PE32 and PE32+.
- Exit test: real mingw `.exe`/`.dll` fixtures plus malformed mutations under
  ASan/UBSan; `scripts/test-pe.sh` prints `pe-test: PASS`.
- Compiled into the module; M0 gate remains green.

Caveats carried forward: PE32 and PE32+ are covered, other machines are not;
long section names are stored as `/nnn`; coverage-guided fuzzing is not
implemented yet.

## Checkpoint after M1 (2026-11-25)

M1 is complete. `scripts/test-pe.sh` was re-run after moving the tree and
passes. The M0 boot gate and the live-image serial test were not re-run on this
machine (no QEMU, kernel headers or ISO); the GitHub Actions ISO job is the
real-image gate.

## M2 — image mapping, PEB/TEB, first PE execution (in progress)

M2 mapping groundwork is in `kernel/nt/pe_map.c` and `kernel/nt/nt_peb.c`: a
page plan with section-overlap and W^X rejection, image copying, base
relocation application (`ABSOLUTE`, `HIGH`, `LOW`, `HIGHLOW`, `DIR64`), and the
x64 PEB/TEB offsets and initialization. `scripts/test-pe.sh` now runs both the
mapping and PEB/TEB host gates under ASan/UBSan.

This is not execution: the module still returns `-ENOEXEC`, no address space is
allocated, and there is no import thunk or entry transition. M2 is not done.

Design note: [`PEB.md`](PEB.md).

Map sections at their preferred base (or relocate), never map a page writable
and executable at the same time, build the PEB/TEB and loader data, and enter a
static hello-world. No imports beyond a loader-provided thunk page; the program
reaches the kernel through a direct `NtWriteFile` stub or a temporary syscall
gate.

- Exit test: a static PE prints one line and exits with a known status; the
  kernel reports the status and the image's sections/relocations are verified
  against the parse.
- Requires the PEB/TEB layout note first (`docs/nt-compat/PEB.md`).

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

1. ✅ M2 design: pin the PEB/TEB layout and loader data for the reference build
   from public symbols and `phnt`; write `docs/nt-compat/PEB.md` before mapping
   code.
2. ✅ M2 mapping groundwork: page plan with W^X/overlap rejection, image copy,
   base-relocation application and PEB/TEB initialization; host-tested against
   the M1 parse (no execution yet).
3. M2 execution (next): allocate the address space, map the plan, build an
   import thunk for `NtWriteFile`, enter a static hello-world, capture its exit
   status, and make it the M2 gate.

## Risks

- **Scope**: the NT kernel is decades of work. Prioritise what real binaries and
  real drivers import; do not aim for completeness.
- **In-tree patches**: carrying a patch series means rebasing on every kernel
  bump. Keep the diff minimal and test Linux userland after each rebase. The
  patch queue and rebase gate are the top item in `NEXT-STEPS.md`.
- **Driver signing**: a `.sys` signed for Windows will not validate against a
  FosteriOS chain. Test with test-signed builds; document the production gap.
- **Anticheat**: attestation cannot be legitimately reproduced. Expect products
  that require it to refuse to run; that is the honest outcome.
