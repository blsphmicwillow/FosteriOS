# Beyond M1: ranked next steps

This is a proposal, not a plan of record. Nothing here is started. M1 (the
PE/COFF parser) is the current milestone; the items below are what should come
after it, ordered by how much they de-risk or accelerate the rest of the
project. Ideas marked **new** have not been raised earlier in this project.

## 1. Build the in-tree patch queue and a rebase gate now — before M3

The syscall collision is already established: x64 Windows and Linux share the
`syscall` instruction and colliding numbers, so the NT ABI needs a change in the
kernel entry path. That patch does not exist yet, but its **infrastructure**
should exist before M2 writes loader code that depends on it:

- `kernel/patches/` as a numbered series against a pinned Linux version;
- a script that applies the series to a clean tree and builds;
- a CI job that rebases the series on each kernel bump and boots a Linux
  userland smoke test, plus the M0 gate.

Why it matters: the patch is small but touches the hottest path in the kernel.
Without a rebase gate it will rot silently, and every later stage will be built
on an unbuildable base. This is the cheapest insurance in the project.

## 2. Harvest `.sys` imports before designing the export shim (**new**)

Collect a corpus of legitimate Windows drivers (Microsoft samples, vendor
drivers from the user's own Windows installation) and statically extract their
imports from `ntoskrnl.exe`/`hal.dll`. Produce a frequency table and dependency
graph.

Why it matters: M6/M8 can then implement the 30 exports that cover most drivers
instead of guessing. It also tells us early which drivers are realistic and
which need subsystems (WFP, minifilters, KMDF) we do not have. This is pure
static analysis; it needs no running Windows kernel.

## 3. An NTSTATUS oracle and differential tests (**new**)

Windows behaviour is often defined by the exact status code, not by success or
failure: `STATUS_OBJECT_NAME_NOT_FOUND` vs `STATUS_OBJECT_PATH_NOT_FOUND`,
`STATUS_BUFFER_OVERFLOW`, `STATUS_PENDING`, and the information classes returned
alongside them. Build a table-driven oracle (from Microsoft docs, ReactOS
behaviour and recorded traces) and assert that every implemented `Nt*` returns
the same status and output lengths for a matrix of edge cases.

Why it matters: application compatibility fails first on error paths, and a
wrong status is much harder to debug than a crash. Doing this from M2 onward
prevents a large class of regressions that would otherwise only appear in games.

## 4. Record real syscall traces on the user's Windows machine (**new**)

On a Windows VM owned by the user, record the syscall sequence of a small set of
target programs (a console app, a GUI app, one game launcher) with an existing
tracer. Commit only the traces (never the binaries). Replay them against
FosteriOS to find missing calls in the order a real program needs them.

Why it matters: it replaces guesswork with a workload. The syscall coverage
table becomes a target list sorted by actual use, and progress is measurable
("the hello trace completes", then "the GUI trace reaches the message loop").
This cannot be done in this build VM, which has no Windows and no KVM; it needs
the user's machine.

## 5. Syscall tracing and fault injection from the first NT call (**new**)

A ring-buffer monitor (`/proc/forsteri_nt/trace` or a debugfs file) that logs
NT syscall number, arguments, status and duration, with per-call counters and a
one-shot "first failure" dump including user registers.

Why it matters: once unmodified binaries run, a failure inside `ntdll` is
opaque. A trace is the difference between "it exits 0xC0000135" and "it asked
for `KERNEL32.dll` before any file was opened". Adding it in M2 is cheap;
retrofitting it after the dispatcher grows is not.

## 6. A snapshot-based boot harness (**new**)

Boot the test image once in QEMU, save a VM snapshot after userspace is up, and
restore that snapshot for each test instead of cold-booting. Keep one snapshot
per kernel/module build.

Why it matters: the M0 gate is seconds, but a full live ISO boot is tens of
seconds under TCG and will grow. Fast, deterministic test cycles compound across
hundreds of future changes; this is infrastructure that pays for itself early.

## 7. A loader conformance PE (**new**)

One mingw-built binary that deliberately exercises loader features: imports by
name and ordinal, forwarded exports, base relocations, TLS callbacks, x64
unwind info, SEH, a DLL dependency, and a static CRT. Its output enumerates what
worked.

Why it matters: the hello-world proves almost nothing. A single conformance
binary turns M2's "it ran" into a checklist and becomes the regression test for
every loader change, including the .sys loader later.

## 8. Treat PE images and drivers as hostile from day one (**new**)

Map images W^X, never write to executable pages, bound every copy, and fuzz the
parser and later the loader with libFuzzer/AFL using the mutation corpus already
in `tests/pe`. Add a seccomp-style filter for the NT syscall surface so a
malformed PE cannot call arbitrary kernel services during early bring-up.

Why it matters: the end goal runs kernel-mode anticheat, i.e. code with full
privileges written by third parties. A loader bug is a host compromise. Building
the security posture now is far cheaper than auditing a mature loader later.

## 9. Licence and provenance gate (**new**)

A checked-in policy plus a CI check: SPDX headers, no copied ReactOS/Wine code,
and a provenance note for every structure layout (public docs, PDB, or phnt).
Keep Windows binaries and extracted PDBs out of the repository by construction.

Why it matters: the project deliberately reads GPL/LGPL implementations for
behaviour. One accidental copy would relicense the kernel side and could sink
the distribution. A mechanical gate is the only reliable defence.

## 10. Pin the reference build by fingerprint, not by name (**new**)

For every Windows build used (26H2 initially), record the `ntoskrnl.exe` version,
PDB GUID/age, and a hash of the syscall table. Stamp every coverage table and
structure layout with that fingerprint.

Why it matters: syscall numbers and layouts change between builds. "Windows 11"
is not a reference; a specific binary is. This prevents the classic failure of
testing against one build and shipping assumptions from another.

## 11. Decide the registry boundary before writing it

Registry as a userland broker (hive parsing in a service, kernel exposes a
narrow RPC surface) versus an in-kernel key tree. The broker is easier to crash
isolate, reuses existing parsers, and keeps GPL surface smaller; the in-kernel
tree has better fidelity for drivers that touch the registry at high IRQL.

Why it matters: this choice shapes the object-manager interface in M4 and cannot
be deferred to M5 without rework. It is a decision, not an implementation.

## 12. Set a syscall-latency budget before optimisation

Once the NT path exists, measure `NtClose`/`NtCreateFile` round trips and set a
budget relative to native Linux syscalls (for example, no more than 2× the
equivalent). Record it in the roadmap and check it at each milestone.

Why it matters: games are latency-sensitive, and architectural mistakes in the
dispatcher (extra copies, global locks) are cheap to avoid now and expensive to
remove later. This is a low-cost guardrail, not an optimisation project.

## Explicitly not proposed

- Spoofing or defeating anticheat, hiding the kernel, or faking attestation.
- Running Windows itself inside the kernel.
- Chasing syscall coverage percentage as a goal; coverage follows workloads.

## Suggested order

1 → 2 → 3 → 6 → 7 → 5 → 4 → 8 → 9 → 10 → 11 → 12, with 11 decided during M4
design and 12 measured as soon as the first NT call exists.
