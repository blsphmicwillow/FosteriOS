# Frost state

Updated: 2026-11-25. This file is the honest inventory. It is updated after
every milestone, with evidence, before the roadmap.

## Verified working

### M0 — module, proc hook, binfmt hook

Kernel: Linux 7.3.5-arch1-1, QEMU TCG, x86-64. Evidence from the M0 gate:

```
BOOT-TEST: insmod ok
pe_seen    0
execve: Exec format error
pe_seen    1
BOOT-TEST: binfmt counted the PE
ntpersonality: PE image recognised: /test.exe (e_lfanew=128)
BOOT-TEST: PASS
```

That proves module loading, `/proc/forsteri_nt`, PE magic detection through
`linux_binfmt`, and an honest `ENOEXEC` for an unloadable format. It runs no PE
code.

### M1 — PE/COFF parser

`kernel/nt/pe.c` and `pe.h` parse, without allocation and without trusting the
input:

- DOS, COFF and optional headers, PE32 and PE32+;
- section table, with RVA-to-file-offset mapping that requires file backing;
- import descriptors, DLL names, thunk arrays (named and ordinal imports);
- export directory, named exports and ordinals;
- base relocation blocks and entries;
- TLS directory and callback array.

Evidence from `scripts/test-pe.sh` (ASan + UBSan, `-fno-sanitize-recover=all`):

- `hello.exe` (mingw, 19 sections): machine `0x8664`, PE32+, entry `0x1440`,
  image base `0x140000000`, 9 import DLLs, 2 relocation blocks, no exports.
- `hello32.exe` (PE32): machine `0x14c`, entry `0x401460`, image base
  `0x400000`, imports and relocations present, no exports.
- `libfixture.dll`: 6 import DLLs, 1 named export `forsteri_test_export`,
  ordinal 1.
- Mutation table (truncations, bad signatures, huge counts, overflowing RVAs,
  section ranges outside the file, broken relocation blocks, export-array
  overruns): every case rejected, no ASan/UBSan reports.
- `pe-test: PASS`.

The parser is compiled into `ntpersonality.ko` (composite module) so kernel
context compilation is part of the gate, and the M0 QEMU gate still passes with
it linked in.

### M2 mapping groundwork (host gate)

`kernel/nt/pe_map.c` builds a page plan for headers and sections, rejects
overlaps and any section that is both writable and executable, copies the file
image into a caller-owned buffer, and applies `ABSOLUTE`, `HIGH`, `LOW`,
`HIGHLOW` and `DIR64` base relocations. `kernel/nt/nt_peb.c` writes only the
loader-owned x64 PEB/TEB pointers and IDs; the layout is documented in
`PEB.md`. `scripts/test-pe.sh` runs the parser, mapping and PEB/TEB gates under
ASan/UBSan. This is mapping groundwork, not execution: no address space is
allocated and no PE entry point is entered.

### Live ISO integration

The Forsteri ISO was rebuilt with the module in the live `airootfs` and a
systemd unit that loads it. A real-image QEMU test (`scripts/test-iso.sh` in the
distribution tree) boots the ISO's own kernel, initramfs and squashfs with
`forsteri.nt_test=1`; the serial log shows:

```
Starting Forsteri NT personality (ntpersonality)...
[  OK  ] Finished Forsteri NT personality (ntpersonality).
FORSTERI-NT-TEST: begin (7.3.5-arch1-1)
FORSTERI-NT-TEST: module loaded
name       ntpersonality
version    0.0.1
stage      M0 (hooks only, no image loader)
pe_seen    0
binfmt     registered
FORSTERI-NT-TEST: PASS
```

## What this is not

No Windows binary has been mapped or executed. M1 parses an image; M2 has
host-tested mapping decisions and a PEB/TEB layout, but no kernel call site
maps an image. There is no `ntdll`, no NT syscall dispatcher, no object
manager, no registry, no I/O manager, no driver loading.

## Missing, in dependency order

1. **Image mapping**: page plan, W^X/overlap decisions, relocations and
   PEB/TEB layout are host-tested; the kernel address-space allocation, import
   thunk and first entry are still missing.
2. **A minimal `ntdll`/`kernel32`** sufficient for a static hello-world.
3. **NT syscall dispatch**: in-tree patch to the x86-64 entry path, per-task
   format flag, NT syscall table and coverage tracking. A module cannot do this
   (same `syscall` instruction, colliding numbers).
4. **Object manager**: NT namespace, object types, handles, reference counts.
5. **Tokens/SIDs/ACLs** over Linux credentials and LSM hooks.
6. **Registry**: hive parsing and a key tree; decide kernel service vs userland
   broker in M5 (design the object-manager interface so either fits).
7. **I/O manager**: IRPs, device objects, `DriverEntry`, WDM dispatch; later a
   KMDF subset and kernel-side PE `.sys` loading.
8. **Memory manager semantics**: section objects, protection, MDLs, paging
   behaviour visible to drivers and `Nt*` calls.
9. **`ntoskrnl`/`hal` export shim**, driven by real driver imports.
10. **Graphics/audio**: DXVK/VKD3D-style userland translation, once Win32
    processes run at all.
11. **Anticheat requirements matrix**, documented, never spoofed.

## Known limitations

- PE32 and PE32+ are both covered by fixtures now; other machines (ARM64) are
  parsed structurally but not tested.
- COFF long section names (`/nnn`) are stored verbatim; the loader must resolve
  them against the string table.
- The parser is fuzzed by mutation, not by a coverage-guided fuzzer; the
  libFuzzer harness is proposed in `NEXT-STEPS.md`, not implemented.
- Image mapping and execution will need hardening (W^X, no executable writes)
  before any untrusted binary is run.

## Environment constraints

- No KVM in this build VM; QEMU runs under TCG. The M0 initramfs gate is ~3 s;
  a full live ISO boot is tens of seconds.
- Module builds use `linux-headers 7.3.5-arch1-1` in an Arch chroot against the
  Forsteri ISO kernel. Modules are self-signed by the kernel build and load
  with a taint because `CONFIG_MODULE_SIG_FORCE` is not set.
- Windows 11 media cannot be fetched programmatically and is not stored here.
  Extracted binaries (`ntdll.dll`, `ntoskrnl.exe`, drivers) are needed for M2+
  and must be supplied manually; see `SOURCES.md`.
- The distribution tree is separate and still has no Git history of its own;
  this repository owns the kernel work.

## Next

M2: wire the host-tested plan into a real address space, build the import
thunk, enter a static hello-world and capture its exit status. The layout note
and mapping groundwork are done. See `ROADMAP.md`.
