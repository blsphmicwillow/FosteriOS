# State

Updated: 2026-11-25. This file is the honest inventory. It is updated after
every milestone, with evidence, before the roadmap.

## Verified working (M0)

Kernel: Linux 7.3.5-arch1-1 (the Forsteri ISO kernel), QEMU TCG, x86-64.

Evidence from `build/boot.log` of the M0 gate:

```
BOOT-TEST: kernel 7.3.5-arch1-1
BOOT-TEST: insmod ok
...
pe_seen    0
execve: Exec format error
...
pe_seen    1
BOOT-TEST: binfmt counted the PE
[    3.469493] ntpersonality: PE image recognised: /test.exe (e_lfanew=128)
BOOT-TEST: PASS
```

What that demonstrates, precisely:

- `kernel/nt/ntpersonality.c` compiles against the distribution's headers and
  loads into the running kernel (self-signed, kernel tainted — expected).
- `register_binfmt()` links successfully and the handler is invoked for a
  non-ELF file; the kernel's binfmt list is not the blocker.
- `/proc/forsteri_nt` reports state and counters, readable from an initramfs.
- PE magic detection works on a 132-byte synthetic image with `e_lfanew=0x80`.
- `execve()` of an unhandled format still returns `ENOEXEC`; the module changes
  nothing about normal execution.

## What this is not

No Windows binary has been loaded. M0 runs no PE code, maps no image, and knows
nothing about `ntdll`. The "PE recognised" line means the magic matched; the
next line of work is the loader.

## Missing, in dependency order

1. **PE/COFF parser** beyond the magic: headers, sections, imports, exports,
   relocations, TLS. Host-side tests with real and malformed images.
2. **Image mapping** into a new address space, with PEB/TEB and loader data.
3. **A minimal `ntdll`/`kernel32`** sufficient for a static hello-world.
4. **NT syscall dispatch**: in-tree patch to the x86-64 entry path, per-task
   format flag, NT syscall table and coverage tracking. A module cannot do this
   (equal `syscall` instruction, colliding numbers).
5. **Object manager**: NT namespace, object types, handles, reference counts.
6. **Tokens/SIDs/ACLs** over Linux credentials and LSM hooks.
7. **Registry**: hive parsing and a key tree; decide kernel service vs userland
   broker.
8. **I/O manager**: IRPs, device objects, `DriverEntry`, WDM dispatch; later a
   KMDF subset and PE `.sys` loading in kernel.
9. **Memory manager semantics**: section objects, protection, MDLs, paging
   behaviour visible to drivers and `Nt*` calls.
10. **`ntoskrnl`/`hal` export shim** driven by the imports of the drivers under
    test.
11. **Graphics/audio**: DXVK/VKD3D-style userland translation, once Win32
    processes run at all.
12. **Anticheat requirements matrix**, documented, not spoofed.

## Environment constraints

- No KVM in this build VM (`/dev/kvm` unavailable); QEMU runs under TCG, so
  tests are slow but functional. Boot gate is ~3 s to userspace in the M0
  initramfs.
- The module is built in an Arch chroot against `linux-headers 7.3.5.arch1-1`;
  the kernel image is the one from the Forsteri ISO.
- Windows 11 media cannot be fetched programmatically and is not stored here.
  Extracted binaries (`ntdll.dll`, `ntoskrnl.exe`, driver samples) are needed
  for M1/M2 and must be supplied manually; see `SOURCES.md`.
- Signing: modules are self-signed by the kernel build and load with a taint
  because `CONFIG_MODULE_SIG_FORCE` is not set. An in-tree Forsteri kernel will
  sign with the distribution key in a later stage.

## Next

M1: a PE parser with tests. See `ROADMAP.md` for the exit criterion and the
next three tasks.
