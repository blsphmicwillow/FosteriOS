# FosteriOS

FosteriOS is the NT-compatibility effort for [Forsteri OS](../forsteri). It
keeps the Linux kernel as the machine's kernel — drivers, filesystems,
scheduler, hardware support — and grows Windows NT kernel semantics inside it,
so that PE/COFF binaries and, eventually, WDM/KMDF-style drivers can run on a
Forsteri system without a Windows kernel underneath.

This repository is the kernel-side work. The distribution (archiso image,
`forst` package manager, installer, desktops, themes) lives in the Forsteri
repository.

## Status: M0

M0 is a boot-tested kernel-module skeleton. It proves the plumbing, not the
compatibility:

- an out-of-tree `ntpersonality` module builds against the distribution kernel
  (7.3.5-arch1-1) and loads in QEMU;
- it exposes `/proc/forsteri_nt` with version, stage and counters;
- it registers a `linux_binfmt` that recognises `MZ`/`PE\0\0` images at
  `execve()` time, logs them, and returns `-ENOEXEC` because no image loader
  exists yet.

That last point is deliberate. A recognised-but-unloadable format must fail the
way the kernel fails every unknown format, not pretend to run.

## Build and test

Requirements: Arch/Fosteri with `base-devel`, `linux-headers` matching the
running kernel, `busybox`, `cpio`, `qemu-system-x86`. On a normal Forsteri
machine:

```sh
scripts/run-m0.sh
```

The script builds the module, builds a minimal initramfs (busybox + module + two
static test helpers), boots it with QEMU, and greps the serial log for
`BOOT-TEST: PASS`. Any kernel or module failure fails the script.

Explicit paths, useful on a build host whose running kernel differs from the
target:

```sh
KVER=7.3.5-arch1-1 \
KDIR=/usr/lib/modules/7.3.5-arch1-1/build \
BUSYBOX=/usr/bin/busybox \
KERNEL=/boot/vmlinuz-linux \
scripts/run-m0.sh
```

## Layout

```
kernel/nt/            ntpersonality module (M0)
scripts/              build-module, build-initramfs, boot-test, run-m0
docs/ARCHITECTURE.md  why Linux + NT personality, and what that costs
docs/nt-compat/       state, roadmap, source log
```

## What this is not

It is not Wine: Wine is a userland implementation and never runs kernel-mode
code. It is not a Windows kernel clone either. The target is a Linux kernel that
implements enough NT semantics — object manager, IRPs, sections, tokens,
registry, PE loading, the `Nt*` ABI — for real Windows binaries and legitimate
drivers to run. That is a multi-year scope; the roadmap is explicit about what
is reachable and what is not.

Nothing here spoofs, hides from or defeats anticheat. Attestation-backed
protections (TPM, Secure Boot, HVCI, signed-driver chains) are documented as
requirements; if FosteriOS cannot provide them legitimately, it says so.

## Licence

GPL-2.0. The module links against the Linux kernel and carries
`MODULE_LICENSE("GPL")`.
