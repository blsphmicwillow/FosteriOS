# FosteriOS

FosteriOS is the NT-compatibility effort for the Forsteri OS distribution. It
keeps the Linux kernel as the machine's kernel — drivers, filesystems,
scheduler, hardware support — and grows Windows NT kernel semantics inside it,
so that PE/COFF binaries and, eventually, WDM/KMDF-style drivers can run on a
Forsteri system without a Windows kernel underneath.

This repository is the kernel-side work. The distribution (archiso image,
`forst` package manager, installer, desktops, themes) lives in the Forsteri
repository.

## Status: M0 and M1

**M0 — kernel plumbing, boot-tested.** An out-of-tree `ntpersonality` module
builds against the distribution kernel (7.3.5-arch1-1), loads in QEMU, exposes
`/proc/forsteri_nt`, and registers a `linux_binfmt` that recognises `MZ`/`PE\0\0`
images at `execve()` time and returns `-ENOEXEC` because no image loader exists
yet.

**M1 — PE/COFF parser, host-tested and compiled into the module.** A
bounds-checked, allocation-free parser covers DOS/COFF/optional headers,
sections, imports, exports, base relocations and TLS, for PE32 and PE32+. It is
tested against real mingw-built `.exe`/`.dll` fixtures and a mutation table
under ASan/UBSan. It does not load anything yet.

The live ISO integration is in the Forsteri tree: systemd loads the module on a
normal boot, and an opt-in serial self-test (`forsteri.nt_test=1`) verifies
`/proc/forsteri_nt` from the real live image. Both the synthetic M0 gate and the
real-image test pass.

## Build and test

Requirements for the kernel tests: Arch/Fosteri with `base-devel`,
`linux-headers` matching the running kernel, `busybox`, `cpio`,
`qemu-system-x86`. For the parser tests: a host C compiler with ASan/UBSan.

```sh
# PE parser: real images + malformed mutations, ASan/UBSan
scripts/test-pe.sh

# M0 boot gate: module + minimal initramfs + QEMU assertions
scripts/run-m0.sh
```

The M0 gate builds the module, builds a minimal initramfs (busybox + module +
two static helpers), boots it with QEMU and greps the serial log for
`BOOT-TEST: PASS`. Explicit paths, useful when the build host kernel differs
from the target:

```sh
KVER=7.3.5-arch1-1 \
KDIR=/usr/lib/modules/7.3.5-arch1-1/build \
BUSYBOX=/usr/bin/busybox \
KERNEL=/boot/vmlinuz-linux \
scripts/run-m0.sh
```

## Layout

```
kernel/nt/            ntpersonality module (M0) and pe.c/pe.h (M1)
tests/pe/             host tests and mingw-built fixtures
scripts/              test-pe, build-module, build-initramfs, boot-test, run-m0
docs/ARCHITECTURE.md  why Linux + NT personality, and what that costs
docs/nt-compat/       state, roadmap, source log, ranked next steps
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
