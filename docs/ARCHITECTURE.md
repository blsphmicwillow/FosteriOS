# Architecture: Frost, an NT personality in Linux

## Decision

Frost uses the **Linux kernel as the base kernel** and implements NT kernel
architecture **inside it**, shipped with the Forsteri userland. The alternative
routes (a greenfield kernel, or a microkernel hosting an NT server) were
considered and rejected for this project because the distribution already
depends on Linux drivers and hardware support, and because the stated goal is
one bootable system rather than a research kernel.

This is a hybrid, and the hybrid has hard edges. They are listed here so that
later stages do not discover them by surprise.

## Mapping

| NT concept | Linux substrate | Frost work |
|---|---|---|
| Process / thread | `task_struct`, `mm_struct` | per-task NT state, PEB/TEB, NT exit status, handle table |
| Object manager | VFS, `kobject`, file descriptors | `\??\` namespace, object types, reference counts, NT handle tables |
| Registry | none | hive parser and key tree; kernel service or userland broker |
| I/O manager / IRP | block/char devices, `file_operations` | IRP emulation, device objects, dispatch routines, driver host |
| Memory manager | `mm`, VMAs, page cache | section objects over files/shmem, NT protection, MDLs |
| `Nt*` syscalls | `sys_call_table` | NT ABI entry, SSDT, per-build syscall numbers |
| PE loader | `binfmt_elf` | `binfmt_pe`, image mapping, imports, relocations, TLS |
| Security | credentials, LSM | tokens, SIDs, ACL checks |
| `ntoskrnl`/`hal` exports | kernel symbols | compatibility shim for driver-facing exports |

## The syscall collision (why modules are not enough)

x86-64 Windows and Linux both enter the kernel with the `syscall` instruction.
The instruction carries no format bit: the kernel sees only a number in `rax`
and arguments in registers. Windows syscall numbers (`NtCreateFile` = 0x55 on
many builds) collide with Linux numbers (`getuid` = 102, etc.).

A loadable module cannot distinguish a PE task from an ELF task at the syscall
entry point without changing the entry path. Therefore stage 3.2 requires a
small **in-tree patch series** to `arch/x86/entry/` and the syscall dispatcher:

1. mark tasks created from PE images (`TIF_*` or a task flag);
2. in the syscall entry, branch to an NT dispatcher for those tasks;
3. keep the Linux path untouched for everything else, so Forsteri userland
   continues to work.

Everything that can remain a module should. The patch series stays minimal and
is carried in this repository as `kernel/patches/`; the build produces a
Forsteri kernel from a pinned Linux version plus those patches. This is the
single most important architectural consequence of choosing Linux as the base,
and it is why M0 is a module but 3.2 is not.

## PE loading

`binfmt_pe` sees only the first 256 bytes (`BINPRM_BUF_SIZE`). The real loader
must reopen the image and read the full headers, map sections at their
`ImageBase` (or relocate), apply base relocations, resolve imports against a
FosteriOS `ntdll`/`kernel32`, set up TLS, build the PEB/TEB, and enter at
`AddressOfEntryPoint`. Unmodified binaries import `ntdll.dll` and
`kernel32.dll` by name; those must exist as PE images (or as a loader-provided
thunk layer) before a hello-world can run.

## Drivers

Windows drivers are PE files loaded by the NT I/O manager, with imports from
`ntoskrnl.exe` and `hal.dll`. Running them on Linux needs:

- a kernel-side PE loader for `.sys` images (different from userland PE loading:
  kernel relocations, no user address space);
- an IRP/device-object layer with WDM semantics first, KMDF later;
- a growing export shim (`IoCreateDevice`, `IoCallDriver`, `KeWaitForSingleObject`,
  …), with correct IRQL and locking semantics;
- memory-manager services drivers actually use (MDLs, nonpaged pool).

This is the largest single piece of work after the syscall layer.

## Anticheat: the honest boundary

Kernel anticheat drivers expect, at minimum: a Windows kernel version and
build, documented and undocumented `ntoskrnl` exports, object callbacks
(`ObRegisterCallbacks`), process/thread notifications, minifilter or WFP hooks,
and platform attestation (TPM measurements, Secure Boot state, HVCI, signed
driver chain). FosteriOS cannot manufacture a genuine attestation chain, and it
will not spoof one. Stage 10 documents what each product requires and reports
the gap; products that require hardware-rooted attestation will not run
faithfully, and that is a finding, not a bug to work around.

## Licensing

The kernel side is GPL-2.0. ReactOS and Wine are behavioural references only;
their code is not copied. Windows binaries used for testing are not
redistributed.
