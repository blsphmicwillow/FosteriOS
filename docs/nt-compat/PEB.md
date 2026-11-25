# PEB/TEB layout (M2)

Reference build: Windows 11 26H2, x64. These offsets are from public Windows
x64 layouts (`phnt`/WinDbg `dt`/Microsoft symbol definitions). They are not a
promise that every 26H2 field is present; only the fields listed here are used
by the loader.

The constants live in `kernel/nt/nt_peb.h`. `nt_peb_init()` writes only the
loader-owned PEB pointers. It deliberately does not write `BeingDebugged`,
signature state, secure-boot state or any other platform assertion: pretending
to be a different platform would make compatibility data untrustworthy.

## PEB (x64)

| Offset | Field | Type |
| --- | --- | --- |
| `0x000` | `InheritedAddressSpace` | `UCHAR` |
| `0x002` | `BeingDebugged` | `UCHAR` |
| `0x008` | `Mutant` | pointer |
| `0x010` | `ImageBaseAddress` | pointer |
| `0x018` | `Ldr` | `PEB_LDR_DATA *` |
| `0x020` | `ProcessParameters` | `RTL_USER_PROCESS_PARAMETERS *` |
| `0x028` | `SubSystemData` | pointer |
| `0x030` | `ProcessHeap` | pointer |
| `0x038` | `FastPebLock` | pointer |
| `0x040` | `AtlThunkSListPtr` | pointer |
| `0x048` | `IFEOKey` | pointer |
| `0x050` | `CrossProcessFlags` | `ULONG` |
| `0x058` | `UserSharedInfoPtr` | pointer |
| `0x068` | `TlsExpansionCounter` | `ULONG` |
| `0x070` | `TlsBitmap` | pointer |
| `0x0b0` | `NumberOfProcessors` | `ULONG` |
| `0x0b4` | `NtGlobalFlag` | `ULONG` |
| `0x0e8` | `ProcessHeaps` | pointer |
| `0x108` | `LoaderLock` | pointer |

## TEB (x64, beginning with NT_TIB)

| Offset | Field | Type |
| --- | --- | --- |
| `0x000` | `ExceptionList` | pointer |
| `0x008` | `StackBase` | pointer |
| `0x010` | `StackLimit` | pointer |
| `0x018` | `SubSystemTib` | pointer |
| `0x020` | `FiberData` | pointer |
| `0x028` | `ArbitraryUserPointer` | pointer |
| `0x030` | `Self` | pointer |
| `0x038` | `EnvironmentPointer` | pointer |
| `0x040` | `ClientId.UniqueProcess` | pointer |
| `0x048` | `ClientId.UniqueThread` | pointer |
| `0x050` | `ActiveRpcHandle` | pointer |
| `0x058` | `ThreadLocalStoragePointer` | pointer |
| `0x060` | `ProcessEnvironmentBlock` | `PEB *` |
| `0x068` | `LastErrorValue` | `ULONG` |
| `0x06c` | `CountOfOwnedCriticalSections` | `ULONG` |
| `0x070` | `CsrClientThread` | pointer |
| `0x078` | `Win32ThreadInfo` | pointer |

## Loader data

`PEB_LDR_DATA` (x64): `Length` `0x000`, `Initialized` `0x004`, `SsHandle`
`0x008`, `InLoadOrderModuleList` `0x010`, `InMemoryOrderModuleList` `0x020`,
`InInitializationOrderModuleList` `0x030`, `EntryInProgress` `0x040`,
`ShutdownInProgress` `0x048`.

`LDR_DATA_TABLE_ENTRY` (x64): load-order links `0x000`, memory-order links
`0x010`, initialization-order links `0x020`, `DllBase` `0x030`, `EntryPoint`
`0x038`, `SizeOfImage` `0x040`, `FullDllName` `0x048`, `BaseDllName` `0x058`,
`Flags` `0x068`, `LoadCount` `0x06c`, `TlsIndex` `0x06e`, hash links `0x070`,
`TimeDateStamp` `0x080`, `LoadTime` `0x0f0`.

`RTL_USER_PROCESS_PARAMETERS` (x64): `MaximumLength` `0x000`, `Length` `0x004`,
`Flags` `0x008`, `DebugFlags` `0x00c`, console handles `0x010`-`0x030`,
`CurrentDirectory` `0x038`, `DllPath` `0x050`, `ImagePathName` `0x060`,
`CommandLine` `0x070`, `Environment` `0x080`, `WindowTitle` `0x0ac`.
`UNICODE_STRING` is 16 bytes on x64: `Length` `0x000`, `MaximumLength` `0x002`,
`Buffer` `0x008`.

## What is implemented

- `kernel/nt/nt_peb.{h,c}`: x64 offsets, PEB pointer initialization and TEB
  self/PEB/client-id initialization.
- `kernel/nt/pe_map.{h,c}`: page plan for headers and sections, section overlap
  rejection, W^X rejection, image copy, base-relocation application for
  `ABSOLUTE`, `HIGH`, `LOW`, `HIGHLOW` and `DIR64`.
- `tests/pe/pe_map_test.c` and `tests/pe/peb_test.c` run under ASan/UBSan with
  the real PE fixtures.

## Not implemented yet

- No kernel call sites allocate an address space or map the plan with
  `vm_mmap`; the module still returns `-ENOEXEC` after recognising a PE.
- No import thunk page, ntdll hand-off, TLS callback invocation or first
  user-mode entry. M2's execution gate is still open.
- Relocation types other than those listed are rejected. Rebasing below the
  preferred base is rejected; the loader must allocate at or above it until a
  signed delta is implemented.
