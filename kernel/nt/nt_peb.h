/* SPDX-License-Identifier: GPL-2.0 */
/*
 * x64 PEB/TEB layout used by the NT personality.
 *
 * These are the public Windows x64 offsets, not a private ABI guess. The
 * structures are kept as offsets plus narrow accessors so the kernel does not
 * depend on compiler packing for an ABI it does not own. M2 initializes only
 * the fields the loader owns; the rest is filled by the future ntdll hand-off.
 */
#ifndef FORSTERI_NT_PEB_H
#define FORSTERI_NT_PEB_H

#include "pe.h"

/* PEB (x64). */
#define NT_PEB64_INHERITED_ADDRESS_SPACE	0x000
#define NT_PEB64_BEING_DEBUGGED			0x002
#define NT_PEB64_MUTANT				0x008
#define NT_PEB64_IMAGE_BASE_ADDRESS		0x010
#define NT_PEB64_LDR				0x018
#define NT_PEB64_PROCESS_PARAMETERS		0x020
#define NT_PEB64_SUBSYSTEM_DATA			0x028
#define NT_PEB64_PROCESS_HEAP			0x030
#define NT_PEB64_FAST_PEB_LOCK			0x038
#define NT_PEB64_ATL_THUNK_SLIST_PTR		0x040
#define NT_PEB64_IFEO_KEY			0x048
#define NT_PEB64_CROSS_PROCESS_FLAGS		0x050
#define NT_PEB64_USER_SHARED_INFO_PTR		0x058
#define NT_PEB64_TLS_EXPANSION_COUNTER		0x068
#define NT_PEB64_TLS_BITMAP			0x070
#define NT_PEB64_NUMBER_OF_PROCESSORS		0x0b0
#define NT_PEB64_NT_GLOBAL_FLAG			0x0b4
#define NT_PEB64_PROCESS_HEAPS			0x0e8
#define NT_PEB64_LOADER_LOCK			0x108

/* TEB (x64), which begins with NT_TIB. */
#define NT_TEB64_EXCEPTION_LIST			0x000
#define NT_TEB64_STACK_BASE			0x008
#define NT_TEB64_STACK_LIMIT			0x010
#define NT_TEB64_SUBSYSTEM_TIB			0x018
#define NT_TEB64_FIBER_DATA			0x020
#define NT_TEB64_ARBITRARY_USER_POINTER		0x028
#define NT_TEB64_SELF				0x030
#define NT_TEB64_ENVIRONMENT_POINTER		0x038
#define NT_TEB64_CLIENT_ID_PROCESS		0x040
#define NT_TEB64_CLIENT_ID_THREAD		0x048
#define NT_TEB64_ACTIVE_RPC_HANDLE		0x050
#define NT_TEB64_TLS_POINTER			0x058
#define NT_TEB64_PEB				0x060
#define NT_TEB64_LAST_ERROR_VALUE		0x068
#define NT_TEB64_COUNT_OF_OWNED_CRITICAL_SECTIONS 0x06c
#define NT_TEB64_CSR_CLIENT_THREAD		0x070
#define NT_TEB64_WIN32_THREAD_INFO		0x078

/* PEB_LDR_DATA (x64). */
#define NT_LDR64_LENGTH				0x000
#define NT_LDR64_INITIALIZED			0x004
#define NT_LDR64_SS_HANDLE			0x008
#define NT_LDR64_IN_LOAD_ORDER_MODULE_LIST	0x010
#define NT_LDR64_IN_MEMORY_ORDER_MODULE_LIST	0x020
#define NT_LDR64_IN_INITIALIZATION_ORDER_LIST	0x030
#define NT_LDR64_ENTRY_IN_PROGRESS		0x040
#define NT_LDR64_SHUTDOWN_IN_PROGRESS		0x048

/* LDR_DATA_TABLE_ENTRY (x64). */
#define NT_LDR_ENTRY64_IN_LOAD_ORDER_LINKS	0x000
#define NT_LDR_ENTRY64_IN_MEMORY_ORDER_LINKS	0x010
#define NT_LDR_ENTRY64_IN_INITIALIZATION_LINKS	0x020
#define NT_LDR_ENTRY64_DLL_BASE			0x030
#define NT_LDR_ENTRY64_ENTRY_POINT		0x038
#define NT_LDR_ENTRY64_SIZE_OF_IMAGE		0x040
#define NT_LDR_ENTRY64_FULL_DLL_NAME		0x048
#define NT_LDR_ENTRY64_BASE_DLL_NAME		0x058
#define NT_LDR_ENTRY64_FLAGS			0x068
#define NT_LDR_ENTRY64_LOAD_COUNT		0x06c
#define NT_LDR_ENTRY64_TLS_INDEX		0x06e
#define NT_LDR_ENTRY64_HASH_LINKS		0x070
#define NT_LDR_ENTRY64_TIME_DATE_STAMP		0x080
#define NT_LDR_ENTRY64_LOAD_TIME		0x0f0

/* RTL_USER_PROCESS_PARAMETERS (x64). */
#define NT_PARAMS64_MAXIMUM_LENGTH		0x000
#define NT_PARAMS64_LENGTH			0x004
#define NT_PARAMS64_FLAGS			0x008
#define NT_PARAMS64_DEBUG_FLAGS			0x00c
#define NT_PARAMS64_CONSOLE_HANDLE		0x010
#define NT_PARAMS64_CONSOLE_FLAGS		0x018
#define NT_PARAMS64_STANDARD_INPUT		0x020
#define NT_PARAMS64_STANDARD_OUTPUT		0x028
#define NT_PARAMS64_STANDARD_ERROR		0x030
#define NT_PARAMS64_CURRENT_DIRECTORY		0x038
#define NT_PARAMS64_DLL_PATH			0x050
#define NT_PARAMS64_IMAGE_PATH_NAME		0x060
#define NT_PARAMS64_COMMAND_LINE		0x070
#define NT_PARAMS64_ENVIRONMENT			0x080
#define NT_PARAMS64_WINDOW_TITLE		0x0ac

/* UNICODE_STRING (x64). */
#define NT_UNICODE_STRING64_LENGTH		0x000
#define NT_UNICODE_STRING64_MAXIMUM_LENGTH	0x002
#define NT_UNICODE_STRING64_BUFFER		0x008

/*
 * Initialize the loader-owned PEB fields. Other fields are left untouched so
 * the future ntdll environment can populate them; in particular this function
 * never invents debugger, signature or secure-boot state.
 */
void nt_peb_init(void *peb, u64 image_base, void *ldr, void *params);

/* Initialize TEB self/PEB/client-id fields. */
void nt_teb_init(void *teb, void *peb, u64 process_id, u64 thread_id);

#endif /* FORSTERI_NT_PEB_H */
