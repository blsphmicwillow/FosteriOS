// SPDX-License-Identifier: GPL-2.0
/*
 * PEB/TEB initialization for the x64 NT personality.
 *
 * Only pointers and IDs owned by the loader are written. This code does not
 * set BeingDebugged, signature state, secure-boot state or any other value that
 * could make a process believe it is running under a different platform than
 * it is.
 */

#include "nt_peb.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

static void put64(void *base, u32 off, u64 value)
{
	memcpy((u8 *)base + off, &value, sizeof value);
}

static void put32(void *base, u32 off, u32 value)
{
	memcpy((u8 *)base + off, &value, sizeof value);
}

static u64 ptr_value(const void *p)
{
	return (u64)(unsigned long)p;
}

void nt_peb_init(void *peb, u64 image_base, void *ldr, void *params)
{
	if (!peb)
		return;
	put64(peb, NT_PEB64_IMAGE_BASE_ADDRESS, image_base);
	put64(peb, NT_PEB64_LDR, ptr_value(ldr));
	put64(peb, NT_PEB64_PROCESS_PARAMETERS, ptr_value(params));
}

void nt_teb_init(void *teb, void *peb, u64 process_id, u64 thread_id)
{
	if (!teb)
		return;
	put64(teb, NT_TEB64_SELF, ptr_value(teb));
	put64(teb, NT_TEB64_CLIENT_ID_PROCESS, process_id);
	put64(teb, NT_TEB64_CLIENT_ID_THREAD, thread_id);
	put64(teb, NT_TEB64_PEB, ptr_value(peb));
	put32(teb, NT_TEB64_LAST_ERROR_VALUE, 0);
	put32(teb, NT_TEB64_COUNT_OF_OWNED_CRITICAL_SECTIONS, 0);
}
