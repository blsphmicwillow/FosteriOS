// SPDX-License-Identifier: GPL-2.0
/* Host checks for the x64 PEB/TEB offsets and loader-owned fields. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nt_peb.h"

static int failures;

#define CHECK(cond)                                                          \
	do {                                                                 \
		if (!(cond)) {                                               \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, \
				#cond);                                      \
			failures++;                                          \
		}                                                            \
	} while (0)

static uint64_t rd64(const void *p, unsigned off)
{
	uint64_t v;

	memcpy(&v, (const uint8_t *)p + off, sizeof v);
	return v;
}

static uint32_t rd32(const void *p, unsigned off)
{
	uint32_t v;

	memcpy(&v, (const uint8_t *)p + off, sizeof v);
	return v;
}

int main(void)
{
	uint8_t peb[0x200];
	uint8_t teb[0x200];
	uint8_t ldr[0x100];
	uint8_t params[0x100];

	memset(peb, 0, sizeof peb);
	memset(teb, 0, sizeof teb);
	memset(ldr, 0, sizeof ldr);
	memset(params, 0, sizeof params);
	peb[NT_PEB64_BEING_DEBUGGED] = 0xaa;

	CHECK(NT_PEB64_IMAGE_BASE_ADDRESS == 0x010);
	CHECK(NT_PEB64_LDR == 0x018);
	CHECK(NT_PEB64_PROCESS_PARAMETERS == 0x020);
	CHECK(NT_TEB64_SELF == 0x030);
	CHECK(NT_TEB64_CLIENT_ID_PROCESS == 0x040);
	CHECK(NT_TEB64_CLIENT_ID_THREAD == 0x048);
	CHECK(NT_TEB64_PEB == 0x060);
	CHECK(NT_PARAMS64_DLL_PATH == 0x050);
	CHECK(NT_PARAMS64_IMAGE_PATH_NAME == 0x060);
	CHECK(NT_PARAMS64_COMMAND_LINE == 0x070);
	CHECK(NT_PARAMS64_ENVIRONMENT == 0x080);

	nt_peb_init(peb, 0x140000000ULL, ldr, params);
	CHECK(rd64(peb, NT_PEB64_IMAGE_BASE_ADDRESS) == 0x140000000ULL);
	CHECK(rd64(peb, NT_PEB64_LDR) == (uint64_t)(uintptr_t)ldr);
	CHECK(rd64(peb, NT_PEB64_PROCESS_PARAMETERS) ==
	      (uint64_t)(uintptr_t)params);
	/* BeingDebugged is owned by the debugger hand-off, not this loader. */
	CHECK(peb[NT_PEB64_BEING_DEBUGGED] == 0xaa);

	nt_teb_init(teb, peb, 0x1234, 0x5678);
	CHECK(rd64(teb, NT_TEB64_SELF) == (uint64_t)(uintptr_t)teb);
	CHECK(rd64(teb, NT_TEB64_PEB) == (uint64_t)(uintptr_t)peb);
	CHECK(rd64(teb, NT_TEB64_CLIENT_ID_PROCESS) == 0x1234);
	CHECK(rd64(teb, NT_TEB64_CLIENT_ID_THREAD) == 0x5678);
	CHECK(rd32(teb, NT_TEB64_LAST_ERROR_VALUE) == 0);
	CHECK(rd32(teb, NT_TEB64_COUNT_OF_OWNED_CRITICAL_SECTIONS) == 0);

	if (failures) {
		fprintf(stderr, "%d PEB/TEB test(s) failed\n", failures);
		return 1;
	}
	puts("PEB/TEB layout tests passed");
	return 0;
}
