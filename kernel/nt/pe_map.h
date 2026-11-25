/* SPDX-License-Identifier: GPL-2.0 */
/*
 * M2 host-testable PE mapping decisions.
 *
 * This is intentionally separate from the M1 parser and from the Linux mm
 * code: it decides which pages an image needs, rejects W+X sections and
 * overlapping regions, copies a file image into a caller-owned buffer, and
 * applies base relocations. The kernel loader can use the same decisions when
 * it allocates the real address space; no user execution is claimed here.
 */
#ifndef FORSTERI_NT_PE_MAP_H
#define FORSTERI_NT_PE_MAP_H

#include "pe.h"

#define PE_MAP_READ		0x1u
#define PE_MAP_WRITE		0x2u
#define PE_MAP_EXEC		0x4u

#define PE_MAP_MAX_REGIONS	(PE_MAX_SECTIONS + 1)

struct pe_map_region {
	u32 rva;		/* page-aligned image RVA */
	u32 size;		/* page-rounded mapped size */
	u32 file_offset;
	u32 file_size;
	u32 prot;		/* PE_MAP_* flags */
	u16 section;		/* section index, or 0xffff for headers */
};

struct pe_map_plan {
	u64 preferred_base;
	u64 actual_base;
	u64 delta;
	u32 image_size;		/* page-rounded SizeOfImage */
	u32 region_count;
	struct pe_map_region regions[PE_MAP_MAX_REGIONS];
};

/*
 * Build a page plan. actual_base must be page aligned. A nonzero delta from
 * the preferred base requires base relocations; an image whose relocation
 * directory is empty is rejected rather than silently loaded at the wrong
 * address.
 */
bool pe_map_plan_build(const struct pe_image *img, u64 actual_base,
		       struct pe_map_plan *plan, char *err, size_t err_cap);

/* Copy headers and section data into a caller-owned image_size buffer. */
bool pe_map_copy(const struct pe_image *img, const struct pe_map_plan *plan,
		 void *dest, size_t dest_size, char *err, size_t err_cap);

/* Apply IMAGE_REL_BASED_* entries for plan->delta to a mapped copy. */
bool pe_map_apply_relocs(const struct pe_image *img,
			 const struct pe_map_plan *plan, void *image,
			 size_t image_size, char *err, size_t err_cap);

#endif /* FORSTERI_NT_PE_MAP_H */
