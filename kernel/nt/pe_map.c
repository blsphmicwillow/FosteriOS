// SPDX-License-Identifier: GPL-2.0
/*
 * PE section mapping and base relocations for M2.
 *
 * The code is deliberately deterministic and allocation-free. The future
 * binfmt loader supplies the address-space mapping; this file supplies the
 * decisions and the contents of the mapped image. Keeping this layer separate
 * lets the host sanitizer tests exercise overlap, W^X and relocation failures
 * without a kernel or a Windows machine.
 */

#include "pe_map.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#define PE_PAGE_SIZE		0x1000u
#define PE_SCN_MEM_WRITE	0x80000000u
#define PE_IMAGE_FILE_DLL	0x2000u
#define PE_IMAGE_FILE_RELOCS_STRIPPED 0x0001u

#define PE_REL_ABSOLUTE	0
#define PE_REL_HIGH	1
#define PE_REL_LOW	2
#define PE_REL_HIGHLOW	3
#define PE_REL_DIR64	10

enum {
	PE_MAP_HEADER_REGION = 0xffff
};

static bool map_fail(char *err, size_t cap, const char *msg)
{
	size_t i;

	if (err && cap) {
		for (i = 0; i + 1 < cap && msg[i]; i++)
			err[i] = msg[i];
		err[i] = 0;
	}
	return false;
}

static bool align_up(u32 value, u32 alignment, u32 *out)
{
	u64 rounded = ((u64)value + alignment - 1) & ~((u64)alignment - 1);

	if (rounded > 0xffffffffULL)
		return false;
	*out = (u32)rounded;
	return true;
}

static bool ranges_overlap(u64 a, u64 asz, u64 b, u64 bsz)
{
	return a < b + bsz && b < a + asz;
}

static bool add_region(struct pe_map_plan *plan, u32 rva, u32 size,
		       u32 file_offset, u32 file_size, u32 prot, u16 section,
		       char *err, size_t cap)
{
	u32 i;

	if (plan->region_count >= PE_MAP_MAX_REGIONS)
		return map_fail(err, cap, "too many mapped regions");
	for (i = 0; i < plan->region_count; i++) {
		if (ranges_overlap(rva, size, plan->regions[i].rva,
				   plan->regions[i].size))
			return map_fail(err, cap, "overlapping PE regions");
	}
	plan->regions[plan->region_count].rva = rva;
	plan->regions[plan->region_count].size = size;
	plan->regions[plan->region_count].file_offset = file_offset;
	plan->regions[plan->region_count].file_size = file_size;
	plan->regions[plan->region_count].prot = prot;
	plan->regions[plan->region_count].section = section;
	plan->region_count++;
	return true;
}

bool pe_map_plan_build(const struct pe_image *img, u64 actual_base,
		       struct pe_map_plan *plan, char *err, size_t err_cap)
{
	u32 hdr_size, image_size, i;

	if (!img || !plan)
		return map_fail(err, err_cap, "null PE image or plan");
	if (actual_base & (PE_PAGE_SIZE - 1))
		return map_fail(err, err_cap, "actual image base is not page aligned");
	if (!img->size_of_image || !img->size_of_headers)
		return map_fail(err, err_cap, "image has no size");
	if (img->image_base & (PE_PAGE_SIZE - 1))
		return map_fail(err, err_cap, "preferred image base is not page aligned");
	if (actual_base < img->image_base)
		return map_fail(err, err_cap,
				"rebasing below the preferred base is not supported yet");

	memset(plan, 0, sizeof *plan);
	plan->preferred_base = img->image_base;
	plan->actual_base = actual_base;
	plan->delta = actual_base - img->image_base;

	if (!align_up(img->size_of_image, PE_PAGE_SIZE, &image_size))
		return map_fail(err, err_cap, "image size overflows");
	if (!align_up(img->size_of_headers, PE_PAGE_SIZE, &hdr_size))
		return map_fail(err, err_cap, "header size overflows");
	if (hdr_size > image_size)
		return map_fail(err, err_cap, "PE headers exceed SizeOfImage");
	if (img->size_of_headers > img->size)
		return map_fail(err, err_cap, "PE headers outside file");
	plan->image_size = image_size;

	if (!add_region(plan, 0, hdr_size, 0,
			img->size_of_headers < img->size ?
				img->size_of_headers : (u32)img->size,
			PE_MAP_READ, PE_MAP_HEADER_REGION, err, err_cap))
		return false;

	for (i = 0; i < img->num_sections; i++) {
		const struct pe_section *s = &img->sections[i];
		u32 span = s->virtual_size > s->raw_size ?
			   s->virtual_size : s->raw_size;
		u32 mapped;
		u32 prot;
		u64 end;

		if (!span)
			continue;
		if (s->virtual_address & (PE_PAGE_SIZE - 1))
			return map_fail(err, err_cap,
					"section RVA is not page aligned");
		if (!align_up(span, PE_PAGE_SIZE, &mapped))
			return map_fail(err, err_cap, "section size overflows");
		end = (u64)s->virtual_address + mapped;
		if (end > image_size)
			return map_fail(err, err_cap, "section exceeds mapped image");
		if (s->raw_size &&
		    (u64)s->raw_offset + s->raw_size > img->size)
			return map_fail(err, err_cap, "section data outside file");

		if ((s->characteristics & PE_SCN_MEM_EXECUTE) &&
		    (s->characteristics & PE_SCN_MEM_WRITE))
			return map_fail(err, err_cap,
					"section is writable and executable");
		prot = PE_MAP_READ;
		if (s->characteristics & PE_SCN_MEM_EXECUTE)
			prot |= PE_MAP_EXEC;
		if (s->characteristics & PE_SCN_MEM_WRITE)
			prot |= PE_MAP_WRITE;
		if (!add_region(plan, s->virtual_address, mapped, s->raw_offset,
				s->raw_size, prot, (u16)i, err, err_cap))
			return false;
	}

	if (img->entry_point) {
		bool in_exec = false;

		for (i = 0; i < plan->region_count; i++) {
			const struct pe_map_region *r = &plan->regions[i];

			if ((r->prot & PE_MAP_EXEC) &&
			    img->entry_point >= r->rva &&
			    (u64)img->entry_point < (u64)r->rva + r->size) {
				in_exec = true;
				break;
			}
		}
		if (!in_exec)
			return map_fail(err, err_cap,
					"entry point is not in an executable section");
	} else if (!(img->characteristics & PE_IMAGE_FILE_DLL)) {
		return map_fail(err, err_cap, "executable image has no entry point");
	}

	if (plan->delta) {
		if (img->characteristics & PE_IMAGE_FILE_RELOCS_STRIPPED)
			return map_fail(err, err_cap,
					"image has relocations stripped but needs rebasing");
		if (!img->reloc_count || !img->reloc_block_count)
			return map_fail(err, err_cap,
					"image needs rebasing but has no relocations");
	}

	if (err && err_cap)
		err[0] = 0;
	return true;
}

bool pe_map_copy(const struct pe_image *img, const struct pe_map_plan *plan,
		 void *dest, size_t dest_size, char *err, size_t err_cap)
{
	u32 i;

	if (!img || !plan || !dest)
		return map_fail(err, err_cap, "null image, plan or destination");
	if (dest_size < plan->image_size)
		return map_fail(err, err_cap, "destination is smaller than the image");
	memset(dest, 0, plan->image_size);

	for (i = 0; i < plan->region_count; i++) {
		const struct pe_map_region *r = &plan->regions[i];

		if (!r->file_size)
			continue;
		if ((u64)r->file_offset + r->file_size > img->size)
			return map_fail(err, err_cap, "region file range outside image");
		if ((u64)r->rva + r->file_size > plan->image_size)
			return map_fail(err, err_cap, "region copy exceeds image");
		memcpy((u8 *)dest + r->rva, img->data + r->file_offset,
		       r->file_size);
	}
	return true;
}

static u16 get_u16(const void *p)
{
	const u8 *b = p;

	return (u16)b[0] | ((u16)b[1] << 8);
}

static u32 get_u32(const void *p)
{
	const u8 *b = p;

	return (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) |
	       ((u32)b[3] << 24);
}

static u64 get_u64(const void *p)
{
	return (u64)get_u32(p) | ((u64)get_u32((const u8 *)p + 4) << 32);
}

static void put_u16(void *p, u16 v)
{
	u8 *b = p;

	b[0] = (u8)v;
	b[1] = (u8)(v >> 8);
}

static void put_u32(void *p, u32 v)
{
	u8 *b = p;

	b[0] = (u8)v;
	b[1] = (u8)(v >> 8);
	b[2] = (u8)(v >> 16);
	b[3] = (u8)(v >> 24);
}

static void put_u64(void *p, u64 v)
{
	put_u32(p, (u32)v);
	put_u32((u8 *)p + 4, (u32)(v >> 32));
}

bool pe_map_apply_relocs(const struct pe_image *img,
			 const struct pe_map_plan *plan, void *image,
			 size_t image_size, char *err, size_t err_cap)
{
	u32 block;

	if (!img || !plan || !image)
		return map_fail(err, err_cap, "null image, plan or mapping");
	if (image_size < plan->image_size)
		return map_fail(err, err_cap, "mapping is smaller than the image");
	if (!plan->delta)
		return true;

	for (block = 0; block < img->reloc_block_count; block++) {
		u32 count, entry;

		if (!pe_reloc_block(img, block, NULL, &count))
			return map_fail(err, err_cap, "cannot read relocation block");
		for (entry = 0; entry < count; entry++) {
			u32 rva;
			u16 type;

			if (!pe_reloc_entry(img, block, entry, &rva, &type))
				return map_fail(err, err_cap,
						"cannot read relocation entry");
			if (type == PE_REL_ABSOLUTE)
				continue;
			if (rva >= plan->image_size)
				return map_fail(err, err_cap,
						"relocation target outside image");

			switch (type) {
			case PE_REL_HIGH: {
				u32 delta_hi = (u32)(plan->delta >> 16);
				u16 old;

				if ((u64)rva + 2 > plan->image_size)
					return map_fail(err, err_cap,
							"HIGH relocation overruns image");
				old = get_u16((u8 *)image + rva);
				put_u16((u8 *)image + rva, (u16)(old + delta_hi));
				break;
			}
			case PE_REL_LOW: {
				u16 delta_lo = (u16)plan->delta;
				u16 old;

				if ((u64)rva + 2 > plan->image_size)
					return map_fail(err, err_cap,
							"LOW relocation overruns image");
				old = get_u16((u8 *)image + rva);
				put_u16((u8 *)image + rva, (u16)(old + delta_lo));
				break;
			}
			case PE_REL_HIGHLOW: {
				u32 old, delta32;

				if (plan->delta > 0xffffffffULL)
					return map_fail(err, err_cap,
							"32-bit relocation delta does not fit");
				if ((u64)rva + 4 > plan->image_size)
					return map_fail(err, err_cap,
							"HIGHLOW relocation overruns image");
				delta32 = (u32)plan->delta;
				old = get_u32((u8 *)image + rva);
				if ((u64)old + delta32 > 0xffffffffULL)
					return map_fail(err, err_cap,
							"32-bit relocation overflows");
				put_u32((u8 *)image + rva, old + delta32);
				break;
			}
			case PE_REL_DIR64: {
				u64 old;

				if ((u64)rva + 8 > plan->image_size)
					return map_fail(err, err_cap,
							"DIR64 relocation overruns image");
				old = get_u64((u8 *)image + rva);
				if (old > ~(u64)0 - plan->delta)
					return map_fail(err, err_cap,
							"DIR64 relocation overflows");
				put_u64((u8 *)image + rva, old + plan->delta);
				break;
			}
			default:
				return map_fail(err, err_cap,
						"unsupported base relocation type");
			}
		}
	}
	return true;
}
