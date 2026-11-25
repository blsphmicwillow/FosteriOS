// SPDX-License-Identifier: GPL-2.0
/*
 * Bounds-checked PE/COFF parsing. See pe.h for the contract.
 *
 * Rules followed throughout:
 *   - no allocation, no libc;
 *   - every file offset is checked against img->size before reading;
 *   - every RVA goes through pe_rva_to_offset(), which consults the section
 *     table and requires the range to be file-backed;
 *   - all loop bounds are explicit and all sizes are checked for overflow in
 *     64 bits before being narrowed.
 */

#include "pe.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#define PE_PTR32	4
#define PE_PTR64	8

static bool pe_fail(char *err, size_t cap, const char *msg)
{
	size_t i;

	if (err && cap) {
		for (i = 0; i + 1 < cap && msg[i]; i++)
			err[i] = msg[i];
		err[i] = 0;
	}
	return false;
}

static bool pe_read(const struct pe_image *img, size_t off, size_t len,
		    void *out)
{
	if (!img || !img->data)
		return false;
	if (off > img->size || len > img->size - off)
		return false;
	if (out)
		memcpy(out, img->data + off, len);
	return true;
}

static bool pe_u16(const struct pe_image *img, size_t off, u16 *out)
{
	if (!pe_read(img, off, 2, NULL))
		return false;
	*out = (u16)img->data[off] | (u16)((u16)img->data[off + 1] << 8);
	return true;
}

static bool pe_u32(const struct pe_image *img, size_t off, u32 *out)
{
	if (!pe_read(img, off, 4, NULL))
		return false;
	*out = (u32)img->data[off] |
	       ((u32)img->data[off + 1] << 8) |
	       ((u32)img->data[off + 2] << 16) |
	       ((u32)img->data[off + 3] << 24);
	return true;
}

static bool pe_u64(const struct pe_image *img, size_t off, u64 *out)
{
	u32 lo, hi;

	if (!pe_u32(img, off, &lo) || !pe_u32(img, off + 4, &hi))
		return false;
	*out = (u64)lo | ((u64)hi << 32);
	return true;
}

bool pe_rva_to_offset(const struct pe_image *img, u32 rva, u32 size, u32 *off)
{
	u64 end = (u64)rva + size;
	u32 i;

	if (!img || !img->data)
		return false;
	if (end > 0xffffffffULL)
		return false;

	if (rva < img->size_of_headers) {
		if (end > img->size_of_headers || end > img->size)
			return false;
		if (off)
			*off = rva;
		return true;
	}

	for (i = 0; i < img->num_sections; i++) {
		const struct pe_section *s = &img->sections[i];
		u64 delta;

		if (rva < s->virtual_address)
			continue;
		delta = (u64)rva - s->virtual_address;
		if (delta >= s->virtual_size)
			continue;
		if (delta + size > s->raw_size)
			return false;
		if ((u64)s->raw_offset + delta + size > img->size)
			return false;
		if (off)
			*off = (u32)((u64)s->raw_offset + delta);
		return true;
	}
	return false;
}

static bool pe_string(const struct pe_image *img, u32 rva, char *out,
		      size_t cap)
{
	size_t i;

	if (!out || cap < 2)
		return false;
	for (i = 0; i + 1 < cap; i++) {
		u32 off;
		u8 c;

		if ((u64)rva + i > 0xffffffffULL)
			return false;
		if (!pe_rva_to_offset(img, rva + (u32)i, 1, &off))
			return false;
		c = img->data[off];
		out[i] = (char)c;
		if (!c)
			return i > 0;
	}
	out[cap - 1] = 0;
	return false;
}

static bool pe_ptr(const struct pe_image *img, u32 rva, u64 *val)
{
	u32 off, v32;

	if (img->optional_magic == PE_OPT_MAGIC_PE32P) {
		if (!pe_rva_to_offset(img, rva, PE_PTR64, &off))
			return false;
		return pe_u64(img, off, val);
	}
	if (!pe_rva_to_offset(img, rva, PE_PTR32, &off))
		return false;
	if (!pe_u32(img, off, &v32))
		return false;
	*val = v32;
	return true;
}

struct pe_import_desc {
	u32 oft;
	u32 timestamp;
	u32 forwarder;
	u32 name;
	u32 ft;
};

/*
 * Read descriptor `index`. Returns true for the all-zero terminator as well,
 * so the caller can tell "end of list" from "could not read".
 */
static bool pe_import_at(const struct pe_image *img, u32 index,
			 struct pe_import_desc *out)
{
	u32 rva = img->dir_rva[PE_DIR_IMPORT];
	u32 size = img->dir_size[PE_DIR_IMPORT];
	u32 i;

	if (!rva || !size)
		return false;
	for (i = 0; i <= index; i++) {
		u32 off;
		struct pe_import_desc d;
		u64 desc_rva = (u64)rva + (u64)i * 20;

		if (desc_rva + 20 > 0xffffffffULL)
			return false;
		if ((u64)(i + 1) * 20 > size)
			return false;
		if (!pe_rva_to_offset(img, (u32)desc_rva, 20, &off))
			return false;
		if (!pe_u32(img, off, &d.oft) ||
		    !pe_u32(img, off + 4, &d.timestamp) ||
		    !pe_u32(img, off + 8, &d.forwarder) ||
		    !pe_u32(img, off + 12, &d.name) ||
		    !pe_u32(img, off + 16, &d.ft))
			return false;
		if (i == index) {
			*out = d;
			return true;
		}
		if (!d.oft && !d.timestamp && !d.forwarder && !d.name && !d.ft)
			return false;
	}
	return false;
}

static bool pe_thunks(const struct pe_image *img, u32 thunk_rva, u32 *count)
{
	u32 psize = img->optional_magic == PE_OPT_MAGIC_PE32P ?
		    PE_PTR64 : PE_PTR32;
	u32 i;

	if (!thunk_rva)
		return false;
	for (i = 0; i < PE_MAX_THUNKS; i++) {
		u64 val;
		u32 entry_rva;
		bool ordinal;

		if ((u64)thunk_rva + (u64)i * psize > 0xffffffffULL)
			return false;
		entry_rva = thunk_rva + i * psize;
		if (!pe_ptr(img, entry_rva, &val))
			return false;
		if (!val) {
			*count = i;
			return true;
		}
		if (psize == PE_PTR64)
			ordinal = (val & (1ULL << 63)) != 0;
		else
			ordinal = (val & (1ULL << 31)) != 0;
		if (ordinal)
			continue;
		if (val > 0xffffffffULL)
			return false;
		if (!pe_rva_to_offset(img, (u32)val, 2, NULL))
			return false;
		{
			char name[PE_NAME_MAX];

			if (!pe_string(img, (u32)val + 2, name, sizeof name))
				return false;
		}
	}
	return false;
}

static bool pe_thunk_array(const struct pe_image *img, u32 array_rva,
			   u32 count)
{
	u32 psize = img->optional_magic == PE_OPT_MAGIC_PE32P ?
		    PE_PTR64 : PE_PTR32;
	u64 bytes = (u64)count * psize;

	if (!count)
		return true;
	if (bytes > 0xffffffffULL)
		return false;
	return pe_rva_to_offset(img, array_rva, (u32)bytes, NULL);
}

static bool pe_parse_imports(struct pe_image *img, char *err, size_t cap)
{
	u32 i;

	if (!img->dir_rva[PE_DIR_IMPORT] && !img->dir_size[PE_DIR_IMPORT])
		return true;
	if (!img->dir_rva[PE_DIR_IMPORT] || !img->dir_size[PE_DIR_IMPORT])
		return pe_fail(err, cap, "inconsistent import directory");

	for (i = 0; i < PE_MAX_IMPORT_DLLS; i++) {
		struct pe_import_desc d;
		char name[PE_NAME_MAX];
		u32 thunks;

		if (!pe_import_at(img, i, &d))
			return pe_fail(err, cap, "import descriptor walk failed");
		if (!d.oft && !d.timestamp && !d.forwarder && !d.name && !d.ft)
			return true;
		if (!d.name || !d.ft)
			return pe_fail(err, cap, "incomplete import descriptor");
		if (!pe_string(img, d.name, name, sizeof name))
			return pe_fail(err, cap, "invalid import DLL name");
		if (!pe_thunks(img, d.oft ? d.oft : d.ft, &thunks))
			return pe_fail(err, cap, "invalid import thunks");
		if (!pe_thunk_array(img, d.ft, thunks))
			return pe_fail(err, cap, "IAT is not file-backed");
		img->import_dll_count++;
	}
	return pe_fail(err, cap, "too many import descriptors");
}

static bool pe_parse_exports(struct pe_image *img, char *err, size_t cap)
{
	u32 rva = img->dir_rva[PE_DIR_EXPORT];
	u32 size = img->dir_size[PE_DIR_EXPORT];
	u32 off, nfuncs, nnames, aof, aon, aoo, base;

	if (!rva && !size)
		return true;
	if (!rva || !size)
		return pe_fail(err, cap, "inconsistent export directory");
	if (size < 40)
		return pe_fail(err, cap, "truncated export directory");
	if (!pe_rva_to_offset(img, rva, 40, &off))
		return pe_fail(err, cap, "export directory is not file-backed");
	if (!pe_u32(img, off + 16, &base) ||
	    !pe_u32(img, off + 20, &nfuncs) ||
	    !pe_u32(img, off + 24, &nnames) ||
	    !pe_u32(img, off + 28, &aof) ||
	    !pe_u32(img, off + 32, &aon) ||
	    !pe_u32(img, off + 36, &aoo))
		return pe_fail(err, cap, "truncated export directory");
	if (nfuncs > PE_MAX_EXPORT_NAMES || nnames > PE_MAX_EXPORT_NAMES)
		return pe_fail(err, cap, "unreasonable export counts");
	if (nnames > nfuncs)
		return pe_fail(err, cap, "more export names than functions");
	if (!pe_rva_to_offset(img, aof, nfuncs * 4, NULL) ||
	    !pe_rva_to_offset(img, aon, nnames * 4, NULL) ||
	    !pe_rva_to_offset(img, aoo, nnames * 2, NULL))
		return pe_fail(err, cap, "export arrays are not file-backed");

	img->export_count = nnames;
	img->export_base = base;
	img->export_dir_rva = rva;
	img->export_dir_size = size;
	return true;
}

static bool pe_parse_relocs(struct pe_image *img, char *err, size_t cap)
{
	u32 rva = img->dir_rva[PE_DIR_BASERELOC];
	u32 size = img->dir_size[PE_DIR_BASERELOC];
	u64 pos = 0;

	if (!rva && !size)
		return true;
	if (!rva || !size)
		return pe_fail(err, cap, "inconsistent relocation directory");
	if (size < 8)
		return pe_fail(err, cap, "truncated relocation directory");

	while (pos < size) {
		u32 off, page, block_size, entries;
		u64 block_pos = (u64)rva + pos;

		if (size - pos < 8)
			return pe_fail(err, cap, "truncated relocation block");
		if (block_pos + 8 > 0xffffffffULL)
			return pe_fail(err, cap, "relocation block RVA overflow");
		if (!pe_rva_to_offset(img, (u32)block_pos, 8, &off))
			return pe_fail(err, cap, "relocation block is not mapped");
		if (!pe_u32(img, off, &page) ||
		    !pe_u32(img, off + 4, &block_size))
			return pe_fail(err, cap, "truncated relocation block");
		if (block_size < 8 || ((block_size - 8) & 1))
			return pe_fail(err, cap, "invalid relocation block size");
		if ((u64)block_size > size - pos)
			return pe_fail(err, cap, "relocation block overruns directory");
		if (block_pos + block_size > 0xffffffffULL)
			return pe_fail(err, cap, "relocation block RVA overflow");
		if (!pe_rva_to_offset(img, (u32)block_pos, block_size, NULL))
			return pe_fail(err, cap, "relocation block is not mapped");
		(void)page;
		entries = (block_size - 8) / 2;
		if (entries > PE_MAX_RELOCS - img->reloc_count)
			return pe_fail(err, cap, "too many relocations");
		img->reloc_count += entries;
		img->reloc_block_count++;
		if (img->reloc_block_count > PE_MAX_RELOC_BLOCKS)
			return pe_fail(err, cap, "too many relocation blocks");
		pos += block_size;
	}
	return true;
}

static bool pe_parse_tls(struct pe_image *img, char *err, size_t cap)
{
	u32 rva = img->dir_rva[PE_DIR_TLS];
	u32 size = img->dir_size[PE_DIR_TLS];
	u32 off, need, psize, i, cb_rva;
	u64 cb_va;

	if (!rva && !size)
		return true;
	if (!rva || !size)
		return pe_fail(err, cap, "inconsistent TLS directory");
	psize = img->optional_magic == PE_OPT_MAGIC_PE32P ? PE_PTR64 : PE_PTR32;
	need = img->optional_magic == PE_OPT_MAGIC_PE32P ? 40 : 24;
	if (size < need)
		return pe_fail(err, cap, "truncated TLS directory");
	if (!pe_rva_to_offset(img, rva, need, &off))
		return pe_fail(err, cap, "TLS directory is not mapped");
	if (img->optional_magic == PE_OPT_MAGIC_PE32P) {
		if (!pe_u64(img, off + 24, &cb_va))
			return pe_fail(err, cap, "truncated TLS directory");
	} else {
		u32 v;

		if (!pe_u32(img, off + 12, &v))
			return pe_fail(err, cap, "truncated TLS directory");
		cb_va = v;
	}
	if (!cb_va)
		return true;
	if (cb_va < img->image_base)
		return pe_fail(err, cap, "TLS callbacks below image base");
	cb_va -= img->image_base;
	if (cb_va > 0xffffffffULL)
		return pe_fail(err, cap, "TLS callbacks RVA overflow");
	cb_rva = (u32)cb_va;

	for (i = 0; i < PE_MAX_TLS_CALLBACKS; i++) {
		u64 va;

		if ((u64)cb_rva + (u64)i * psize > 0xffffffffULL)
			return pe_fail(err, cap, "TLS callback array overflow");
		if (!pe_ptr(img, cb_rva + i * psize, &va))
			return pe_fail(err, cap, "TLS callback array is not mapped");
		if (!va)
			return true;
		if (va < img->image_base)
			return pe_fail(err, cap, "TLS callback below image base");
		if (va - img->image_base >= img->size_of_image)
			return pe_fail(err, cap, "TLS callback outside image");
		img->tls_callback_count++;
	}
	return pe_fail(err, cap, "too many TLS callbacks");
}

bool pe_parse(const void *data, size_t size, struct pe_image *img,
	      char *err, size_t err_cap)
{
	struct pe_image t;
	u32 lfanew, sig, size_opt, opt, sec_off, ndirs, avail;
	u16 dos, machine, magic, num_sections;
	u32 entry, image_base32, size_image, size_headers, align_sec, align_file;
	u32 nrva, dirlen, dirs, nrva_off;

	if (!img)
		return pe_fail(err, err_cap, "no output image");
	memset(&t, 0, sizeof t);
	t.data = data;
	t.size = size;

	if (!data)
		return pe_fail(err, err_cap, "null image");
	if (size < 0x40)
		return pe_fail(err, err_cap, "truncated DOS header");
	if (!pe_u16(&t, 0, &dos) || dos != PE_DOS_SIGNATURE)
		return pe_fail(err, err_cap, "missing MZ signature");
	if (!pe_u32(&t, 0x3c, &lfanew))
		return pe_fail(err, err_cap, "truncated DOS header");
	if ((u64)lfanew + 4 > size)
		return pe_fail(err, err_cap, "e_lfanew outside file");
	if (!pe_u32(&t, lfanew, &sig) || sig != PE_NT_SIGNATURE)
		return pe_fail(err, err_cap, "missing PE signature");
	if ((u64)lfanew + 24 > size)
		return pe_fail(err, err_cap, "truncated COFF header");
	if (!pe_u16(&t, lfanew + 4, &machine) ||
	    !pe_u16(&t, lfanew + 6, &num_sections) ||
	    !pe_u16(&t, lfanew + 20, &dos) ||
	    !pe_u16(&t, lfanew + 22, &t.characteristics))
		return pe_fail(err, err_cap, "truncated COFF header");
	size_opt = dos;
	if (size_opt < 96)
		return pe_fail(err, err_cap, "optional header too small");
	if (!num_sections || num_sections > PE_MAX_SECTIONS)
		return pe_fail(err, err_cap, "invalid section count");
	opt = lfanew + 24;
	if ((u64)opt + size_opt > size)
		return pe_fail(err, err_cap, "optional header outside file");
	if (!pe_u16(&t, opt, &magic))
		return pe_fail(err, err_cap, "truncated optional header");
	if (magic != PE_OPT_MAGIC_PE32 && magic != PE_OPT_MAGIC_PE32P)
		return pe_fail(err, err_cap, "unsupported optional header magic");

	t.machine = machine;
	t.optional_magic = magic;
	if (!pe_u32(&t, opt + 16, &entry) ||
	    !pe_u32(&t, opt + 32, &align_sec) ||
	    !pe_u32(&t, opt + 36, &align_file) ||
	    !pe_u32(&t, opt + 56, &size_image) ||
	    !pe_u32(&t, opt + 60, &size_headers) ||
	    !pe_u16(&t, opt + 68, &t.subsystem) ||
	    !pe_u16(&t, opt + 70, &t.dll_characteristics))
		return pe_fail(err, err_cap, "truncated optional header");
	nrva_off = magic == PE_OPT_MAGIC_PE32P ? 108 : 92;
	if (!pe_u32(&t, opt + nrva_off, &nrva))
		return pe_fail(err, err_cap, "truncated optional header");

	if (magic == PE_OPT_MAGIC_PE32P) {
		u64 base64;

		if (!pe_u64(&t, opt + 24, &base64))
			return pe_fail(err, err_cap, "truncated optional header");
		t.image_base = base64;
	} else {
		if (!pe_u32(&t, opt + 28, &image_base32))
			return pe_fail(err, err_cap, "truncated optional header");
		t.image_base = image_base32;
	}

	if (!align_sec || (align_sec & (align_sec - 1)))
		return pe_fail(err, err_cap, "invalid section alignment");
	if (!align_file || (align_file & (align_file - 1)))
		return pe_fail(err, err_cap, "invalid file alignment");
	if (align_sec < align_file)
		return pe_fail(err, err_cap, "section alignment below file alignment");
	if (!size_image || !size_headers)
		return pe_fail(err, err_cap, "empty image or header size");
	if (size_headers > size)
		return pe_fail(err, err_cap, "headers outside file");
	if (entry && entry >= size_image)
		return pe_fail(err, err_cap, "entry point outside image");

	t.entry_point = entry;
	t.section_alignment = align_sec;
	t.file_alignment = align_file;
	t.size_of_image = size_image;
	t.size_of_headers = size_headers;

	dirlen = magic == PE_OPT_MAGIC_PE32P ? 112 : 96;
	if (size_opt < dirlen)
		return pe_fail(err, err_cap, "optional header too small for dirs");
	avail = (size_opt - dirlen) / 8;
	if (nrva > PE_DIR_COUNT)
		return pe_fail(err, err_cap, "too many data directories");
	ndirs = nrva;
	if (ndirs > avail)
		return pe_fail(err, err_cap, "data directories outside optional header");
	for (dirs = 0; dirs < ndirs; dirs++) {
		if (!pe_u32(&t, opt + dirlen + dirs * 8, &t.dir_rva[dirs]) ||
		    !pe_u32(&t, opt + dirlen + dirs * 8 + 4, &t.dir_size[dirs]))
			return pe_fail(err, err_cap, "truncated data directory");
	}

	sec_off = opt + size_opt;
	if ((u64)sec_off + (u64)num_sections * 40 > size)
		return pe_fail(err, err_cap, "section table outside file");
	t.num_sections = num_sections;
	for (dirs = 0; dirs < num_sections; dirs++) {
		struct pe_section *s = &t.sections[dirs];
		size_t so = (size_t)sec_off + (size_t)dirs * 40;
		u64 extent;

		if (!pe_read(&t, so, 8, s->name))
			return pe_fail(err, err_cap, "truncated section table");
		s->name[8] = 0;
		if (!pe_u32(&t, so + 8, &s->virtual_size) ||
		    !pe_u32(&t, so + 12, &s->virtual_address) ||
		    !pe_u32(&t, so + 16, &s->raw_size) ||
		    !pe_u32(&t, so + 20, &s->raw_offset) ||
		    !pe_u32(&t, so + 36, &s->characteristics))
			return pe_fail(err, err_cap, "truncated section table");
		if (s->raw_size &&
		    (u64)s->raw_offset + s->raw_size > size)
			return pe_fail(err, err_cap, "section data outside file");
		extent = s->virtual_size ? s->virtual_size : s->raw_size;
		if ((u64)s->virtual_address + extent > 0xffffffffULL)
			return pe_fail(err, err_cap, "section virtual range overflow");
		if ((u64)s->virtual_address + extent > size_image)
			return pe_fail(err, err_cap, "section outside image");
	}

	t.import_dll_count = 0;
	if (!pe_parse_imports(&t, err, err_cap))
		return false;
	if (!pe_parse_exports(&t, err, err_cap))
		return false;
	if (!pe_parse_relocs(&t, err, err_cap))
		return false;
	if (!pe_parse_tls(&t, err, err_cap))
		return false;

	if (entry && !pe_rva_to_offset(&t, entry, 1, NULL))
		return pe_fail(err, err_cap, "entry point is not file-backed");

	*img = t;
	if (err && err_cap)
		err[0] = 0;
	return true;
}

bool pe_import_dll(const struct pe_image *img, u32 index, char *name,
		   size_t name_cap, u32 *iat_rva, u32 *thunk_count)
{
	struct pe_import_desc d;
	u32 thunks;

	if (!img || index >= img->import_dll_count)
		return false;
	if (!pe_import_at(img, index, &d))
		return false;
	if (!d.name || !d.ft)
		return false;
	if (!pe_string(img, d.name, name, name_cap))
		return false;
	if (!pe_thunks(img, d.oft ? d.oft : d.ft, &thunks))
		return false;
	if (iat_rva)
		*iat_rva = d.ft;
	if (thunk_count)
		*thunk_count = thunks;
	return true;
}

bool pe_export_name(const struct pe_image *img, u32 index, char *name,
		    size_t name_cap, u32 *rva, u16 *ordinal)
{
	u32 off, aof, aon, aoo, nfuncs;
	u32 name_rva, func_rva;
	u16 ord_index;
	u64 ord;

	if (!img || index >= img->export_count)
		return false;
	if (!pe_rva_to_offset(img, img->export_dir_rva, 40, &off))
		return false;
	if (!pe_u32(img, off + 20, &nfuncs) ||
	    !pe_u32(img, off + 28, &aof) ||
	    !pe_u32(img, off + 32, &aon) ||
	    !pe_u32(img, off + 36, &aoo))
		return false;
	if (index >= nfuncs)
		return false;
	if (!pe_rva_to_offset(img, aon + index * 4, 4, &off) ||
	    !pe_u32(img, off, &name_rva))
		return false;
	if (!pe_rva_to_offset(img, aoo + index * 2, 2, &off) ||
	    !pe_u16(img, off, &ord_index))
		return false;
	if (ord_index >= nfuncs)
		return false;
	if (!pe_rva_to_offset(img, aof + (u32)ord_index * 4, 4, &off) ||
	    !pe_u32(img, off, &func_rva))
		return false;
	if (!pe_string(img, name_rva, name, name_cap))
		return false;
	ord = (u64)img->export_base + ord_index;
	if (ord > 0xffff)
		return false;
	if (rva)
		*rva = func_rva;
	if (ordinal)
		*ordinal = (u16)ord;
	return true;
}

bool pe_reloc_block(const struct pe_image *img, u32 index, u32 *page_rva,
		    u32 *entry_count)
{
	u32 rva, size, pos = 0, seen = 0;

	if (!img || index >= img->reloc_block_count)
		return false;
	rva = img->dir_rva[PE_DIR_BASERELOC];
	size = img->dir_size[PE_DIR_BASERELOC];
	while (pos + 8 <= size) {
		u32 off, page, block_size;

		if (!pe_rva_to_offset(img, rva + pos, 8, &off))
			return false;
		if (!pe_u32(img, off, &page) || !pe_u32(img, off + 4, &block_size))
			return false;
		if (block_size < 8 || block_size > size - pos)
			return false;
		if (seen == index) {
			if (page_rva)
				*page_rva = page;
			if (entry_count)
				*entry_count = (block_size - 8) / 2;
			return true;
		}
		seen++;
		pos += block_size;
	}
	return false;
}

bool pe_tls_callback(const struct pe_image *img, u32 index, u64 *va)
{
	u32 rva, size, need, psize, i, cb_rva;
	u32 off;
	u64 cb_va;

	if (!img || index >= img->tls_callback_count)
		return false;
	rva = img->dir_rva[PE_DIR_TLS];
	size = img->dir_size[PE_DIR_TLS];
	psize = img->optional_magic == PE_OPT_MAGIC_PE32P ? PE_PTR64 : PE_PTR32;
	need = img->optional_magic == PE_OPT_MAGIC_PE32P ? 40 : 24;
	if (!rva || size < need)
		return false;
	if (!pe_rva_to_offset(img, rva, need, &off))
		return false;
	if (img->optional_magic == PE_OPT_MAGIC_PE32P) {
		if (!pe_u64(img, off + 24, &cb_va))
			return false;
	} else {
		u32 v;

		if (!pe_u32(img, off + 12, &v))
			return false;
		cb_va = v;
	}
	if (!cb_va || cb_va < img->image_base)
		return false;
	cb_rva = (u32)(cb_va - img->image_base);
	for (i = 0; i <= index; i++) {
		if (!pe_ptr(img, cb_rva + i * psize, &cb_va))
			return false;
		if (!cb_va)
			return false;
	}
	if (va)
		*va = cb_va;
	return true;
}
