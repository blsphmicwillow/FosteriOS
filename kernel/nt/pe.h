/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PE/COFF image parsing for the FosteriOS NT personality.
 *
 * The parser never allocates and never trusts the image. All offsets are
 * checked against the buffer; every RVA is resolved through the section table
 * before a byte is read. It is used first by host tests (M1) and later by the
 * kernel-side loader (M2) and the .sys loader (M6).
 */
#ifndef FORSTERI_NT_PE_H
#define FORSTERI_NT_PE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

#define PE_DOS_SIGNATURE	0x5a4d
#define PE_NT_SIGNATURE		0x00004550
#define PE_OPT_MAGIC_PE32	0x010b
#define PE_OPT_MAGIC_PE32P	0x020b

#define PE_DIR_EXPORT		0
#define PE_DIR_IMPORT		1
#define PE_DIR_BASERELOC	5
#define PE_DIR_TLS		9
#define PE_DIR_COUNT		16

#define PE_MAX_SECTIONS		96
#define PE_MAX_IMPORT_DLLS	256
#define PE_MAX_THUNKS		65536
#define PE_MAX_EXPORT_NAMES	1048576
#define PE_MAX_RELOC_BLOCKS	65536
#define PE_MAX_RELOCS		1048576
#define PE_MAX_TLS_CALLBACKS	64
#define PE_NAME_MAX		256

#define PE_SCN_MEM_EXECUTE	0x20000000u
#define PE_SCN_MEM_READ		0x40000000u

struct pe_section {
	char name[9];
	u32 virtual_address;
	u32 virtual_size;
	u32 raw_offset;
	u32 raw_size;
	u32 characteristics;
};

struct pe_image {
	const u8 *data;
	size_t size;

	u16 machine;
	u16 characteristics;
	u16 optional_magic;
	u16 subsystem;
	u16 dll_characteristics;

	u32 entry_point;
	u64 image_base;
	u32 section_alignment;
	u32 file_alignment;
	u32 size_of_image;
	u32 size_of_headers;

	u32 num_sections;
	struct pe_section sections[PE_MAX_SECTIONS];

	u32 dir_rva[PE_DIR_COUNT];
	u32 dir_size[PE_DIR_COUNT];

	u32 import_dll_count;
	u32 export_count;
	u32 export_base;
	u32 export_dir_rva;
	u32 export_dir_size;
	u32 reloc_block_count;
	u32 reloc_count;
	u32 tls_callback_count;
};

/*
 * Parse headers, sections, directories, imports, exports, base relocations and
 * TLS. Returns false with a message in err on any malformed input. img is only
 * written on success.
 */
bool pe_parse(const void *data, size_t size, struct pe_image *img,
	      char *err, size_t err_cap);

/* Map an RVA range to a file offset. Fails if the range is not file-backed. */
bool pe_rva_to_offset(const struct pe_image *img, u32 rva, u32 size, u32 *off);

/* Import descriptor iteration. iat_rva is FirstThunk, thunk_count includes 0. */
bool pe_import_dll(const struct pe_image *img, u32 index, char *name,
		   size_t name_cap, u32 *iat_rva, u32 *thunk_count);

/* Named export iteration. ordinal is the NT ordinal (Base + index). */
bool pe_export_name(const struct pe_image *img, u32 index, char *name,
		    size_t name_cap, u32 *rva, u16 *ordinal);

/* Base relocation block iteration. */
bool pe_reloc_block(const struct pe_image *img, u32 index, u32 *page_rva,
		    u32 *entry_count);

/* TLS callback iteration. Returns the callback virtual address. */
bool pe_tls_callback(const struct pe_image *img, u32 index, u64 *va);

#endif /* FORSTERI_NT_PE_H */
