// SPDX-License-Identifier: GPL-2.0
/*
 * Host tests for the M1 PE parser. Run through scripts/test-pe.sh, which builds
 * this with ASan/UBSan. Fixtures are mingw-built and committed under
 * tests/pe/fixtures, so the test needs no Windows toolchain at run time.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe.h"

static int failures;

#define CHECK(cond)                                                          \
	do {                                                                 \
		if (!(cond)) {                                               \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, \
				#cond);                                      \
			failures++;                                          \
		}                                                            \
	} while (0)

static uint16_t rd16(const uint8_t *p, size_t off)
{
	return (uint16_t)(p[off] | ((uint16_t)p[off + 1] << 8));
}

static uint32_t rd32(const uint8_t *p, size_t off)
{
	return (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8) |
	       ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24);
}

static void wr16(uint8_t *p, size_t off, uint16_t v)
{
	p[off] = (uint8_t)v;
	p[off + 1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t *p, size_t off, uint32_t v)
{
	p[off] = (uint8_t)v;
	p[off + 1] = (uint8_t)(v >> 8);
	p[off + 2] = (uint8_t)(v >> 16);
	p[off + 3] = (uint8_t)(v >> 24);
}

static int load_file(const char *path, uint8_t **out, size_t *len)
{
	FILE *f;
	long n;
	uint8_t *buf;

	f = fopen(path, "rb");
	if (!f) {
		perror(path);
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return -1;
	}
	n = ftell(f);
	if (n < 0) {
		fclose(f);
		return -1;
	}
	rewind(f);
	buf = malloc((size_t)n + 1);
	if (!buf) {
		fclose(f);
		return -1;
	}
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf);
		fclose(f);
		return -1;
	}
	fclose(f);
	*out = buf;
	*len = (size_t)n;
	return 0;
}

static uint8_t *copy_of(const uint8_t *src, size_t len)
{
	uint8_t *p = malloc(len ? len : 1);

	if (p)
		memcpy(p, src, len);
	return p;
}

static void expect_reject(const char *label, const uint8_t *buf, size_t len)
{
	struct pe_image img;
	char err[160];

	if (pe_parse(buf, len, &img, err, sizeof err)) {
		fprintf(stderr, "FAIL malformed accepted: %s\n", label);
		failures++;
	}
}

static void test_valid_exe(const char *dir)
{
	char path[512];
	uint8_t *buf = NULL;
	size_t len = 0, i;
	struct pe_image img;
	char err[160];
	int found_text = 0, found_idata = 0, found_dll = 0;
	uint32_t reloc_sum = 0;
	uint32_t text_va = 0, text_size = 0, max_raw_end = 0;

	snprintf(path, sizeof path, "%s/hello.exe", dir);
	if (load_file(path, &buf, &len) != 0) {
		failures++;
		return;
	}
	CHECK(pe_parse(buf, len, &img, err, sizeof err));
	CHECK(img.machine == 0x8664);
	CHECK(img.optional_magic == PE_OPT_MAGIC_PE32P);
	CHECK(img.num_sections >= 5);
	CHECK(img.entry_point != 0);
	CHECK(img.image_base >= 0x10000);
	CHECK(img.import_dll_count >= 1);
	CHECK(img.export_count == 0);
	CHECK(img.reloc_block_count >= 1);
	CHECK(img.size_of_image >= img.size_of_headers);

	for (i = 0; i < img.num_sections; i++) {
		CHECK(img.sections[i].name[0] != 0);
		if (!strcmp(img.sections[i].name, ".text")) {
			found_text = 1;
			text_va = img.sections[i].virtual_address;
			text_size = img.sections[i].virtual_size;
		}
		if (!strcmp(img.sections[i].name, ".idata"))
			found_idata = 1;
		if ((uint64_t)img.sections[i].raw_offset +
			    img.sections[i].raw_size > max_raw_end)
			max_raw_end = img.sections[i].raw_offset +
				      img.sections[i].raw_size;
	}
	CHECK(max_raw_end > 0 && max_raw_end <= len);
	CHECK(found_text);
	CHECK(found_idata);
	CHECK(text_size > 0);
	CHECK(img.entry_point >= text_va && img.entry_point < text_va + text_size);

	for (i = 0; i < img.import_dll_count; i++) {
		char name[PE_NAME_MAX];
		uint32_t iat = 0, thunks = 0;

		CHECK(pe_import_dll(&img, i, name, sizeof name, &iat, &thunks));
		CHECK(name[0] != 0);
		CHECK(iat != 0);
		CHECK(thunks > 0);
		if (strstr(name, "KERNEL32.dll") || strstr(name, "kernel32.dll"))
			found_dll = 1;
	}
	CHECK(found_dll);

	for (i = 0; i < img.reloc_block_count; i++) {
		uint32_t page = 0, entries = 0;

		CHECK(pe_reloc_block(&img, i, &page, &entries));
		CHECK(entries <= PE_MAX_RELOCS);
		reloc_sum += entries;
	}
	CHECK(reloc_sum == img.reloc_count);

	/* RVA mapping must refuse unmapped and header-overrun ranges. */
	{
		uint32_t off;

		CHECK(pe_rva_to_offset(&img, img.entry_point, 1, &off));
		CHECK(off < len);
		CHECK(!pe_rva_to_offset(&img, img.size_of_image, 1, &off));
		CHECK(!pe_rva_to_offset(&img, 0, img.size_of_headers + 1, &off));
	}

	free(buf);
}

static void test_valid_dll(const char *dir)
{
	char path[512];
	uint8_t *buf = NULL;
	size_t len = 0, i;
	struct pe_image img;
	char err[160];
	int found = 0;

	snprintf(path, sizeof path, "%s/libfixture.dll", dir);
	if (load_file(path, &buf, &len) != 0) {
		failures++;
		return;
	}
	CHECK(pe_parse(buf, len, &img, err, sizeof err));
	CHECK(img.machine == 0x8664);
	CHECK(img.optional_magic == PE_OPT_MAGIC_PE32P);
	CHECK(img.import_dll_count >= 1);
	CHECK(img.export_count >= 1);
	CHECK(img.export_base == 1);

	for (i = 0; i < img.export_count; i++) {
		char name[PE_NAME_MAX];
		uint32_t rva = 0;
		uint16_t ord = 0;

		CHECK(pe_export_name(&img, i, name, sizeof name, &rva, &ord));
		CHECK(name[0] != 0);
		CHECK(rva != 0);
		CHECK(ord >= 1);
		if (!strcmp(name, "forsteri_test_export"))
			found = 1;
	}
	CHECK(found);
	free(buf);
}

static void test_malformed(const char *dir)
{
	char path[512];
	uint8_t *buf = NULL, *m;
	size_t len = 0;
	struct pe_image img;
	char err[160];
	uint32_t nt, size_opt, opt, sec_off, lfanew;

	snprintf(path, sizeof path, "%s/hello.exe", dir);
	if (load_file(path, &buf, &len) != 0) {
		failures++;
		return;
	}
	CHECK(pe_parse(buf, len, &img, err, sizeof err));

	lfanew = rd32(buf, 0x3c);
	nt = lfanew;
	size_opt = rd16(buf, nt + 20);
	opt = nt + 24;
	sec_off = opt + size_opt;

	expect_reject("null buffer", NULL, 0);
	expect_reject("short DOS header", buf, 0x20);
	expect_reject("truncated at half", buf, len / 2);
	{
		uint32_t max_end = 0;

		for (size_t i = 0; i < img.num_sections; i++) {
			uint32_t end = img.sections[i].raw_offset +
				       img.sections[i].raw_size;

			if (end > max_end)
				max_end = end;
		}
		CHECK(max_end > 0);
		expect_reject("truncated section data", buf, max_end - 1);
	}

	m = copy_of(buf, len);
	CHECK(m != NULL);
	wr16(m, 0, 0x1234);
	expect_reject("bad DOS magic", m, len);
	free(m);

	m = copy_of(buf, len);
	wr32(m, 0x3c, 0xfffffff0);
	expect_reject("e_lfanew huge", m, len);
	wr32(m, 0x3c, (uint32_t)(len - 2));
	expect_reject("e_lfanew at EOF", m, len);
	free(m);

	m = copy_of(buf, len);
	wr32(m, nt, 0xdeadbeef);
	expect_reject("bad PE signature", m, len);
	free(m);

	m = copy_of(buf, len);
	wr16(m, nt + 6, 0);
	expect_reject("zero sections", m, len);
	wr16(m, nt + 6, 0xffff);
	expect_reject("too many sections", m, len);
	free(m);

	m = copy_of(buf, len);
	wr16(m, nt + 20, 0);
	expect_reject("zero optional size", m, len);
	wr16(m, nt + 20, 0xffff);
	expect_reject("huge optional size", m, len);
	free(m);

	m = copy_of(buf, len);
	wr16(m, opt, 0x999);
	expect_reject("bad optional magic", m, len);
	free(m);

	m = copy_of(buf, len);
	wr32(m, opt + 108, 0xffffffff);
	expect_reject("huge NumberOfRvaAndSizes", m, len);
	free(m);

	m = copy_of(buf, len);
	wr32(m, opt + 16, img.size_of_image);
	expect_reject("entry outside image", m, len);
	free(m);

	m = copy_of(buf, len);
	wr32(m, opt + 56, 0);
	expect_reject("zero SizeOfImage", m, len);
	free(m);

	m = copy_of(buf, len);
	wr32(m, opt + 32, 3);
	expect_reject("bad section alignment", m, len);
	free(m);

	m = copy_of(buf, len);
	wr32(m, sec_off + 16, 0xfffffff0);
	expect_reject("section raw size overflow", m, len);
	wr32(m, sec_off + 12, 0xffffffe0);
	expect_reject("section VA overflow", m, len);
	free(m);

	/* Import descriptor name RVA, found from the valid parse. */
	{
		uint32_t imp_rva = img.dir_rva[PE_DIR_IMPORT];
		uint32_t imp_off = 0;

		CHECK(pe_rva_to_offset(&img, imp_rva, 20, &imp_off));
		m = copy_of(buf, len);
		wr32(m, imp_off + 12, 0xfffffff0);
		expect_reject("import name RVA outside file", m, len);
		free(m);

		m = copy_of(buf, len);
		wr32(m, imp_off + 16, 0xfffffff0);
		expect_reject("IAT RVA outside file", m, len);
		free(m);
	}

	/* Relocation block size smaller than its header. */
	{
		uint32_t rel_rva = img.dir_rva[PE_DIR_BASERELOC];
		uint32_t rel_off = 0;

		CHECK(pe_rva_to_offset(&img, rel_rva, 8, &rel_off));
		m = copy_of(buf, len);
		wr32(m, rel_off + 4, 6);
		expect_reject("short relocation block", m, len);
		wr32(m, rel_off + 4, 0xfffffff0u);
		expect_reject("huge relocation block", m, len);
		free(m);
	}

	free(buf);

	/* Export table mutations on the DLL. */
	snprintf(path, sizeof path, "%s/libfixture.dll", dir);
	if (load_file(path, &buf, &len) != 0) {
		failures++;
		return;
	}
	CHECK(pe_parse(buf, len, &img, err, sizeof err));
	{
		uint32_t exp_off = 0;

		CHECK(pe_rva_to_offset(&img, img.dir_rva[PE_DIR_EXPORT], 40,
				       &exp_off));
		m = copy_of(buf, len);
		wr32(m, exp_off + 24, 0xffffffff);
		expect_reject("huge export name count", m, len);
		wr32(m, exp_off + 20, 1);
		wr32(m, exp_off + 24, 2);
		expect_reject("more names than functions", m, len);
		free(m);

		m = copy_of(buf, len);
		wr32(m, exp_off + 32, 0xfffffff0);
		expect_reject("export names array outside file", m, len);
		free(m);
	}
	free(buf);
}

int main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : "tests/pe/fixtures";

	printf("pe-test: fixtures %s\n", dir);
	test_valid_exe(dir);
	test_valid_dll(dir);
	test_malformed(dir);

	if (failures) {
		printf("pe-test: FAIL (%d)\n", failures);
		return 1;
	}
	printf("pe-test: PASS\n");
	return 0;
}
