// SPDX-License-Identifier: GPL-2.0
/*
 * Host tests for the M2 mapping layer. These use the same real mingw fixtures
 * as the parser tests and run under ASan/UBSan through scripts/test-pe.sh.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe.h"
#include "pe_map.h"

static int failures;

#define CHECK(cond)                                                          \
	do {                                                                 \
		if (!(cond)) {                                               \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, \
				#cond);                                      \
			failures++;                                          \
		}                                                            \
	} while (0)

static uint32_t rd32(const uint8_t *p, size_t off)
{
	return (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8) |
	       ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24);
}

static uint64_t rd64(const uint8_t *p, size_t off)
{
	return (uint64_t)rd32(p, off) | ((uint64_t)rd32(p, off + 4) << 32);
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

static int region_contains(const struct pe_map_plan *plan, uint32_t rva,
			   uint32_t prot)
{
	uint32_t i;

	for (i = 0; i < plan->region_count; i++) {
		const struct pe_map_region *r = &plan->regions[i];

		if ((r->prot & prot) && rva >= r->rva &&
		    (uint64_t)rva < (uint64_t)r->rva + r->size)
			return 1;
	}
	return 0;
}

static void test_real_image(const char *dir, const char *name)
{
	char path[512];
	uint8_t *file = NULL;
	size_t len = 0, mapped_size;
	struct pe_image img;
	struct pe_map_plan plan;
	char err[160];
	uint32_t i;

	snprintf(path, sizeof path, "%s/%s", dir, name);
	if (load_file(path, &file, &len) != 0) {
		failures++;
		return;
	}
	CHECK(pe_parse(file, len, &img, err, sizeof err));
	CHECK(pe_map_plan_build(&img, img.image_base, &plan, err, sizeof err));
	CHECK(plan.image_size >= img.size_of_image);
	CHECK(plan.region_count >= 2);
	CHECK(plan.regions[0].prot == PE_MAP_READ);
	CHECK(!(plan.regions[0].prot & (PE_MAP_WRITE | PE_MAP_EXEC)));
	CHECK(img.entry_point == 0 ||
	      region_contains(&plan, img.entry_point, PE_MAP_EXEC));

	for (i = 0; i < plan.region_count; i++) {
		const struct pe_map_region *r = &plan.regions[i];

		CHECK(!((r->prot & PE_MAP_WRITE) && (r->prot & PE_MAP_EXEC)));
		CHECK(r->size != 0);
		CHECK((uint64_t)r->rva + r->size <= plan.image_size);
	}

	mapped_size = plan.image_size;
	{
		uint8_t *mapped = calloc(1, mapped_size);

		CHECK(mapped != NULL);
		if (mapped) {
			CHECK(pe_map_copy(&img, &plan, mapped, mapped_size,
					  err, sizeof err));
			CHECK(mapped[0] == 'M' && mapped[1] == 'Z');
			CHECK(!pe_map_copy(&img, &plan, mapped, 1, err,
					   sizeof err));

			if (img.reloc_count) {
				struct pe_map_plan moved;
				uint32_t rva = 0;
				uint16_t type = 0;
				uint64_t before = 0, after = 0;
				uint32_t n = 0;

				CHECK(pe_reloc_entry(&img, 0, 0, &rva, &type));
				while (type == 0 && n + 1 < img.reloc_count) {
					n++;
					if (!pe_reloc_entry(&img, 0, n, &rva,
							    &type))
						break;
				}
				if (type == 3) {
					before = rd32(mapped, rva);
				} else if (type == 10) {
					before = rd64(mapped, rva);
				}
				CHECK(pe_map_plan_build(&img,
					img.image_base + 0x100000, &moved,
					err, sizeof err));
				CHECK(moved.delta == 0x100000);
				CHECK(pe_map_copy(&img, &moved, mapped,
						  mapped_size, err, sizeof err));
				CHECK(pe_map_apply_relocs(&img, &moved, mapped,
							  mapped_size, err,
							  sizeof err));
				if (type == 3)
					after = rd32(mapped, rva);
				else if (type == 10)
					after = rd64(mapped, rva);
				if (type == 3 || type == 10)
					CHECK(after == before + 0x100000);
			}
			free(mapped);
		}
	}

	/* A relocation directory is required when the base actually moves. */
	if (!img.reloc_count) {
		struct pe_map_plan moved;

		CHECK(!pe_map_plan_build(&img, img.image_base + 0x100000,
					 &moved, err, sizeof err));
	}

	/* Reject unaligned bases and a lower-than-preferred base. */
	{
		struct pe_map_plan bad;

		CHECK(!pe_map_plan_build(&img, img.image_base + 1, &bad,
					 err, sizeof err));
		CHECK(!pe_map_plan_build(&img, 0x1000, &bad, err,
					 sizeof err));
	}

	/* Mutating a section to W+X must be refused by the map, not ignored. */
	if (img.num_sections) {
		struct pe_image bad = img;
		struct pe_map_plan plan_bad;

		bad.sections[0].characteristics |= 0x80000000u;
		CHECK(!pe_map_plan_build(&bad, bad.image_base, &plan_bad,
					 err, sizeof err));
	}

	/* Overlapping sections must be refused even if the parser accepted them. */
	if (img.num_sections > 1) {
		struct pe_image bad = img;
		struct pe_map_plan plan_bad;
		uint32_t j;

		for (j = 1; j < bad.num_sections; j++) {
			if (bad.sections[j].virtual_size ||
			    bad.sections[j].raw_size) {
				bad.sections[j].virtual_address =
					bad.sections[0].virtual_address;
				break;
			}
		}
		if (j < bad.num_sections)
			CHECK(!pe_map_plan_build(&bad, bad.image_base,
						 &plan_bad, err,
						 sizeof err));
	}

	free(file);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s FIXTURE_DIR\n", argv[0]);
		return 2;
	}
	test_real_image(argv[1], "hello.exe");
	test_real_image(argv[1], "hello32.exe");
	test_real_image(argv[1], "libfixture.dll");

	if (failures) {
		fprintf(stderr, "%d mapping test(s) failed\n", failures);
		return 1;
	}
	puts("PE mapping tests passed");
	return 0;
}
