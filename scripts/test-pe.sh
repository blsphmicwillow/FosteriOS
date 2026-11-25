#!/usr/bin/env bash
# Host-side gates for the PE parser: real mingw images, malformed mutations,
# ASan/UBSan. No kernel, no QEMU, no Windows needed.
#
#   scripts/test-pe.sh
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${OUT:-"$ROOT/build/pe-test"}
CC=${CC:-cc}

mkdir -p "$(dirname "$OUT")"

"$CC" -std=c11 -O1 -g -Wall -Wextra -Werror \
	-fsanitize=address,undefined -fno-sanitize-recover=all \
	-fno-omit-frame-pointer \
	-I"$ROOT/kernel/nt" \
	"$ROOT/kernel/nt/pe.c" "$ROOT/tests/pe/pe_test.c" \
	-o "$OUT"

"$OUT" "$ROOT/tests/pe/fixtures"

"$CC" -std=c11 -O1 -g -Wall -Wextra -Werror \
	-fsanitize=address,undefined -fno-sanitize-recover=all \
	-fno-omit-frame-pointer \
	-I"$ROOT/kernel/nt" \
	"$ROOT/kernel/nt/pe.c" "$ROOT/kernel/nt/pe_map.c" \
	"$ROOT/tests/pe/pe_map_test.c" -o "$OUT-map"

"$OUT-map" "$ROOT/tests/pe/fixtures"

"$CC" -std=c11 -O1 -g -Wall -Wextra -Werror \
	-fsanitize=address,undefined -fno-sanitize-recover=all \
	-fno-omit-frame-pointer \
	-I"$ROOT/kernel/nt" \
	"$ROOT/kernel/nt/nt_peb.c" "$ROOT/tests/pe/peb_test.c" \
	-o "$OUT-peb"

"$OUT-peb"
