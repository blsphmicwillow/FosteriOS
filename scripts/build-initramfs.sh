#!/usr/bin/env bash
# Build the M0 test initramfs: busybox, the module, a small execve helper and
# a synthetic PE file. No distribution userland is involved, so a failure here
# is a kernel/module failure, not a Forsteri one.
#
#   BUSYBOX=/usr/bin/busybox scripts/build-initramfs.sh
#
# Environment:
#   BUSYBOX   static busybox binary (default: busybox in PATH)
#   OUT       output cpio.gz (default: build/initramfs.cpio.gz)
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${OUT:-"$ROOT/build/initramfs.cpio.gz"}
BUSYBOX=${BUSYBOX:-$(command -v busybox || true)}
MODULE="$ROOT/kernel/nt/ntpersonality.ko"

[[ -n $BUSYBOX && -x $BUSYBOX ]] || {
	echo "build-initramfs: set BUSYBOX to a static busybox binary" >&2
	exit 1
}
[[ -f $MODULE ]] || {
	echo "build-initramfs: $MODULE is missing; run scripts/build-module.sh first" >&2
	exit 1
}

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/bin" "$STAGE/proc" "$STAGE/sys" "$STAGE/dev" "$STAGE/tmp"

install -m755 "$BUSYBOX" "$STAGE/bin/busybox"
install -m644 "$MODULE" "$STAGE/ntpersonality.ko"

# Direct execve(2), so the shell's "run it as a script" fallback cannot mask
# the binfmt result.
cat >"$STAGE/exectest.c" <<'C'
#include <stdio.h>
#include <unistd.h>
int main(void) {
	char *argv[] = { "/test.exe", 0 };
	execve("/test.exe", argv, 0);
	perror("execve");
	return 0;
}
C
gcc -static -O2 -o "$STAGE/exectest" "$STAGE/exectest.c"
rm -f "$STAGE/exectest.c"

# MZ header, e_lfanew=0x80 at offset 0x3c, "PE\0\0" at 0x80. 132 bytes.
# Built in C so the image does not depend on the build host's /dev/zero.
cat >"$STAGE/mkpe.c" <<'C'
#include <stdio.h>
#include <sys/stat.h>
int main(void) {
	unsigned char b[132] = { 0 };
	b[0] = 'M'; b[1] = 'Z';
	b[0x3c] = 0x80;
	b[0x80] = 'P'; b[0x81] = 'E';
	FILE *f = fopen("/test.exe", "wb");
	if (!f) return 1;
	if (fwrite(b, 1, sizeof b, f) != sizeof b) return 1;
	fclose(f);
	return chmod("/test.exe", 0755);
}
C
gcc -static -O2 -o "$STAGE/mkpe" "$STAGE/mkpe.c"
rm -f "$STAGE/mkpe.c"

cat >"$STAGE/init" <<'INIT'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /tmp

ok=1
echo "BOOT-TEST: kernel $(uname -r)"
if insmod /ntpersonality.ko; then
	echo "BOOT-TEST: insmod ok"
else
	echo "BOOT-TEST: insmod FAILED"
	ok=0
fi

echo "BOOT-TEST: proc before exec"
cat /proc/forsteri_nt || ok=0

/mkpe
/exectest
cat /proc/forsteri_nt

if grep -q '^pe_seen    1$' /proc/forsteri_nt; then
	echo "BOOT-TEST: binfmt counted the PE"
else
	echo "BOOT-TEST: binfmt did not count the PE"
	ok=0
fi

echo "BOOT-TEST: dmesg"
dmesg | grep -i ntpersonality || ok=0

if [ "$ok" = 1 ]; then
	echo "BOOT-TEST: PASS"
else
	echo "BOOT-TEST: FAIL"
fi

poweroff -f
INIT
chmod 755 "$STAGE/init"

mkdir -p "$(dirname "$OUT")"
( cd "$STAGE" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 ) >"$OUT"
echo "build-initramfs: $OUT ($(stat -c %s "$OUT") bytes)"
