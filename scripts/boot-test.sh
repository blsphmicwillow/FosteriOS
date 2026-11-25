#!/usr/bin/env bash
# Boot the M0 initramfs in QEMU and assert the module's markers on the serial
# console. This is the gate for every kernel commit.
#
#   KERNEL=/boot/vmlinuz-linux scripts/boot-test.sh
#   INITRD=build/initramfs.cpio.gz scripts/boot-test.sh
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
KERNEL=${KERNEL:-/boot/vmlinuz-linux}
INITRD=${INITRD:-"$ROOT/build/initramfs.cpio.gz"}
LOG=${LOG:-"$ROOT/build/boot.log"}
QEMU=${QEMU:-qemu-system-x86_64}
TIMEOUT=${TIMEOUT:-120}

[[ -f $KERNEL ]] || { echo "boot-test: no kernel at $KERNEL" >&2; exit 1; }
[[ -f $INITRD ]] || { echo "boot-test: no initramfs at $INITRD" >&2; exit 1; }
command -v "$QEMU" >/dev/null 2>&1 || { echo "boot-test: $QEMU not found" >&2; exit 1; }

accel=(-accel tcg)
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
	accel=(-accel kvm)
fi

mkdir -p "$(dirname "$LOG")"
rm -f "$LOG"

set +e
timeout "$TIMEOUT" "$QEMU" \
	"${accel[@]}" -cpu max -m 512 -smp 2 -display none -no-reboot \
	-kernel "$KERNEL" -initrd "$INITRD" \
	-append "console=ttyS0 rdinit=/init panic=-1" \
	-serial "file:$LOG"
status=$?
set -e

if [[ $status -eq 124 ]]; then
	echo "boot-test: QEMU hit the ${TIMEOUT}s timeout" >&2
fi

if grep -q 'BOOT-TEST: PASS' "$LOG"; then
	echo "boot-test: PASS ($LOG)"
	exit 0
fi

echo "boot-test: FAIL ($LOG)"
grep -E 'BOOT-TEST|ntpersonality|Kernel panic|not syncing' "$LOG" | tail -30 || true
exit 1
