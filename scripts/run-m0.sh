#!/usr/bin/env bash
# The whole M0 gate: module, initramfs, QEMU, assertions.
#
#   KERNEL=/boot/vmlinuz-linux scripts/run-m0.sh
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

"$ROOT/scripts/build-module.sh"
"$ROOT/scripts/build-initramfs.sh"
"$ROOT/scripts/boot-test.sh"
