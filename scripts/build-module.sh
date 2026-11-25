#!/usr/bin/env bash
# Build the ntpersonality module for one kernel tree.
#
#   scripts/build-module.sh
#   KVER=7.3.5-arch1-1 scripts/build-module.sh
#   KDIR=/path/to/linux-build scripts/build-module.sh
#
# Needs kernel headers for KVER (Arch: pacman -S linux-headers) and a C
# toolchain. The module is self-signed by the kernel build; without
# CONFIG_MODULE_SIG_FORCE that is enough to insmod (the kernel marks itself
# tainted, which is expected for out-of-tree work).
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
KVER=${KVER:-$(uname -r)}
KDIR=${KDIR:-/lib/modules/$KVER/build}

[[ -d $KDIR ]] || {
	echo "build-module: no kernel build tree at $KDIR" >&2
	echo "build-module: install linux-headers for $KVER, or set KDIR" >&2
	exit 1
}

echo "build-module: KVER=$KVER"
echo "build-module: KDIR=$KDIR"
make -C "$KDIR" M="$ROOT/kernel/nt" modules

modinfo "$ROOT/kernel/nt/ntpersonality.ko" 2>/dev/null | sed -n '1,8p' || true
echo "build-module: built $ROOT/kernel/nt/ntpersonality.ko"
