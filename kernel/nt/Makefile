# SPDX-License-Identifier: GPL-2.0
#
# Build the NT personality module against the running (or given) kernel.
#
#   make                      uses /lib/modules/$(uname -r)/build
#   make KDIR=/path/to/build  uses an explicit kernel build tree
#
# scripts/build-module.sh wraps this and fills in KDIR for you.
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m += ntpersonality.o
ntpersonality-y := ntpersonality_main.o pe.o pe_map.o nt_peb.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

.PHONY: all clean install
