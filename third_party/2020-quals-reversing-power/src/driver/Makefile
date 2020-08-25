# Copyright 2020 Google LLC
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

KMISC=$(shell pwd)/../linux-5.6.14/drivers/acpi

ifneq ($(KERNELRELEASE),)

	obj-m := chck.o
	chck-y := main.o chck_dev.o

else

	PWD := $(shell pwd)
	KERN_DIR ?= $(PWD)/../linux-5.6.14

default:
	export ARCH=x86
	$(MAKE) -C $(KERN_DIR) ARCH=x86 CROSS_COMPILE= M=$(PWD) modules

endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
