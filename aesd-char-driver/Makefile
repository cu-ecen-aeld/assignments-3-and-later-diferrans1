# Comment/uncomment to disable/enable debug output
#DEBUG = y

ifeq ($(DEBUG),y)
DEBFLAGS = -O -g -DAESD_DEBUG
else
DEBFLAGS = -O2
endif

EXTRA_CFLAGS += $(DEBFLAGS)

ifneq ($(KERNELRELEASE),)
obj-m := aesdchar.o
aesdchar-y := aesd-circular-buffer.o main.o
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions modules.order Module.symvers
