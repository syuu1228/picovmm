KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
EXTRA_CFLAGS := -I$(PWD)/../libpico

obj-m	:= pico.o

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) EXTRA_CFLAGS=$(EXTRA_CFLAGS) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c Module.symvers modules.order .tmp_versions
