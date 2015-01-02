obj-m	:= pico.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) LDDINCDIR=$(PWD)/../include modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c Module.symvers modules.order .tmp_versions
