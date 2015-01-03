#ifndef PICO_H
#define PICO_H

#include <asm/types.h>
#include <linux/ioctl.h>

struct pico_vmcs_arg {
	unsigned long field;
	unsigned long value;
};

#define PICO_MAGIC		'p'
#define PICO_VMENTRY		_IO(PICO_MAGIC, 0)
#define PICO_VMCS_READ		_IOWR(PICO_MAGIC, 1, struct pico_vmcs_arg)
#define PICO_VMCS_WRITE		_IOWR(PICO_MAGIC, 2, struct pico_vmcs_arg)
#endif
