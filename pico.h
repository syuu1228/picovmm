#ifndef PICO_H
#define PICO_H

#include <asm/types.h>
#include <linux/ioctl.h>

enum {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
	NR_VCPU_REGS
};

struct pico_reg {
	unsigned long field;
	unsigned long value;
};

#define PICO_MAGIC		'p'
#define PICO_VMENTRY		_IO(PICO_MAGIC, 0)
#define PICO_VMCS_READ		_IOWR(PICO_MAGIC, 1, struct pico_reg)
#define PICO_VMCS_WRITE		_IOWR(PICO_MAGIC, 2, struct pico_reg)
#define PICO_REG_READ		_IOWR(PICO_MAGIC, 3, struct pico_reg)
#define PICO_REG_WRITE		_IOWR(PICO_MAGIC, 4, struct pico_reg)
#define PICO_CREG_READ		_IOWR(PICO_MAGIC, 5, struct pico_reg)
#define PICO_CREG_WRITE		_IOWR(PICO_MAGIC, 6, struct pico_reg)
#endif
