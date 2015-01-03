#ifndef PICO_H
#define PICO_H

#include <asm/types.h>
#include <linux/ioctl.h>

/* for PICO_RUN */
struct pico_run {
	/* in */
	__u32 vcpu;
	__u32 emulated;  /* skip current instruction */
	__u32 mmio_completed; /* mmio request completed */

	/* out */
	__u32 exit_type;
	__u32 exit_reason;
	__u32 instruction_length;
	union {
		/* KVM_EXIT_UNKNOWN */
		struct {
			__u32 hardware_exit_reason;
		} hw;
		/* KVM_EXIT_EXCEPTION */
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;
		/* KVM_EXIT_IO */
		struct {
#define PICO_EXIT_IO_IN  0
#define PICO_EXIT_IO_OUT 1
			__u8 direction;
			__u8 size; /* bytes */
			__u8 string;
			__u8 string_down;
			__u8 rep;
			__u8 pad;
			__u16 port;
			__u64 count;
			union {
				__u64 address;
				__u32 value;
			};
		} io;
		/* PICO_EXIT_MMIO */
		struct {
			__u64 phys_addr;
			__u8  data[8];
			__u32 len;
			__u8  is_write;
		} mmio;
	};
};

#define PICO_MAGIC		'p'
#define PICO_RUN		_IOWR(PICO_MAGIC, 0, struct pico_run)
#endif
