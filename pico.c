/*
 * picovmm
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright (C) 2015 Takuya ASADA
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <asm/processor.h>
#include <asm/processor-flags.h>
#include <asm/msr-index.h>

MODULE_AUTHOR("Takuya ASADA");
MODULE_DESCRIPTION("tiny VMM implementation");
MODULE_LICENSE("GPL");

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

static int size, order;
static u32 revision_id;

static inline void vmxon(u64 paddr)
{
	asm volatile ("vmxon %0" : : "m"(paddr) : "memory", "cc");
}

static inline void vmxoff(void)
{
	asm volatile ("vmxoff" : : : "cc");
}

static int pico_dev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int pico_dev_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static long pico_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	return 0;
}

static int pico_dev_fault(struct vm_area_struct *vma,
			 struct vm_fault *vmf)
{
	return 0;
}

static struct vm_operations_struct pico_dev_vm_ops = {
	.fault = pico_dev_fault,
};

static int pico_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &pico_dev_vm_ops;
	return 0;
}

static struct file_operations pico_chardev_ops = {
	.owner		= THIS_MODULE,
	.open		= pico_dev_open,
	.release        = pico_dev_release,
	.unlocked_ioctl = pico_dev_ioctl,
	.compat_ioctl   = pico_dev_ioctl,
	.mmap           = pico_dev_mmap,
};

static struct miscdevice pico_dev = {
	MISC_DYNAMIC_MINOR,
	"pico",
	&pico_chardev_ops,
};

static int pico_init(void)
{
	int err = 0;
	unsigned long ecx;
	u64 msrl;
	u32 msr_low, msr_high;

	ecx = cpuid_ecx(1);
	if (test_bit(5, &ecx)) {
		printk(KERN_ERR "pico: VT-x is not supported\n");
		return -EOPNOTSUPP;
	}

	rdmsrl(MSR_IA32_FEATURE_CONTROL, msrl);
	if ((msrl & 5) == 1) {
		printk(KERN_ERR "pico: VT-x disabled\n");
		return -EOPNOTSUPP;
	} else if ((msrl & 5) == 0) {
		wrmsrl(MSR_IA32_FEATURE_CONTROL, msrl | 5);
	}

	write_cr4(read_cr4() | X86_CR4_VMXE);

	rdmsr(MSR_IA32_VMX_BASIC, msr_low, msr_high);
	size = msr_high & 0x1ffff;
	order = get_order(size);
	revision_id = msr_low;

	err = misc_register(&pico_dev);
	if (err) {
		printk(KERN_ERR "pico: cannot register device\n");
		return err;
	}

	return 0;
}

static __exit void pico_exit(void)
{
	misc_deregister(&pico_dev);
}

module_init(pico_init);
module_exit(pico_exit);
