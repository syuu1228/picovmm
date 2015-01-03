/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 */
/*
 * picovmm
 *
 * Copyright (C) 2015 Takuya ASADA
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <asm/processor.h>
#include <asm/processor-flags.h>
#include <asm/msr-index.h>
#include "pico.h"

MODULE_AUTHOR("Takuya ASADA");
MODULE_DESCRIPTION("KVM like tiny VMM implementation for an education");
MODULE_LICENSE("GPL");

#define MINOR_COUNT 1

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

static dev_t dev_id;
static struct cdev c_dev;
static struct class *cl;
static int vmcs_size, vmcs_order;
static u32 vmcs_revision_id;
static struct vmcs *vmcs;

static inline void vmxon(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);

	asm volatile ("vmxon %0" : : "m"(phys_addr) : "memory", "cc");
}

static inline void vmxoff(void)
{
	asm volatile ("vmxoff" : : : "cc");
}

static inline void vmclear(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile ("vmclear %1; setna %0"
		       : "=m"(error) : "m"(phys_addr) : "cc", "memory" );
	if (error)
		printk(KERN_ERR "kvm: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
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

static struct vm_operations_struct pico_vm_ops = {
	.fault = pico_dev_fault,
};

static int pico_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &pico_vm_ops;
	return 0;
}

static struct file_operations pico_file_ops = {
	.owner		= THIS_MODULE,
	.open		= pico_dev_open,
	.release        = pico_dev_release,
	.unlocked_ioctl = pico_dev_ioctl,
	.compat_ioctl   = pico_dev_ioctl,
	.mmap           = pico_dev_mmap,
};

static __init int cpu_has_vmx_support(void)
{
	unsigned long ecx = cpuid_ecx(1);
	return test_bit(5, &ecx); /* CPUID.1:ECX.VMX[bit 5] -> VT */
}

static __init int vmx_disabled_by_bios(void)
{
	u64 msr;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, msr);
	return (msr & 5) == 1; /* locked but not enabled */
}

static __init void load_vmx_basic_msr(void)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);
	vmcs_size = vmx_msr_high & 0x1fff;
	vmcs_order = get_order(vmcs_size);
	vmcs_revision_id = vmx_msr_low;
};

static __init int alloc_vmcs(void)
{
	int node = cpu_to_node(smp_processor_id());
	struct page *pages;

	pages = alloc_pages_node(node, GFP_KERNEL, vmcs_order);
	if (!pages)
		return -1;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_size);
	vmcs->revision_id = vmcs_revision_id; /* vmcs revision id */
	return 0;
}

static void free_vmcs(void)
{
	free_pages((unsigned long)vmcs, vmcs_order);
}

static __init void vmx_enable(void)
{
	u64 old;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);
	if ((old & 5) == 0)
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | 5);
	write_cr4(read_cr4() | X86_CR4_VMXE); /* FIXME: not cpu hotplug safe */
	vmxon(vmcs);
}

static __exit void vmx_disable(void)
{
	vmxoff();
}

static __init int pico_init(void)
{
	int r;
	static struct device *dev;

	if (!cpu_has_vmx_support()) {
		printk(KERN_ERR "pico: no hardware support\n");
		return -EOPNOTSUPP;
	}

	if (vmx_disabled_by_bios()) {
		printk(KERN_ERR "pico: disabled by bios\n");
		return -EOPNOTSUPP;
	}

	load_vmx_basic_msr();

	if (alloc_vmcs()) {
		printk(KERN_ERR "pico: page allocation failed\n");
		goto err_vmcs;
	}

	vmx_enable();

	r = alloc_chrdev_region(&dev_id, 0, MINOR_COUNT, "pico");
	if (r < 0) {
		printk(KERN_ERR "pico: device allocation failed\n");
		goto err_chrdev;
	}

	cl = class_create(THIS_MODULE, "pico");
	if (!cl) {
		printk(KERN_ERR "pico: class creation failed\n");
		goto err_class;
	}
	
	dev = device_create(cl, NULL, dev_id, NULL, "pico");
	if (!dev) {
		printk(KERN_ERR "pico: device creation failed\n");
		goto err_dev;
	}

	cdev_init(&c_dev, &pico_file_ops);
	c_dev.owner = THIS_MODULE;

	r = cdev_add(&c_dev, dev_id, 1);
	if (r) {
		printk(KERN_ERR "pico: cdev add failed\n");
		goto err_add;
	}
	
	printk(KERN_INFO "pico is loaded\n");
	printk(KERN_INFO "pico: major=%d minor=%d\n", MAJOR(dev_id), MINOR(dev_id));
	return 0;

err_add:
	device_destroy(cl, dev_id);
err_dev:
	class_destroy(cl);
err_class:
	unregister_chrdev_region(dev_id, MINOR_COUNT);
err_chrdev:
	vmx_disable();
err_vmcs:
	free_vmcs();
	return -1;
}

static __exit void pico_exit(void)
{
	cdev_del(&c_dev);
	device_destroy(cl, dev_id);
	class_destroy(cl);
	unregister_chrdev_region(dev_id, MINOR_COUNT);
	vmx_disable();
	free_vmcs();
	printk(KERN_INFO "pico is unloaded\n");
}

module_init(pico_init);
module_exit(pico_exit);
