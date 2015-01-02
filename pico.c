#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <asm/processor.h>

MODULE_AUTHOR("Takuya ASADA");
MODULE_DESCRIPTION("tiny VMM implementation");
MODULE_LICENSE("GPL");

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
	u64 msr;

	ecx = cpuid_ecx(1);
	if (test_bit(5, &ecx)) {
		printk(KERN_ERR "pico: VT-x is not supported\n");
		return -EOPNOTSUPP;
	}
	rdmsrl(MSR_IA32_FEATURE_CONTROL, msr);
	if ((msr & 5) == 1) {
		printk(KERN_ERR "pico: VT-x disabled\n");
		return -EOPNOTSUPP;
	}
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
