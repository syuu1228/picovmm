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
#include <linux/slab.h>
#include <asm/processor.h>
#include <asm/processor-flags.h>
#include <asm/msr-index.h>
#include <asm/uaccess.h>
#include "pico.h"
#include "vmx.h"

MODULE_AUTHOR("Takuya ASADA");
MODULE_DESCRIPTION("KVM like tiny VMM implementation for an education");
MODULE_LICENSE("GPL");

#define MINOR_COUNT 1

static const u32 vmx_msr_index[] = {
	MSR_SYSCALL_MASK, MSR_LSTAR, MSR_CSTAR, MSR_KERNEL_GS_BASE,
	MSR_EFER, MSR_STAR,
};
#define NR_VMX_MSR (sizeof(vmx_msr_index) / sizeof(*vmx_msr_index))
#define NR_BAD_MSRS 2

#define MSR_IA32_VMX_PINBASED_CTLS_MSR		0x481
#define MSR_IA32_VMX_PROCBASED_CTLS_MSR		0x482
#define MSR_IA32_VMX_EXIT_CTLS_MSR		0x483
#define MSR_IA32_VMX_ENTRY_CTLS_MSR		0x484

#define PF_VECTOR 14

#define CR0_PE_MASK (1ULL << 0)
#define CR0_TS_MASK (1ULL << 3)
#define CR0_NE_MASK (1ULL << 5)
#define CR0_WP_MASK (1ULL << 16)
#define CR0_NW_MASK (1ULL << 29)
#define CR0_CD_MASK (1ULL << 30)
#define CR0_PG_MASK (1ULL << 31)

#define CR4_VME_MASK (1ULL << 0)
#define CR4_PSE_MASK (1ULL << 4)
#define CR4_PAE_MASK (1ULL << 5)
#define CR4_PGE_MASK (1ULL << 7)
#define CR4_VMXE_MASK (1ULL << 13)

#define KVM_GUEST_CR0_MASK \
	(CR0_PG_MASK | CR0_PE_MASK | CR0_WP_MASK | CR0_NE_MASK)
#define KVM_VM_CR0_ALWAYS_ON KVM_GUEST_CR0_MASK

#define KVM_GUEST_CR4_MASK \
	(CR4_PSE_MASK | CR4_PAE_MASK | CR4_PGE_MASK | CR4_VMXE_MASK | CR4_VME_MASK)
#define KVM_PMODE_VM_CR4_ALWAYS_ON (CR4_VMXE_MASK | CR4_PAE_MASK)
#define KVM_RMODE_VM_CR4_ALWAYS_ON (CR4_VMXE_MASK | CR4_PAE_MASK | CR4_VME_MASK)

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

struct vmx_msr_entry {
	u32 index;
	u32 reserved;
	u64 data;
};

struct vcpu_state {
	struct vmcs *vmcs;
	struct page *page;
	int   launched;
	unsigned long regs[NR_VCPU_REGS]; /* for rsp: vcpu_load_rsp_rip() */
	unsigned long rip;      /* needs vcpu_load_rsp_rip() */

	unsigned long cr2;
	int nmsrs;
	struct vmx_msr_entry *guest_msrs;
	struct vmx_msr_entry *host_msrs;
};

struct descriptor_table {
	u16 limit;
	unsigned long base;
} __attribute__((packed));

struct segment_descriptor {
	u16 limit_low;
	u16 base_low;
	u8  base_mid;
	u8  type : 4;
	u8  system : 1;
	u8  dpl : 2;
	u8  present : 1;
	u8  limit_high : 4;
	u8  avl : 1;
	u8  long_mode : 1;
	u8  default_op : 1;
	u8  granularity : 1;
	u8  base_high;
} __attribute__((packed));

// LDT or TSS descriptor in the GDT. 16 bytes.
struct segment_descriptor_64 {
	struct segment_descriptor s;
	u32 base_higher;
	u32 pad_zero;
};

static dev_t dev_id;
static struct cdev c_dev;
static struct class *cl;
static int vmcs_size, vmcs_order;
static u32 vmcs_revision_id;
static struct vcpu_state *vcpu0;
static struct vmcs *vmcs_init;

static inline void vmxon(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);

	asm volatile ("vmxon %0" : : "m"(phys_addr) : "memory", "cc");
}

static inline void vmxoff(void)
{
	asm volatile ("vmxoff" : : : "cc");
}

static inline int vmptrld(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile ("vmptrld %1; setna %0"
		       : "=m"(error) : "m"(phys_addr) : "cc" );
	if (error)
		printk(KERN_ERR "pico: vmptrld %p/%llx fail\n",
		       vmcs, phys_addr);
	return error ? -1 : 0;
}

static inline int vmclear(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile ("vmclear %1; setna %0"
		       : "=m"(error) : "m"(phys_addr) : "cc", "memory" );
	if (error)
		printk(KERN_ERR "pico: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
	return error ? -1 : 0;
}

static inline unsigned long vmcs_readl(unsigned long field);
static inline int vmcs_read(unsigned long field, unsigned long *valuep)
{
	unsigned long value;
	u8 error;

	asm volatile ("vmread %2, %1; setna %0"
			: "=g"(error), "=g"(value) : "r"(field) : "cc");
	if (error)
		printk(KERN_ERR "pico: vmread error: reg %lx (err %d)\n",
		       field, (u32)vmcs_readl(VM_INSTRUCTION_ERROR));

	*valuep = value;
	return error ? -1 : 0;
}

static inline int vmcs_write(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile ("vmwrite %1, %2; setna %0"
		       : "=g"(error) : "r"(value), "r"(field) : "cc" );
	if (error)
		printk(KERN_ERR "pico: vmwrite error: reg %lx value %lx (err %d)\n",
		       field, value, (u32)vmcs_readl(VM_INSTRUCTION_ERROR));
	return error ? -1 : 0;
}

static inline unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value;
	vmcs_read(field, &value);
	return value;
}

static inline u16 vmcs_read16(unsigned long field)
{
	return vmcs_readl(field);
}

static inline u32 vmcs_read32(unsigned long field)
{
	return vmcs_readl(field);
}

static inline u64 vmcs_read64(unsigned long field)
{
	return vmcs_readl(field);
}

static inline void vmcs_writel(unsigned long field, unsigned long value)
{
	vmcs_write(field, value);
}

static inline void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_writel(field, value);
}

static inline void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_writel(field, value);
}

static inline void vmcs_write64(unsigned long field, u64 value)
{
	vmcs_writel(field, value);
}

static inline void vmcs_write32_fixedbits(u32 msr, u32 vmcs_field, u32 val)
{
	u32 msr_high, msr_low;

	rdmsr(msr, msr_low, msr_high);

	val &= msr_high;
	val |= msr_low;
	vmcs_write32(vmcs_field, val);
}

static inline void get_gdt(struct descriptor_table *table)
{
	asm ("sgdt %0" : "=m"(*table));
}

static void get_idt(struct descriptor_table *table)
{
	asm ("sidt %0" : "=m"(*table));
}

static inline u16 read_fs(void)
{
	u16 seg;
	asm ("mov %%fs, %0" : "=g"(seg));
	return seg;
}

static inline u16 read_gs(void)
{
	u16 seg;
	asm ("mov %%gs, %0" : "=g"(seg));
	return seg;
}

static inline u16 read_ldt(void)
{
	u16 ldt;
	asm ("sldt %0" : "=g"(ldt));
	return ldt;
}

static inline void load_fs(u16 sel)
{
	asm ("mov %0, %%fs" : : "g"(sel));
}

static inline void load_gs(u16 sel)
{
	asm ("mov %0, %%gs" : : "g"(sel));
}

static inline void load_ldt(u16 sel)
{
	asm ("lldt %0" : : "g"(sel));
}

static inline unsigned long read_msr(unsigned long msr)
{
	u64 value;

	rdmsrl(msr, value);
	return value;
}

static void reload_tss(void)
{
	/*
	 * VT restores TR but not its size.  Useless.
	 */
	struct descriptor_table gdt;
	struct segment_descriptor *descs;

	get_gdt(&gdt);
	descs = (void *)gdt.base;
	descs[GDT_ENTRY_TSS].type = 9; /* available TSS */
	load_TR_desc();
}

static int pico_dev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int pico_dev_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int pico_vcpu_setup(struct vcpu_state *vcpu)
{
	vmptrld(vcpu->vmcs);
	vmclear(vcpu->vmcs);
#if 0
	extern asmlinkage void pico_vmx_return(void);
	u32 host_sysenter_cs;
	u32 junk;
	unsigned long a;
	struct descriptor_table dt;
	int i;
	int ret;
	u64 tsc;
	int nr_good_msrs;
	unsigned long cr0, cr4;
	char *instr;

#define SEG_SETUP(seg) do {					\
		vmcs_write16(GUEST_##seg##_SELECTOR, 0);	\
		vmcs_writel(GUEST_##seg##_BASE, 0);		\
		vmcs_write32(GUEST_##seg##_LIMIT, 0xffff);	\
		vmcs_write32(GUEST_##seg##_AR_BYTES, 0x93); 	\
	} while (0)

	vmcs_write16(GUEST_CS_SELECTOR, 0xf000);
	vmcs_writel(GUEST_CS_BASE, 0x000f0000);
	vmcs_write32(GUEST_CS_LIMIT, 0xffff);
	vmcs_write32(GUEST_CS_AR_BYTES, 0x9b);

	SEG_SETUP(DS);
	SEG_SETUP(ES);
	SEG_SETUP(FS);
	SEG_SETUP(GS);
	SEG_SETUP(SS);

	vmcs_write16(GUEST_TR_SELECTOR, 0);
	vmcs_writel(GUEST_TR_BASE, 0);
	vmcs_write32(GUEST_TR_LIMIT, 0xffff);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_write32(GUEST_LDTR_LIMIT, 0xffff);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x00082);

	vmcs_write32(GUEST_SYSENTER_CS, 0);
	vmcs_writel(GUEST_SYSENTER_ESP, 0);
	vmcs_writel(GUEST_SYSENTER_EIP, 0);

	vmcs_writel(GUEST_RFLAGS, 0x02);
	vmcs_writel(GUEST_RIP, 0x0);
	vmcs_writel(GUEST_RSP, 0);

	vmcs_writel(GUEST_CR3, 0);

	vmcs_writel(GUEST_DR7, 0x400);

	vmcs_writel(GUEST_GDTR_BASE, 0);
	vmcs_write32(GUEST_GDTR_LIMIT, 0xffff);

	vmcs_writel(GUEST_IDTR_BASE, 0);
	vmcs_write32(GUEST_IDTR_LIMIT, 0xffff);

	vmcs_write32(GUEST_ACTIVITY_STATE, 0);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	/* I/O */
	vmcs_write64(IO_BITMAP_A, 0);
	vmcs_write64(IO_BITMAP_B, 0);

	rdtscll(tsc);
	vmcs_write64(TSC_OFFSET, -tsc);

	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Special registers */
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	/* Control */
	vmcs_write32_fixedbits(MSR_IA32_VMX_PINBASED_CTLS_MSR,
			       PIN_BASED_VM_EXEC_CONTROL,
			       PIN_BASED_EXT_INTR_MASK   /* 20.6.1 */
			       | PIN_BASED_NMI_EXITING   /* 20.6.1 */
			);
	vmcs_write32_fixedbits(MSR_IA32_VMX_PROCBASED_CTLS_MSR,
			       CPU_BASED_VM_EXEC_CONTROL,
			       CPU_BASED_HLT_EXITING         /* 20.6.2 */
			       | CPU_BASED_CR8_LOAD_EXITING    /* 20.6.2 */
			       | CPU_BASED_CR8_STORE_EXITING   /* 20.6.2 */
			       | CPU_BASED_UNCOND_IO_EXITING   /* 20.6.2 */
			       | CPU_BASED_INVDPG_EXITING
			       | CPU_BASED_MOV_DR_EXITING
			       | CPU_BASED_USE_TSC_OFFSETING   /* 21.3 */
			);

	vmcs_write32(EXCEPTION_BITMAP, 1 << PF_VECTOR);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	vmcs_write32(CR3_TARGET_COUNT, 0);           /* 22.2.1 */

	vmcs_writel(HOST_CR0, read_cr0());  /* 22.2.3 */
	vmcs_writel(HOST_CR4, read_cr4());  /* 22.2.3, 22.2.5 */
	vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3  FIXME: shadow tables */

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_FS_SELECTOR, read_fs());    /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, read_gs());    /* 22.2.4 */
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	rdmsrl(MSR_FS_BASE, a);
	vmcs_writel(HOST_FS_BASE, a); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, a);
	vmcs_writel(HOST_GS_BASE, a); /* 22.2.4 */

	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	get_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.base);   /* 22.2.4 */


	vmcs_writel(HOST_RIP, (unsigned long)pico_vmx_return); /* 22.2.5 */

	rdmsr(MSR_IA32_SYSENTER_CS, host_sysenter_cs, junk);
	vmcs_write32(HOST_IA32_SYSENTER_CS, host_sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, a);   /* 22.2.3 */
	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, a);   /* 22.2.3 */

	ret = -ENOMEM;
	vcpu->guest_msrs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!vcpu->guest_msrs)
		goto out;
	vcpu->host_msrs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!vcpu->host_msrs)
		goto out_free_guest_msrs;

	for (i = 0; i < NR_VMX_MSR; ++i) {
		u32 index = vmx_msr_index[i];
		u32 data_low, data_high;
		u64 data;
		int j = vcpu->nmsrs;

		if (rdmsr_safe(index, &data_low, &data_high) < 0)
			continue;
		data = data_low | ((u64)data_high << 32);
		vcpu->host_msrs[j].index = index;
		vcpu->host_msrs[j].reserved = 0;
		vcpu->host_msrs[j].data = data;
		vcpu->guest_msrs[j] = vcpu->host_msrs[j];
		++vcpu->nmsrs;
	}
	printk("pico: msrs: %d\n", vcpu->nmsrs);

	nr_good_msrs = vcpu->nmsrs - NR_BAD_MSRS;
	vmcs_writel(VM_ENTRY_MSR_LOAD_ADDR,
		    virt_to_phys(vcpu->guest_msrs + NR_BAD_MSRS));
	vmcs_writel(VM_EXIT_MSR_STORE_ADDR,
		    virt_to_phys(vcpu->guest_msrs + NR_BAD_MSRS));
	vmcs_writel(VM_EXIT_MSR_LOAD_ADDR,
		    virt_to_phys(vcpu->host_msrs + NR_BAD_MSRS));
	vmcs_write32_fixedbits(MSR_IA32_VMX_EXIT_CTLS_MSR, VM_EXIT_CONTROLS,
		     	       (1 << 9));  /* 22.2,1, 20.7.1 */
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, nr_good_msrs); /* 22.2.2 */
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, nr_good_msrs);  /* 22.2.2 */
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, nr_good_msrs); /* 22.2.2 */

	/* 22.2.1, 20.8.1 */
	vmcs_write32_fixedbits(MSR_IA32_VMX_ENTRY_CTLS_MSR,
                               VM_ENTRY_CONTROLS, 0);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */

	vmcs_writel(VIRTUAL_APIC_PAGE_ADDR, 0);
	vmcs_writel(TPR_THRESHOLD, 0);

	vmcs_writel(CR0_GUEST_HOST_MASK, KVM_GUEST_CR0_MASK);
	vmcs_writel(CR4_GUEST_HOST_MASK, KVM_GUEST_CR4_MASK);

	cr0 = 0x60000010;
	vmcs_writel(CR0_READ_SHADOW, cr0);
	vmcs_writel(GUEST_CR0, cr0 | KVM_VM_CR0_ALWAYS_ON);
	cr4 = 0;
	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_CR4, cr4 | KVM_PMODE_VM_CR4_ALWAYS_ON);

	instr = 0x0;
	instr[0] = 0xb0;
	instr[1] = 0x0a;
	instr[2] = 0xe6;
	instr[3] = 0x60;

	return ret;

out_free_guest_msrs:
	kfree(vcpu->guest_msrs);
out:
	return ret;
#endif
	return 0;
}

static int pico_dev_ioctl_vmentry(struct vcpu_state *vcpu)
{
	u8 fail;
	u16 fs_sel, gs_sel, ldt_sel;
	int fs_gs_ldt_reload_needed;

	/*
	 * Set host fs and gs selectors.  Unfortunately, 22.2.3 does not
	 * allow segment selectors with cpl > 0 or ti == 1.
	 */
	fs_sel = read_fs();
	gs_sel = read_gs();
	ldt_sel = read_ldt();
	fs_gs_ldt_reload_needed = (fs_sel & 7) | (gs_sel & 7) | ldt_sel;
	if (!fs_gs_ldt_reload_needed) {
		vmcs_write16(HOST_FS_SELECTOR, fs_sel);
		vmcs_write16(HOST_GS_SELECTOR, gs_sel);
	} else {
		vmcs_write16(HOST_FS_SELECTOR, 0);
		vmcs_write16(HOST_GS_SELECTOR, 0);
	}

	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));

	asm (
		/* Store host registers */
		"pushf \n\t"
		"push %%rax; push %%rbx; push %%rdx;"
		"push %%rsi; push %%rdi; push %%rbp;"
		"push %%r8;  push %%r9;  push %%r10; push %%r11;"
		"push %%r12; push %%r13; push %%r14; push %%r15;"
		"push %%rcx \n\t"
		"vmwrite %%rsp, %2 \n\t"
		/* Check if vmlaunch of vmresume is needed */
		"cmp $0, %1 \n\t"
		/* Load guest registers.  Don't clobber flags. */
		"mov %c[cr2](%3), %%rax \n\t"
		"mov %%rax, %%cr2 \n\t"
		"mov %c[rax](%3), %%rax \n\t"
		"mov %c[rbx](%3), %%rbx \n\t"
		"mov %c[rdx](%3), %%rdx \n\t"
		"mov %c[rsi](%3), %%rsi \n\t"
		"mov %c[rdi](%3), %%rdi \n\t"
		"mov %c[rbp](%3), %%rbp \n\t"
		"mov %c[r8](%3),  %%r8  \n\t"
		"mov %c[r9](%3),  %%r9  \n\t"
		"mov %c[r10](%3), %%r10 \n\t"
		"mov %c[r11](%3), %%r11 \n\t"
		"mov %c[r12](%3), %%r12 \n\t"
		"mov %c[r13](%3), %%r13 \n\t"
		"mov %c[r14](%3), %%r14 \n\t"
		"mov %c[r15](%3), %%r15 \n\t"
		"mov %c[rcx](%3), %%rcx \n\t" /* kills %3 (rcx) */
		/* Enter guest mode */
		"jne launched \n\t"
		"vmlaunch \n\t"
		"jmp pico_vmx_return \n\t"
		"launched: vmresume \n\t"
		".globl pico_vmx_return \n\t"
		"pico_vmx_return: "
		/* Save guest registers, load host registers, keep flags */
		"xchg %3,     0(%%rsp) \n\t"
		"mov %%rax, %c[rax](%3) \n\t"
		"mov %%rbx, %c[rbx](%3) \n\t"
		"pushq 0(%%rsp); popq %c[rcx](%3) \n\t"
		"mov %%rdx, %c[rdx](%3) \n\t"
		"mov %%rsi, %c[rsi](%3) \n\t"
		"mov %%rdi, %c[rdi](%3) \n\t"
		"mov %%rbp, %c[rbp](%3) \n\t"
		"mov %%r8,  %c[r8](%3) \n\t"
		"mov %%r9,  %c[r9](%3) \n\t"
		"mov %%r10, %c[r10](%3) \n\t"
		"mov %%r11, %c[r11](%3) \n\t"
		"mov %%r12, %c[r12](%3) \n\t"
		"mov %%r13, %c[r13](%3) \n\t"
		"mov %%r14, %c[r14](%3) \n\t"
		"mov %%r15, %c[r15](%3) \n\t"
		"mov %%cr2, %%rax   \n\t"
		"mov %%rax, %c[cr2](%3) \n\t"
		"mov 0(%%rsp), %3 \n\t"

		"pop  %%rcx; pop  %%r15; pop  %%r14; pop  %%r13; pop  %%r12;"
		"pop  %%r11; pop  %%r10; pop  %%r9;  pop  %%r8;"
		"pop  %%rbp; pop  %%rdi; pop  %%rsi;"
		"pop  %%rdx; pop  %%rbx; pop  %%rax \n\t"
		"setbe %0 \n\t"
		"popf \n\t"
	      : "=g" (fail)
	      : "r"(vcpu->launched), "r"((unsigned long)HOST_RSP),
		"c"(vcpu),
		[rax]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_RBP])),
		[r8 ]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_R8 ])),
		[r9 ]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_R9 ])),
		[r10]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vcpu_state, regs[VCPU_REGS_R15])),
		[cr2]"i"(offsetof(struct vcpu_state, cr2))
	      : "cc", "memory" );

	if (!fail) {
		if (fs_gs_ldt_reload_needed) {
			load_ldt(ldt_sel);
			load_fs(fs_sel);
			/*
			 * If we have to reload gs, we must take care to
			 * preserve our gs base.
			 */
			local_irq_disable();
			load_gs(gs_sel);
			wrmsrl(MSR_GS_BASE, vmcs_readl(HOST_GS_BASE));
			local_irq_enable();

			reload_tss();
		}
		vcpu->launched = 1;
	}
	put_cpu();
	return fail ? -1 : 0;
}

static long pico_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	struct vcpu_state *vcpu = vcpu0;
	long r = -EINVAL;

	switch (ioctl) {
	case PICO_VMENTRY:
		r = pico_dev_ioctl_vmentry(vcpu);
		break;
	case PICO_VMCS_READ: {
		struct pico_reg reg;

		r = -EFAULT;
		if (copy_from_user(&reg, (void *)arg, sizeof reg))
			goto out;
		r = vmcs_read(reg.field, &reg.value);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user((void *)arg, &reg, sizeof reg))
			goto out;
		r = 0;
		break;
	}
	case PICO_VMCS_WRITE: {
		struct pico_reg reg;

		r = -EFAULT;
		if (copy_from_user(&reg, (void *)arg, sizeof reg))
			goto out;
		r = vmcs_write(reg.field, reg.value);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user((void *)arg, &reg, sizeof reg))
			goto out;
		r = 0;
		break;
	}
	case PICO_VMCS_WRITE_EXEC_CTL: {
		struct pico_exec_ctl reg;

		r = -EFAULT;
		if (copy_from_user(&reg, (void *)arg, sizeof reg))
			goto out;
		vmcs_write32_fixedbits(reg.msr, reg.field, reg.value);
		r = -EFAULT;
		if (copy_to_user((void *)arg, &reg, sizeof reg))
			goto out;
		r = 0;
		break;
	}
	case PICO_REG_READ: {
		struct pico_reg reg;

		r = -EFAULT;
		if (copy_from_user(&reg, (void *)arg, sizeof reg))
			goto out;
		if (reg.field >= NR_VCPU_REGS) {
			r = -EINVAL;
			goto out;
		}
		reg.value = vcpu->regs[reg.field];
		r = -EFAULT;
		if (copy_to_user((void *)arg, &reg, sizeof reg))
			goto out;
		r = 0;
		break;
	}
	case PICO_REG_WRITE: {
		struct pico_reg reg;

		r = -EFAULT;
		if (copy_from_user(&reg, (void *)arg, sizeof reg))
			goto out;
		if (reg.field >= NR_VCPU_REGS) {
			r = -EINVAL;
			goto out;
		}
		vcpu->regs[reg.field] = reg.value;
		r = -EFAULT;
		if (copy_to_user((void *)arg, &reg, sizeof reg))
			goto out;
		r = 0;
		break;
	}
	case PICO_CREG_READ: {
		struct pico_reg reg;

		r = -EFAULT;
		if (copy_from_user(&reg, (void *)arg, sizeof reg))
			goto out;
		switch (reg.field) {
		case 2:
			reg.value = vcpu->cr2;
			r = 0;
			break;
		default:
			r = -EINVAL;
			goto out;
		}
		r = -EFAULT;
		if (copy_to_user((void *)arg, &reg, sizeof reg))
			goto out;
		r = 0;
		break;
	}
	case PICO_CREG_WRITE: {
		struct pico_reg reg;

		r = -EFAULT;
		if (copy_from_user(&reg, (void *)arg, sizeof reg))
			goto out;
		switch (reg.field) {
		case 2:
			vcpu->cr2 = reg.value;
			r = 0;
			break;
		default:
			r = -EINVAL;
			goto out;
		}
		r = -EFAULT;
		if (copy_to_user((void *)arg, &reg, sizeof reg))
			goto out;
		r = 0;
		break;
	}

	}
out:
	return r;
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

static __init struct vmcs *alloc_vmcs(void)
{
	int node = cpu_to_node(smp_processor_id());
	struct page *pages;
	struct vmcs *vmcs;

	pages = alloc_pages_node(node, GFP_KERNEL, vmcs_order);
	if (!pages)
		return NULL;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_size);
	vmcs->revision_id = vmcs_revision_id; /* vmcs revision id */
	return vmcs;
}

static void free_vmcs(struct vmcs *vmcs)
{
	free_pages((unsigned long)vmcs, vmcs_order);
}

static __init struct vcpu_state *alloc_vcpu(void)
{
	struct vcpu_state *vcpu;
	struct vmcs *vmcs;
	struct page *page;

	vmcs = alloc_vmcs();
	if (!vmcs)
		goto err_vmcs;
	page = alloc_page(GFP_KERNEL);
	if (!page)
		goto err_page;
	vcpu = kzalloc(sizeof(struct vcpu_state), GFP_KERNEL);
	if (!vcpu)
		goto err_vcpu;
	vcpu->vmcs = vmcs;
	vcpu->page = page;
	return vcpu;

err_vcpu:
	free_page((unsigned long)page_address(page));
err_page:
	free_vmcs(vmcs);
err_vmcs:
	return NULL;
}

static void free_vcpu(struct vcpu_state *vcpu)
{
	free_page((unsigned long)page_address(vcpu->page));
	free_vmcs(vcpu->vmcs);
	kfree(vcpu);
}

static __init void vmx_enable(struct vmcs *vmcs)
{
	u64 old;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);
	if ((old & 5) == 0)
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | 5);
	write_cr4(read_cr4() | X86_CR4_VMXE); /* FIXME: not cpu hotplug safe */
	vmxon(vmcs);
}

static void vmx_disable(void)
{
	vmxoff();
}

static __init int pico_init(void)
{
	int r;
	struct device *dev;

	if (!cpu_has_vmx_support()) {
		printk(KERN_ERR "pico: no hardware support\n");
		return -EOPNOTSUPP;
	}

	if (vmx_disabled_by_bios()) {
		printk(KERN_ERR "pico: disabled by bios\n");
		return -EOPNOTSUPP;
	}

	load_vmx_basic_msr();

	vmcs_init = alloc_vmcs();
	if (!vmcs_init) {
		printk(KERN_ERR "pico: vmcs allocation failed\n");
		goto err_vmcs;
	}

	vmx_enable(vmcs_init);

	vcpu0 = alloc_vcpu();
	if (!vcpu0) {
		printk(KERN_ERR "pico: vcpu allocation failed\n");
		goto err_vcpu;
	}

	pico_vcpu_setup(vcpu0);

	r = alloc_chrdev_region(&dev_id, 0, MINOR_COUNT, "pico");
	if (r < 0) {
		printk(KERN_ERR "pico: device allocation failed\n");
		goto err_vcpu;
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
	free_vcpu(vcpu0);
err_vcpu:
	vmx_disable();
	free_vmcs(vmcs_init);
err_vmcs:
	return -1;
}

static __exit void pico_exit(void)
{
	cdev_del(&c_dev);
	device_destroy(cl, dev_id);
	class_destroy(cl);
	unregister_chrdev_region(dev_id, MINOR_COUNT);
	vmx_disable();
	free_vcpu(vcpu0);
	printk(KERN_INFO "pico is unloaded\n");
}

module_init(pico_init);
module_exit(pico_exit);
