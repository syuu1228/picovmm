#include "pico.h"
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

pico_handle_t pico_open(void)
{
	pico_handle_t handle = open("/dev/pico", O_RDWR);
	if (handle < 0) {
		perror("open");
		return handle;
	}
	return handle;
}

void pico_close(pico_handle_t handle)
{
	close(handle);
}

int pico_vmentry(pico_handle_t handle)
{
	return ioctl(handle, PICO_VMENTRY);
}

uint64_t pico_vmread(pico_handle_t handle, unsigned long field)
{
	struct pico_reg reg;
	int ret;

	reg.field = field;
	ret = ioctl(handle, PICO_VMREAD, &reg);
	assert(ret);
	return reg.value;
}

void pico_vmwrite(pico_handle_t handle, unsigned long field,
	unsigned long value)
{
	struct pico_reg reg;
	int ret;

	reg.field = field;
	reg.value = value;
	ret = ioctl(handle, PICO_VMWRITE, &reg);
	assert(ret);
}

uint64_t pico_reg_read(pico_handle_t handle, enum vcpu_regs index)
{
	struct pico_reg reg;
	int ret;

	reg.field = index;
	ret = ioctl(handle, PICO_REG_READ, &reg);
	assert(ret);
	return reg.value;
}

void pico_reg_write(pico_handle_t handle, enum vcpu_regs index, unsigned long value)
{
	struct pico_reg reg;
	int ret;

	reg.field = index;
	reg.value = value;
	ret = ioctl(handle, PICO_REG_WRITE, &reg);
	assert(ret);
}

uint64_t pico_creg_read(pico_handle_t handle, int index)
{
	struct pico_reg reg;
	int ret;

	reg.field = index;
	ret = ioctl(handle, PICO_CREG_READ, &reg);
	assert(ret);
	return reg.value;
}

void pico_creg_write(pico_handle_t handle,  int index, unsigned long value)
{
	struct pico_reg reg;
	int ret;

	reg.field = index;
	reg.value = value;
	ret = ioctl(handle, PICO_CREG_WRITE, &reg);
	assert(ret);
}

