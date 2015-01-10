#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "pico.h"
#include "vmx.h"


int main(void)
{
	int fd = open("/dev/pico", O_RDWR);
	if (fd < 0) {
		perror("open");
		return fd;
	}
	struct pico_reg reg;
	reg.field = GUEST_CR0; 
	reg.value = 0x3;
	int ret = ioctl(fd, PICO_VMWRITE, &reg);
	if (ret < 0) {
		perror("vmwrite");
		close(fd);
		return ret;
	}
	printf("write cr0:%lx\n", reg.value);
	reg.field = GUEST_CR0; 
	ret = ioctl(fd, PICO_VMREAD, &reg);
	if (ret < 0) {
		perror("vmread");
		close(fd);
		return ret;
	}
	printf("read cr0:%lx\n", reg.value);
	return 0;
}

