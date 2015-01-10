#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "pico.h"

int main(void)
{
	pico_handle_t handle = pico_open();
	int ret = pico_vmentry(handle);
	printf("ret:%d\n", ret);
	pico_close(handle);
}
