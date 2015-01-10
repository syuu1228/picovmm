#ifndef PICO_H
#define PICO_H

#include "picodev.h"
#include "vmx.h"
#include <stdint.h>

typedef int pico_handle_t;

pico_handle_t pico_open(void);
void pico_close(pico_handle_t handle);
int pico_vmentry(pico_handle_t handle);
uint64_t pico_vmread(pico_handle_t handle, unsigned long field);
void pico_vmwrite(pico_handle_t handle,  unsigned long field, unsigned long value);

#endif
