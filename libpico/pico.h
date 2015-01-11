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
uint64_t pico_reg_read(pico_handle_t handle, enum vcpu_regs index);
void pico_reg_write(pico_handle_t handle, enum vcpu_regs index, unsigned long value);
uint64_t pico_creg_read(pico_handle_t handle, int index);
void pico_creg_write(pico_handle_t handle,  int index, unsigned long value);

#endif
