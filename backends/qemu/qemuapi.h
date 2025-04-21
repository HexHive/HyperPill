#ifndef HYPERPILL_QEMUAPI_H
#define HYPERPILL_QEMUAPI_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

void aarch64_set_esr_el2_for_hvc();
void aarch64_set_esr_el2_for_data_abort(int sas, int srt, int write_or_read);
void aarch64_set_far_el2(uint64_t far);
uint64_t aarch64_get_far_el2(void);
uint64_t aarch64_get_hpfar_el2(void);
void aarch64_set_hpfar_el2(uint64_t addr);
void aarch64_set_xreg(uint64_t index, uint64_t value);

/* Concurrency related stuff */
void qemu_wait_until_stop();
bool qemu_is_running();

// breakpoints.cc
bool __add_breakpoint(uint64_t addr, int (*h)(void));

// instrument.cc
void write_pcs_execution(uint64_t pc, uint64_t pc_last);
void qemu_ctrl_flow_insn(uint64_t branch_pc, uint64_t new_pc);
bool fuzz_hook_back_to_el1_kernel();
void qemu_tb_before_execution(void *i);
void qemu_tb_after_execution(void *i);

// fuzz.cc
void fuzz_dma_read_cb(uint64_t addr, unsigned len, void* data);
bool __fuzz_emu_stop_normal(void);

#endif