#ifndef HYPERPILL_QEMU_H
#define HYPERPILL_QEMU_H

#ifdef __cplusplus
extern "C" {
#endif

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/thread.h"
#include "migration/snapshot.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"
#include "sysemu/runstate.h"
#include "sysemu/cpus.h"
#include "exec/hwaddr.h"
#include "exec/gdbstub.h"
#include "gdbstub/internals.h"

#include "hw/registerfields.h"
/* <qemu>/target/arm/ */
#include "cpu.h"

#include "accel/tcg/internal-target.h"

#include "qemu/qemu-plugin.h"
#include "qemu/plugin-memory.h"
#include "plugin.h"

typedef uint64_t hp_address;
typedef uint64_t hp_phy_address;
typedef void hp_instruction;

extern CPUState cpu0;
extern CPUState shadow_cpu0;
#define QEMU_CPU(x) (&cpu0)

extern QemuMutex barrier_mutex;
extern QemuCond barrier_cond;
bool qemu_reload_vm(char *tag);

/* AARCH64 cpu related functions */
void aarch64_set_xregs(uint64_t xregs[32]);

typedef enum aa64_syndrom {
    HVC = 0,
    RW,
} aa64_syndrom;

const uint8_t excp_codes[2] = {
    0x16,   // AA64_HVC
    0x24    // DATAABORT
};

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
void qemu_tb_before_execution(hp_instruction *i);
void qemu_tb_after_execution(hp_instruction *i);

// control.c
bool __cpu0_get_fuzztrace(void);
void __cpu0_set_fuzztrace(bool fuzztrace);
bool __cpu0_get_fuzz_executing_input(void);
void __cpu0_set_fuzz_executing_input(bool fuzzing);

// mem.c
void __cpu0_mem_read_physical_page(uint64_t addr, size_t len, void *buf);
void __cpu0_mem_write_physical_page(uint64_t addr, size_t len, void *buf);
int __cpu0_memory_rw_debug(uint64_t addr, void *ptr, size_t len, bool is_write);

// regs.c
uint64_t __cpu0_get_pc();
void __cpu0_set_pc(uint64_t pc);
void __dump_regs();


// fuzz.cc
void fuzz_dma_read_cb(hp_phy_address addr, unsigned len, void* data);
bool __fuzz_emu_stop_normal(void);

#ifdef __cplusplus
}
#endif

#endif
