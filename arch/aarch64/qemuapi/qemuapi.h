#ifndef HYPERPILL_QEMU_API_H
#define HYPERPILL_QEMU_API_H

#ifdef __cplusplus
extern "C" {
#endif

/* QEMU related functionality */
void init_qemu(int argc, char **argv, char *snapshot_tag);

bool qemu_reload_vm(char *tag);

void qemu_start_vm();

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

void aarch64_set_esr_el2(aa64_syndrom syndrom);

/* Concurrency related stuff */
void qemu_wait_until_stop();
void qemu_signal_stop();
void qemu_set_running();
bool qemu_is_running();

// mem.c
int __cpu0_memory_rw_debug(uint64_t addr, void *ptr, size_t len, bool is_write);

// regs.c
uint64_t __cpu0_get_pc();
void __cpu0_set_pc(uint64_t pc);
void __dump_regs();

// instrument.cc
void qemu_ctrl_flow_insn(uint64_t branch_pc, uint64_t new_pc);

#ifdef __cplusplus
}
#endif

#endif