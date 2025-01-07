#ifndef HYPERPILL_QEMU_API_H
#define HYPERPILL_QEMU_API_H

#ifdef __cplusplus
extern "C" {
#endif

/* QEMU related functionality */
void init_qemu(int argc, char **argv, char *snapshot_tag);

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

void aarch64_set_esr_el2(aa64_syndrom syndrom);

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
void qemu_ctrl_flow_insn(uint64_t branch_pc, uint64_t new_pc);

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



#ifdef __cplusplus
}
#endif

#endif
