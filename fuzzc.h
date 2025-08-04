#ifndef FUZZC_H
#define FUZZC_H

// backends/xxx/control
bool cpu0_get_fuzztrace(void);
void cpu0_set_fuzztrace(bool fuzztrace);
bool cpu0_get_fuzz_executing_input(void);
void cpu0_set_fuzz_executing_input(bool fuzzing);
void cpu0_run_loop();

// backends/xxx/mem
void cpu0_mem_read_physical_page(bx_phy_address addr, size_t len, void *buf);
void cpu0_mem_write_physical_page(bx_phy_address addr, size_t len, void *buf);

// backends/xxx/regs
uint64_t cpu0_get_pc(void);
void cpu0_set_pc(uint64_t rip);
void save_cpu();
void restore_cpu();

// cov.cc
void print_stacktrace();
void add_edge(uint64_t prev_rip, uint64_t new_rip);
// sysret (x86) -> eret (AARCH64)
uint32_t get_sysret_status();
void reset_sysret_status();
void set_sysret_status(uint32_t new_status);
void add_stacktrace(bx_address branch_rip, bx_address new_rip);
void pop_stacktrace(void);
bool empty_stacktrace(void);
void fuzz_stacktrace();

#endif
