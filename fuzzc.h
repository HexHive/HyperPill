#ifndef FUZZC_H
#define FUZZC_H

// backends/xxx/control
bool cpu0_get_fuzztrace(void);
void cpu0_set_fuzztrace(bool fuzztrace);
bool cpu0_get_fuzz_executing_input(void);
void cpu0_set_fuzz_executing_input(bool fuzzing);
void cpu0_run_loop();

// backends/xxx/breakpoints
void handle_breakpoints(bxInstruction_c *i);
void handle_syscall_hooks(bxInstruction_c *i);
void apply_breakpoints_linux();

// backends/xxx/mem
void cpu0_mem_read_physical_page(bx_phy_address addr, size_t len, void *buf);
void cpu0_mem_write_physical_page(bx_phy_address addr, size_t len, void *buf);

// backends/xxx/regs
uint64_t cpu0_get_vmcsptr(void);
void icp_init_regs(const char* filename);
void dump_regs();
uint64_t cpu0_get_pc(void);
void cpu0_set_pc(uint64_t rip);
size_t init_random_register_data_len();
bool cpu0_get_user_pl(void);
void save_cpu();
void restore_cpu();
void init_cpu();
void cpu0_set_general_purpose_reg64(unsigned reg, uint64_t value);
uint64_t cpu0_get_general_purpose_reg64(unsigned reg);

// fuzz.cc
void fuzz_dma_read_cb(bx_phy_address addr, unsigned len, void* data);

// main.cc
void fuzz_emu_stop_normal();
void fuzz_emu_stop_unhealthy();
void fuzz_emu_stop_crash(const char *type);
void fuzz_hook_exception(unsigned vector, unsigned error_code);
void fuzz_hook_hlt();
void fuzz_interrupt(unsigned cpu, unsigned vector);
void fuzz_after_execution(bxInstruction_c *i);
void fuzz_before_execution(uint64_t icount);

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
