#ifndef FUZZC_H
#define FUZZC_H

#if defined(HP_X86_64)
#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#define NM_PREFIX ""
#endif

#if defined(HP_X86_64)
typedef bx_address hp_address;
typedef bx_phy_address hp_phy_address;
typedef bxInstruction_c hp_instruction;
#endif

// backends/xxx/control
bool cpu0_get_fuzztrace(void);
void cpu0_set_fuzztrace(bool fuzztrace);
bool cpu0_get_fuzz_executing_input(void);
void cpu0_set_fuzz_executing_input(bool fuzzing);
void cpu0_run_loop();

// backends/xxx/breakpoints
void apply_breakpoints_linux();

// backends/xxx/init
void icp_init_backend();

// backends/xxx/mem
void fuzz_hook_memory_access(hp_address phy, unsigned len,
                             unsigned memtype, unsigned rw, void* data);
void fuzz_clear_dirty();
void fuzz_watch_memory_inc();
void fuzz_reset_memory();
void icp_init_mem(const char* filename);
void cpu0_read_virtual(hp_address start, size_t size, void *data);
void cpu0_write_virtual(hp_address start, size_t size, void *data);
bool cpu0_read_instr_buf(size_t pc, uint8_t *instr_buf);
hp_phy_address cpu0_virt2phy(hp_address start);
void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf);
void cpu0_mem_write_physical_page(hp_phy_address addr, size_t len, void *buf);
void cpu0_tlb_flush(void);

void cpu_physical_memory_read_fastpath(uint64_t addr, void* dest, size_t len);
void cpu_physical_memory_write_fastpath(uint64_t addr, const void* src, size_t len);

// backends/xxx/regs
#if defined(HP_X86_64)
uint64_t cpu0_get_vmcsptr(void);
#endif
void icp_init_regs(const char* filename);
void dump_regs();
uint64_t cpu0_get_pc(void);
void cpu0_set_pc(uint64_t rip);
size_t init_random_register_data_len();
bool cpu0_get_user_pl(void);
void save_cpu();
void restore_cpu();
void cpu0_set_general_purpose_reg64(unsigned reg, uint64_t value);
uint64_t cpu0_get_general_purpose_reg64(unsigned reg);

// backends/xxx/ept/s2pt
void mark_page_not_guest(hp_phy_address addr, int level);
void mark_l2_guest_page(uint64_t paddr, uint64_t len, uint64_t addr);
void mark_l2_guest_pagetable(uint64_t paddr, uint64_t len, uint8_t level);
int gpa2hpa(hp_phy_address guest_paddr, hp_phy_address *phy, int *translation_level);
bool gva2hpa(hp_address laddr, hp_phy_address *phy);
#if defined(HP_X86_64)
void ept_locate_pc();
void ept_mark_page_table();
#endif

bool frame_is_guest(hp_phy_address addr);

// fuzz.cc
void fuzz_dma_read_cb(hp_phy_address addr, unsigned len, void* data);

// main.cc
void fuzz_emu_stop_normal();
void fuzz_emu_stop_unhealthy();
void fuzz_emu_stop_crash(const char *type);
void fuzz_hook_exception(unsigned vector, unsigned error_code);
void fuzz_hook_hlt();
void fuzz_interrupt(unsigned cpu, unsigned vector);
void fuzz_after_execution(hp_instruction *i);
void fuzz_before_execution(uint64_t icount);

// cov.cc
void print_stacktrace();
void add_edge(uint64_t prev_rip, uint64_t new_rip);
// sysret (x86) -> eret (AARCH64)
uint32_t get_sysret_status();
void reset_sysret_status();
void set_sysret_status(uint32_t new_status);
void add_stacktrace(hp_address branch_rip, hp_address new_rip);
void pop_stacktrace(void);
bool empty_stacktrace(void);
void fuzz_stacktrace();

// feedback.cc
#if defined(HP_X86_64)
bool fuzz_hook_vmlaunch();
#endif
void fuzz_hook_cmp(uint64_t op1, uint64_t op2, size_t size);

// slat.cc
uint64_t pow64(uint64_t x, uint64_t y);

// hmem.cc
extern uint8_t* is_l2_page_bitmap; /* Page is in L2 */
extern uint8_t* is_l2_pagetable_bitmap; /* Page is in L2 */
void fuzz_mark_l2_guest_page(uint64_t paddr, uint64_t len);
void fuzz_reset_watched_pages();

// sym2addr_linux.cc
typedef struct addr_bin_name {
    size_t addr;
    const char *bin;
    const char *name;
    int off;
} addr_bin_name;
bool addr_to_sym(addr_bin_name *addr_bin_name);
bool sym_to_addr(addr_bin_name *addr_bin_name);
uint64_t sym_to_addr2(const char *bin, const char *name);

#endif
