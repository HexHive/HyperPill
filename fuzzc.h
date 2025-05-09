#ifndef FUZZC_H
#define FUZZC_H

#ifndef HP_BACKEND_QEMU
#define HP_BACKEND_QEMU
#endif
#ifndef HP_AARCH64
#define HP_AARCH64
#endif

#if defined(HP_X86_64)
typedef bx_address hp_address;
typedef bx_phy_address hp_phy_address;
typedef bxInstruction_c hp_instruction;
#elif defined(HP_AARCH64)
typedef uint64_t hp_address;
typedef uint64_t hp_phy_address;
typedef void hp_instruction;
#endif

#ifdef __cplusplus
#if defined(HP_BACKEND_QEMU)
extern "C" {
#endif
#endif

#if defined(HP_X86_64)
#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#define NM_PREFIX ""
#elif defined(HP_AARCH64)
#include <libgen.h>
#define NM_PREFIX "aarch64-linux-gnu-"
#endif

extern size_t maxaddr;

// backends/xxx/control
bool cpu0_get_fuzztrace(void);
void cpu0_set_fuzztrace(bool fuzztrace);
bool cpu0_get_fuzz_executing_input(void);
void cpu0_set_fuzz_executing_input(bool fuzzing);
void cpu0_run_loop();

// backends/xxx/breakpoints
void handle_syscall_hooks(hp_instruction *i);
void apply_breakpoints_linux();

// backends/xxx/dbg
void icp_init_gdb();

// backends/xxx/init
void icp_init_backend();

// backends/xxx/instrument
#if defined(HP_AARCH64)
void write_pcs_execution(uint64_t pc, uint64_t pc_last);
void qemu_ctrl_flow_insn(uint64_t branch_pc, uint64_t new_pc);
#endif

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
void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf);
void cpu0_mem_write_physical_page(hp_phy_address addr, size_t len, void *buf);
void cpu0_tlb_flush(void);

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
#if defined(HP_AARCH64)
void aarch64_set_esr_el2_for_hvc();
void aarch64_set_esr_el2_for_data_abort(int sas, int srt, int write_or_read);
void aarch64_set_far_el2(uint64_t far);
uint64_t aarch64_get_far_el2(void);
void aarch64_set_hpfar_el2(uint64_t addr);
uint64_t aarch64_get_hpfar_el2(void);
#endif

// backends/xxx/ept/s2pt
#if defined(HP_X86_64)
void ept_locate_pc();
#endif
void mark_page_not_guest(hp_phy_address addr, int level);
void mark_l2_guest_page(uint64_t paddr, uint64_t len, uint64_t addr);
void mark_l2_guest_pagetable(uint64_t paddr, uint64_t len, uint8_t level);
int gpa2hpa(hp_phy_address guest_paddr, hp_phy_address *phy, int *translation_level);
bool gva2hpa(hp_address laddr, hp_phy_address *phy);
#if defined(HP_X86_64)
void ept_mark_page_table();
#elif defined(HP_AARCH64)
void s2pt_mark_page_table();
#endif

// fuzz.cc
void fuzz_dma_read_cb(hp_phy_address addr, unsigned len, void* data);

// main.cc
void fuzz_emu_stop_normal();
void fuzz_emu_stop_unhealthy();
void fuzz_emu_stop_crash(const char *type);
void fuzz_hook_exception(unsigned vector, unsigned error_code);
void fuzz_hook_hlt();
unsigned long int get_icount();
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
#elif defined(HP_AARCH64)
bool fuzz_hook_back_to_el1_kernel(void);
#endif
void fuzz_hook_cmp(uint64_t op1, uint64_t op2, size_t size);

// slat.cc
uint64_t pow64(uint64_t x, uint64_t y);

// mem.cc
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

#ifdef __cplusplus
#if defined(HP_BACKEND_QEMU)
}
#endif
#endif

#endif
