#ifndef FUZZ_H
#define FUZZ_H

#include <stdint.h>

#ifdef __cplusplus
#include <map>
#include <vector>
#include <cstring>
#include <tsl/robin_set.h>
#endif

#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(HP_BACKEND_QEMU)
extern "C" {
#endif
#if defined(HP_X86_64)
#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#define NM_PREFIX ""
#elif defined(HP_AARCH64)
#include "qemuapi.h"
#include <libgen.h>
#define NM_PREFIX "aarch64-linux-gnu-"
#endif
#if defined(HP_BACKEND_QEMU)
}
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

extern bool fuzzing;
extern tsl::robin_set<hp_address> cur_input;
extern size_t maxaddr;
extern bool master_fuzzer;
extern bool verbose;
extern std::vector<size_t> guest_page_scratchlist;

#define verbose_printf(...) if(verbose) printf(__VA_ARGS__)

#include "conveyor.h"

#if defined(HP_BACKEND_QEMU)
extern "C" {
#endif
uint64_t lookup_gpa_by_hpa(uint64_t hpa);

void hp_cpu_physical_memory_read(uint64_t addr, void* dest, size_t len);
void hp_cpu_physical_memory_write(uint64_t addr, const void* src, size_t len);
void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf);
void cpu0_mem_write_physical_page(hp_phy_address addr, size_t len, void *buf);
void cpu0_read_virtual(hp_address start, size_t size, void *data);
void cpu0_write_virtual(hp_address start, size_t size, void *data);
bool cpu0_read_instr_buf(size_t pc, uint8_t *instr_buf);
void cpu0_tlb_flush(void);
void mark_l2_guest_page(uint64_t paddr, uint64_t len, uint64_t addr);
void mark_l2_guest_pagetable(uint64_t paddr, uint64_t len, uint8_t level);
void add_persistent_memory_range(hp_address start, size_t len);

void icp_init_backend();
void icp_init_mem(const char* filename);
void icp_init_regs(const char* filename);
#if defined(HP_X86_64)
void icp_init_shadow_vmcs_layout(const char* filename);
void icp_set_vmcs(uint64_t vmcs);
void icp_set_vmcs_map();
void bx_init_pc_system();
#endif
#if defined(HP_BACKEND_QEMU)
}
#endif

void clear_seen_dma();
void fuzz_dma_read_cb(hp_phy_address addr, unsigned len, void* data);

extern int in_clock_step;
enum {
	CLOCK_STEP_NONE,
	CLOCK_STEP_GET_DEADLINE,
	CLOCK_STEP_GET_NS,
	CLOCK_STEP_WARP,
	CLOCK_STEP_DONE
};
bool op_clock_step();

void fuzz_hook_memory_access(hp_address phy, unsigned len,
                             unsigned memtype, unsigned rw, void* data);
void fuzz_hook_exception(unsigned vector, unsigned error_code);
void fuzz_hook_hlt();
void fuzz_hook_cmp(uint64_t op1, uint64_t op2, size_t size);
#if defined(HP_X86_64)
bool fuzz_hook_vmlaunch();
#elif defined(HP_AARCH64)
bool fuzz_hook_back_to_el1_kernel(void);
#endif

// sysret (x86) -> eret (AARCH64)
uint32_t get_sysret_status();
void reset_sysret_status();
void set_sysret_status(uint32_t new_status);

#if defined(HP_BACKEND_QEMU)
extern "C" {
#endif
size_t init_random_register_data_len();

void fuzz_reset_memory();
void fuzz_watch_memory_inc();
void fuzz_clear_dirty();

#if defined(HP_X86_64)
extern uint64_t vmcs_addr;
void redo_paging();
void vmcs_fixup();
#endif

void add_indicator_value(uint64_t val);
void clear_indicator_values();
void dump_indicators();
void aggregate_indicators();
void indicator_cb(void(*cb)(uint64_t));

hp_phy_address cpu0_virt2phy(hp_address addr);
bool gva2hpa(hp_address laddr, hp_phy_address *phy);
int gpa2hpa(hp_phy_address guest_paddr, hp_phy_address *phy, int *translation_level);
void walk_s1_slow(
    bool guest,
    void (*page_table_cb)(hp_phy_address address, int level),
    void (*leaf_pte_cb)(hp_phy_address addr, hp_phy_address pte, hp_phy_address mask)
);
void s2pt_mark_page_table();
void ept_locate_pc();
extern void mark_page_not_guest(hp_phy_address addr, int level);
bool frame_is_guest(hp_phy_address addr);

#if defined(HP_X86_64)
uint64_t cpu0_get_vmcsptr(void);
#endif
bool cpu0_get_user_pl(void);
uint64_t cpu0_get_pc(void);
void cpu0_set_general_purpose_reg64(unsigned reg, uint64_t value);
uint64_t cpu0_get_general_purpose_reg64(unsigned reg);
void cpu0_set_pc(uint64_t rip);
bool cpu0_get_fuzztrace(void);
void cpu0_set_fuzztrace(bool fuzztrace);
bool cpu0_get_fuzz_executing_input(void);
void cpu0_set_fuzz_executing_input(bool fuzzing);
void save_cpu();
void restore_cpu();
void cpu0_run_loop();
void start_cpu();
void dump_regs();
unsigned long int get_icount();
#if defined(HP_X86_64)
unsigned long int get_pio_icount();
#endif
void reset_vm();

void fuzz_walk_slat();
void fuzz_walk_cr3();

typedef void (*breakpoint_handler_t)(hp_instruction *);
hp_address add_breakpoint(hp_address addr, breakpoint_handler_t h);
void handle_breakpoints(hp_instruction *i);
void __handle_syscall_hooks(hp_instruction *i);
void __apply_breakpoints_linux();
#if defined(HP_BACKEND_QEMU)
}
#endif

// core
void fuzz_instr_before_execution(hp_instruction *i);
void fuzz_instr_after_execution(hp_instruction *i);
void fuzz_instr_interrupt(unsigned cpu, unsigned vector);
void add_edge(hp_address prev_rip, hp_address new_rip);
void print_stacktrace();
bool ignore_pc(hp_address pc);
void add_pc_range(size_t base, size_t len);

void fuzz_emu_stop_normal();
void fuzz_emu_stop_unhealthy();
void fuzz_emu_stop_crash(const char *type);

#if defined(HP_X86_64)
void enum_pio_regions();
#endif
void enum_mmio_regions();
void enum_handle_s2pt_gap(unsigned int gap_reason,
        hp_address gap_start, hp_address gap_end);

#if defined(HP_X86_64)
bool inject_in(uint16_t addr, uint16_t size);
bool inject_out(uint16_t addr, uint16_t size, uint32_t value);
#endif
bool inject_read(hp_address addr, int size);
bool inject_write(hp_address addr, int size, uint64_t val);

#if defined(HP_X86_64)
bool inject_halt();
uint32_t inject_pci_read(uint8_t device, uint8_t function, uint8_t offset);
bool inject_pci_write(uint8_t device, uint8_t function, uint8_t offset, uint32_t value);
uint64_t inject_rdmsr(hp_address msr);
bool inject_wrmsr(hp_address msr, uint64_t value);
void set_pci_device(uint8_t dev, uint8_t function);
#endif

#if defined(HP_X86_64)
void add_pio_region(uint16_t addr, uint16_t size);
#endif
void add_mmio_region(uint64_t addr, uint64_t size);
void add_mmio_range_all(uint64_t addr, uint64_t end);

void open_db(const char* path);
void insert_mmio(uint64_t addr, uint64_t len);
void insert_pio(uint16_t addr, uint16_t len);
void load_regions(std::map<uint16_t, uint16_t> &pio_regions, std::map<hp_address, uint32_t> &mmio_regions);
void load_manual_ranges(char* range_file, char* range_regex, std::map<uint16_t, uint16_t> &pio_regions, std::map<hp_address, uint32_t> &mmio_regions);
void init_regions(const char* path);

void init_register_feedback();
void insert_register_value_into_fuzz_input(int idx);

void fuzz_run_input(const uint8_t* Data, size_t Size);

void reset_op_cov();
void reset_cur_cov();
void load_symbolization_files(char* path);
void symbolize(size_t pc);

// sym2addr_linux.cc
void load_symbol_map(char *path);
hp_address sym_to_addr(std::string bin, std::string name);
std::pair<std::string, std::string> addr_to_sym(size_t addr);

// link_map.c
void load_link_map(char* map_path, char* obj_regex, size_t base);

// sourcecov.c
void write_source_cov();
void init_sourcecov(size_t baseaddr);
void setup_periodic_coverage();
void check_write_coverage();

// breakpoints.cc
void handle_syscall_hooks(hp_instruction *i);
void apply_breakpoints_linux();

//stacktrace
void fuzz_stacktrace();
void add_stacktrace(hp_address branch_rip, hp_address new_rip);
void pop_stacktrace(void);
bool empty_stacktrace(void);

#endif
