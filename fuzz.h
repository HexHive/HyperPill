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

#if defined(HP_X86_64)
#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"
#elif defined(HP_AARCH64)
// TODO
#else
#error
#endif

#if defined(HP_X86_64)
typedef bx_address hp_address;
typedef bx_phy_address hp_phy_address;
typedef bxInstruction_c hp_instruction;
#elif defined(HP_AARCH64)
typedef uint64_t hp_address; // TODO
typedef uint64_t hp_phy_address; // TODO
typedef void hp_instruction; // TODO
#else
#error
#endif

extern bool fuzzing;
extern size_t maxaddr;
extern bool master_fuzzer;
extern bool verbose;
#ifdef __cplusplus
extern tsl::robin_set<hp_address> cur_input;
extern std::vector<size_t> guest_page_scratchlist; 
#endif

#define verbose_printf(...) if(verbose) printf(__VA_ARGS__)

// arch-specific APIs
uint64_t lookup_gpa_by_hpa(uint64_t hpa);
void cpu_physical_memory_read(uint64_t addr, void* dest, size_t len);
void cpu_physical_memory_write(uint64_t addr, const void* src, size_t len);
void cpu0_mem_write_physical_page(hp_phy_address addr, size_t len, void *buf);
void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf);
void cpu0_read_virtual(hp_address start, size_t size, void *data);
void cpu0_write_virtual(hp_address start, size_t size, void *data);
bool cpu0_read_instr_buf(size_t pc, uint8_t *instr_buf);
void mark_l2_guest_page(uint64_t paddr, uint64_t len, uint64_t addr);
void mark_l2_guest_pagetable(uint64_t paddr, uint64_t len, uint8_t level);
void hp_add_persistent_memory_range(hp_address start, size_t len);
void icp_init_params();
void icp_init_mem(const char* filename);
void icp_init_regs(const char* filename);
void fuzz_reset_memory();
void fuzz_watch_memory_inc();
void fuzz_clear_dirty();
bool cpu0_get_fuzztrace(void);
void cpu0_set_fuzztrace(bool fuzztrace);
extern "C" bool cpu0_get_fuzz_executing_input(void);
extern "C" void cpu0_set_fuzz_executing_input(bool fuzzing);

#if defined(HP_X86_64)
extern uint64_t vmcs_addr;
void icp_set_vmcs(uint64_t vmcs);
void redo_paging();
void vmcs_fixup();
void icp_init_shadow_vmcs_layout(const char* filename);
bool vmcs_linear2phy(bx_address laddr, bx_phy_address *phy);
int vmcs_translate_guest_physical_ept(bx_phy_address guest_paddr, bx_phy_address *phy, int *translation_level);
#endif

void ept_mark_page_table();
void ept_locate_pc();
void mark_page_not_guest(hp_phy_address addr, int level);
bool frame_is_guest(hp_phy_address addr);
void dump_regs();
void walk_ept(bool enum_mmio);
void fuzz_walk_ept();
void fuzz_walk_cr3();
void fuzz_hook_memory_access(hp_address phy, unsigned len, 
                             unsigned memtype, unsigned rw, void* data);
void handle_breakpoints(hp_instruction *i);
void handle_syscall_hooks(hp_instruction *i);
void apply_breakpoints_linux();
uint64_t cpu0_get_pc(void);
void cpu0_set_pc(uint64_t rip);

// fuzz.cc
void clear_seen_dma();
void hyperpill_fuzz_dma_read_cb(hp_phy_address addr, unsigned len, void* data);
bool op_clock_step();
bool inject_in(uint16_t addr, uint16_t size);
bool inject_out(uint16_t addr, uint16_t size, uint32_t value);
bool inject_read(hp_address addr, int size);
bool inject_write(hp_address addr, int size, uint64_t val);
bool inject_halt();
uint32_t inject_pci_read(uint8_t device, uint8_t function, uint8_t offset);
bool inject_pci_write(uint8_t device, uint8_t function, uint8_t offset, uint32_t value);
uint64_t inject_rdmsr(hp_address msr);
bool inject_wrmsr(hp_address msr, uint64_t value);
void insert_register_value_into_fuzz_input(int idx);
void set_pci_device(uint8_t dev, uint8_t function);
void init_regions(const char* path);
void add_pio_region(uint16_t addr, uint16_t size);
void add_mmio_region(uint64_t addr, uint64_t size);
void add_mmio_range_alt(uint64_t addr, uint64_t end);

// main.cc
void fuzz_instr_before_execution(hp_instruction *i);
void fuzz_instr_after_execution(hp_instruction *i);
void fuzz_instr_interrupt(unsigned cpu, unsigned vector);
extern "C" void fuzz_emu_stop_normal();
void fuzz_emu_stop_unhealthy();
void fuzz_emu_stop_crash(const char *type);
void fuzz_hook_exception(unsigned vector, unsigned error_code);
void fuzz_hook_hlt();
void fuzz_reset_exception_counter();
void fuzz_run_input(const uint8_t* Data, size_t Size);
void start_cpu();
unsigned long int get_icount();
unsigned long int get_pio_icount();
void reset_vm();

// conveyor.h
#include "conveyor.h"

// cov.cc
void add_pc_range(size_t base, size_t len);
bool ignore_pc(hp_address pc);
void print_stacktrace();
void add_edge(hp_address prev_rip, hp_address new_rip);
void reset_op_cov(void);
void reset_cur_cov(void);
// sysret means returning from a syscall to user mode
// equivalent of sysret on ARMv8 is eret
uint32_t get_sysret_status(void);
void reset_sysret_status(void);
void set_sysret_status(uint32_t new_status);
void add_stacktrace(hp_address branch_rip, hp_address new_rip);
void pop_stacktrace(void);
void fuzz_stacktrace(void);
bool empty_stacktrace(void);

// db.cc
void open_db(const char* path);
void insert_mmio(uint64_t addr, uint64_t len);
void insert_pio(uint16_t addr, uint16_t len);
#ifdef __cplusplus
void load_regions(std::map<uint16_t, uint16_t> &pio_regions, std::map<hp_address, uint32_t> &mmio_regions);
void load_manual_ranges(char* range_file, char* range_regex, std::map<uint16_t, uint16_t> &pio_regions, std::map<hp_address, uint32_t> &mmio_regions);
#endif

// enum.cc
void enum_pio_regions();
void enum_mmio_regions();
void enum_handle_ept_gap(unsigned int gap_reason,
        hp_address gap_start, hp_address gap_end);

// feedback.c
void add_indicator_value(uint64_t val);
void clear_indicator_values();
void dump_indicators();
void aggregate_indicators();
void indicator_cb(void(*cb)(uint64_t));
void fuzz_hook_cmp(uint64_t op1, uint64_t op2, size_t size);
size_t init_random_register_data_len();
void init_register_feedback();
#if defined(HP_X86_64)
bool fuzz_hook_vmlaunch();
#elif defined(HP_AARCH64)
// TODO
#else
#error
#endif

// link_map.c
void load_link_map(char* map_path, char* obj_regex, size_t base);

// sourcecov.c
void init_sourcecov(size_t baseaddr);
void setup_periodic_coverage();
void check_write_coverage();

// sym2addr_linux.cc
#ifdef __cplusplus
void load_symbol_map(char *path);
hp_address sym_to_addr(std::string bin, std::string name);
std::pair<std::string, std::string> addr_to_sym(size_t addr);
#endif

// symbolize.cc
void load_symbolization_files(char* path);
void symbolize(size_t pc);

#endif
