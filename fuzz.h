#ifndef FUZZ_H
#define FUZZ_H

#include <stdint.h>
#include <map>
#include <vector>
#include <cstring>
#include <tsl/robin_set.h>

#include "bochs.h"
#include "cpu/cpu.h"
#include "memory/memory-bochs.h"

#define PG_PRESENT_BIT  0
#define PG_RW_BIT       1
#define PG_USER_BIT     2
#define PG_PWT_BIT      3
#define PG_PCD_BIT      4
#define PG_ACCESSED_BIT 5
#define PG_DIRTY_BIT    6
#define PG_PSE_BIT      7
#define PG_GLOBAL_BIT   8
#define PG_PSE_PAT_BIT  12
#define PG_PKRU_BIT     59
#define PG_NX_BIT       63

#define PG_PRESENT_MASK  (1 << PG_PRESENT_BIT)
#define PG_RW_MASK       (1 << PG_RW_BIT)
#define PG_USER_MASK     (1 << PG_USER_BIT)
#define PG_PWT_MASK      (1 << PG_PWT_BIT)
#define PG_PCD_MASK      (1 << PG_PCD_BIT)
#define PG_ACCESSED_MASK (1 << PG_ACCESSED_BIT)
#define PG_DIRTY_MASK    (1 << PG_DIRTY_BIT)
#define PG_PSE_MASK      (1 << PG_PSE_BIT)
#define PG_GLOBAL_MASK   (1 << PG_GLOBAL_BIT)
#define PG_PSE_PAT_MASK  (1 << PG_PSE_PAT_BIT)
#define PG_ADDRESS_MASK  0x000ffffffffff000LL
#define PG_HI_USER_MASK  0x7ff0000000000000LL
#define PG_PKRU_MASK     (15ULL << PG_PKRU_BIT)
#define PG_NX_MASK       (1ULL << PG_NX_BIT)


extern bool fuzzing;
extern tsl::robin_set<bx_address> cur_input;
extern size_t maxaddr;
extern bool master_fuzzer;
extern bool verbose;
extern std::vector<size_t> guest_page_scratchlist; 

#define verbose_printf(...) if(verbose) printf(__VA_ARGS__)

enum {
  BX_LEVEL_PML4 = 3,
  BX_LEVEL_PDPTE = 2,
  BX_LEVEL_PDE = 1,
  BX_LEVEL_PTE = 0
};

enum {
  BX_EPT_READ    = 0x01,
  BX_EPT_WRITE   = 0x02,
  BX_EPT_EXECUTE = 0x04,

  BX_EPT_MBE_SUPERVISOR_EXECUTE = BX_EPT_EXECUTE,
  BX_EPT_MBE_USER_EXECUTE = 0x400
};

/* EPT access mask */
enum {
  BX_EPT_ENTRY_NOT_PRESENT        = 0x00,
  BX_EPT_ENTRY_READ_ONLY          = 0x01,
  BX_EPT_ENTRY_WRITE_ONLY         = 0x02,
  BX_EPT_ENTRY_READ_WRITE         = 0x03,
  BX_EPT_ENTRY_EXECUTE_ONLY       = 0x04,
  BX_EPT_ENTRY_READ_EXECUTE       = 0x05,
  BX_EPT_ENTRY_WRITE_EXECUTE      = 0x06,
  BX_EPT_ENTRY_READ_WRITE_EXECUTE = 0x07
};


uint64_t lookup_gpa_by_hpa(uint64_t hpa);

void cpu_physical_memory_read(uint64_t addr, void* dest, size_t len);
void cpu_physical_memory_write(uint64_t addr, const void* src, size_t len);
void fuzz_identify_l2_pages();
void mark_l2_guest_page(uint64_t paddr, uint64_t len, uint64_t addr);
void mark_l2_guest_pagetable(uint64_t paddr, uint64_t len, uint8_t level);
const char *get_memtype_name(BxMemtype memtype);
void add_persistent_memory_range(bx_phy_address start, bx_phy_address len);

void icp_init_params();
void icp_init_mem(const char* filename);
void icp_init_regs(const char* filename);
void icp_init_shadow_vmcs_layout(const char* filename);
void icp_init_vmcs_layout(const char* filename);
void icp_set_vmcs(uint64_t vmcs);
void bx_init_pc_system();

void clear_seen_dma();
void fuzz_dma_read_cb(bx_phy_address addr, unsigned len, void* data);
void fuzz_inject_mmio_write(uint64_t addr, uint64_t val);
void fuzz_inject_pio_read(uint64_t addr, uint64_t val);
void fuzz_inject_vmcall(uint64_t rcx, uint64_t r8, const void* xmm0, const void* xmm3 );

extern int in_clock_step;
enum {
	CLOCK_STEP_NONE,
	CLOCK_STEP_GET_DEADLINE,
	CLOCK_STEP_GET_NS,
	CLOCK_STEP_WARP,
	CLOCK_STEP_FLUSH,
	CLOCK_STEP_DONE
};
bool op_clock_step();

void fuzz_hook_memory_access(bx_address phy, unsigned len, 
                             unsigned memtype, unsigned rw, void* data);
void fuzz_hook_exception(unsigned vector, unsigned error_code);
void fuzz_hook_hlt();
void fuzz_hook_cr3_change(bx_address old, bx_address val);
void fuzz_reset_exception_counter();
void clear_l2_bitmaps();
void restore_l2_bitmaps();
void snapshot_l2_bitmaps();

uint32_t get_sysret_status();
void reset_sysret_status();

void fuzz_reset_memory();
void fuzz_watch_memory_inc();
void fuzz_clear_dirty();

void fuzz_instr_cnear_branch_taken(bx_address branch_rip,
                                 bx_address new_rip);
void fuzz_instr_cnear_branch_not_taken(bx_address branch_rip);
void fuzz_instr_ucnear_branch(unsigned what, bx_address branch_rip,
                            bx_address new_rip);
void fuzz_instr_far_branch(unsigned what, Bit16u prev_cs,
                         bx_address prev_rip, Bit16u new_cs,
                         bx_address new_rip);
void fuzz_instr_before_execution(bxInstruction_c *i);
void fuzz_instr_after_execution(bxInstruction_c *i);
void fuzz_instr_interrupt(unsigned cpu, unsigned vector);
void add_edge(bx_address prev_rip, bx_address new_rip);
void print_stacktrace();
bool ignore_pc(bx_address pc);
bool found_pc(uint64_t pc);
void add_pc_range(size_t base, size_t len);

void fuzz_emu_stop_normal();
void fuzz_emu_stop_unhealthy();
void fuzz_emu_stop_crash(const char *type);

extern uint64_t vmcs_addr;
void redo_paging();
void vmcs_fixup();

void add_indicator_value(uint64_t val);
void clear_indicator_values();
void dump_indicators();
void aggregate_indicators();
void indicator_cb(void(*cb)(uint64_t));

bool vmcs_linear2phy(bx_address laddr, bx_phy_address *phy);
int vmcs_translate_guest_physical_ept(bx_phy_address guest_paddr, bx_phy_address *phy, int *translation_level);

void ept_mark_page_table();
void ept_locate_pc();
void mark_page_not_guest(bx_phy_address addr, int level);
bool frame_is_guest(bx_phy_address addr);
void start_cpu();
void dump_regs();
unsigned long int get_icount();
unsigned long int get_pio_icount();
void reset_bx_vm();

void walk_ept(bool enum_mmio);
void fuzz_walk_ept();
void fuzz_walk_cr3();
void enum_pio_regions();
void enum_pio_regions_kvm();
void enum_pio_regions_macos();
void enum_mmio_regions();
void enum_handle_ept_gap(unsigned int gap_reason,
        bx_address gap_start, bx_address gap_end);

bool inject_in(uint16_t addr, uint16_t size);
bool inject_out(uint16_t addr, uint16_t size, uint32_t value);
bool inject_read(bx_address addr, int size);
bool inject_write(bx_address addr, int size, uint64_t val);
bool inject_halt();
uint32_t inject_pci_read(uint8_t device, uint8_t function, uint8_t offset);
bool inject_pci_write(uint8_t device, uint8_t function, uint8_t offset, uint32_t value);
uint64_t inject_rdmsr(bx_address msr);
bool inject_wrmsr(bx_address msr, uint64_t value);
void set_pci_device(uint8_t dev, uint8_t function);

void add_pio_region(uint16_t addr, uint16_t size);
void add_mmio_region(uint64_t addr, uint64_t size);
void add_mmio_range_alt(uint64_t addr, uint64_t end);
void add_ept_misconfig_range(bx_address start, bx_address end);
void add_ept_violation_range(bx_address start, bx_address end);



void open_db(const char* path);
void insert_mmio(uint64_t addr, uint64_t len);
void insert_pio(uint16_t addr, uint16_t len);
void load_regions(std::map<uint16_t, uint16_t> &pio_regions, std::map<bx_address, uint32_t> &mmio_regions);
void load_manual_ranges(char* range_file, char* range_regex, std::map<uint16_t, uint16_t> &pio_regions, std::map<bx_address, uint32_t> &mmio_regions);
void init_regions(const char* path);

void init_register_feedback();
void insert_register_value_into_fuzz_input(int idx);

void fuzz_run_input(const uint8_t* Data, size_t Size);

void cov_notimeout();
void dump_timeout_pcs();
void reset_op_cov();
void reset_cur_cov();
void dump_cur_cov();
void load_symbolization_files(char* path);
void symbolize(size_t pc);

// sym2addr_linux.cc
void load_symbol_map(char *path);
bx_address sym_to_addr(std::string bin, std::string name);
std::pair<std::string, std::string> addr_to_sym(size_t addr);

// link_map.c
void load_link_map(char* map_path, char* obj_regex, size_t base);

// sourcecov.c

void write_source_cov();
void init_sourcecov(size_t baseaddr);
void setup_periodic_coverage();
void check_write_coverage();

// breakpoints.cc
void handle_breakpoints(bxInstruction_c *i);
void handle_syscall_hooks(bxInstruction_c *i);
void apply_breakpoints_linux();

//stacktrace
void fuzz_stacktrace();

#endif
