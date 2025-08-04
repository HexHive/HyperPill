#ifndef FUZZ_H
#define FUZZ_H

#include <stdint.h>
#include <map>
#include <vector>
#include <cstring>
#include <tsl/robin_set.h>

#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fuzzc.h"

extern bool fuzzing;
#if defined(HP_X86_64)
extern std::vector<size_t> guest_page_scratchlist;
#endif

extern tsl::robin_set<hp_address> cur_input;
extern size_t maxaddr;
extern bool master_fuzzer;
extern bool verbose;

#define verbose_printf(...) if(verbose) printf(__VA_ARGS__)


void cpu_physical_memory_read(uint64_t addr, void* dest, size_t len);
void cpu_physical_memory_write(uint64_t addr, const void* src, size_t len);

void icp_init_params();
void icp_init_vmcs_layoddut(const char* filename);

// backends/bochs/system.cc
void bx_init_pc_system();

#if defined(HP_X86_64)
// backends/bochs/vmcs.cc
extern uint64_t vmcs_addr;
void icp_init_shadow_vmcs_layout(const char* filename);
void icp_set_vmcs(uint64_t vmcs);
void icp_set_vmcs_map();
void redo_paging();
void vmcs_fixup();
#endif

// fuzz.cc
void clear_seen_dma();
unsigned int num_mmio_regions();
#if defined(HP_X86_64)
bool inject_halt();
#endif
bool inject_write(hp_address addr, int size, uint64_t val);
bool inject_read(hp_address addr, int size);
#if defined(HP_X86_64)
bool inject_in(uint16_t addr, uint16_t size);
bool inject_out(uint16_t addr, uint16_t size, uint32_t value);
uint32_t inject_pci_read(uint8_t device, uint8_t function, uint8_t offset);
bool inject_pci_write(uint8_t device, uint8_t function, uint8_t offset, uint32_t value);
uint64_t inject_rdmsr(hp_address msr);
bool inject_wrmsr(hp_address msr, uint64_t value);
#endif
bool op_write();
bool op_read();
#if defined(HP_X86_64)
bool op_out();
bool op_in();
void set_pci_device(uint8_t dev, uint8_t function);
bool op_pci_write();
bool op_msr_write();
#endif
void insert_register_value_into_fuzz_input(int idx);
bool op_vmcall();
void fuzz_run_input(const uint8_t* Data, size_t Size);
#if defined(HP_X86_64)
void add_pio_region(uint16_t addr, uint16_t size);
#endif
void add_mmio_region(uint64_t addr, uint64_t size);
void add_mmio_range_all(uint64_t addr, uint64_t end);
void init_regions(const char* path);

// main.cc
unsigned long int get_icount();
#if defined(HP_X86_64)
unsigned long int get_pio_icount();
#endif
void start_cpu();
void reset_vm();

#include "conveyor.h"

// cov.cc
void add_pc_range(size_t base, size_t len);
bool ignore_pc(hp_address pc);
void reset_op_cov();
void reset_cur_cov();

// db.cc
void open_db(const char* path);
void insert_mmio(uint64_t addr, uint64_t len);
void insert_pio(uint16_t addr, uint16_t len);
void load_regions(std::map<uint16_t, uint16_t> &pio_regions, std::map<hp_address, uint32_t> &mmio_regions);
void load_manual_ranges(char* range_file, char* range_regex, std::map<uint16_t, uint16_t> &pio_regions, std::map<hp_address, uint32_t> &mmio_regions);

// enum.cc
#if defined(HP_X86_64)
void enum_pio_regions();
void enum_handle_ept_gap(unsigned int gap_reason,
        hp_address gap_start, hp_address gap_end);
#endif
void enum_handle_slat_gap(unsigned int gap_reason,
        hp_address gap_start, hp_address gap_end);
void enum_mmio_regions();

// feedback.cc
void add_indicator_value(uint64_t val);
void clear_indicator_values();
void aggregate_indicators();
void dump_indicators();
void indicator_cb(void(*cb)(uint64_t));
void init_register_feedback();

// link_map.cc
void load_link_map(char* map_path, char* obj_regex, size_t base);

// hmem.cc
extern size_t guest_mem_size;
uint64_t lookup_gpa_by_hpa(uint64_t hpa);
void add_persistent_memory_range(hp_phy_address start, hp_phy_address len);

// slat.cc
void walk_slat();
void fuzz_walk_slat();
void slat_locate_pc();
void slat_mark_page_table();

// sourcecov.cc
void write_source_cov();
void check_write_coverage();
void init_sourcecov(size_t baseaddr);
void setup_periodic_coverage();

// sym2addr_linux.cc
void load_symbol_map(char *path);

// symbolize.cc
void load_symbolization_files(char* path);
void symbolize(size_t pc);

void hp_gdbstub_debug_loop();
int hp_gdbstub_mem_check(unsigned cpu, uint64_t lin, unsigned len, unsigned rw);

#endif
