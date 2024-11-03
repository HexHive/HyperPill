#include "fuzz.h"

uint64_t lookup_gpa_by_hpa(uint64_t hpa) { return hpa; }

void cpu0_read_virtual(hp_address start, size_t size, void *data) { }

void cpu0_write_virtual(hp_address start, size_t size, void *data) { }

void cpu0_mem_write_physical_page(hp_phy_address addr, size_t len, void *buf) { }

void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf) { }

void icp_init_mem(const char *filename) {
}

void mark_l2_guest_page(uint64_t paddr, uint64_t len, uint64_t addr){
}

void mark_l2_guest_pagetable(uint64_t paddr, uint64_t len, uint8_t level) {
}

bool cpu0_read_instr_buf(size_t pc, uint8_t *instr_buf) { return false; }

void cpu_physical_memory_read(uint64_t addr, void* dest, size_t len){
}

void cpu_physical_memory_write(uint64_t addr, const void* src, size_t len){
}

void hp_add_persistent_memory_range(hp_address start, size_t len) { }