#include "qemu.h"

uint64_t lookup_gpa_by_hpa(uint64_t hpa) { assert(0); }

void cpu0_read_virtual(hp_address start, size_t size, void *data) {
    cpu_memory_rw_debug(QEMU_CPU(0), start, data, size, false);
}

void cpu0_write_virtual(hp_address start, size_t size, void *data) {
    cpu_memory_rw_debug(QEMU_CPU(0), start, data, size, true);
}

void cpu0_mem_write_physical_page(hp_phy_address addr, size_t len, void *buf) {
}

void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf) {
}

/* given a virtual address of L1, return the instruction bytes */
bool cpu0_read_instr_buf(size_t pc, uint8_t *instr_buf) {
    if (cpu_memory_rw_debug(QEMU_CPU(0), pc, instr_buf, 4096, false) == 0) {
        return true;
    } else {
        return false;
    }
}

void add_persistent_memory_range(hp_address start, size_t len) { assert(0); }

void icp_init_mem(const char *filename) {}

void cpu0_tlb_flush(void) { assert(0); }

void fuzz_reset_memory() { assert(0); }

void fuzz_watch_memory_inc() { assert(0); }

void fuzz_walk_ept() { assert(0); }

void ept_mark_page_table() { assert(0); }