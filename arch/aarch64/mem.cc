#include "fuzz.h"
#include "qemuapi.h"

uint64_t lookup_gpa_by_hpa(uint64_t hpa) { assert(0); }

void cpu0_read_virtual(hp_address start, size_t size, void *data) {
    __cpu0_memory_rw_debug(start, data, size, false);
}

void cpu0_write_virtual(hp_address start, size_t size, void *data) {
    __cpu0_memory_rw_debug(start, data, size, true);
}

void cpu0_mem_write_physical_page(hp_phy_address addr, size_t len, void *buf) {
    __cpu0_mem_write_physical_page(addr, len, buf);
}

void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf) {
    __cpu0_mem_read_physical_page(addr, len, buf);
}

/* given a virtual address of L1, return the instruction bytes */
bool cpu0_read_instr_buf(size_t pc, uint8_t *instr_buf) {
    if (__cpu0_memory_rw_debug(pc, instr_buf, 4096, false) == 0) {
        return true;
    } else {
        return false;
    }
}

void hp_add_persistent_memory_range(hp_address start, size_t len) { assert(0); }
