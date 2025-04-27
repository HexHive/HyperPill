#include "qemu.h"
#include "sys/param.h"

void add_persistent_memory_range(hp_address start, size_t len) {
	assert(0);
}

void cpu0_read_virtual(hp_address start, size_t size, void *data) {
	cpu_memory_rw_debug(QEMU_CPU(0), start, data, size, false);
}

void cpu0_write_virtual(hp_address start, size_t size, void *data) {
	cpu_memory_rw_debug(QEMU_CPU(0), start, data, size, true);
}

/* given a virtual address of L1, return the instruction bytes */
bool cpu0_read_instr_buf(size_t pc, uint8_t *instr_buf) {
	if (cpu_memory_rw_debug(QEMU_CPU(0), pc, instr_buf, 4096, false) == 0) {
		return true;
	} else {
		return false;
	}
}

void cpu0_mem_write_physical_page(hp_phy_address addr, size_t len, void *buf) {
}

void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf) {
}

void cpu0_tlb_flush(void) {
	tlb_flush(CPU(ARM_CPU(QEMU_CPU(0))));
}
