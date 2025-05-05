#include "qemu.h"
#include <sys/param.h>

static uint8_t watch_level = 0;

static size_t ramsize;
static uint8_t *ram;
static uint8_t *shadowram;

void fuzz_clear_dirty() {
	RAMBlock *ram_block;
	RAMBLOCK_FOREACH(ram_block) {
		if (strcmp(ram_block->idstr, "mach-virt.ram")) {
			continue;
		}
		uint64_t pages = ram_block->used_length >> 12;
		bitmap_set(ram_block->bmap, 0, pages);
		break;
	}
}

void fuzz_watch_memory_inc() {
	RAMBlock *ram_block;
	switch (watch_level) {
	case 0:
		RAMBLOCK_FOREACH(ram_block) {
			if (strcmp(ram_block->idstr, "mach-virt.ram")) {
				continue;
			}
			uint64_t pages = ram_block->used_length >> 12;
			ram_block->bmap = bitmap_new(pages);
			bitmap_set(ram_block->bmap, 0, pages);
			break;
		}
		memory_global_dirty_log_start(GLOBAL_DIRTY_MIGRATION);
		break;
	default:
		break;
	}
	watch_level++;
}

void fuzz_reset_memory() {
	return;
	if (watch_level <= 1)
		return;

	// memory_global_dirty_log_stop(GLOBAL_DIRTY_MIGRATION);

	RAMBlock *ram_block;
	RAMBLOCK_FOREACH(ram_block) {
		if (strcmp(ram_block->idstr, "mach-virt.ram")) {
			continue;
		}
		uint64_t pages = ram_block->used_length >> 12;

		uint64_t dirty = find_next_bit(ram_block->bmap, pages, 0);
		while (dirty < pages) {
			memcpy(ram + (dirty << 12), shadowram + (dirty << 12),
			       1 << 12);
			dirty = find_next_bit(ram_block->bmap, pages, dirty);
			break;
		}
	}
	fuzz_clear_dirty();
}

void add_persistent_memory_range(hp_phy_address start, hp_phy_address len) {
}

void icp_init_mem(const char *filename) {
	Error *err = NULL;
	hp_load_devices_state(filename, &err);

	RAMBlock *ram_block;
	RAMBLOCK_FOREACH(ram_block) {
		if (strcmp(ram_block->idstr, "mach-virt.ram")) {
			continue;
		}
		ram = qemu_ram_get_host_addr(ram_block);
		ramsize = qemu_ram_get_used_length(ram_block);
		break;
	}

	shadowram = (uint8_t *)malloc(ramsize);
	memcpy(shadowram, (void *)ram, ramsize);
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
	cpu_physical_memory_write(addr, buf, len);
}

void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf) {
	cpu_physical_memory_read(addr, buf, len);
}

void cpu0_tlb_flush(void) {
	tlb_flush(CPU(ARM_CPU(QEMU_CPU(0))));
}
