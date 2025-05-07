#include "qemu.h"
#include <sys/param.h>

static uint8_t watch_level = 0;

static size_t ramsize;
static uint8_t *ram;
static uint8_t *shadowram;

static uint64_t prioraccess = 0;
enum Sizes { Byte, Word, Long, Quad, end_sizes };
void hp_vcpu_mem_access(
        unsigned int cpu_index, qemu_plugin_meminfo_t meminfo,
        uint64_t vaddr, void *userdata, enum qemu_plugin_pos pos, uint32_t size) {
    if (QEMU_CPU(0)->cpu_index != cpu_index) {
        return;
    }
	if (watch_level<=1) {
		return;
	}
    if (pos == QEMU_PLUGIN_UNKNOW_POS) {
        abort();
    }
	enum qemu_plugin_mem_rw rw;
    rw = get_plugin_meminfo_rw(meminfo);
	if (pos == QEMU_PLUGIN_BEFORE && (!((rw == QEMU_PLUGIN_MEM_R) || (rw == QEMU_PLUGIN_MEM_RW)))) {
		return;
	}
	if (pos == QEMU_PLUGIN_AFTER && (!((rw == QEMU_PLUGIN_MEM_W) || (rw == QEMU_PLUGIN_MEM_RW)))) {
		return;
	}

    struct qemu_plugin_hwaddr *hwaddr;
    hwaddr = qemu_plugin_get_hwaddr(meminfo, vaddr);
    if (hwaddr && qemu_plugin_hwaddr_is_io(hwaddr)) {
        return;
    }
	uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);

	if (addr >= ramsize) {
		return;
	}
	uint64_t aligned = addr & (~0xFFFLL);

	if (aligned == prioraccess) {
		return;
	}

	const char *name = qemu_plugin_hwaddr_device_name(hwaddr);
	if (strncmp("RAM", name, strlen("RAM")) != 0) {
		return;
	}
    
    if (rw == QEMU_PLUGIN_MEM_W || rw == QEMU_PLUGIN_MEM_RW ) {
		prioraccess = aligned;
		RAMBlock *ram_block;
		RAMBLOCK_FOREACH(ram_block) {
			if (strcmp(ram_block->idstr, "mach-virt.ram")) {
				continue;
			}
			uint64_t pages = addr >> 12;
			test_and_set_bit(pages, ram_block->bmap);
			break;
		}
    } 

	if (rw == QEMU_PLUGIN_MEM_R) {
		size_t __size = 0;
		switch (size) {
			case Byte: __size = 1; break;
			case Word: __size = 2; break;
			case Long: __size = 4; break;
			case Quad: __size = 8; break;
			case end_sizes: __size = 16; break;
			default: abort();
		}
		uint8_t data[__size];
		// printf("load, 0x%08"PRIx64", %lx\n", addr, size);
		// if (is_l2_page_bitmap[hwaddr >> 12]) {
		if (0) {
				if (cpu0_get_fuzztrace()) {
					/* printf(".dma inject: %lx +%lx ",phy, len); */
				}
				fuzz_dma_read_cb(hwaddr->phys_addr, __size, data);
			}
		// __cpu0_mem_write_physical_page(hwaddr->phys_addr, __size, data);
	}
}

void fuzz_clear_dirty() {
	RAMBlock *ram_block;
	RAMBLOCK_FOREACH(ram_block) {
		if (strcmp(ram_block->idstr, "mach-virt.ram")) {
			continue;
		}
		uint64_t pages = ram_block->used_length >> 12;
		bitmap_clear(ram_block->bmap, 0, pages);
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
			bitmap_clear(ram_block->bmap, 0, pages);
			break;
		}
		break;
	default:
		break;
	}
	watch_level++;
}

/**
 * During fuzzing, there is a chance that new guest addresses get paged in.
 * The corresponding HPAs have not been marked as guest pages, so we mark them.
 * However, the EPT is reset across fuzz iterations, so have to unmark
 * the pages that have been marked during the current fuzz iteration
*/
#define PG_PRESENT_BIT  0
#define PG_PRESENT_MASK  (1 << PG_PRESENT_BIT)
void fuzz_mark_l2_guest_page(uint64_t paddr, uint64_t len) {
    uint64_t pg_entry;
    cpu_physical_memory_read(paddr, &pg_entry, sizeof(pg_entry));
    hp_phy_address new_addr = pg_entry & 0x3fffffffff000ULL;
    uint8_t new_pgtable_lvl = is_l2_pagetable_bitmap[paddr >> 12] - 1;
    uint8_t pg_present = pg_entry & PG_PRESENT_MASK;

    if (!pg_present || new_addr >= ramsize)
      return;

    // store all updates made for the current fuzzing iteration
	fuzzed_guest_paged_push_back(new_addr, new_pgtable_lvl, is_l2_pagetable_bitmap[new_addr>>12]);
    //printf("!fuzz_mark_l2_guest_page Mark 0x%lx lvl %x as tmp guest page\n", new_addr, new_pgtable_lvl);
    if (new_pgtable_lvl) {
        mark_l2_guest_pagetable(new_addr, len, new_pgtable_lvl - 1);
    } else {
        mark_l2_guest_page(new_addr, len, 0);
    }
}

void add_persistent_memory_range(hp_phy_address start, hp_phy_address len) {
}

void find_diff(const void *a, const void *b, size_t n) {
    const uint64_t *pa = (const uint64_t *)a;
    const uint64_t *pb = (const uint64_t *)b;

    for (size_t i = 0; i < n / 8; i++) {
        if (pa[i] != pb[i]) {
			printf("diffat 0x%016lx\n", i * 8);
        }
    }
}

void fuzz_reset_memory() {
	if (watch_level <= 1)
		return;

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
			dirty = find_next_bit(ram_block->bmap, pages, dirty + 1);
		}
		memcpy(ram + 0xc0000000, shadowram + 0xc0000000, 0x10000000);
		break;
	}
	fuzz_clear_dirty();
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

uint64_t cpu0_virt2phy(uint64_t start) {

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
