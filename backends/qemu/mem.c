#include "qemu.h"
#include "sys/param.h"

void add_persistent_memory_range(hp_address start, size_t len) {
	assert(0);
}

// code from the linux kernel
struct s2_walk_info {
	void (*read_desc)(uint64_t pa, uint64_t *desc);
	uint64_t baddr;
	unsigned int max_oa_bits;
	unsigned int pgshift;
	unsigned int sl;
	unsigned int t0sz;
	bool be;
};

static void read_guest_s2_desc(uint64_t pa, uint64_t *desc){
	cpu0_mem_read_physical_page(pa, sizeof(*desc), desc);
}

// vtcr_el2, 64 bit
// PS, bits [18:16], physical address Size for the second stage of translation
#define VTCR_EL2_PS_SHIFT 16
#define VTCR_EL2_PS_MASK (7 << VTCR_EL2_PS_SHIFT)
// TG0, bits [15:14], granule size for the VTTBR_EL2
#define VTCR_EL2_TG0_SHIFT 14
#define VTCR_EL2_TG0_MASK (3 << VTCR_EL2_TG0_SHIFT)
#define VTCR_EL2_TG0_4K (0 << VTCR_EL2_TG0_SHIFT)
#define VTCR_EL2_TG0_64K (1 << VTCR_EL2_TG0_SHIFT)
#define VTCR_EL2_TG0_16K (2 << VTCR_EL2_TG0_SHIFT)
// SL0, bits[7:6], starting level of the stage 2 translation lookup
#define VTCR_EL2_SL0_SHIFT 6
#define VTCR_EL2_SL0_MASK (3 << VTCR_EL2_SL0_SHIFT)
// T0SZ, bits [5:0]
// The size of the memory region addressed by VTTBR_EL2 is 2^(64-T0SZ) bytes.
#define VTCR_EL2_T0SZ_MASK 0x3f

static inline unsigned int ps_to_output_size(unsigned int ps) {
	switch (ps) {
	case 0:
		return 32;
	case 1:
		return 36;
	case 2:
		return 40;
	case 3:
		return 42;
	case 4:
		return 44;
	case 5:
	default:
		return 48;
	}
}

// sctrl_el2, 64 bit
// EE, bits [25], endianness of data accesses at EL2
#define SCTLR_ELx_EE (1 << 25)

uint64_t get_s2ptp(void) {
	struct s2_walk_info wi;

	uint64_t vtcr_el2 = ARM_CPU(QEMU_CPU(0))->env.cp15.vtcr_el2;

	wi.read_desc = read_guest_s2_desc;
	wi.max_oa_bits = MIN(48, ps_to_output_size(
		(vtcr_el2 & VTCR_EL2_PS_MASK) >> VTCR_EL2_PS_SHIFT));

	switch (vtcr_el2 & VTCR_EL2_TG0_MASK) {
	case VTCR_EL2_TG0_4K:
		wi.pgshift = 12;
		break;
	case VTCR_EL2_TG0_16K:
		wi.pgshift = 14;
		break;
	case VTCR_EL2_TG0_64K:
	default: /* IMPDEF: treat any other value as 64k */
		wi.pgshift = 16;
		break;
	}

	wi.sl = ((vtcr_el2 & VTCR_EL2_SL0_MASK) >> VTCR_EL2_SL0_SHIFT);
	wi.t0sz = vtcr_el2 & VTCR_EL2_T0SZ_MASK;
	wi.be = (ARM_CPU(QEMU_CPU(0))->env.cp15.sctlr_el[2]) & SCTLR_ELx_EE;

	int first_block_level, level, stride, input_size, base_lower_bound;
	switch (wi.pgshift) {
	case 14:
	case 16:
		level = 3 - wi.sl;
		first_block_level = 2;
		break;
	case 12:
		level = 2 - wi.sl;
		first_block_level = 1;
	}
	stride = wi.pgshift - 3;
	input_size = 64 - wi.t0sz;
	assert(input_size <= 48 && input_size >= 25);

	base_lower_bound = 3 + input_size - ((3 - level) * stride + wi.pgshift);
	// base_addr = wi->baddr & 



	// switch (1 << wi.pgshift)


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

void ept_mark_page_table() {
	assert(0);
}

void cpu0_mem_write_physical_page(hp_phy_address addr, size_t len, void *buf) {
}

void cpu0_mem_read_physical_page(hp_phy_address addr, size_t len, void *buf) {
}

void cpu0_tlb_flush(void) {
	tlb_flush(CPU(ARM_CPU(QEMU_CPU(0))));
}
