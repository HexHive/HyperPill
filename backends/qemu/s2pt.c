#include "qemu.h"
#include "s2pt.h"

// code from the Linux kernel: 5bc10186 (Ari 26, 2025)
#define GENMASK_64(high, low) (((1ULL << ((high) - (low) + 1)) - 1) << (low))

int gpa2hpa(uint64_t gipa, uint64_t *phy, int *translation_level) {
	struct s2_trans output;
	int ret = walk_nested_s2(gipa, &output);
	*translation_level = 3 - output.level;
	if (ret) { /* just faulty */
		*phy = 0;
		return output.esr;
	} else {
		*phy = output.output;
		return output.esr;
	}
}

// Translate GVA -> GPA -> HPA
bool gva2hpa(uint64_t gva, uint64_t *phy) {
	// there are four kinds of addresses
	// - host el0/el2 -> ttbr0/1_el2
	// - guest el0/el1 -> ttbr0/1_el1
	// however, this function only handes guest el0/el1 addresses
	int ret;
	if (gva & (1UL << 55)) {
		at_s12(OP_AT_S12E1R, gva, phy);
	} else {
		at_s12(OP_AT_S12E0R, gva, phy);
	}
	*phy = *phy & GENMASK(47, 12);
	return true;
}

void s2pt_locate_pc() {
	uint64_t phyaddr;

	uint64_t faulty_va = aarch64_get_far_el2();
	gva2hpa(faulty_va, &phyaddr);
	printf("%lx -> %lx\n", faulty_va, phyaddr);

	gva2hpa(0, &phyaddr);
	printf("%lx -> %lx\n", 0, phyaddr);
}

void walk_guest_pt_with_handler(bool userspace,
				void (*page_table_cb)(uint64_t address,
						      int level)) {
	uint64_t vaddr_start, vaddr_end;
	uint8_t op = 0;
	if (userspace) {
		vaddr_start = 0x0;
		vaddr_end = 0x000fffffffffffff;
		op = OP_AT_S1E0R;
	} else {
		vaddr_start = 0xfff0000000000000;
		vaddr_end = 0xffffffffffffffff;
		op = OP_AT_S1E1R;
	}
	uint64_t vaddr = vaddr_start;
	struct s1_walk_result wr = {};
	struct s1_walk_info wi = {};

	setup_s1_walk(op, &wi, &wr, vaddr);
	unsigned int ia_bits = 64 - wi.txsz;
	if (userspace) {
		vaddr_end = GENMASK(ia_bits - 1, 0);
	} else {
		vaddr = vaddr_start = GENMASK(63, ia_bits);
	}

	wi.page_table_cb = page_table_cb;
	bool perm_fail = false;
	int ret, idx;
	uint8_t translation_level;
	do {
		ret = setup_s1_walk(op, &wi, &wr, vaddr);
		if (ret)
			break;

		if (wr.level == S1_MMU_DISABLED)
			goto skip;

		ret = walk_s1(&wi, &wr, vaddr);
		if (ret)
			goto skip;
skip:
		translation_level = 3 - wr.level;
		// printf("vaddr=0x%016lx size=0x%016lx\n", vaddr,
		//    0x1000 * pow64(512, translation_level));
		vaddr += 0x1000 * pow64(512, translation_level);
	} while (vaddr && vaddr < vaddr_end);
}

void s2pt_mark_page_table() {
	walk_guest_pt_with_handler(/*userspace=*/true, mark_page_not_guest);
	walk_guest_pt_with_handler(/*userspace=*/false, mark_page_not_guest);

	uint64_t phyaddr;
	if (gva2hpa(aarch64_get_far_el2(), &phyaddr)) {
		mark_page_not_guest(phyaddr, 0);
	} else {
		fprintf(stderr, "GUEST_RIP page not mapped");
		abort();
	}
}
