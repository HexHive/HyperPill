#include "qemu.h"
#include "nested.h"

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

void s2pt_mark_page_table() {
	
}
