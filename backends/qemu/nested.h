#ifndef NESTED_H
#define NESTED_H

#include "qemu.h"

struct s2_trans {
	uint64_t output;
	unsigned long block_size;
	bool writable;
	bool readable;
	int level;
	uint32_t esr;
	uint64_t desc;
};

static inline uint64_t s2_trans_output(struct s2_trans *trans) {
	return trans->output;
}

static inline unsigned long s2_trans_size(struct s2_trans *trans) {
	return trans->block_size;
}

static inline uint32_t s2_trans_esr(struct s2_trans *trans) {
	return trans->esr;
}

static inline bool s2_trans_readable(struct s2_trans *trans) {
	return trans->readable;
}

static inline bool s2_trans_writable(struct s2_trans *trans) {
	return trans->writable;
}

static inline bool s2_trans_executable(struct s2_trans *trans) {
	return !(trans->desc & BIT(54));
}

extern int walk_nested_s2(uint64_t gipa, struct s2_trans *result);

#define SZ_4K 0x00001000
#define SZ_16K 0x00004000
#define SZ_64K 0x00010000
#define PTE_CONT		((1UL) << 52)	/* Contiguous range */
/* Adjust alignment for the contiguous bit as per StageOA() */
#define contiguous_bit_shift(d, wi, l)                    \
	({                                                \
		uint8_t shift = 0;                             \
                                                          \
		if ((d) & PTE_CONT) {                     \
			switch (BIT((wi)->pgshift)) {     \
			case SZ_4K:                       \
				shift = 4;                \
				break;                    \
			case SZ_16K:                      \
				shift = (l) == 2 ? 5 : 7; \
				break;                    \
			case SZ_64K:                      \
				shift = 5;                \
				break;                    \
			}                                 \
		}                                         \
                                                          \
		shift;                                    \
	})

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

#endif /* NESTED_H */
