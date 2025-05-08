#ifndef S2PT_H
#define S2PT_H

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
#define PTE_CONT ((1UL) << 52) /* Contiguous range */
/* Adjust alignment for the contiguous bit as per StageOA() */
#define contiguous_bit_shift(d, wi, l)                    \
	({                                                \
		uint8_t shift = 0;                        \
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

#define S1_MMU_DISABLED (-127)

#define SYS_PAR_EL1_F BIT(0)
/* When PAR_EL1.F == 1 */
#define SYS_PAR_EL1_FST GENMASK(6, 1)
#define SYS_PAR_EL1_PTW BIT(8)
#define SYS_PAR_EL1_S BIT(9)
#define SYS_PAR_EL1_AssuredOnly BIT(12)
#define SYS_PAR_EL1_TopLevel BIT(13)
#define SYS_PAR_EL1_Overlay BIT(14)
#define SYS_PAR_EL1_DirtyBit BIT(15)
#define SYS_PAR_EL1_F1_IMPDEF GENMASK_ULL(63, 48)
#define SYS_PAR_EL1_F1_RES0 (BIT(7) | BIT(10) | GENMASK_ULL(47, 16))
#define SYS_PAR_EL1_RES1 BIT(11)
/* When PAR_EL1.F == 0 */
#define SYS_PAR_EL1_SH GENMASK_ULL(8, 7)
#define SYS_PAR_EL1_NS BIT(9)
#define SYS_PAR_EL1_F0_IMPDEF BIT(10)
#define SYS_PAR_EL1_NSE BIT(11)
#define SYS_PAR_EL1_PA GENMASK_ULL(51, 12)
#define SYS_PAR_EL1_ATTR GENMASK_ULL(63, 56)
#define SYS_PAR_EL1_F0_RES0 (GENMASK_ULL(6, 1) | GENMASK_ULL(55, 52))

#define OP_AT_S1E1R 1
#define OP_AT_S1E1W 2
#define OP_AT_S1E0R 3
#define OP_AT_S1E0W 4
#define OP_AT_S12E1R 5
#define OP_AT_S12E1W 6
#define OP_AT_S12E0R 7
#define OP_AT_S12E0W 8

/* Common SCTLR_ELx flags. */
#define SCTLR_ELx_ENTP2 (BIT(60))
#define SCTLR_ELx_DSSBS (BIT(44))
#define SCTLR_ELx_ATA (BIT(43))

#define SCTLR_ELx_EE_SHIFT 25
#define SCTLR_ELx_ENIA_SHIFT 31

#define SCTLR_ELx_ITFSB (BIT(37))
#define SCTLR_ELx_ENIA (BIT(SCTLR_ELx_ENIA_SHIFT))
#define SCTLR_ELx_ENIB (BIT(30))
#define SCTLR_ELx_LSMAOE (BIT(29))
#define SCTLR_ELx_nTLSMD (BIT(28))
#define SCTLR_ELx_ENDA (BIT(27))
#define SCTLR_ELx_EE (BIT(SCTLR_ELx_EE_SHIFT))
#define SCTLR_ELx_EIS (BIT(22))
#define SCTLR_ELx_IESB (BIT(21))
#define SCTLR_ELx_TSCXT (BIT(20))
#define SCTLR_ELx_WXN (BIT(19))
#define SCTLR_ELx_ENDB (BIT(13))
#define SCTLR_ELx_I (BIT(12))
#define SCTLR_ELx_EOS (BIT(11))
#define SCTLR_ELx_SA (BIT(3))
#define SCTLR_ELx_C (BIT(2))
#define SCTLR_ELx_A (BIT(1))
#define SCTLR_ELx_M (BIT(0))

enum trans_regime {
	TR_EL10,
	TR_EL20,
	TR_EL2,
};

struct s1_walk_info {
	uint64_t baddr;
	enum trans_regime regime;
	unsigned int max_oa_bits;
	unsigned int pgshift;
	unsigned int txsz;
	int sl;
	bool be;
	bool s2;
	void (*page_table_cb)(uint64_t address, int level);
};

struct s1_walk_result {
	union {
		struct {
			uint64_t desc;
			uint64_t pa;
			int8_t level;
		};
		struct {
			uint8_t fst;
			bool ptw;
			bool s2;
		};
	};
	bool failed;
};

int setup_s1_walk(uint8_t op, struct s1_walk_info *wi,
		  struct s1_walk_result *wr, uint64_t va);
int walk_s1(struct s1_walk_info *wi, struct s1_walk_result *wr, uint64_t va);
uint64_t compute_par_s1(struct s1_walk_result *wr, enum trans_regime regime);

#endif /* S2PT_H */