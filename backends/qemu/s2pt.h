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
#define OP_AT_S1E2R 9
#define OP_AT_S1E2W 10
#define OP_AT_S1E2A 11

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
void at_s12(uint8_t op, uint64_t vaddr, uint64_t *phy);

// hcr_el2: Hypervisor Configuration Register
// vm, bit[0], if 1, EL1&0 stage 2 address translation enabled
// dc, bit[12], if 1, the PE behaves as if the value of the HCR_EL2.VM field is
// 1 tge, bit[27], if 1, all exceptions that would be routed to EL1 are routed
// to EL2 e2h, bit[34], if 1, the facilities to support a Host Operating System
// at EL2 are enabled

/*
 * TCR flags.
 */
#define TCR_T0SZ_OFFSET 0
#define TCR_T1SZ_OFFSET 16
#define TCR_T0SZ(x) (((64UL) - (x)) << TCR_T0SZ_OFFSET)
#define TCR_T1SZ(x) (((64UL) - (x)) << TCR_T1SZ_OFFSET)
#define TCR_TxSZ(x) (TCR_T0SZ(x) | TCR_T1SZ(x))
#define TCR_TxSZ_WIDTH 6
#define TCR_T0SZ_MASK ((((1UL) << TCR_TxSZ_WIDTH) - 1) << TCR_T0SZ_OFFSET)
#define TCR_T1SZ_MASK ((((1UL) << TCR_TxSZ_WIDTH) - 1) << TCR_T1SZ_OFFSET)

#define TCR_EPD0_SHIFT 7
#define TCR_EPD0_MASK ((1UL) << TCR_EPD0_SHIFT)
#define TCR_IRGN0_SHIFT 8
#define TCR_IRGN0_MASK ((3UL) << TCR_IRGN0_SHIFT)
#define TCR_IRGN0_NC ((0UL) << TCR_IRGN0_SHIFT)
#define TCR_IRGN0_WBWA ((1UL) << TCR_IRGN0_SHIFT)
#define TCR_IRGN0_WT ((2UL) << TCR_IRGN0_SHIFT)
#define TCR_IRGN0_WBnWA ((3UL) << TCR_IRGN0_SHIFT)

#define TCR_EPD1_SHIFT 23
#define TCR_EPD1_MASK ((1UL) << TCR_EPD1_SHIFT)
#define TCR_IRGN1_SHIFT 24
#define TCR_IRGN1_MASK ((3UL) << TCR_IRGN1_SHIFT)
#define TCR_IRGN1_NC ((0Ul) << TCR_IRGN1_SHIFT)
#define TCR_IRGN1_WBWA ((1UL) << TCR_IRGN1_SHIFT)
#define TCR_IRGN1_WT ((2UL) << TCR_IRGN1_SHIFT)
#define TCR_IRGN1_WBnWA ((3Ul) << TCR_IRGN1_SHIFT)

#define TCR_IRGN_NC (TCR_IRGN0_NC | TCR_IRGN1_NC)
#define TCR_IRGN_WBWA (TCR_IRGN0_WBWA | TCR_IRGN1_WBWA)
#define TCR_IRGN_WT (TCR_IRGN0_WT | TCR_IRGN1_WT)
#define TCR_IRGN_WBnWA (TCR_IRGN0_WBnWA | TCR_IRGN1_WBnWA)
#define TCR_IRGN_MASK (TCR_IRGN0_MASK | TCR_IRGN1_MASK)

#define TCR_ORGN0_SHIFT 10
#define TCR_ORGN0_MASK ((3UL) << TCR_ORGN0_SHIFT)
#define TCR_ORGN0_NC ((0UL) << TCR_ORGN0_SHIFT)
#define TCR_ORGN0_WBWA ((1UL) << TCR_ORGN0_SHIFT)
#define TCR_ORGN0_WT ((2UL) << TCR_ORGN0_SHIFT)
#define TCR_ORGN0_WBnWA ((3UL) << TCR_ORGN0_SHIFT)

#define TCR_ORGN1_SHIFT 26
#define TCR_ORGN1_MASK ((3UL) << TCR_ORGN1_SHIFT)
#define TCR_ORGN1_NC ((0Ul) << TCR_ORGN1_SHIFT)
#define TCR_ORGN1_WBWA ((1UL) << TCR_ORGN1_SHIFT)
#define TCR_ORGN1_WT ((2UL) << TCR_ORGN1_SHIFT)
#define TCR_ORGN1_WBnWA ((3UL) << TCR_ORGN1_SHIFT)

#define TCR_ORGN_NC (TCR_ORGN0_NC | TCR_ORGN1_NC)
#define TCR_ORGN_WBWA (TCR_ORGN0_WBWA | TCR_ORGN1_WBWA)
#define TCR_ORGN_WT (TCR_ORGN0_WT | TCR_ORGN1_WT)
#define TCR_ORGN_WBnWA (TCR_ORGN0_WBnWA | TCR_ORGN1_WBnWA)
#define TCR_ORGN_MASK (TCR_ORGN0_MASK | TCR_ORGN1_MASK)

#define TCR_SH0_SHIFT 12
#define TCR_SH0_MASK ((3UL) << TCR_SH0_SHIFT)
#define TCR_SH0_INNER ((3UL) << TCR_SH0_SHIFT)

#define TCR_SH1_SHIFT 28
#define TCR_SH1_MASK ((3UL) << TCR_SH1_SHIFT)
#define TCR_SH1_INNER ((3UL) << TCR_SH1_SHIFT)
#define TCR_SHARED (TCR_SH0_INNER | TCR_SH1_INNER)

#define TCR_TG0_SHIFT 14
#define TCR_TG0_WIDTH 2
#define TCR_TG0_MASK ((3UL) << TCR_TG0_SHIFT)
#define TCR_TG0_4K ((0UL) << TCR_TG0_SHIFT)
#define TCR_TG0_64K ((1UL) << TCR_TG0_SHIFT)
#define TCR_TG0_16K ((2UL) << TCR_TG0_SHIFT)

#define TCR_TG1_SHIFT 30
#define TCR_TG1_WIDTH 2
#define TCR_TG1_MASK ((3UL) << TCR_TG1_SHIFT)
#define TCR_TG1_16K ((1UL) << TCR_TG1_SHIFT)
#define TCR_TG1_4K ((2UL) << TCR_TG1_SHIFT)
#define TCR_TG1_64K ((3UL) << TCR_TG1_SHIFT)

#define TCR_IPS_SHIFT 32
#define TCR_IPS_MASK ((7UL) << TCR_IPS_SHIFT)
#define TCR_A1 ((1UL) << 22)
#define TCR_ASID16 ((1UL) << 36)
#define TCR_TBI0_SHIFT 37
#define TCR_TBI0 ((1UL) << 37)
#define TCR_TBI1_SHIFT 38
#define TCR_TBI1 ((1UL) << 38)
#define TCR_HA ((1UL) << 39)
#define TCR_HD ((1UL) << 40)
#define TCR_HPD0_SHIFT 41
#define TCR_HPD0 ((1UL) << TCR_HPD0_SHIFT)
#define TCR_HPD1_SHIFT 42
#define TCR_HPD1 ((1UL) << TCR_HPD1_SHIFT)
#define TCR_TBID0 ((1UL) << 51)
#define TCR_TBID1 ((1UL) << 52)
#define TCR_NFD0 ((1UL) << 53)
#define TCR_NFD1 ((1UL) << 54)
#define TCR_E0PD0 ((1UL) << 55)
#define TCR_E0PD1 ((1UL) << 56)
#define TCR_TCMA0 ((1UL) << 57)
#define TCR_TCMA1 ((1UL) << 58)
#define TCR_DS ((1UL) << 59)

/* TCR_EL2 Registers bits */
#define TCR_EL2_DS		(1UL << 32)
#define TCR_EL2_RES1		((1U << 31) | (1 << 23))
#define TCR_EL2_HPD		(1 << 24)
#define TCR_EL2_TBI		(1 << 20)
#define TCR_EL2_PS_SHIFT	16
#define TCR_EL2_PS_MASK		(7 << TCR_EL2_PS_SHIFT)
#define TCR_EL2_PS_40B		(2 << TCR_EL2_PS_SHIFT)
#define TCR_EL2_TG0_MASK	TCR_TG0_MASK
#define TCR_EL2_SH0_MASK	TCR_SH0_MASK
#define TCR_EL2_ORGN0_MASK	TCR_ORGN0_MASK
#define TCR_EL2_IRGN0_MASK	TCR_IRGN0_MASK
#define TCR_EL2_T0SZ_MASK	0x3f
#define TCR_EL2_MASK	(TCR_EL2_TG0_MASK | TCR_EL2_SH0_MASK | \
			 TCR_EL2_ORGN0_MASK | TCR_EL2_IRGN0_MASK)

/* Shared ISS fault status code(IFSC/DFSC) for Data/Instruction aborts */
#define ESR_ELx_FSC (0x3F)
#define ESR_ELx_FSC_TYPE (0x3C)
#define ESR_ELx_FSC_LEVEL (0x03)
#define ESR_ELx_FSC_EXTABT (0x10)
#define ESR_ELx_FSC_MTE (0x11)
#define ESR_ELx_FSC_SERROR (0x11)
#define ESR_ELx_FSC_ACCESS (0x08)
#define ESR_ELx_FSC_FAULT (0x04)
#define ESR_ELx_FSC_PERM (0x0C)
#define ESR_ELx_FSC_SEA_TTW(n) (0x14 + (n))
#define ESR_ELx_FSC_SECC (0x18)
#define ESR_ELx_FSC_SECC_TTW(n) (0x1c + (n))
#define ESR_ELx_FSC_ADDRSZ (0x00)

/*
 * Annoyingly, the negative levels for Address size faults aren't laid out
 * contiguously (or in the desired order)
 */
#define ESR_ELx_FSC_ADDRSZ_nL(n) ((n) == -1 ? 0x25 : 0x2C)
#define ESR_ELx_FSC_ADDRSZ_L(n) \
	((n) < 0 ? ESR_ELx_FSC_ADDRSZ_nL(n) : (ESR_ELx_FSC_ADDRSZ + (n)))

/* Status codes for individual page table levels */
#define ESR_ELx_FSC_ACCESS_L(n) (ESR_ELx_FSC_ACCESS + (n))
#define ESR_ELx_FSC_PERM_L(n) (ESR_ELx_FSC_PERM + (n))

#define ESR_ELx_FSC_FAULT_nL (0x2C)
#define ESR_ELx_FSC_FAULT_L(n) \
	(((n) < 0 ? ESR_ELx_FSC_FAULT_nL : ESR_ELx_FSC_FAULT) + (n))

#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_PREP(_mask, _val) \
	({ ((typeof(_mask))(_val) << __bf_shf(_mask)) & (_mask); })
#define FIELD_GET(_mask, _reg) \
	({ (typeof(_mask))(((_reg) & (_mask)) >> __bf_shf(_mask)); })

#endif /* S2PT_H */