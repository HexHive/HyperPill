// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 - Linaro Ltd
 * Author: Jintack Lim <jintack.lim@linaro.org>
 *
 * Modified by Qiang Liu <cyruscyliu@gmail.com>
 */

#include "qemu.h"
#include "s2pt.h"

static void fail_s1_walk(struct s1_walk_result *wr, uint8_t fst, bool ptw,
			 bool s2) {
	wr->fst = fst;
	wr->ptw = ptw;
	wr->s2 = s2;
	wr->failed = true;
}

static int get_ia_size(struct s1_walk_info *wi) {
	return 64 - wi->txsz;
}

/* Return true if the IPA is out of the OA range */
static bool check_output_size(uint64_t ipa, struct s1_walk_info *wi) {
	return wi->max_oa_bits < 48 && (ipa & GENMASK_ULL(47, wi->max_oa_bits));
}

static inline bool isar_feature_aa64_s1pie() {
	return false;
}

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

static inline int64_t sign_extend64(uint64_t value, int index) {
	uint8_t shift = 63 - index;
	return (int64_t)(value << shift) >> shift;
}

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

int setup_s1_walk(uint8_t op, struct s1_walk_info *wi,
		  struct s1_walk_result *wr, uint64_t va) {
	uint64_t hcr, sctlr, tcr, tg, ps, ia_bits, ttbr;
	unsigned int stride, x;
	bool va55, tbi, lva, as_el0;

	hcr = ARM_CPU(QEMU_CPU(0))->env.cp15.hcr_el2;

	wi->regime = TR_EL10;
	as_el0 = (op == OP_AT_S1E0R || op == OP_AT_S1E0W);

	va55 = va & BIT(55);

	wi->s2 = hcr & (HCR_VM | HCR_DC);

	sctlr = ARM_CPU(QEMU_CPU(0))->env.cp15.sctlr_el[1];
	tcr = ARM_CPU(QEMU_CPU(0))->env.cp15.tcr_el[1];
	ttbr = (va55 ? ARM_CPU(QEMU_CPU(0))->env.cp15.ttbr1_el[1] :
		       ARM_CPU(QEMU_CPU(0))->env.cp15.ttbr0_el[1]);

	tbi = (va55 ? extract64(tcr, TCR_TBI1_SHIFT, 1) :
		      extract64(tcr, TCR_TBI0_SHIFT, 1));

	if (!tbi && (uint64_t)sign_extend64(va, 55) != va)
		goto addrsz;

	va = (uint64_t)sign_extend64(va, 55);

	if (hcr & (HCR_DC | HCR_TGE)) {
		wr->level = S1_MMU_DISABLED;
	}
	if (!(sctlr & SCTLR_ELx_M)) {
		wr->level = S1_MMU_DISABLED;
	}

	if (wr->level == S1_MMU_DISABLED) {
		if (va >= (1UL << 48))
			goto addrsz;

		wr->pa = va;
		return 0;
	}

	wi->be = sctlr & SCTLR_ELx_EE;

	/* Someone was silly enough to encode TG0/TG1 differently */
	if (va55) {
		wi->txsz = extract64(tcr, TCR_T1SZ_OFFSET, TCR_TxSZ_WIDTH);
		tg = extract64(tcr, TCR_TG1_SHIFT, TCR_TG1_WIDTH);

		switch (tg << TCR_TG1_SHIFT) {
		case TCR_TG1_4K:
			wi->pgshift = 12;
			break;
		case TCR_TG1_16K:
			wi->pgshift = 14;
			break;
		case TCR_TG1_64K:
		default: /* IMPDEF: treat any other value as 64k */
			wi->pgshift = 16;
			break;
		}
	} else {
		wi->txsz = extract64(tcr, TCR_T0SZ_OFFSET, TCR_TxSZ_WIDTH);
		tg = extract64(tcr, TCR_TG0_SHIFT, TCR_TG0_WIDTH);

		switch (tg << TCR_TG0_SHIFT) {
		case TCR_TG0_4K:
			wi->pgshift = 12;
			break;
		case TCR_TG0_16K:
			wi->pgshift = 14;
			break;
		case TCR_TG0_64K:
		default: /* IMPDEF: treat any other value as 64k */
			wi->pgshift = 16;
			break;
		}
	}

	/* R_PLCGL, R_YXNYW */
	if (!isar_feature_aa64_st(&(ARM_CPU(QEMU_CPU(0))->isar))) {
		if (wi->txsz > 39)
			goto transfault_l0;
	} else {
		if (wi->txsz > 48 ||
		    (BIT(wi->pgshift) == SZ_64K && wi->txsz > 47))
			goto transfault_l0;
	}

	/* R_GTJBY, R_SXWGM */
	switch (BIT(wi->pgshift)) {
	case SZ_4K:
		lva = isar_feature_aa64_tgran4(&(ARM_CPU(QEMU_CPU(0))->isar));
		lva &= tcr & TCR_DS;
		break;
	case SZ_16K:
		lva = isar_feature_aa64_tgran16(&(ARM_CPU(QEMU_CPU(0))->isar));
		lva &= tcr & TCR_DS;
		break;
	case SZ_64K:
		lva = isar_feature_aa64_lva(&(ARM_CPU(QEMU_CPU(0))->isar));
		break;
	}

	if ((lva && wi->txsz < 12) || (!lva && wi->txsz < 16))
		goto transfault_l0;

	ia_bits = get_ia_size(wi);

	/* R_YYVYV, I_THCZK */
	if ((!va55 && va > GENMASK(ia_bits - 1, 0)) ||
	    (va55 && va < GENMASK(63, ia_bits)))
		goto transfault_l0;

	/* I_ZFSYQ */
	if ((tcr & (va55 ? TCR_EPD1_MASK : TCR_EPD0_MASK)))
		goto transfault_l0;

	/* R_BNDVG and following statements */
	if (isar_feature_aa64_e0pd(&(ARM_CPU(QEMU_CPU(0))->isar)) && as_el0 &&
	    (tcr & (va55 ? TCR_E0PD1 : TCR_E0PD0)))
		goto transfault_l0;

	/* AArch64.S1StartLevel() */
	stride = wi->pgshift - 3;
	wi->sl = 3 - (((ia_bits - 1) - wi->pgshift) / stride);

	ps = FIELD_GET(TCR_IPS_MASK, tcr);

	wi->max_oa_bits = MIN(48, ps_to_output_size(ps));

	/* Compute minimal alignment */
	x = 3 + ia_bits - ((3 - wi->sl) * stride + wi->pgshift);

	wi->baddr = ttbr & GENMASK_ULL(47, 1);

	/* R_VPBBF */
	if (check_output_size(wi->baddr, wi))
		goto addrsz;

	wi->baddr &= GENMASK_ULL(wi->max_oa_bits - 1, x);

	return 0;

addrsz: /* Address Size Fault level 0 */
	fail_s1_walk(wr, ESR_ELx_FSC_ADDRSZ_L(0), false, false);
	return -1;

transfault_l0: /* Translation Fault level 0 */
	fail_s1_walk(wr, ESR_ELx_FSC_FAULT_L(0), false, false);
	return -1;
}

int walk_s1(struct s1_walk_info *wi, struct s1_walk_result *wr, uint64_t va) {
	uint64_t va_top, va_bottom, baddr, desc;
	int level, stride, ret;

	level = wi->sl;
	stride = wi->pgshift - 3;
	baddr = wi->baddr;

	va_top = get_ia_size(wi) - 1;

	while (1) {
		uint64_t index, ipa;

		va_bottom = (3 - level) * stride + wi->pgshift;
		index = (va & GENMASK_ULL(va_top, va_bottom)) >>
			(va_bottom - 3);

		ipa = baddr | index;
		wr->level = level;

		if (wi->s2) {
			struct s2_trans s2_trans = {};

			ret = walk_nested_s2(ipa, &s2_trans);
			if (ret) {
				fail_s1_walk(wr,
					     (s2_trans.esr &
					      ~ESR_ELx_FSC_LEVEL) |
						     level,
					     true, true);
				return ret;
			}

			ipa = s2_trans_output(&s2_trans);
		}

		if (wi->page_table_cb) {
			wi->page_table_cb(ipa, 3 - level);
		}
		cpu_physical_memory_read(ipa, &desc, sizeof(desc));
		wr->desc = desc;

		if (wi->be)
			desc = be64_to_cpu(desc);
		else
			desc = le64_to_cpu(desc);

		/* Invalid descriptor */
		if (!(desc & BIT(0)))
			goto transfault;

		/* Block mapping, check validity down the line */
		if (!(desc & BIT(1)))
			break;

		/* Page mapping */
		if (level == 3)
			break;

		baddr = desc & GENMASK_ULL(47, wi->pgshift);

		/* Check for out-of-range OA */
		if (check_output_size(baddr, wi))
			goto addrsz;

		/* Prepare for next round */
		va_top = va_bottom - 1;
		level++;
	}

	/* Block mapping, check the validity of the level */
	if (!(desc & BIT(1))) {
		bool valid_block = false;

		switch (BIT(wi->pgshift)) {
		case SZ_4K:
			valid_block = level == 1 || level == 2;
			break;
		case SZ_16K:
		case SZ_64K:
			valid_block = level == 2;
			break;
		}

		if (!valid_block)
			goto transfault;
	}

	if (check_output_size(desc & GENMASK(47, va_bottom), wi))
		goto addrsz;

	va_bottom += contiguous_bit_shift(desc, wi, level);

	wr->failed = false;
	wr->level = level;
	wr->desc = desc;
	wr->pa = desc & GENMASK(47, va_bottom);
	wr->pa |= va & GENMASK_ULL(va_bottom - 1, 0);

	return 0;

addrsz:
	fail_s1_walk(wr, ESR_ELx_FSC_ADDRSZ_L(level), true, false);
	return -EINVAL;
transfault:
	fail_s1_walk(wr, ESR_ELx_FSC_FAULT_L(level), true, false);
	return -ENOENT;
}

#define MEMATTR(ic, oc) (MEMATTR_##oc << 4 | MEMATTR_##ic)
#define MEMATTR_NC 0b0100
#define MEMATTR_Wt 0b1000
#define MEMATTR_Wb 0b1100
#define MEMATTR_WbRaWa 0b1111

#define MEMATTR_IS_DEVICE(m) (((m) & GENMASK(7, 4)) == 0)

static uint8_t s2_memattr_to_attr(uint8_t memattr) {
	memattr &= 0b1111;

	switch (memattr) {
	case 0b0000:
	case 0b0001:
	case 0b0010:
	case 0b0011:
		return memattr << 2;
	case 0b0100:
		return MEMATTR(Wb, Wb);
	case 0b0101:
		return MEMATTR(NC, NC);
	case 0b0110:
		return MEMATTR(Wt, NC);
	case 0b0111:
		return MEMATTR(Wb, NC);
	case 0b1000:
		/* Reserved, assume NC */
		return MEMATTR(NC, NC);
	case 0b1001:
		return MEMATTR(NC, Wt);
	case 0b1010:
		return MEMATTR(Wt, Wt);
	case 0b1011:
		return MEMATTR(Wb, Wt);
	case 0b1100:
		/* Reserved, assume NC */
		return MEMATTR(NC, NC);
	case 0b1101:
		return MEMATTR(NC, Wb);
	case 0b1110:
		return MEMATTR(Wt, Wb);
	case 0b1111:
		return MEMATTR(Wb, Wb);
	default:
		abort();
	}
}

static uint8_t combine_s1_s2_attr(uint8_t s1, uint8_t s2) {
	bool transient;
	uint8_t final = 0;

	/* Upgrade transient s1 to non-transient to simplify things */
	switch (s1) {
	case 0b0001 ... 0b0011: /* Normal, Write-Through Transient */
		transient = true;
		s1 = MEMATTR_Wt | (s1 & GENMASK(1, 0));
		break;
	case 0b0101 ... 0b0111: /* Normal, Write-Back Transient */
		transient = true;
		s1 = MEMATTR_Wb | (s1 & GENMASK(1, 0));
		break;
	default:
		transient = false;
	}

	/* S2CombineS1AttrHints() */
	if ((s1 & GENMASK(3, 2)) == MEMATTR_NC ||
	    (s2 & GENMASK(3, 2)) == MEMATTR_NC)
		final = MEMATTR_NC;
	else if ((s1 & GENMASK(3, 2)) == MEMATTR_Wt ||
		 (s2 & GENMASK(3, 2)) == MEMATTR_Wt)
		final = MEMATTR_Wt;
	else
		final = MEMATTR_Wb;

	if (final != MEMATTR_NC) {
		/* Inherit RaWa hints form S1 */
		if (transient) {
			switch (s1 & GENMASK(3, 2)) {
			case MEMATTR_Wt:
				final = 0;
				break;
			case MEMATTR_Wb:
				final = MEMATTR_NC;
				break;
			}
		}

		final |= s1 & GENMASK(1, 0);
	}

	return final;
}

#define ATTR_NSH 0b00
#define ATTR_RSV 0b01
#define ATTR_OSH 0b10
#define ATTR_ISH 0b11

#define PTE_SHARED ((3UL) << 8) /* SH[1:0], inner shareable */

static uint8_t compute_sh(uint8_t attr, uint64_t desc) {
	uint8_t sh;

	/* Any form of device, as well as NC has SH[1:0]=0b10 */
	if (MEMATTR_IS_DEVICE(attr) || attr == MEMATTR(NC, NC))
		return ATTR_OSH;

	sh = FIELD_GET(PTE_SHARED, desc);
	if (sh == ATTR_RSV) /* Reserved, mapped to NSH */
		sh = ATTR_NSH;

	return sh;
}

static uint8_t combine_sh(uint8_t s1_sh, uint8_t s2_sh) {
	if (s1_sh == ATTR_OSH || s2_sh == ATTR_OSH)
		return ATTR_OSH;
	if (s1_sh == ATTR_ISH || s2_sh == ATTR_ISH)
		return ATTR_ISH;

	return ATTR_NSH;
}

static inline bool isar_feature_aa64_mteperm() {
	return false;
}

static uint64_t compute_par_s12(uint64_t s1_par, struct s2_trans *tr) {
	uint8_t s1_parattr, s2_memattr, final_attr;
	uint64_t par;

	/* If S2 has failed to translate, report the damage */
	if (tr->esr) {
		par = SYS_PAR_EL1_RES1;
		par |= SYS_PAR_EL1_F;
		par |= SYS_PAR_EL1_S;
		par |= FIELD_PREP(SYS_PAR_EL1_FST, tr->esr);
		return par;
	}

	s1_parattr = FIELD_GET(SYS_PAR_EL1_ATTR, s1_par);
	s2_memattr = FIELD_GET(GENMASK(5, 2), tr->desc);

	if (ARM_CPU(QEMU_CPU(0))->env.cp15.hcr_el2 & HCR_FWB) {
		if (!isar_feature_aa64_mteperm())
			s2_memattr &= ~BIT(3);

		/* Combination of R_VRJSW and R_RHWZM */
		switch (s2_memattr) {
		case 0b0101:
			if (MEMATTR_IS_DEVICE(s1_parattr))
				final_attr = s1_parattr;
			else
				final_attr = MEMATTR(NC, NC);
			break;
		case 0b0110:
		case 0b1110:
			final_attr = MEMATTR(WbRaWa, WbRaWa);
			break;
		case 0b0111:
		case 0b1111:
			/* Preserve S1 attribute */
			final_attr = s1_parattr;
			break;
		case 0b0100:
		case 0b1100:
		case 0b1101:
			/* Reserved, do something non-silly */
			final_attr = s1_parattr;
			break;
		default:
			/*
			 * MemAttr[2]=0, Device from S2.
			 *
			 * FWB does not influence the way that stage 1
			 * memory types and attributes are combined
			 * with stage 2 Device type and attributes.
			 */
			final_attr =
				MIN(s2_memattr_to_attr(s2_memattr), s1_parattr);
		}
	} else {
		/* Combination of R_HMNDG, R_TNHFM and R_GQFSF */
		uint8_t s2_parattr = s2_memattr_to_attr(s2_memattr);

		if (MEMATTR_IS_DEVICE(s1_parattr) ||
		    MEMATTR_IS_DEVICE(s2_parattr)) {
			final_attr = MIN(s1_parattr, s2_parattr);
		} else {
			/* At this stage, this is memory vs memory */
			final_attr = combine_s1_s2_attr(s1_parattr & 0xf,
							s2_parattr & 0xf);
			final_attr |= combine_s1_s2_attr(s1_parattr >> 4,
							 s2_parattr >> 4)
				      << 4;
		}
	}

	if ((ARM_CPU(QEMU_CPU(0))->env.cp15.hcr_el2 & HCR_CD) &&
	    !MEMATTR_IS_DEVICE(final_attr))
		final_attr = MEMATTR(NC, NC);

	par = FIELD_PREP(SYS_PAR_EL1_ATTR, final_attr);
	par |= tr->output & GENMASK(47, 12);
	par |= FIELD_PREP(SYS_PAR_EL1_SH,
			  combine_sh(FIELD_GET(SYS_PAR_EL1_SH, s1_par),
				     compute_sh(final_attr, tr->desc)));

	return par;
}

#define PTE_ATTRINDX_MASK ((7UL) << 2)
uint64_t compute_par_s1(struct s1_walk_result *wr, enum trans_regime regime) {
	uint64_t par;

	if (wr->failed) {
		par = SYS_PAR_EL1_RES1;
		par |= SYS_PAR_EL1_F;
		par |= FIELD_PREP(SYS_PAR_EL1_FST, wr->fst);
		par |= wr->ptw ? SYS_PAR_EL1_PTW : 0;
		par |= wr->s2 ? SYS_PAR_EL1_S : 0;
	} else if (wr->level == S1_MMU_DISABLED) {
		/* MMU off or HCR_EL2.DC == 1 */
		par = SYS_PAR_EL1_NSE;
		par |= wr->pa & GENMASK_ULL(47, 12);

		if (regime == TR_EL10 &&
		    (ARM_CPU(QEMU_CPU(0))->env.cp15.hcr_el2 & HCR_DC)) {
			par |= FIELD_PREP(SYS_PAR_EL1_ATTR,
					  MEMATTR(WbRaWa, WbRaWa));
			par |= FIELD_PREP(SYS_PAR_EL1_SH, ATTR_NSH);
		} else {
			par |= FIELD_PREP(SYS_PAR_EL1_ATTR, 0); /* nGnRnE */
			par |= FIELD_PREP(SYS_PAR_EL1_SH, ATTR_OSH);
		}
	} else {
		uint64_t mair, sctlr;
		uint8_t sh;

		par = SYS_PAR_EL1_NSE;

		mair = ARM_CPU(QEMU_CPU(0))->env.cp15.mair_el[1];

		mair >>= FIELD_GET(PTE_ATTRINDX_MASK, wr->desc) * 8;
		mair &= 0xff;

		sctlr = ARM_CPU(QEMU_CPU(0))->env.cp15.sctlr_el[1];

		/* Force NC for memory if SCTLR_ELx.C is clear */
		if (!(sctlr & SCTLR_ELx_C) && !MEMATTR_IS_DEVICE(mair))
			mair = MEMATTR(NC, NC);

		par |= FIELD_PREP(SYS_PAR_EL1_ATTR, mair);
		par |= wr->pa & GENMASK_ULL(47, 12);

		sh = compute_sh(mair, wr->desc);
		par |= FIELD_PREP(SYS_PAR_EL1_SH, sh);
	}

	return par;
}

static uint64_t handle_at_slow(uint8_t op, uint64_t vaddr) {
	struct s1_walk_result wr = {};
	struct s1_walk_info wi = {};
	bool perm_fail = false;
	int ret, idx;

	ret = setup_s1_walk(op, &wi, &wr, vaddr);
	if (ret)
		goto compute_par;

	if (wr.level == S1_MMU_DISABLED)
		goto compute_par;

	ret = walk_s1(&wi, &wr, vaddr);

compute_par:
	return compute_par_s1(&wr, wi.regime);
}

uint64_t at_s1e01(uint8_t op, uint64_t vaddr) {
	return handle_at_slow(op, vaddr);
}

static inline bool isar_feature_aa64_nv1() {
	return false;
}

static inline bool el2_e2h_is_set() {
	return (!isar_feature_aa64_nv1() ||
		(ARM_CPU(QEMU_CPU(0))->env.cp15.hcr_el2 & HCR_E2H));
}

static inline bool el2_tge_is_set() {
	return ARM_CPU(QEMU_CPU(0))->env.cp15.hcr_el2 & HCR_TGE;
}

/* Performs stage 1 and 2 address translations */
uint64_t at_s12(uint8_t op, uint64_t vaddr) {
	struct s2_trans out = {};
	uint64_t ipa, par;
	bool write;
	int ret;

	/* Do the stage-1 translation */
	switch (op) {
	case OP_AT_S12E1R:
		op = OP_AT_S1E1R;
		write = false;
		break;
	case OP_AT_S12E1W:
		op = OP_AT_S1E1W;
		write = true;
		break;
	case OP_AT_S12E0R:
		op = OP_AT_S1E0R;
		write = false;
		break;
	case OP_AT_S12E0W:
		op = OP_AT_S1E0W;
		write = true;
		break;
	default:
		abort();
	}

	par = at_s1e01(op, vaddr);
	if (par & SYS_PAR_EL1_F /* Address translation aborted */)
		abort();

	/*
	 * If we only have a single stage of translation (E2H=0 or
	 * TGE=1), exit early. Same thing if {VM,DC}=={0,0}.
	 */
	if (!el2_e2h_is_set() || el2_tge_is_set() ||
	    !(ARM_CPU(QEMU_CPU(0))->env.cp15.hcr_el2 & (HCR_VM | HCR_DC)))
		return ~(0UL);

	/* Do the stage-2 translation */
	ipa = (par & GENMASK_ULL(47, 12)) | (vaddr & GENMASK_ULL(11, 0));
	out.esr = 0;
	ret = walk_nested_s2(ipa, &out);
	if (ret < 0)
		return ~(0UL);

	par = compute_par_s12(par, &out);
	return par;
}
