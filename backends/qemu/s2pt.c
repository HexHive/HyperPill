#include "qemu.h"

// code from the Linux kernel: 5bc10186 (Ari 26, 2025)
#define GENMASK_64(high, low) (((1ULL << ((high) - (low) + 1)) - 1) << (low))

struct s2_walk_info {
	int (*read_desc)(uint64_t pa, uint64_t *desc);
	uint64_t baddr;
	unsigned int max_oa_bits;
	unsigned int pgshift;
	unsigned int sl;
	unsigned int t0sz;
	bool be;
};

struct s2_trans {
	uint64_t output;
	unsigned long block_size;
	bool writable;
	bool readable;
	int level;
	uint32_t esr;
	uint64_t desc;
};

static uint32_t compute_fsc(int level, uint32_t fsc) {
	return fsc | (level & 0x3);
}

// The region size is 2^(64-T0SZ) bytes.
static int get_ia_size(struct s2_walk_info *wi) {
	return 64 - wi->t0sz;
}

#define SZ_4K 0x00001000
#define SZ_16K 0x00004000
#define SZ_64K 0x00010000
static int check_base_s2_limits(struct s2_walk_info *wi, int level,
				int input_size, int stride) {
	int start_size, ia_size;

	ia_size = get_ia_size(wi);

	/* Check translation limits */
	switch (BIT(wi->pgshift)) {
	case SZ_64K:
		if (level == 0 || (level == 1 && ia_size <= 42))
			return -1;
		break;
	case SZ_16K:
		if (level == 0 || (level == 1 && ia_size <= 40))
			return -1;
		break;
	case SZ_4K:
		if (level < 0 || (level == 0 && ia_size <= 42))
			return -1;
		break;
	}

	/* Check input size limits */
	if (input_size > ia_size)
		return -1;

	/* Check number of entries in starting level table */
	start_size = input_size - ((3 - level) * stride + wi->pgshift);
	if (start_size < 1 || start_size > stride + 4)
		return -1;

	return 0;
}

/* Check if output is within boundaries */
static int check_output_size(struct s2_walk_info *wi, uint64_t output) {
	unsigned int output_size = wi->max_oa_bits;

	if (output_size != 48 && (output & GENMASK_64(47, output_size)))
		return -1;

	return 0;
}

typedef uint64_t pteval_t;
#define _AT(T, X) ((T)(X))
#define PTE_CONT (_AT(pteval_t, 1) << 52) /* Contiguous range */

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
static int walk_s2(uint64_t ipa, struct s2_walk_info *wi,
		   struct s2_trans *output) {
	int first_block_level, level, stride, input_size, base_lower_bound;
	uint64_t base_addr;
	unsigned int addr_top, addr_bottom;
	uint64_t desc; /* page table entry */
	int ret;
	uint64_t paddr;

	switch (BIT(wi->pgshift)) {
	default:
	case SZ_64K:
	case SZ_16K:
		level = 3 - wi->sl;
		first_block_level = 2;
		break;
	case SZ_4K:
		level = 2 - wi->sl;
		first_block_level = 1;
		break;
	}

	stride = wi->pgshift - 3;
	input_size = get_ia_size(wi);
	if (input_size > 48 || input_size < 25)
		return -1;

	ret = check_base_s2_limits(wi, level, input_size, stride);
	if (ret)
		return ret;

	base_lower_bound =
		3 + input_size - ((3 - level) * stride + wi->pgshift);
	base_addr = wi->baddr & GENMASK_64(47, base_lower_bound);

	if (check_output_size(wi, base_addr)) {
		output->esr = compute_fsc(level, ESR_ELx_FSC_ADDRSZ);
		return -1;
	}

	// 10, 9, 9, 12
	addr_top = input_size - 1;

	while (1) {
		uint64_t index;

		addr_bottom = (3 - level) * stride + wi->pgshift;
		// [39: 30], [29: 21], [20: 12], [11: 0]
		index = (ipa & GENMASK_64(addr_top, addr_bottom)) >>
			(addr_bottom - 3);

		paddr = base_addr | index;
		ret = wi->read_desc(paddr, &desc);

		/*
		 * Handle reversedescriptors if endianness differs between the
		 * host and the guest hypervisor.
		 */
		if (wi->be)
			desc = be64_to_cpu(desc);
		else
			desc = le64_to_cpu(desc);

		/* Check for valid descriptor at this point */
		if (!(desc & 1) || ((desc & 3) == 1 && level == 3)) {
			output->esr = compute_fsc(level, ESR_ELx_FSC_FAULT);
			output->desc = desc;
			output->level = level;
			return -1;
		}

		/* We're at the final level or block translation level */
		if ((desc & 3) == 1 || level == 3)
			break;

		if (check_output_size(wi, desc)) {
			output->esr = compute_fsc(level, ESR_ELx_FSC_ADDRSZ);
			output->desc = desc;
			output->level = level;
			return -1;
		}

		base_addr = desc & GENMASK_64(47, wi->pgshift);

		level += 1;
		addr_top = addr_bottom - 1;
	}

	if (level < first_block_level) {
		output->esr = compute_fsc(level, ESR_ELx_FSC_FAULT);
		output->desc = desc;
		output->level = level;
		return -1;
	}

	if (check_output_size(wi, desc)) {
		output->esr = compute_fsc(level, ESR_ELx_FSC_ADDRSZ);
		output->desc = desc;
		output->level = level;
		return -1;
	}

	if (!(desc & BIT(10))) {
		output->esr = compute_fsc(level, ESR_ELx_FSC_ACCESS);
		output->desc = desc;
		output->level = level;
		return -1;
	}

	addr_bottom += contiguous_bit_shift(desc, wi, level);

	/* Calculate and return the result */
	paddr = (desc & GENMASK_64(47, addr_bottom)) |
		(ipa & GENMASK_64(addr_bottom - 1, 0));
	output->output = paddr;
	output->block_size = 1UL << ((3 - level) * stride + wi->pgshift);
	output->readable = desc & (0b01 << 6);
	output->writable = desc & (0b10 << 6);
	output->level = level;
	output->desc = desc;
	return 0;
}

static int read_guest_s2_desc(uint64_t pa, uint64_t *desc) {
	hp_cpu_physical_memory_read(pa, desc, sizeof(*desc));
}

#define TCR_EL2_PS_SHIFT 16
#define TCR_EL2_PS_MASK (7 << TCR_EL2_PS_SHIFT)
#define TCR_TG0_SHIFT 14
#define TCR_TG0_MASK (3 << TCR_TG0_SHIFT)
#define TCR_TG0_4K (0 << TCR_TG0_SHIFT)
#define TCR_TG0_64K (1 << TCR_TG0_SHIFT)
#define TCR_TG0_16K (2 << TCR_TG0_SHIFT)
#define TCR_EL2_T0SZ_MASK 0x3f
#define VTCR_EL2_PS_SHIFT TCR_EL2_PS_SHIFT
#define VTCR_EL2_PS_MASK TCR_EL2_PS_MASK
#define VTCR_EL2_TG0_MASK TCR_TG0_MASK
#define VTCR_EL2_TG0_4K TCR_TG0_4K
#define VTCR_EL2_TG0_16K TCR_TG0_16K
#define VTCR_EL2_TG0_64K TCR_TG0_64K
#define VTCR_EL2_SL0_SHIFT 6
#define VTCR_EL2_SL0_MASK (3 << VTCR_EL2_SL0_SHIFT)

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

static void vtcr_to_walk_info(uint64_t vtcr, struct s2_walk_info *wi) {
	wi->t0sz = vtcr & TCR_EL2_T0SZ_MASK;

	switch (vtcr & VTCR_EL2_TG0_MASK) {
	case VTCR_EL2_TG0_4K:
		wi->pgshift = 12;
		break;
	case VTCR_EL2_TG0_16K:
		wi->pgshift = 14;
		break;
	case VTCR_EL2_TG0_64K:
	default: /* IMPDEF: treat any other value as 64k */
		wi->pgshift = 16;
		break;
	}

	wi->sl = ((vtcr & VTCR_EL2_SL0_MASK) >> VTCR_EL2_SL0_SHIFT);
	/* Global limit for now, should eventually be per-VM */
	wi->max_oa_bits = MIN(48, ps_to_output_size((vtcr & VTCR_EL2_PS_MASK) >>
						    VTCR_EL2_PS_SHIFT));
}

#define SCTLR_ELx_EE_SHIFT 25
#define SCTLR_ELx_EE (1 << SCTLR_ELx_EE_SHIFT)
int gpa2hpa(uint64_t gipa, uint64_t *phy, int *translation_level) {
	uint64_t vtcr_el2 = (ARM_CPU(QEMU_CPU(0))->env).cp15.vtcr_el2;

	struct s2_walk_info wi;
	struct s2_trans output;

	output.esr = 0;

	wi.read_desc = read_guest_s2_desc;
	wi.baddr = (ARM_CPU(QEMU_CPU(0))->env).cp15.vttbr_el2;

	vtcr_to_walk_info(vtcr_el2, &wi);

	wi.be = ((ARM_CPU(QEMU_CPU(0))->env).cp15.sctlr_el[2]) & SCTLR_ELx_EE;
	int ret = walk_s2(gipa, &wi, &output);
	if (ret) {
		*phy = 0;
		*translation_level = 3 - output.level;
		return output.esr;
	} else {
		*phy = output.output;
		*translation_level = 3 - output.level;
		return output.esr;
	}
}

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
	bool hpd;
	bool e0poe;
	bool poe;
	bool pan;
	bool be;
	bool s2;
};

struct s1_walk_result {
	union {
		struct {
			uint64_t desc;
			uint64_t pa;
			s8 level;
			u8 APTable;
			bool UXNTable;
			bool PXNTable;
			bool uwxn;
			bool uov;
			bool ur;
			bool uw;
			bool ux;
			bool pwxn;
			bool pov;
			bool pr;
			bool pw;
			bool px;
		};
		struct {
			u8 fst;
			bool ptw;
			bool s2;
		};
	};
	bool failed;
};

static enum trans_regime compute_translation_regime(struct kvm_vcpu *vcpu,
						    u32 op) {
	/*
	 * We only get here from guest EL2, so the translation
	 * regime AT applies to is solely defined by {E2H,TGE}.
	 */
	switch (op) {
	case OP_AT_S1E2R:
	case OP_AT_S1E2W:
	case OP_AT_S1E2A:
		return vcpu_el2_e2h_is_set(vcpu) ? TR_EL20 : TR_EL2;
		break;
	default:
		return (vcpu_el2_e2h_is_set(vcpu) &&
			vcpu_el2_tge_is_set(vcpu)) ?
			       TR_EL20 :
			       TR_EL10;
	}
}

static int setup_s1_walk(struct s1_walk_info *wi, struct s1_walk_result *wr,
			 uint64_t va) {
	uint64_t hcr, sctlr, tcr, tg, ps, ia_bits, ttbr;
	unsigned int stride, x;
	bool va55, tbi, lva, as_el0;

	hcr = __vcpu_sys_reg(vcpu, HCR_EL2);

	wi->regime = compute_translation_regime(op);
	as_el0 = (op == OP_AT_S1E0R || op == OP_AT_S1E0W);
	wi->pan = (op == OP_AT_S1E1RP || op == OP_AT_S1E1WP) &&
		  (*vcpu_cpsr(vcpu) & PSR_PAN_BIT);

	va55 = va & BIT(55);

	if (wi->regime == TR_EL2 && va55)
		goto addrsz;

	wi->s2 = wi->regime == TR_EL10 && (hcr & (HCR_VM | HCR_DC));

	switch (wi->regime) {
	case TR_EL10:
		sctlr = vcpu_read_sys_reg(vcpu, SCTLR_EL1);
		tcr = vcpu_read_sys_reg(vcpu, TCR_EL1);
		ttbr = (va55 ? vcpu_read_sys_reg(vcpu, TTBR1_EL1) :
			       vcpu_read_sys_reg(vcpu, TTBR0_EL1));
		break;
	case TR_EL2:
	case TR_EL20:
		sctlr = vcpu_read_sys_reg(vcpu, SCTLR_EL2);
		tcr = vcpu_read_sys_reg(vcpu, TCR_EL2);
		ttbr = (va55 ? vcpu_read_sys_reg(vcpu, TTBR1_EL2) :
			       vcpu_read_sys_reg(vcpu, TTBR0_EL2));
		break;
	default:
		BUG();
	}

	tbi = (wi->regime == TR_EL2 ? FIELD_GET(TCR_EL2_TBI, tcr) :
				      (va55 ? FIELD_GET(TCR_TBI1, tcr) :
					      FIELD_GET(TCR_TBI0, tcr)));

	if (!tbi && (uint64_t)sign_extend64(va, 55) != va)
		goto addrsz;

	va = (uint64_t)sign_extend64(va, 55);

	/* Let's put the MMU disabled case aside immediately */
	switch (wi->regime) {
	case TR_EL10:
		/*
		 * If dealing with the EL1&0 translation regime, 3 things
		 * can disable the S1 translation:
		 *
		 * - HCR_EL2.DC = 1
		 * - HCR_EL2.{E2H,TGE} = {0,1}
		 * - SCTLR_EL1.M = 0
		 *
		 * The TGE part is interesting. If we have decided that this
		 * is EL1&0, then it means that either {E2H,TGE} == {1,0} or
		 * {0,x}, and we only need to test for TGE == 1.
		 */
		if (hcr & (HCR_DC | HCR_TGE)) {
			wr->level = S1_MMU_DISABLED;
			break;
		}
		fallthrough;
	case TR_EL2:
	case TR_EL20:
		if (!(sctlr & SCTLR_ELx_M))
			wr->level = S1_MMU_DISABLED;
		break;
	}

	if (wr->level == S1_MMU_DISABLED) {
		if (va >= BIT(kvm_get_pa_bits(vcpu->kvm)))
			goto addrsz;

		wr->pa = va;
		return 0;
	}

	wi->be = sctlr & SCTLR_ELx_EE;

	wi->hpd = kvm_has_feat(vcpu->kvm, ID_AA64MMFR1_EL1, HPDS, IMP);
	wi->hpd &= (wi->regime == TR_EL2 ? FIELD_GET(TCR_EL2_HPD, tcr) :
					   (va55 ? FIELD_GET(TCR_HPD1, tcr) :
						   FIELD_GET(TCR_HPD0, tcr)));
	/* R_JHSVW */
	wi->hpd |= s1pie_enabled(vcpu, wi->regime);

	/* Do we have POE? */
	compute_s1poe(vcpu, wi);

	/* R_BVXDG */
	wi->hpd |= (wi->poe || wi->e0poe);

	/* Someone was silly enough to encode TG0/TG1 differently */
	if (va55) {
		wi->txsz = FIELD_GET(TCR_T1SZ_MASK, tcr);
		tg = FIELD_GET(TCR_TG1_MASK, tcr);

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
		wi->txsz = FIELD_GET(TCR_T0SZ_MASK, tcr);
		tg = FIELD_GET(TCR_TG0_MASK, tcr);

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
	if (!kvm_has_feat_enum(vcpu->kvm, ID_AA64MMFR2_EL1, ST, 48_47)) {
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
		lva = kvm_has_feat(vcpu->kvm, ID_AA64MMFR0_EL1, TGRAN4, 52_BIT);
		lva &= tcr & (wi->regime == TR_EL2 ? TCR_EL2_DS : TCR_DS);
		break;
	case SZ_16K:
		lva = kvm_has_feat(vcpu->kvm, ID_AA64MMFR0_EL1, TGRAN16,
				   52_BIT);
		lva &= tcr & (wi->regime == TR_EL2 ? TCR_EL2_DS : TCR_DS);
		break;
	case SZ_64K:
		lva = kvm_has_feat(vcpu->kvm, ID_AA64MMFR2_EL1, VARange, 52);
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
	if (wi->regime != TR_EL2 &&
	    (tcr & (va55 ? TCR_EPD1_MASK : TCR_EPD0_MASK)))
		goto transfault_l0;

	/* R_BNDVG and following statements */
	if (kvm_has_feat(vcpu->kvm, ID_AA64MMFR2_EL1, E0PD, IMP) && as_el0 &&
	    (tcr & (va55 ? TCR_E0PD1 : TCR_E0PD0)))
		goto transfault_l0;

	/* AArch64.S1StartLevel() */
	stride = wi->pgshift - 3;
	wi->sl = 3 - (((ia_bits - 1) - wi->pgshift) / stride);

	ps = (wi->regime == TR_EL2 ? FIELD_GET(TCR_EL2_PS_MASK, tcr) :
				     FIELD_GET(TCR_IPS_MASK, tcr));

	wi->max_oa_bits = min(get_kvm_ipa_limit(), ps_to_output_size(ps));

	/* Compute minimal alignment */
	x = 3 + ia_bits - ((3 - wi->sl) * stride + wi->pgshift);

	wi->baddr = ttbr & TTBRx_EL1_BADDR;

	/* R_VPBBF */
	if (check_output_size(wi->baddr, wi))
		goto addrsz;

	wi->baddr &= GENMASK_ULL(wi->max_oa_bits - 1, x);

	return 0;

addrsz: /* Address Size Fault level 0 */
	fail_s1_walk(wr, ESR_ELx_FSC_ADDRSZ_L(0), false, false);
	return -EFAULT;

transfault_l0: /* Translation Fault level 0 */
	fail_s1_walk(wr, ESR_ELx_FSC_FAULT_L(0), false, false);
	return -EFAULT;
}

static int walk_s1(struct kvm_vcpu *vcpu, struct s1_walk_info *wi,
		   struct s1_walk_result *wr, uint64_t va) {
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

		if (wi->s2) {
			struct kvm_s2_trans s2_trans = {};

			ret = kvm_walk_nested_s2(vcpu, ipa, &s2_trans);
			if (ret) {
				fail_s1_walk(wr,
					     (s2_trans.esr &
					      ~ESR_ELx_FSC_LEVEL) |
						     level,
					     true, true);
				return ret;
			}

			if (!kvm_s2_trans_readable(&s2_trans)) {
				fail_s1_walk(wr, ESR_ELx_FSC_PERM_L(level),
					     true, true);

				return -EPERM;
			}

			ipa = kvm_s2_trans_output(&s2_trans);
		}

		ret = kvm_read_guest(vcpu->kvm, ipa, &desc, sizeof(desc));
		if (ret) {
			fail_s1_walk(wr, ESR_ELx_FSC_SEA_TTW(level), true,
				     false);
			return ret;
		}

		if (wi->be)
			desc = be64_to_cpu((__force __be64)desc);
		else
			desc = le64_to_cpu((__force __le64)desc);

		/* Invalid descriptor */
		if (!(desc & BIT(0)))
			goto transfault;

		/* Block mapping, check validity down the line */
		if (!(desc & BIT(1)))
			break;

		/* Page mapping */
		if (level == 3)
			break;

		/* Table handling */
		if (!wi->hpd) {
			wr->APTable |= FIELD_GET(S1_TABLE_AP, desc);
			wr->UXNTable |= FIELD_GET(PMD_TABLE_UXN, desc);
			wr->PXNTable |= FIELD_GET(PMD_TABLE_PXN, desc);
		}

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

void walk_s1_slow(
    bool guest, // Translate guest addresses to host (are we walking the guest's page table ?)
    void (*page_table_cb)(bx_phy_address address, int level), // cb for each frame that belongs to the page-table tree
    void (*leaf_pte_cb)(bx_phy_address addr, bx_phy_address pte, bx_phy_address mask) // cb for each leaf pte
) {
	struct s1_walk_result wr = {};
	struct s1_walk_info wi = {};
	bool perm_fail = false;
	int ret, idx;

	ret = setup_s1_walk(vcpu, op, &wi, &wr, vaddr);
	if (ret)
		goto compute_par;

	if (wr.level == S1_MMU_DISABLED)
		goto compute_par;

	idx = srcu_read_lock(&vcpu->kvm->srcu);

	ret = walk_s1(vcpu, &wi, &wr, vaddr);

	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	if (ret)
		goto compute_par;

	compute_s1_permissions(vcpu, &wi, &wr);

	switch (op) {
	case OP_AT_S1E1RP:
	case OP_AT_S1E1R:
	case OP_AT_S1E2R:
		perm_fail = !wr.pr;
		break;
	case OP_AT_S1E1WP:
	case OP_AT_S1E1W:
	case OP_AT_S1E2W:
		perm_fail = !wr.pw;
		break;
	case OP_AT_S1E0R:
		perm_fail = !wr.ur;
		break;
	case OP_AT_S1E0W:
		perm_fail = !wr.uw;
		break;
	case OP_AT_S1E1A:
	case OP_AT_S1E2A:
		break;
	default:
		BUG();
	}

	if (perm_fail)
		fail_s1_walk(&wr, ESR_ELx_FSC_PERM_L(wr.level), false, false);

compute_par:
	return compute_par_s1(vcpu, &wr, wi.regime);
}
