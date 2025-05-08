// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 - Columbia University and Linaro Ltd.
 * Author: Jintack Lim <jintack.lim@linaro.org>
 *
 * Modified by Qiang Liu <cyruscyliu@gmail.com>
 */

#include "qemu.h"
#include "nested.h"

struct s2_walk_info {
	void (*read_desc)(uint64_t pa, uint64_t *desc);
	u64 baddr;
	unsigned int max_oa_bits;
	unsigned int pgshift;
	unsigned int sl;
	unsigned int t0sz;
	bool be;
};

static u32 compute_fsc(int level, u32 fsc) {
	return fsc | (level & 0x3);
}

// The region size is 2^(64-T0SZ) bytes.
static int get_ia_size(struct s2_walk_info *wi) {
	return 64 - wi->t0sz;
}

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
static int check_output_size(struct s2_walk_info *wi, phys_addr_t output) {
	unsigned int output_size = wi->max_oa_bits;

	if (output_size != 48 && (output & GENMASK_ULL(47, output_size)))
		return -1;

	return 0;
}

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
 * This is essentially a C-version of the pseudo code from the ARM ARM
 * AArch64.TranslationTableWalk  function.  I strongly recommend looking at
 * that pseudocode in trying to understand this.
 *
 * Must be called with the kvm->srcu read lock held
 */
static int walk_nested_s2_pgd(phys_addr_t ipa, struct s2_walk_info *wi,
			      struct s2_trans *out) {
	int first_block_level, level, stride, input_size, base_lower_bound;
	phys_addr_t base_addr;
	unsigned int addr_top, addr_bottom;
	u64 desc; /* page table entry */
	int ret;
	phys_addr_t paddr;

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
		return -EFAULT;

	ret = check_base_s2_limits(wi, level, input_size, stride);
	if (WARN_ON(ret))
		return ret;

	base_lower_bound =
		3 + input_size - ((3 - level) * stride + wi->pgshift);
	base_addr = wi->baddr & GENMASK_ULL(47, base_lower_bound);

	if (check_output_size(wi, base_addr)) {
		out->esr = compute_fsc(level, ESR_ELx_FSC_ADDRSZ);
		return 1;
	}

	// 10, 9, 9, 12
	addr_top = input_size - 1;

	while (1) {
		phys_addr_t index;

		addr_bottom = (3 - level) * stride + wi->pgshift;
		index = (ipa & GENMASK_ULL(addr_top, addr_bottom)) >>
			(addr_bottom - 3);

		paddr = base_addr | index;
		ret = wi->read_desc(paddr, &desc, wi->data);

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
			out->esr = compute_fsc(level, ESR_ELx_FSC_FAULT);
			out->desc = desc;
			return 1;
		}

		/* We're at the final level or block translation level */
		if ((desc & 3) == 1 || level == 3)
			break;

		if (check_output_size(wi, desc)) {
			out->esr = compute_fsc(level, ESR_ELx_FSC_ADDRSZ);
			out->desc = desc;
			return 1;
		}

		base_addr = desc & GENMASK_ULL(47, wi->pgshift);

		level += 1;
		addr_top = addr_bottom - 1;
	}

	if (level < first_block_level) {
		out->esr = compute_fsc(level, ESR_ELx_FSC_FAULT);
		out->desc = desc;
		return 1;
	}

	if (check_output_size(wi, desc)) {
		out->esr = compute_fsc(level, ESR_ELx_FSC_ADDRSZ);
		out->desc = desc;
		return 1;
	}

	if (!(desc & BIT(10))) {
		out->esr = compute_fsc(level, ESR_ELx_FSC_ACCESS);
		out->desc = desc;
		return 1;
	}

	addr_bottom += contiguous_bit_shift(desc, wi, level);

	/* Calculate and return the result */
	paddr = (desc & GENMASK_ULL(47, addr_bottom)) |
		(ipa & GENMASK_ULL(addr_bottom - 1, 0));
	out->output = paddr;
	out->block_size = 1UL << ((3 - level) * stride + wi->pgshift);
	out->readable = desc & (0b01 << 6);
	out->writable = desc & (0b10 << 6);
	out->level = level;
	out->desc = desc;
	return 0;
}

static int read_guest_s2_desc(uint64_t pa, uint64_t *desc) {
	cpu_physical_memory_read(pa, desc, sizeof(*desc));
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

static void vtcr_to_walk_info(u64 vtcr, struct s2_walk_info *wi) {
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
	wi->max_oa_bits = min(48, ps_to_output_size((vtcr & VTCR_EL2_PS_MASK) >>
						    VTCR_EL2_PS_SHIFT));
}

static inline bool vcpu_has_nv() { return false; }

#define SCTLR_ELx_EE_SHIFT 25
#define SCTLR_ELx_EE (1 << SCTLR_ELx_EE_SHIFT)
int walk_nested_s2(uint64_t gipa, struct s2_trans *result) {
	uint64_t vtcr_el2 = (ARM_CPU(QEMU_CPU(0))->env).cp15.vtcr_el2;
	struct s2_walk_info wi;
	int ret;

	result->esr = 0;

	if (!vcpu_has_nv(vcpu))
		return 0;

	wi.read_desc = read_guest_s2_desc;
	wi.baddr = ARM_CPU(QEMU_CPU(0))->env.cp15.vttbr_el2;

	vtcr_to_walk_info(vtcr_el2, &wi);

	wi.be = ((ARM_CPU(QEMU_CPU(0))->env).cp15.sctlr_el[2]) & SCTLR_ELx_EE;

	ret = walk_nested_s2_pgd(gipa, &wi, result);
	if (ret)
		result->esr |= (kvm_vcpu_get_esr(vcpu) & ~ESR_ELx_FSC);

	return ret;
}
