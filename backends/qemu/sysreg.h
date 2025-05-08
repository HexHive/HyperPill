/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Macros for accessing system registers with older binutils.
 *
 * Copyright (C) 2014 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#ifndef __ASM_SYSREG_H
#define __ASM_SYSREG_H

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

#endif /* __ASM_SYSREG_H */
