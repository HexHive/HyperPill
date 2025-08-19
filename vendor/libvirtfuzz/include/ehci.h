#ifndef EHCI_H_
#define EHCI_H_

#include <stdint.h>

struct ehci_itd {
	/* first part defined by EHCI spec */
	uint32_t			hw_next;           /* see EHCI 3.3.1 */
	uint32_t			hw_transaction[8]; /* see EHCI 3.3.2 */
#define EHCI_ISOC_ACTIVE        (1<<31)        /* activate transfer this slot */
#define EHCI_ISOC_BUF_ERR       (1<<30)        /* Data buffer error */
#define EHCI_ISOC_BABBLE        (1<<29)        /* babble detected */
#define EHCI_ISOC_XACTERR       (1<<28)        /* XactErr - transaction error */
#define	EHCI_ITD_LENGTH(tok)	(((tok)>>16) & 0x0fff)
#define	EHCI_ITD_IOC		(1 << 15)	/* interrupt on complete */

#define ITD_ACTIVE(ehci)	cpu_to_hc32(ehci, EHCI_ISOC_ACTIVE)

	uint32_t			hw_bufp[7];	/* see EHCI 3.3.3 */
	// uint32_t			hw_bufp_hi[7];	/* Appendix B */
};

struct ehci_sitd {
	/* first part defined by EHCI spec */
	uint32_t			hw_next;
/* uses bit field macros above - see EHCI 0.95 Table 3-8 */
	uint32_t			hw_fullspeed_ep;	/* EHCI table 3-9 */
	uint32_t			hw_uframe;		/* EHCI table 3-10 */
	uint32_t			hw_results;		/* EHCI table 3-11 */
#define	SITD_IOC	(1 << 31)	/* interrupt on completion */
#define	SITD_PAGE	(1 << 30)	/* buffer 0/1 */
#define	SITD_LENGTH(x)	(((x) >> 16) & 0x3ff)
#define	SITD_STS_ACTIVE	(1 << 7)	/* HC may execute this */
#define	SITD_STS_ERR	(1 << 6)	/* error from TT */
#define	SITD_STS_DBE	(1 << 5)	/* data buffer error (in HC) */
#define	SITD_STS_BABBLE	(1 << 4)	/* device was babbling */
#define	SITD_STS_XACT	(1 << 3)	/* illegal IN response */
#define	SITD_STS_MMF	(1 << 2)	/* incomplete split transaction */
#define	SITD_STS_STS	(1 << 1)	/* split transaction state */

#define SITD_ACTIVE(ehci)	cpu_to_hc32(ehci, SITD_STS_ACTIVE)

	uint32_t			hw_buf[2];		/* EHCI table 3-12 */
	uint32_t			hw_backpointer;		/* EHCI table 3-13 */
	// uint32_t			hw_buf_hi[2];		/* Appendix B */
};

struct ehci_qtd {
	/* first part defined by EHCI spec */
	uint32_t			hw_next;	/* see EHCI 3.5.1 */
	uint32_t			hw_alt_next;    /* see EHCI 3.5.2 */
	uint32_t			hw_token;       /* see EHCI 3.5.3 */
#define	QTD_TOGGLE	(1 << 31)	/* data toggle */
#define	QTD_LENGTH(tok)	(((tok)>>16) & 0x7fff)
#define	QTD_IOC		(1 << 15)	/* interrupt on complete */
#define	QTD_CERR(tok)	(((tok)>>10) & 0x3)
#define	QTD_PID(tok)	(((tok)>>8) & 0x3)
#define	QTD_STS_ACTIVE	(1 << 7)	/* HC may execute this */
#define	QTD_STS_HALT	(1 << 6)	/* halted on error */
#define	QTD_STS_DBE	(1 << 5)	/* data buffer error (in HC) */
#define	QTD_STS_BABBLE	(1 << 4)	/* device was babbling (qtd halted) */
#define	QTD_STS_XACT	(1 << 3)	/* device gave illegal response */
#define	QTD_STS_MMF	(1 << 2)	/* incomplete split transaction */
#define	QTD_STS_STS	(1 << 1)	/* split transaction state */
#define	QTD_STS_PING	(1 << 0)	/* issue PING? */

#define ACTIVE_BIT(ehci)	cpu_to_hc32(ehci, QTD_STS_ACTIVE)
#define HALT_BIT(ehci)		cpu_to_hc32(ehci, QTD_STS_HALT)
#define STATUS_BIT(ehci)	cpu_to_hc32(ehci, QTD_STS_STS)

	uint32_t			hw_buf[5];        /* see EHCI 3.5.4 */
	// uint32_t			hw_buf_hi[5];        /* Appendix B */
};

struct ehci_qh {
	uint32_t			hw_next;	/* see EHCI 3.6.1 */
	uint32_t			hw_info1;       /* see EHCI 3.6.2 */
#define	QH_CONTROL_EP	(1 << 27)	/* FS/LS control endpoint */
#define	QH_HEAD		(1 << 15)	/* Head of async reclamation list */
#define	QH_TOGGLE_CTL	(1 << 14)	/* Data toggle control */
#define	QH_HIGH_SPEED	(2 << 12)	/* Endpoint speed */
#define	QH_LOW_SPEED	(1 << 12)
#define	QH_FULL_SPEED	(0 << 12)
#define	QH_INACTIVATE	(1 << 7)	/* Inactivate on next transaction */
	uint32_t			hw_info2;        /* see EHCI 3.6.2 */
#define	QH_SMASK	0x000000ff
#define	QH_CMASK	0x0000ff00
#define	QH_HUBADDR	0x007f0000
#define	QH_HUBPORT	0x3f800000
#define	QH_MULT		0xc0000000
	uint32_t			hw_current;	/* qtd list - see EHCI 3.6.4 */

	/* qtd overlay (hardware parts of a struct ehci_qtd) */
	uint32_t			hw_qtd_next;
	uint32_t			hw_alt_next;
	uint32_t			hw_token;
	uint32_t			hw_buf[5];
	// uint32_t			hw_buf_hi[5];
};

#endif
