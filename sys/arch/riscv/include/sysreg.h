/* $NetBSD: sysreg.h,v 1.3 2015/03/31 01:14:02 matt Exp $ */
/*-
 * Copyright (c) 2014 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Matt Thomas of 3am Software Foundry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RISCV_SYSREG_H_
#define _RISCV_SYSREG_H_

#ifndef _KERNEL
#include <sys/param.h>
#endif

#include <riscv/reg.h>

#define FCSR_FMASK	0	// no exception bits
#define FCSR_FRM	__BITS(7,5)
#define FCSR_FRM_RNE	0b000	// Round Nearest, ties to Even
#define FCSR_FRM_RTZ	0b001	// Round Towards Zero
#define FCSR_FRM_RDN	0b010	// Round DowN (-infinity)
#define FCSR_FRM_RUP	0b011	// Round UP (+infinity)
#define FCSR_FRM_RMM	0b100	// Round to nearest, ties to Max Magnitude
#define FCSR_FFLAGS	__BITS(4,0)	// Sticky bits
#define FCSR_NV		__BIT(4)	// iNValid operation
#define FCSR_DZ		__BIT(3)	// Divide by Zero
#define FCSR_OF		__BIT(2)	// OverFlow
#define FCSR_UF		__BIT(1)	// UnderFlow
#define FCSR_NX		__BIT(0)	// iNeXact

static inline uint32_t
riscvreg_fcsr_read(void)
{
	uint32_t __fcsr;
	__asm("frcsr %0" : "=r"(__fcsr));
	return __fcsr;
}


static inline uint32_t
riscvreg_fcsr_write(uint32_t __new)
{
	uint32_t __old;
	__asm("fscsr %0, %1" : "=r"(__old) : "r"(__new));
	return __old;
}

static inline uint32_t
riscvreg_fcsr_read_fflags(void)
{
	uint32_t __old;
	__asm("frflags %0" : "=r"(__old));
	return __SHIFTOUT(__old, FCSR_FFLAGS);
}

static inline uint32_t
riscvreg_fcsr_write_fflags(uint32_t __new)
{
	uint32_t __old;
	__new = __SHIFTIN(__new, FCSR_FFLAGS);
	__asm("fsflags %0, %1" : "=r"(__old) : "r"(__new));
	return __SHIFTOUT(__old, FCSR_FFLAGS);
}

static inline uint32_t
riscvreg_fcsr_read_frm(void)
{
	uint32_t __old;
	__asm("frrm\t%0" : "=r"(__old));
	return __SHIFTOUT(__old, FCSR_FRM);
}

static inline uint32_t
riscvreg_fcsr_write_frm(uint32_t __new)
{
	uint32_t __old;
	__new = __SHIFTIN(__new, FCSR_FRM);
	__asm volatile("fsrm\t%0, %1" : "=r"(__old) : "r"(__new));
	return __SHIFTOUT(__old, FCSR_FRM);
}

/* Old values from previous spec -- Not sure which one! */
/* #define SR_IP		__BITS(31,24)	// Pending interrupts */
/* #define SR_IM		__BITS(23,16)	// Interrupt Mask */
/* #define SR_VM		__BIT(7)	// MMU On */
/* #define SR_S64		__BIT(6)	// RV64 supervisor mode */
/* #define SR_U64		__BIT(5)	// RV64 user mode */
/* #define SR_EF		__BIT(4)	// Enable Floating Point */
/* #define SR_PEI		__BIT(3)	// Previous EI setting */
/* #define SR_EI		__BIT(2)	// Enable interrupts */
/* #define SR_PS		__BIT(1)	// Previous (S) supervisor setting */
/* #define SR_S		__BIT(0)	// Supervisor */

/* #ifdef _LP64 */
/* #define	SR_USER		(SR_EI|SR_U64|SR_S64|SR_VM|SR_IM) */
/* #define	SR_USER32	(SR_USER & ~SR_U64) */
/* #define	SR_KERNEL	(SR_S|SR_EI|SR_U64|SR_S64|SR_VM) */
/* #else */
/* #define	SR_USER		(SR_EI|SR_VM|SR_IM) */
/* #define	SR_KERNEL	(SR_S|SR_EI|SR_VM) */
/* #endif */

/* Supervisor Status Register */
#ifndef _LP64
#define SR_WPRI __BITS(30,20) | __BIT(17) | __BITS(12,9) | \
                 __BITS(7,6) | __BITS(3,2)
#define SR_SD __BIT(31)
/* Bits 30-20 are WPRI*/
#endif /* !_LP64 */

#ifdef _LP64
#define SR_WPRI __BITS(62, 34) | __BITS(31,20) | __BIT(17) | \
                 __BITS(12,9) | __BITS(7,6) | __BITS(3,2)
#define SR_SD	__BIT(63)
/* Bits 62-34 are WPRI */
#define SR_UXL __BITS(33,32)
/* Bits 31-20 are WPRI*/
#endif /* _LP64 */

/* Both RV32 and RV64 have the bottom 20 bits shared */
#define SR_MXR __BIT(19)
#define SR_SUM __BIT(18)
/* Bit 17 is WPRI */
#define SR_XS __BITS(16,15)
#define SR_FS __BITS(14,13)
/* Bits 12-9 are WPRI */
#define SR_SPP __BIT(8)
/* Bits 7-6 are WPRI */
#define SR_SPIE __BIT(5)
#define SR_UPIE __BIT(4)
/* Bits 3-2 are WPRI */
#define SR_SIE __BIT(1)
#define SR_UIE __BIT(0)

#define SR_USER SR_SIE

static inline uint32_t
riscvreg_status_read(void)
{
	uint32_t __sr;
	__asm("csrr\t%0, sstatus" : "=r"(__sr));
	return __sr;
}

static inline uint32_t
riscvreg_status_clear(uint32_t __mask)
{
	uint32_t __sr;
	if (__builtin_constant_p(__mask) && __mask < 0x20) {
		__asm("csrrci\t%0, sstatus, %1" : "=r"(__sr) : "i"(__mask));
	} else {
		__asm("csrrc\t%0, sstatus, %1" : "=r"(__sr) : "r"(__mask));
	}
	return __sr;
}

static inline uint32_t
riscvreg_status_set(uint32_t __mask)
{
	uint32_t __sr;
	if (__builtin_constant_p(__mask) && __mask < 0x20) {
		__asm("csrrsi\t%0, sstatus, %1" : "=r"(__sr) : "i"(__mask));
	} else {
		__asm("csrrs\t%0, sstatus, %1" : "=r"(__sr) : "r"(__mask));
	}
	return __sr;
}

// Cause register
#define CAUSE_INST_MISALIGNED 0
#define CAUSE_INST_ACCESS_FAULT 1
#define CAUSE_INST_ILLEGAL 2
#define CAUSE_BREAKPOINT 3
/* 4 is Reserved */
#define CAUSE_LOAD_ACCESS_FAULT 5
#define CAUSE_STORE_MISALIGNED 6
#define CAUSE_STORE_ACCESS_FAULT 7
#define CAUSE_SYSCALL 8
/* 9-11 is Reserved */
#define CAUSE_INST_PAGE_FAULT 12
#define CAUSE_LOAD_PAGE_FAULT 13
/* 14 is Reserved */
#define CAUSE_STORE_PAGE_FAULT 15
/* >= 16 is reserved */

static inline uint64_t
riscvreg_cycle_read(void)
{
#ifdef _LP64
	uint64_t __lo;
	__asm __volatile("csrr\t%0, cycle" : "=r"(__lo));
	return __lo;
#else
	uint32_t __hi0, __hi1, __lo0;
	do {
		__asm __volatile(
			"csrr\t%[__hi0], cycleh"
		"\n\t"	"csrr\t%[__lo0], cycle"
		"\n\t"	"csrr\t%[__hi1], cycleh"
		   :	[__hi0] "=r"(__hi0),
			[__lo0] "=r"(__lo0),
			[__hi1] "=r"(__hi1));
	} while (__hi0 != __hi1);
	return ((uint64_t)__hi0 << 32) | (uint64_t)__lo0;
#endif
}

static inline register_t
riscvreg_satp_read(void)
{
	register_t __satp;
	__asm("csrr\t%0, satp" : "=r"(__satp));
	return __satp;
}

static inline void
riscvreg_satp_write(register_t __satp)
{
	__asm("csrw\tsatp, %0" :: "r"(__satp));
	__asm __volatile("sfence.vma" ::: "memory");
}

static inline register_t
riscvreg_satp_ppn_read(void)
{
	register_t __satp;
	__asm("csrr\t%0, satp" : "=r"(__satp));
	return __satp & SATP_PPN_MASK;
}

static inline void
riscvreg_satp_ppn_write(register_t ppn)
{
	register_t __satp = riscvreg_satp_read();
	__satp = (__satp & ~SATP_PPN_MASK) | (ppn & SATP_PPN_MASK);
	__asm __volatile("csrw\tsatp, %0" :: "r"(__satp));
	__asm __volatile("sfence.vma" ::: "memory");
}

static inline uint32_t
riscvreg_satp_asid_read(void)
{
	register_t __asid;
	__asm __volatile("csrr\t%0, satp" : "=r"(__asid));
	return (uint32_t)(__asid >> SATP_ASID_SHIFT);
}

static inline void
riscvreg_satp_asid_write(uint32_t __asid)
{
	register_t satp, asid;
	asid = __asid;
	asid <<= SATP_ASID_SHIFT;
	__asm __volatile("csrr\t%0, satp" : "=r"(satp));
	satp &= ~SATP_ASID_MASK | asid;
	riscvreg_satp_write(satp);
}

#endif /* _RISCV_SYSREG_H_ */
