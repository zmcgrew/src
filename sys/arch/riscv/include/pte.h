/* $NetBSD: pte.h,v 1.1 2014/09/19 17:36:26 matt Exp $ */
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

#ifndef _RISCV_PTE_H_
#define _RISCV_PTE_H_

/*
  Sv39 Page Table Entry (512 GB VA Space)
    [63..54] = 0
    [53..28] = PPN[2]
    [27..19] = PPN[1]
    [18..10] = PPN[0]

  Sv32 Page Table Entry (4 GB VA Space)
    [31..20] = PPN[1]
    [19..10] = PPN[0]

  Common to both:
    [9] = NetBSD specific (Wired = Do Not Delete)
    [8] = NetBSD specific (Not eXecuted)
    [7] = D
    [6] = A
    [5] = G
    [4] = U
    [3] = X
    [2] = W
    [1] = R
    [0] = V
*/

#define NPTEPG		(NBPG / sizeof(void *))	// PTEs per Page

#define NSEGPG		NPTEPG
#define NPDEPG		NPTEPG

#ifdef _LP64 /* Sv39 */
/*
 * XXX --- WARNING
 * These are numbered backwards from the numbering in the Privilege Spec 1.10!
 * 0 = PrivSpec 2
 * 1 = PrivSpec 1
 * 2 = PrivSpec 0
 */
#define	PTE_PPN		__BITS(53, 10)	// Physical Page Number
#define	PTE_PPN0	__BITS(53, 28)	// 512 8-byte SDEs / PAGE
#define	PTE_PPN1	__BITS(27, 19)	// 512 8-byte PDEs / PAGE
#define	PTE_PPN2	__BITS(18, 10)	// 512 8-byte PTEs / PAGE
typedef __uint64_t pt_entry_t;
typedef __uint64_t pd_entry_t;
#define atomic_cas_pte	atomic_cas_64
#define atomic_cas_pde	atomic_cas_64
#else
/*
 * WARNING -- Same as above, but 0 = PS 1, 1 = PS 0
 */ 
#define PTE_PPN		__BITS(31, 10)	// Physical Page Number
#define	PTE_PPN0	__BITS(31, 20)	// 1K 4-byte PDEs / PAGE
#define	PTE_PPN1	__BITS(19, 10)	// 1K 4-byte PTEs / PAGE
typedef __uint32_t pt_entry_t;
typedef __uint32_t pd_entry_t;
#define atomic_cas_pte	atomic_cas_32
#define atomic_cas_pde	atomic_cas_32
#endif

// These only mean something to NetBSD
#define	PTE_WIRED	__BIT(9)	// Do Not Delete
#define	PTE_NX		__BIT(8)	// Not eXecuted?

// These are hardware defined bits
#define	PTE_D		__BIT(7)	// Dirty
#define	PTE_A		__BIT(6)	// Accessed
#define	PTE_G		__BIT(5)	// Global
#define	PTE_U		__BIT(4)	// User
#define	PTE_X		__BIT(3)	// eXecute
#define	PTE_W		__BIT(2)	// Write
#define	PTE_R		__BIT(1)	// Read
#define	PTE_V		__BIT(0)	// Valid

/*
  Helper macro for determining if on a "Transit" (non-leaf) page.
  A previous spec had PTE_T for this.
*/
#define PTE_IS_T(pte)	(((pte) & PTE_V) && !((pte) & (PTE_W|PTE_R|PTE_X)))

/* Constants From FreeBSD RISC-V Port */

/* Level 0 table, 512GiB per entry */
#define	L0_SHIFT	39

/* Level 1 table, 1GiB per entry */
#define	L1_SHIFT	30
#define	L1_SIZE 	(1 << L1_SHIFT)
#define	L1_OFFSET 	(L1_SIZE - 1)

/* Level 2 table, 2MiB per entry */
#define	L2_SHIFT	21
#define	L2_SIZE 	(1 << L2_SHIFT)
#define	L2_OFFSET 	(L2_SIZE - 1)

/* Level 3 table, 4KiB per entry */
#define	L3_SHIFT	12
#define	L3_SIZE 	(1 << L3_SHIFT)
#define	L3_OFFSET 	(L3_SIZE - 1)

#define	Ln_ENTRIES	(1 << 9)
#define	Ln_ADDR_MASK	(Ln_ENTRIES - 1)

#define	PTE_PPN0_S	10
#define	PTE_PPN1_S	19
#define	PTE_PPN2_S	28
#define	PTE_PPN3_S	37
#define	PTE_SIZE	8

/* End FreeBSD RISC-V Constants */

static inline bool
pte_valid_p(pt_entry_t pte)
{
	return (pte & PTE_V) != 0;
}

static inline bool
pte_wired_p(pt_entry_t pte)
{
	return (pte & PTE_WIRED) != 0;
}

static inline bool
pte_modified_p(pt_entry_t pte)
{
	return (pte & PTE_D) != 0;
}

static inline bool
pte_cached_p(pt_entry_t pte)
{
	/* TODO: This seems wrong... */
	return true;
}

static inline bool
pte_deferred_exec_p(pt_entry_t pte)
{
	return (pte & PTE_NX) != 0;
}

static inline pt_entry_t
pte_wire_entry(pt_entry_t pte)
{
	return pte | PTE_WIRED;
}

static inline pt_entry_t   
pte_unwire_entry(pt_entry_t pte)
{
	return pte & ~PTE_WIRED;
}

static inline paddr_t
pte_to_paddr(pt_entry_t pte)
{
	return pte >> PTE_PPN0_S;
}

static inline pt_entry_t
pte_nv_entry(bool kernel_p)
{
	return kernel_p ? PTE_G : 0;
}

static inline pt_entry_t
pte_prot_nowrite(pt_entry_t pte)
{
	return pte & ~PTE_W;
}

static inline pt_entry_t
pte_prot_downgrade(pt_entry_t pte, vm_prot_t newprot)
{
	pte &= ~PTE_W;
	if ((newprot & VM_PROT_EXECUTE) == 0)
		pte &= ~(PTE_NX|PTE_X);
	return pte;
}

static inline pt_entry_t
pte_prot_bits(struct vm_page_md *mdpg, vm_prot_t prot, bool kernel_p)
{
	KASSERT(prot & VM_PROT_READ);
	pt_entry_t pt_entry = PTE_R | (kernel_p ? 0 : PTE_U);
	if (prot & VM_PROT_EXECUTE) {
		if (mdpg != NULL && !VM_PAGEMD_EXECPAGE_P(mdpg))
			pt_entry |= PTE_NX;
		else
			pt_entry |= kernel_p ? 0 : PTE_U;
	}
	if (prot & VM_PROT_WRITE) {
		if (mdpg != NULL && !VM_PAGEMD_MODIFIED_P(mdpg))
			/*
			  TODO: Mark page as not dirty? Was
			  previously "Not Written" (PTE_NW) which no
			  longer exists
			*/
			pt_entry &= ~PTE_D;
		else
			pt_entry |= PTE_W | (kernel_p ? 0 : PTE_U);
	}
	return pt_entry;
}

static inline pt_entry_t
pte_flag_bits(struct vm_page_md *mdpg, int flags, bool kernel_p)
{
#if 0
	if (__predict_false(flags & PMAP_NOCACHE)) {
		if (__predict_true(mdpg != NULL)) {
			return pte_nocached_bits();
		} else {
			return pte_ionocached_bits();
		}
	} else {
		if (__predict_false(mdpg != NULL)) {
			return pte_cached_bits();
		} else {
			return pte_iocached_bits();
		}
	}
#else
	return 0;
#endif
}

static inline pt_entry_t
pte_make_enter(paddr_t pa, struct vm_page_md *mdpg, vm_prot_t prot,
	int flags, bool kernel_p)
{
	pt_entry_t pte = (((pt_entry_t)pa) >> PAGE_SHIFT) << PTE_PPN0_S;

	pte |= pte_flag_bits(mdpg, flags, kernel_p);
	pte |= pte_prot_bits(mdpg, prot, kernel_p);

	if (mdpg == NULL && VM_PAGEMD_REFERENCED_P(mdpg))
		pte |= PTE_V;

	return pte;
}

static inline pt_entry_t
pte_make_kenter_pa(paddr_t pa, struct vm_page_md *mdpg, vm_prot_t prot,
	int flags)
{
	pt_entry_t pte = (((pt_entry_t)pa) >> PAGE_SHIFT) << PTE_PPN0_S;

	pte |= PTE_WIRED | PTE_V;
	pte |= pte_flag_bits(NULL, flags, true);
	pte |= pte_prot_bits(NULL, prot, true); /* pretend unmanaged */

	return pte;
}

static inline void
pte_set(pt_entry_t *ptep, pt_entry_t pte)
{
	*ptep = pte;
}

static inline pd_entry_t
pte_invalid_pde(void)
{
	return 0;
}

static inline pd_entry_t
pte_pde_pdetab(paddr_t pa)
{
	return PTE_V | PTE_G | pa;
}

static inline pd_entry_t
pte_pde_ptpage(paddr_t pa)
{
	return PTE_V | PTE_G | pa;
}

static inline bool
pte_pde_valid_p(pd_entry_t pde)
{
	/* OLD: return (pde & (PTE_V|PTE_T)) == (PTE_V|PTE_T); */
	return PTE_IS_T(pde);
}

static inline paddr_t
pte_pde_to_paddr(pd_entry_t pde)
{
	return pde >> PTE_PPN0_S;
}

static inline pd_entry_t
pte_pde_cas(pd_entry_t *pdep, pd_entry_t opde, pt_entry_t npde)
{
#ifdef MULTIPROCESSOR
#ifdef _LP64
	return atomic_cas_64(pdep, opde, npde);
#else
	return atomic_cas_32(pdep, opde, npde);
#endif
#else
	*pdep = npde;
	return 0;
#endif
}


static inline uint32_t
pte_value(pt_entry_t pte)
{
	return pte;
}
#endif /* _RISCV_PTE_H_ */
