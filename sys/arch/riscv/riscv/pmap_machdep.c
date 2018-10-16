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

#define __PMAP_PRIVATE

#include <sys/cdefs.h>

__RCSID("$NetBSD: pmap_machdep.c,v 1.2 2015/03/31 01:14:57 matt Exp $");

#include <sys/param.h>

#include <uvm/uvm.h>

#include <riscv/locore.h>

int riscv_poolpage_vmfreelist = VM_FREELIST_DEFAULT;

void
pmap_zero_page(paddr_t pa)
{
#ifdef POOL_PHYSTOV
	memset((void *)POOL_PHYSTOV(pa), 0, PAGE_SIZE);
#else
#error FIX pmap_zero_page!
#endif
}

void
pmap_copy_page(paddr_t src, paddr_t dst)
{
#ifdef POOL_PHYSTOV
	memcpy((void *)POOL_PHYSTOV(dst), (const void *)POOL_PHYSTOV(src),
	    PAGE_SIZE);
#else
#error FIX pmap_copy_page!
#endif
}

pd_entry_t *
pmap_md_alloc_pdp(struct pmap *pm, paddr_t *pap)
{
	paddr_t pa;

	UVMHIST_FUNC(__func__);
	UVMHIST_CALLED(pmaphist);

	if (uvm.page_init_done) {
		struct vm_page *pg;

		pg = uvm_pagealloc(NULL, 0, NULL,
		    UVM_PGA_USERESERVE | UVM_PGA_ZERO);
		if (pg == NULL)
			panic("%s: cannot allocate L3 table", __func__);
		pa = VM_PAGE_TO_PHYS(pg);

		/* TODO: Track the pg on the vmlist? pmap_enter_pv()? */
		/* SLIST_INSERT_HEAD(&pm->pm_vmlist, pg, mdpage.mdpg_vmlist); */

		/* TODO: Find/create the appropriate counter in
		   uvm/pmap.c */
		/* PMAP_COUNT(pdp_alloc); */

	} else {
		/* uvm_pageboot_alloc() returns KSEG address */
		pa = POOL_VTOPHYS(uvm_pageboot_alloc(PAGE_SIZE));
		/* TODO: Find/create the appropriate counter in
		   uvm/pmap.c */
		/* PMAP_COUNT(pdp_alloc_boot); */
	}
	if (pap != NULL)
		*pap = pa;

	UVMHIST_LOG(pmaphist, "pa=%llx, va=%llx",
	    pa, POOL_PHYSTOV(pa), 0, 0);

	return (void *)POOL_PHYSTOV(pa);
}

struct vm_page *
pmap_md_alloc_poolpage(int flags)
{
	if (riscv_poolpage_vmfreelist != VM_FREELIST_DEFAULT)
		return uvm_pagealloc_strat(NULL, 0, NULL, flags,
		    UVM_PGA_STRAT_ONLY, riscv_poolpage_vmfreelist);

	return uvm_pagealloc(NULL, 0, NULL, flags);
}

vaddr_t
pmap_md_map_poolpage(paddr_t pa, vsize_t len)
{
	return POOL_PHYSTOV(pa);
}

void
pmap_md_unmap_poolpage(vaddr_t pa, vsize_t len)
{
	/* nothing to do */
}

bool
pmap_md_direct_mapped_vaddr_p(vaddr_t va)
{
	return VM_MAX_KERNEL_ADDRESS <= va && (intptr_t) va < 0;
}

bool
pmap_md_io_vaddr_p(vaddr_t va)
{
	return false;
}

paddr_t
pmap_md_direct_mapped_vaddr_to_paddr(vaddr_t va)
{
	KASSERT(VM_MAX_KERNEL_ADDRESS <= va && (intptr_t) va < 0);

	pmap_pdetab_t *ptb = pmap_kernel()->pm_pdetab;
	pd_entry_t *pdp;
	pd_entry_t  pde;

#ifdef _LP64
	/* L1 -> L3 */
	pdp = (pd_entry_t *)ptb->pde_pde + l1pde_index(va);
	pde = *(pd_entry_t *)pdp;
	if (((pd_entry_t)pde & PTE_V) == 0) {
		return -(paddr_t)1;
	}
	if (!PTE_IS_T(pde)) {
		return pte_pde_to_paddr((pd_entry_t)pde);
	}

	pdp = (pd_entry_t *)POOL_PHYSTOV(pte_pde_to_paddr((pd_entry_t)pdp)) + l2pde_index(va);
	pde = *(pd_entry_t *)pdp;
	if (((pd_entry_t)pde & PTE_V) == 0) {
		return -(paddr_t)1;
	}
	if (!PTE_IS_T(pde)) {
		return pte_pde_to_paddr((pd_entry_t)pde);
	}

	pdp = (pd_entry_t *)POOL_PHYSTOV(pte_pde_to_paddr((pd_entry_t)pdp)) + l3pte_index(va);
	pde = *(pd_entry_t *)pdp;
	if (((pd_entry_t)pde & PTE_V) == 0) {
		return -(paddr_t)1;
	}
	if (!PTE_IS_T(pde)) {
		return pte_pde_to_paddr((pd_entry_t)pde);
	}
#else
	/* XXX 32bit code here */
#endif
	/* Bad things have happened */
	return -(paddr_t)1;
}

vaddr_t
pmap_md_direct_map_paddr(paddr_t pa)
{
	return POOL_PHYSTOV(pa);
}

void
pmap_md_init(void)
{
        pmap_tlb_info_evcnt_attach(&pmap_tlb0_info);
}

bool
pmap_md_ok_to_steal_p(const uvm_physseg_t bank, size_t npgs)
{
	return true;
}

bool
pmap_md_tlb_check_entry(void *ctx, vaddr_t va, tlb_asid_t asid, pt_entry_t pte)
{
	return false;
}

void
pmap_md_pdetab_activate(struct pmap *pmap)
{
	riscvreg_satp_ppn_write(pmap->pm_md.md_ptbr);
	//OLD: __asm("csrw\tsptbr, %0" :: "r"(pmap->pm_md.md_ptbr));
}

void
pmap_md_pdetab_init(struct pmap *pmap)
{
	pmap->pm_pdetab[NPDEPG-1] = pmap_kernel()->pm_pdetab[NPDEPG-1];
	pmap->pm_md.md_ptbr =
	    pmap_md_direct_mapped_vaddr_to_paddr((vaddr_t)pmap->pm_pdetab);
}

pt_entry_t *
pmap_md_pdetab_lookup_ptep(struct pmap *pmap, vaddr_t va)
{
	pmap_pdetab_t *ptb = pmap->pm_pdetab;
	pd_entry_t *pdp;
	pd_entry_t  pde;

#ifdef _LP64
	/* L1 -> L3 */
	/* L1 */
	pdp = (pd_entry_t *)ptb->pde_pde + l1pde_index(va);
	pde = *(pd_entry_t *)pdp;
	if ((pde & PTE_V) == 0)
		return NULL;
	if (!PTE_IS_T(pde))
		return POOL_PHYSTOV(pdp);
	/* L2 */
	pdp = (pd_entry_t *)POOL_PHYSTOV(pte_pde_to_paddr((pd_entry_t)pde)) + l2pde_index(va);
	pde = *(pd_entry_t *)pdp;
	if (!PTE_IS_T(pde))
		return pdp;

	/* L3 */
	pdp = (pd_entry_t *)POOL_PHYSTOV(pte_pde_to_paddr((pd_entry_t)pde)) + l3pte_index(va);
	return pdp;
#else
	/* XXX 32-bit code here */
#endif
	/* Things have gone wrong */
	return NULL;
}

pt_entry_t *
pmap_md_pdetab_lookup_create_ptep(struct pmap *pmap, vaddr_t va)
{
	pmap_pdetab_t *ptb = pmap->pm_pdetab;
	pd_entry_t *pdp;
	pd_entry_t pde;
	paddr_t	pdppa;

#ifdef _LP64
	/* L1 -> L3 */
	/* L1 */
	pdp = (pd_entry_t *)ptb->pde_pde + l1pde_index(va);
	pde = *(pd_entry_t *)pdp;
	if ((pde & PTE_V) == 0) {
		/* Not valid. Alloc a page to point to, then insert it
		   into the table */
		pmap_md_alloc_pdp(pmap, &pdppa);
		KASSERT(pdppa != POOL_PADDR_INVALID);
		atomic_swap_64(pdp, ((pdppa >> PAGE_SHIFT) << PTE_PPN0_S) | PTE_V);
		pde = *(pd_entry_t *)pdp;
	}
	if (!PTE_IS_T(pde))
		return POOL_PHYSTOV(pdp);
	/* L2 */
	pdp = (pd_entry_t *)POOL_PHYSTOV(pte_pde_to_paddr(pde)) + l2pde_index(va);
	pde = *(pd_entry_t *)pdp;
	if ((pde & PTE_V) == 0) {
		/* Not valid. Alloc a page to point to, then insert it
		   into the directory */
		pmap_md_alloc_pdp(pmap, &pdppa);
		KASSERT(pdppa != POOL_PADDR_INVALID);
		atomic_swap_64(pdp, ((pdppa >> PAGE_SHIFT) << PTE_PPN0_S) | PTE_V);
		pde = *(pd_entry_t *)pdp;
	}
	if (!PTE_IS_T(pde))
		return pdp;
	/* L3 */
	pdp = (pd_entry_t *)POOL_PHYSTOV(pte_to_paddr((pt_entry_t)pde)) + l3pte_index(va);
	return pdp;
#else
	/* XXX 32-bit code here */
#endif
	/* Things have gone wrong */
	return NULL;
}

void
pmap_bootstrap(paddr_t pstart, paddr_t pend, vaddr_t kstart, paddr_t kend)
{
	extern __uint64_t l1_pte[512];
	pmap_pdetab_t * const kptb = &pmap_kern_pdetab;
	pmap_t pm = pmap_kernel();

	kend = (kend + 0x200000 - 1) & -0x200000;

	/* Use the tables we already built in init_mmu() */
	pm->pm_pdetab = &l1_pte;

	/* Setup basic info like pagesize=PAGE_SIZE */
	uvm_md_init();

	/* init the lock */
	pmap_tlb_info_init(&pmap_tlb0_info);

	/* TODO: Pretend we have a gigabyte of RAM until this gets FDT */

	/* Don't physload the space where the kernel is loaded, just
	 * the space after it. */
	uvm_page_physload(atop(round_page(kend)), atop(pend),
	    atop(round_page(kend)), atop(pend),
	    riscv_poolpage_vmfreelist);

	/* XXX - How do I really set this? */
	physmem = btoc(0x40000000);

	/* XXX: Mostly from MIPS =) */
	pmap_limits.avail_start = ptoa(uvm_physseg_get_start(uvm_physseg_get_first()));
	pmap_limits.avail_end = ptoa(uvm_physseg_get_end(uvm_physseg_get_last()));
	pmap_limits.virtual_start = kstart;
	pmap_limits.virtual_end = VM_MAX_KERNEL_ADDRESS;

	/*
	 * Initialize the pools.
	 */
	pool_init(&pmap_pmap_pool, PMAP_SIZE, 0, 0, 0, "pmappl",
	    &pool_allocator_nointr, IPL_NONE);
	pool_init(&pmap_pv_pool, sizeof(struct pv_entry), 0, 0, 0, "pvpl",
	    &pmap_pv_page_allocator, IPL_NONE);

	tlb_set_asid(0);
}

// TLB mainenance routines

tlb_asid_t
tlb_get_asid(void)
{
	return riscvreg_satp_asid_read();
}

void
tlb_set_asid(tlb_asid_t asid)
{
	riscvreg_satp_asid_write(asid);
}

#if 0
void    tlb_invalidate_all(void);
void    tlb_invalidate_globals(void);
#endif
void
tlb_invalidate_asids(tlb_asid_t lo, tlb_asid_t hi)
{
	__asm __volatile("sfence.vma" ::: "memory");
}
void
tlb_invalidate_addr(vaddr_t va, tlb_asid_t asid)
{
	__asm __volatile("sfence.vma" ::: "memory");
}

bool
tlb_update_addr(vaddr_t va, tlb_asid_t asid, pt_entry_t pte, bool insert_p)
{
	__asm __volatile("sfence.vma" ::: "memory");
	return false;
}

u_int
tlb_record_asids(u_long *ptr, tlb_asid_t UNUSED)
{
	memset(ptr, 0xff, PMAP_TLB_NUM_PIDS / (8 * sizeof(u_long)));
	ptr[0] = -2UL;
	return PMAP_TLB_NUM_PIDS - 1;
}

void
tlb_walk(void *ctx, bool (*func)(void *, vaddr_t, tlb_asid_t, pt_entry_t))
{
	/* no way to view the TLB */
}

#if 0
void    tlb_enter_addr(size_t, const struct tlbmask *);
void    tlb_read_entry(size_t, struct tlbmask *);
void    tlb_write_entry(size_t, const struct tlbmask *);
void    tlb_dump(void (*)(const char *, ...));
#endif
