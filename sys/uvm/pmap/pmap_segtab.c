/*	$NetBSD: pmap_segtab.c,v 1.6 2017/05/12 12:18:37 skrll Exp $	*/

/*-
 * Copyright (c) 1998, 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center and by Chris G. Demetriou.
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

/*
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and Ralph Campbell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)pmap.c	8.4 (Berkeley) 1/26/94
 */

#include <sys/cdefs.h>

__KERNEL_RCSID(0, "$NetBSD: pmap_segtab.c,v 1.6 2017/05/12 12:18:37 skrll Exp $");

/*
 *	Manages physical address maps.
 *
 *	In addition to hardware address maps, this
 *	module is called upon to provide software-use-only
 *	maps which may or may not be stored in the same
 *	form as hardware maps.  These pseudo-maps are
 *	used to store intermediate results from copy
 *	operations to and from address spaces.
 *
 *	Since the information managed by this module is
 *	also stored by the logical address mapping module,
 *	this module may throw away valid virtual-to-physical
 *	mappings at almost any time.  However, invalidations
 *	of virtual-to-physical mappings must be done as
 *	requested.
 *
 *	In order to cope with hardware architectures which
 *	make virtual-to-physical map invalidates expensive,
 *	this module may delay invalidate or reduced protection
 *	operations until such time as they are actually
 *	necessary.  This module is given full information as
 *	to which processors are currently using which maps,
 *	and to when physical maps must be made correct.
 */

#define __PMAP_PRIVATE

#include "opt_multiprocessor.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mutex.h>
#include <sys/atomic.h>

#include <uvm/uvm.h>


#define MULT_CTASSERT(a,b)	__CTASSERT((a) < (b) || ((a) % (b) == 0))

__CTASSERT(sizeof(pmap_pvpage_t) % NBPG == 0);
__CTASSERT(sizeof(pmap_ptpage_t) == NBPG);

#if defined(PMAP_HWPAGEWALKER)
#ifdef _LP64
MULT_CTASSERT(PMAP_PDETABSIZE, NPDEPG);
MULT_CTASSERT(NPDEPG, PMAP_PDETABSIZE);
MULT_CTASSERT(PMAP_PDETABSIZE, NPDEPG);
#endif /* _LP64 */
MULT_CTASSERT(sizeof(pmap_pdetab_t *), sizeof(pd_entry_t));
MULT_CTASSERT(sizeof(pd_entry_t), sizeof(pmap_pdetab_t));

#ifdef _LP64
static const bool separate_pdetab_root_p = NPDEPG != PMAP_PDETABSIZE;
#else
static const bool separate_pdetab_root_p = true;
#endif /* _LP64 */

typedef struct {
	pmap_pdetab_t *free_pdetab0;	/* free list kept locally */
	pmap_pdetab_t *free_pdetab;	/* free list kept locally */
#ifdef DEBUG
	uint32_t nget;
	uint32_t nput;
	uint32_t npage;
#define	PDETAB_ADD(n, v)	(pmap_segtab_info.pdealloc.n += (v))
#else
#define	PDETAB_ADD(n, v)	((void) 0)
#endif /* DEBUG */
} pmap_pdetab_alloc_t;
#endif /* PMAP_HWPAGEWALKER */

#if !defined(PMAP_HWPAGEWALKER) || !defined(PMAP_MAP_POOLPAGE)
#ifdef _LP64
__CTASSERT(NSEGPG >= PMAP_SEGTABSIZE);
__CTASSERT(NSEGPG % PMAP_SEGTABSIZE == 0);
#endif
CTASSERT(NBPG >= sizeof(pmap_segtab_t));

#ifdef _LP64
static const bool separate_segtab_root_p = NSEGPG > PMAP_SEGTABSIZE;
#else
static const bool separate_segtab_root_p = true;
#endif


typedef struct  {
	pmap_segtab_t *free_segtab0;	/* free list kept locally */
	pmap_segtab_t *free_segtab;	/* free list kept locally */
#ifdef DEBUG
	uint32_t nget_segtab;
	uint32_t nput_segtab;
	uint32_t npage_segtab;
#define	SEGTAB_ADD(n, v)	(pmap_segtab_info.n ## _segtab += (v))
#else
#define	SEGTAB_ADD(n, v)	((void) 0)
#endif
#ifdef PMAP_PTP_CACHE
	struct pgflist ptp_pgflist;	/* Keep a list of idle page tables. */
#endif
} pmap_segtab_alloc_t;
#endif /* !PMAP_HWPAGEWALKER || !PMAP_MAP_POOLPAGE */

struct pmap_segtab_info {
#if defined(PMAP_HWPAGEWALKER)
	pmap_pdetab_alloc_t pdealloc;
#endif
#if !defined(PMAP_HWPAGEWALKER) || !defined(PMAP_MAP_POOLPAGE)
	pmap_segtab_alloc_t segalloc;
#endif
} pmap_segtab_info = {
#ifdef PMAP_PTP_CACHE
	.ptp_pgflist = LIST_HEAD_INITIALIZER(pmap_segtab_info.ptp_pgflist),
#endif
};

kmutex_t pmap_segtab_lock __cacheline_aligned;

static void
pmap_check_stp(pmap_segtab_t *stp, const char *caller, const char *why)
{
#ifdef DEBUG
	for (size_t i = 0; i < PMAP_SEGTABSIZE; i++) {
		if (stp->seg_tab[i] != 0) {
#ifdef DEBUG_NOISY
			for (size_t j = i; j < PMAP_SEGTABSIZE; j++)
				printf("%s: pm_segtab.seg_tab[%zu] = 0x%p\n",
				       caller, j, stp->seg_tab[j]);
#endif
			panic("%s: pm_segtab.seg_tab[%zu] != 0 (0x%p): %s",
			      caller, i, stp->seg_tab[i], why);
		}
	}
#endif
}

static inline struct vm_page *
pmap_pte_pagealloc(void)
{
	struct vm_page *pg;

	pg = PMAP_ALLOC_POOLPAGE(UVM_PGA_ZERO|UVM_PGA_USERESERVE);
	if (pg) {
#ifdef UVM_PAGE_TRKOWN
		pg->owner_tag = NULL;
#endif
		UVM_PAGE_OWN(pg, "pmap-ptp");
	}

	return pg;
}

#if defined(PMAP_HWPAGEWALKER) && defined(PMAP_MAP_POOLPAGE)
static vaddr_t
pmap_pde_to_va(pd_entry_t pde)
{
	if (!pte_pde_valid_p(pde))
		return 0;

	paddr_t pa = pte_pde_to_paddr(pde);
	return pmap_md_direct_map_paddr(pa);
}

static pmap_pdetab_t *
pmap_pde_to_pdetab(pd_entry_t pde)
{
	return (pmap_pdetab_t *) pmap_pde_to_va(pde);
}

static pmap_ptpage_t *
pmap_pde_to_ptpage(pd_entry_t pde)
{
	return (pmap_ptpage_t *) pmap_pde_to_va(pde);
}
#endif

#ifdef _LP64
__CTASSERT((XSEGSHIFT - SEGSHIFT) % (PGSHIFT-3) == 0);
#endif

static inline pmap_ptpage_t *
pmap_ptpage(struct pmap *pmap, vaddr_t va)
{
#if defined(PMAP_HWPAGEWALKER) && defined(PMAP_MAP_POOLPAGE)
	vaddr_t pdetab_mask = PMAP_PDETABSIZE - 1;
	pmap_pdetab_t *ptb = pmap->pm_pdetab;

	KASSERT(pmap != pmap_kernel() || !pmap_md_direct_mapped_vaddr_p(va));

#ifdef _LP64
	for (size_t segshift = XSEGSHIFT;
	     segshift > SEGSHIFT;
	     segshift -= PGSHIFT - 3, pdetab_mask = NSEGPG - 1) {
		ptb = pmap_pde_to_pdetab(ptb->pde_pde[(va >> segshift) & pdetab_mask]);
		if (ptb == NULL);
			return NULL;
	}
#endif
	return pmap_pde_to_ptpage(ptb->pde_pde[(va >> SEGSHIFT) & pdetab_mask]);
#else
	vaddr_t segtab_mask = PMAP_SEGTABSIZE - 1;
	pmap_segtab_t *stb = pmap->pm_segtab;

	KASSERT(pmap != pmap_kernel() || !pmap_md_direct_mapped_vaddr_p(va));

#ifdef _LP64
	for (size_t segshift = XSEGSHIFT;
	     segshift > SEGSHIFT;
	     segshift -= PGSHIFT - 3, segtab_mask = NSEGPG - 1) {
		stb = stb->seg_seg[(va >> segshift) & segtab_mask];
		if (stb == NULL)
			return NULL;
	}
#endif
	return stb->seg_tab[(va >> SEGSHIFT) & segtab_mask];
#endif
}

#if defined(PMAP_HWPAGEWALKER)
bool
pmap_pdetab_fixup(struct pmap *pmap, vaddr_t va)
{
	pmap_pdetab_t * const kptb = &pmap_kern_pdetab;
	pmap_pdetab_t * const uptb = pmap->pm_pdetab;
	size_t idx = PMAP_PDETABSIZE - 1;
#if !defined(PMAP_MAP_POOLPAGE)
	__CTASSERT(PMAP_PDETABSIZE == PMAP_SEGTABSIZE);
	pmap_segtab_t * const kstb = &pmap_kern_segtab;
	pmap_segtab_t * const ustb = pmap->pm_segtab;
#endif

	// Regardless of how many levels deep this page table deep, we only
	// need to verify the first level PDEs match up.
#ifdef XSEGSHIFT
	pde_idx &= va >> XSEGSHIFT;
#else
	pde_idx &= va >> SEGSHIFT;
#endif
	if (uptb->pde_pde[idx] != kptb->pde_pde[idx]) [
		pte_pde_set(&uptb->pde_pde[idx], kptb->pde_pde[idx]);
#if !defined(PMAP_MAP_POOLPAGE)
		ustb->seg_seg[idx] = kstb->seg_seg[idx]; // copy KVA of PTP
#endif
		return true;
	}
	return false;
}
#endif /* PMAP_HWPAGEWALKER */

static inline pt_entry_t *
pmap_segmap(struct pmap *pmap, vaddr_t va)
{
	pmap_segtab_t *stp = pmap->pm_segtab;
	KASSERTMSG(pmap != pmap_kernel() || !pmap_md_direct_mapped_vaddr_p(va),
	    "pmap %p va %#" PRIxVADDR, pmap, va);
#ifdef _LP64
	stp = stp->seg_seg[(va >> XSEGSHIFT) & (NSEGPG - 1)];
	if (stp == NULL)
		return NULL;
#endif

	return stp->seg_tab[(va >> SEGSHIFT) & (PMAP_SEGTABSIZE - 1)];
}

pt_entry_t *
pmap_pte_lookup(pmap_t pmap, vaddr_t va)
{
	pt_entry_t *pte = pmap_segmap(pmap, va);
	if (pte == NULL)
		return NULL;

	return pte + ((va >> PGSHIFT) & (NPTEPG - 1));
}

static void
pmap_segtab_free(pmap_segtab_t *stp)
{
	/*
	 * Insert the the segtab into the segtab freelist.
	 */
	mutex_spin_enter(&pmap_segtab_lock);
#ifdef PMAP_HWPAGEWALKER
	stp->seg_seg[0] = pmap_segtab_info.pdealloc.free_pdetab;
	pmap_segtab_info.pdealloc.free_pdetab = stp;
	PDETAB_ADD(nput, 1);
#else
	stp->seg_seg[0] = pmap_segtab_info.segalloc.free_segtab;
	pmap_segtab_info.segalloc.free_segtab = stp;
	SEGTAB_ADD(nput, 1);
#endif
	mutex_spin_exit(&pmap_segtab_lock);
}

static void
pmap_segtab_release(pmap_t pmap, pmap_segtab_t **stp_p, bool free_stp,
	pte_callback_t callback, uintptr_t flags,
	vaddr_t va, vsize_t vinc)
{
	pmap_segtab_t *stp = *stp_p;

	for (size_t i = (va / vinc) & (PMAP_SEGTABSIZE - 1);
	     i < PMAP_SEGTABSIZE;
	     i++, va += vinc) {
#ifdef _LP64
		if (vinc > NBSEG) {
			if (stp->seg_seg[i] != NULL) {
				pmap_segtab_release(pmap, &stp->seg_seg[i],
				    true, callback, flags, va, vinc / NSEGPG);
				KASSERT(stp->seg_seg[i] == NULL);
			}
			continue;
		}
#endif
		KASSERT(vinc == NBSEG);

		/* get pointer to segment map */
		pt_entry_t *pte = stp->seg_tab[i];
		if (pte == NULL)
			continue;

		/*
		 * If our caller want a callback, do so.
		 */
		if (callback != NULL) {
			(*callback)(pmap, va, va + vinc, pte, flags);
		}
#ifdef DEBUG
		for (size_t j = 0; j < NPTEPG; j++) {
			if (!pte_zero_p(pte[j]))
				panic("%s: pte entry %p not 0 (%#"PRIxPTE")",
				    __func__, &pte[j], pte_value(pte[j]));
		}
#endif
		// PMAP_UNMAP_POOLPAGE should handle any VCA issues itself
		paddr_t pa = PMAP_UNMAP_POOLPAGE((vaddr_t)pte);
		struct vm_page *pg = PHYS_TO_VM_PAGE(pa);
#ifdef PMAP_PTP_CACHE
		mutex_spin_enter(&pmap_segtab_lock);
		LIST_INSERT_HEAD(&pmap_segtab_info.ptp_pgflist, pg, listq.list);
		mutex_spin_exit(&pmap_segtab_lock);
#else
		uvm_pagefree(pg);
#endif

		stp->seg_tab[i] = NULL;
	}

	if (free_stp) {
		pmap_check_stp(stp, __func__,
			       vinc == NBSEG ? "release seg" : "release xseg");
		pmap_segtab_free(stp);
		*stp_p = NULL;
	}
}

/*
 *	Create and return a physical map.
 *
 *	If the size specified for the map
 *	is zero, the map is an actual physical
 *	map, and may be referenced by the
 *	hardware.
 *
 *	If the size specified is non-zero,
 *	the map will be used in software only, and
 *	is bounded by that size.
 */
static pmap_segtab_t *
pmap_segtab_alloc(void)
{
	pmap_segtab_t *stp;
	bool found_on_freelist = false;

 again:
	mutex_spin_enter(&pmap_segtab_lock);
#ifdef PMAP_HWPAGEWALKER
	if (__predict_true((stp = pmap_segtab_info.pdealloc.free_pdetab) != NULL)) {
		pmap_segtab_info.pdealloc.free_pdetab = stp->seg_seg[0];
		PDETAB_ADD(nget, 1);
#else
	if (__predict_true((stp = pmap_segtab_info.segalloc.free_segtab) != NULL)) {
		pmap_segtab_info.segalloc.free_segtab = stp->seg_seg[0];
		SEGTAB_ADD(nget, 1);
#endif
		stp->seg_seg[0] = NULL;
		found_on_freelist = true;
	}
	mutex_spin_exit(&pmap_segtab_lock);

	if (__predict_false(stp == NULL)) {
		struct vm_page * const stp_pg = pmap_pte_pagealloc();

		if (__predict_false(stp_pg == NULL)) {
			/*
			 * XXX What else can we do?  Could we deadlock here?
			 */
			uvm_wait("pmap_create");
			goto again;
		}
#ifdef PMAP_HWPAGEWALKER
		PDETAB_ADD(npage, 1);
#else
		SEGTAB_ADD(npage, 1);
#endif
		const paddr_t stp_pa = VM_PAGE_TO_PHYS(stp_pg);

		stp = (pmap_segtab_t *)PMAP_MAP_POOLPAGE(stp_pa);
		const size_t n = NBPG / sizeof(*stp);
		if (n > 1) {
			/*
			 * link all the segtabs in this page together
			 */
			for (size_t i = 1; i < n - 1; i++) {
				stp[i].seg_seg[0] = &stp[i+1];
			}
			/*
			 * Now link the new segtabs into the free segtab list.
			 */
			mutex_spin_enter(&pmap_segtab_lock);
#ifdef PMAP_HWPAGEWALKER
			stp[n-1].seg_seg[0] = pmap_segtab_info.pdealloc.free_pdetab;
			pmap_segtab_info.pdealloc.free_pdetab = stp + 1;
			PDETAB_ADD(nput, n - 1);
#else
			stp[n-1].seg_seg[0] = pmap_segtab_info.segalloc.free_segtab;
			pmap_segtab_info.segalloc.free_segtab = stp + 1;
			SEGTAB_ADD(nput, n - 1);
#endif
			mutex_spin_exit(&pmap_segtab_lock);
		}
	}

	pmap_check_stp(stp, __func__,
		       found_on_freelist ? "from free list" : "allocated");

	return stp;
}

/*
 * Allocate the top segment table for the pmap.
 */
void
pmap_segtab_init(pmap_t pmap)
{

	pmap->pm_segtab = pmap_segtab_alloc();
}

/*
 *	Retire the given physical map from service.
 *	Should only be called if the map contains
 *	no valid mappings.
 */
void
pmap_segtab_destroy(pmap_t pmap, pte_callback_t func, uintptr_t flags)
{
	if (pmap->pm_segtab == NULL)
		return;

#ifdef _LP64
	const vsize_t vinc = NBXSEG;
#else
	const vsize_t vinc = NBSEG;
#endif
	pmap_segtab_release(pmap, &pmap->pm_segtab,
	    func == NULL, func, flags, pmap->pm_minaddr, vinc);
}

/*
 *	Make a new pmap (vmspace) active for the given process.
 */
void
pmap_segtab_activate(struct pmap *pm, struct lwp *l)
{
	if (l == curlwp) {
		struct cpu_info * const ci = l->l_cpu;
		KASSERT(pm == l->l_proc->p_vmspace->vm_map.pmap);
		if (pm == pmap_kernel()) {
			ci->ci_pmap_user_segtab = PMAP_INVALID_SEGTAB_ADDRESS;
#ifdef _LP64
			ci->ci_pmap_user_seg0tab = PMAP_INVALID_SEGTAB_ADDRESS;
#endif
		} else {
			ci->ci_pmap_user_segtab = pm->pm_segtab;
#ifdef _LP64
			ci->ci_pmap_user_seg0tab = pm->pm_segtab->seg_seg[0];
#endif
		}
	}
}

/*
 *	Act on the given range of addresses from the specified map.
 *
 *	It is assumed that the start and end are properly rounded to
 *	the page size.
 */
void
pmap_pte_process(pmap_t pmap, vaddr_t sva, vaddr_t eva,
	pte_callback_t callback, uintptr_t flags)
{
#if 0
	printf("%s: %p, %"PRIxVADDR", %"PRIxVADDR", %p, %"PRIxPTR"\n",
	    __func__, pmap, sva, eva, callback, flags);
#endif
	while (sva < eva) {
		vaddr_t lastseg_va = pmap_trunc_seg(sva) + NBSEG;
		if (lastseg_va == 0 || lastseg_va > eva)
			lastseg_va = eva;

		/*
		 * If VA belongs to an unallocated segment,
		 * skip to the next segment boundary.
		 */
		pt_entry_t * const pte = pmap_pte_lookup(pmap, sva);
		if (pte != NULL) {
			/*
			 * Callback to deal with the ptes for this segment.
			 */
			(*callback)(pmap, sva, lastseg_va, pte, flags);
		}
		/*
		 * In theory we could release pages with no entries,
		 * but that takes more effort than we want here.
		 */
		sva = lastseg_va;
	}
}

/*
 *	Return a pointer for the pte that corresponds to the specified virtual
 *	address (va) in the target physical map, allocating if needed.
 */
pt_entry_t *
pmap_pte_reserve(pmap_t pmap, vaddr_t va, int flags)
{
	pmap_segtab_t *stp = pmap->pm_segtab;
	pt_entry_t *pte;

	pte = pmap_pte_lookup(pmap, va);
	if (__predict_false(pte == NULL)) {
#ifdef _LP64
		pmap_segtab_t ** const stp_p =
		    &stp->seg_seg[(va >> XSEGSHIFT) & (NSEGPG - 1)];
		if (__predict_false((stp = *stp_p) == NULL)) {
			pmap_segtab_t *nstp = pmap_segtab_alloc();
#ifdef MULTIPROCESSOR
			pmap_segtab_t *ostp = atomic_cas_ptr(stp_p, NULL, nstp);
			if (__predict_false(ostp != NULL)) {
				pmap_check_stp(nstp, __func__, "reserve");
				pmap_segtab_free(nstp);
				nstp = ostp;
			}
#else
			*stp_p = nstp;
#endif /* MULTIPROCESSOR */
			stp = nstp;
		}
		KASSERT(stp == pmap->pm_segtab->seg_seg[(va >> XSEGSHIFT) & (NSEGPG - 1)]);
#endif /* _LP64 */
		struct vm_page *pg = NULL;
#ifdef PMAP_PTP_CACHE
		mutex_spin_enter(&pmap_segtab_lock);
		if ((pg = LIST_FIRST(&pmap_segtab_info.ptp_pgflist)) != NULL) {
			LIST_REMOVE(pg, listq.list);
			KASSERT(LIST_FIRST(&pmap_segtab_info.ptp_pgflist) != pg);
		}
		mutex_spin_exit(&pmap_segtab_lock);
#endif
		if (pg == NULL)
			pg = pmap_pte_pagealloc();
		if (pg == NULL) {
			if (flags & PMAP_CANFAIL)
				return NULL;
			panic("%s: cannot allocate page table page "
			    "for va %" PRIxVADDR, __func__, va);
		}

		const paddr_t pa = VM_PAGE_TO_PHYS(pg);
		pte = (pt_entry_t *)PMAP_MAP_POOLPAGE(pa);
		pt_entry_t ** const pte_p =
		    &stp->seg_tab[(va >> SEGSHIFT) & (PMAP_SEGTABSIZE - 1)];
#ifdef MULTIPROCESSOR
		pt_entry_t *opte = atomic_cas_ptr(pte_p, NULL, pte);
		/*
		 * If another thread allocated the segtab needed for this va
		 * free the page we just allocated.
		 */
		if (__predict_false(opte != NULL)) {
#ifdef PMAP_PTP_CACHE
			mutex_spin_enter(&pmap_segtab_lock);
			LIST_INSERT_HEAD(&pmap_segtab_info.ptp_pgflist,
			    pg, listq.list);
			mutex_spin_exit(&pmap_segtab_lock);
#else
			PMAP_UNMAP_POOLPAGE((vaddr_t)pte);
			uvm_pagefree(pg);
#endif
			pte = opte;
		}
#else
		*pte_p = pte;
#endif
		KASSERT(pte == stp->seg_tab[(va >> SEGSHIFT) & (PMAP_SEGTABSIZE - 1)]);

#ifdef DEBUG
		for (size_t i = 0; i < NPTEPG; i++) {
			if (!pte_zero_p(pte[i]))
				panic("%s: new segmap %p not empty @ %zu",
				    __func__, pte, i);
		}
#endif
		pte += (va >> PGSHIFT) & (NPTEPG - 1);
	}

	return pte;
}
