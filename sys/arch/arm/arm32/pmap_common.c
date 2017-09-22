/*	$NetBSD: pmap.c,v 1.349 2017/05/24 06:31:07 skrll Exp $	*/

/*
 * Copyright 2003 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Steve C. Woodford for Wasabi Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed for the NetBSD Project by
 *      Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2002-2003 Wasabi Systems, Inc.
 * Copyright (c) 2001 Richard Earnshaw
 * Copyright (c) 2001-2002 Christopher Gilbert
 * All rights reserved.
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the company nor the name of the author may be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*-
 * Copyright (c) 1999 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum.
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
 * Copyright (c) 1994-1998 Mark Brinicombe.
 * Copyright (c) 1994 Brini.
 * All rights reserved.
 *
 * This code is derived from software written for Brini by Mark Brinicombe
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Mark Brinicombe.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *
 * RiscBSD kernel project
 *
 * pmap.c
 *
 * Machine dependent vm stuff
 *
 * Created      : 20/09/94
 */

/*
 * armv6 and VIPT cache support by 3am Software Foundry,
 * Copyright (c) 2007 Microsoft
 */

/*
 * Performance improvements, UVM changes, overhauls and part-rewrites
 * were contributed by Neil A. Carson <neil@causality.com>.
 */

/*
 * Overhauled again to speedup the pmap, use MMU Domains so that L1 tables
 * can be shared, and re-work the KVM layout, by Steve Woodford of Wasabi
 * Systems, Inc.
 *
 * There are still a few things outstanding at this time:
 *
 *   - There are some unresolved issues for MP systems:
 *
 *     o The L1 metadata needs a lock, or more specifically, some places
 *       need to acquire an exclusive lock when modifying L1 translation
 *       table entries.
 *
 *     o When one cpu modifies an L1 entry, and that L1 table is also
 *       being used by another cpu, then the latter will need to be told
 *       that a tlb invalidation may be necessary. (But only if the old
 *       domain number in the L1 entry being over-written is currently
 *       the active domain on that cpu). I guess there are lots more tlb
 *       shootdown issues too...
 *
 *     o If the vector_page is at 0x00000000 instead of in kernel VA space,
 *       then MP systems will lose big-time because of the MMU domain hack.
 *       The only way this can be solved (apart from moving the vector
 *       page to 0xffff0000) is to reserve the first 1MB of user address
 *       space for kernel use only. This would require re-linking all
 *       applications so that the text section starts above this 1MB
 *       boundary.
 *
 *     o Tracking which VM space is resident in the cache/tlb has not yet
 *       been implemented for MP systems.
 *
 *     o Finally, there is a pathological condition where two cpus running
 *       two separate processes (not lwps) which happen to share an L1
 *       can get into a fight over one or more L1 entries. This will result
 *       in a significant slow-down if both processes are in tight loops.
 */

/*
 * Special compilation symbols
 * PMAP_DEBUG		- Build in pmap_debug_level code
 */

/* Include header files */

#include "opt_arm_debug.h"
#include "opt_cpuoptions.h"
#include "opt_pmap_debug.h"
#include "opt_ddb.h"
#include "opt_lockdebug.h"
#include "opt_multiprocessor.h"

#ifdef MULTIPROCESSOR
#define _INTR_PRIVATE
#endif

#define __PMAP_PRIVATE

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/types.h>
#include <sys/param.h>

#include <sys/atomic.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/intr.h>
#include <sys/kernel.h>
#include <sys/kernhist.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/pool.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <uvm/uvm.h>
#include <uvm/uvm_physseg.h>
#include <uvm/pmap/pmap_pvt.h>

#include <arm/locore.h>
#include <arm/arm32/pmap_common.h>

#ifdef PMAP_NEED_ALLOC_POOLPAGE
int			arm_poolpage_vmfreelist = VM_FREELIST_DEFAULT;
#endif


/*
 * Pool and cache of l2_dtable structures.
 * We use a cache to avoid clearing the structures when they're
 * allocated. (196 bytes)
 */
static struct pool_cache pmap_l2dtable_cache;


vaddr_t pmap_kernel_l2dtable_kva;
/*
 * Pool and cache of L2 page descriptors.
 * We use a cache to avoid clearing the descriptor table
 * when they're allocated. (1KB)
 */
static struct pool_cache pmap_l2ptp_cache;
vaddr_t pmap_kernel_l2ptp_kva;
paddr_t pmap_kernel_l2ptp_phys;


/*
 * pmap copy/zero page, and mem(5) hook point
 */
static pt_entry_t *csrc_pte, *cdst_pte;
static vaddr_t csrcp, cdstp;
#ifdef MULTIPROCESSOR
static size_t cnptes;
#define	cpu_csrc_pte(o)	(csrc_pte + cnptes * cpu_number() + ((o) >> L2_S_SHIFT))
#define	cpu_cdst_pte(o)	(cdst_pte + cnptes * cpu_number() + ((o) >> L2_S_SHIFT))
#define	cpu_csrcp(o)	(csrcp + L2_S_SIZE * cnptes * cpu_number() + (o))
#define	cpu_cdstp(o)	(cdstp + L2_S_SIZE * cnptes * cpu_number() + (o))
#else
#define	cpu_csrc_pte(o)	(csrc_pte + ((o) >> L2_S_SHIFT))
#define	cpu_cdst_pte(o)	(cdst_pte + ((o) >> L2_S_SHIFT))
#define	cpu_csrcp(o)	(csrcp + (o))
#define	cpu_cdstp(o)	(cdstp + (o))
#endif

extern kmutex_t pmap_lock;

vaddr_t memhook;			/* used by mem.c & others */
kmutex_t memlock __cacheline_aligned;	/* used by mem.c & others */
extern void *msgbufaddr;

#ifndef ARM_MMU_EXTENDED
/*
 * Misc. locking data structures
 */

static inline void
pmap_acquire_pmap_lock(pmap_t pm)
{
	if (pm == pmap_kernel()) {
#ifdef MULTIPROCESSOR
		KERNEL_LOCK(1, NULL);
#endif
	} else {
		mutex_enter(pm->pm_lock);
	}
}

static inline void
pmap_release_pmap_lock(pmap_t pm)
{
	if (pm == pmap_kernel()) {
#ifdef MULTIPROCESSOR
		KERNEL_UNLOCK_ONE(NULL);
#endif
	} else {
		mutex_exit(pm->pm_lock);
	}
}

static inline void
pmap_acquire_page_lock(struct vm_page_md *md)
{
	mutex_enter(&pmap_lock);
}

static inline void
pmap_release_page_lock(struct vm_page_md *md)
{
	mutex_exit(&pmap_lock);
}

#ifdef DIAGNOSTIC
static inline int
pmap_page_locked_p(struct vm_page_md *md)
{
	return mutex_owned(&pmap_lock);
}
#endif
#endif


/*
 * Metadata for L1 translation tables.
 */
struct l1_ttable {
	/* Entry on the L1 Table list */
	SLIST_ENTRY(l1_ttable) l1_link;

	/* Entry on the L1 Least Recently Used list */
	TAILQ_ENTRY(l1_ttable) l1_lru;

	/* Track how many domains are allocated from this L1 */
	volatile u_int l1_domain_use_count;

	/*
	 * A free-list of domain numbers for this L1.
	 * We avoid using ffs() and a bitmap to track domains since ffs()
	 * is slow on ARM.
	 */
	uint8_t l1_domain_first;
	uint8_t l1_domain_free[PMAP_DOMAINS];

	/* Physical address of this L1 page table */
	paddr_t l1_physaddr;

	/* KVA of this L1 page table */
	pd_entry_t *l1_kva;
};


#define pmap_alloc_l2_ptp(pap)		\
	    ((pt_entry_t *)pool_cache_get_paddr(&pmap_l2ptp_cache,\
	    PR_NOWAIT, (pap)))

/*
 * We try to map the page tables write-through, if possible.  However, not
 * all CPUs have a write-through cache mode, so on those we have to sync
 * the cache when we frob page tables.
 *
 * We try to evaluate this at compile time, if possible.  However, it's
 * not always possible to do that, hence this run-time var.
 */
int	pmap_needs_pte_sync;




/*
 * List of functions that need to be provided by the pmap implementation
 */
bool		pmap_set_pt_cache_mode(pd_entry_t *, vaddr_t, size_t);

/*
 * Local prototypes
 */
static void		pmap_alloc_specials(vaddr_t *, int, vaddr_t *,
			    pt_entry_t **);

static int		pmap_l2ptp_ctor(void *, void *, int);
static int		pmap_l2dtable_ctor(void *, void *, int);

static vaddr_t		kernel_pt_lookup(paddr_t);

pv_addrqh_t pmap_boot_freeq = SLIST_HEAD_INITIALIZER(&pmap_boot_freeq);
pv_addr_t kernelpages;
pv_addr_t kernel_l1pt;
pv_addr_t systempage;


static inline uint8_t
pmap_domain(pmap_t pm)
{
#ifdef ARM_MMU_EXTENDED
	return pm == pmap_kernel() ? PMAP_DOMAIN_KERNEL : PMAP_DOMAIN_USER;
#else
	return pm->pm_domain;
#endif
}





static inline pd_entry_t *
pmap_l1_kva(pmap_t pm)
{
#ifdef ARM_MMU_EXTENDED
	return pm->pm_l1;
#else
	return pm->pm_l1->l1_kva;
#endif
}




/*
 * void pmap_free_l2_ptp(pt_entry_t *, paddr_t *)
 *
 * Free an L2 descriptor table.
 */
void
#if defined(PMAP_INCLUDE_PTE_SYNC) && defined(PMAP_CACHE_VIVT)
pmap_free_l2_ptp(bool need_sync, pt_entry_t *l2, paddr_t pa)
#else
pmap_free_l2_ptp(pt_entry_t *l2, paddr_t pa)
#endif
{
#if defined(PMAP_INCLUDE_PTE_SYNC) && defined(PMAP_CACHE_VIVT)
	/*
	 * Note: With a write-back cache, we may need to sync this
	 * L2 table before re-using it.
	 * This is because it may have belonged to a non-current
	 * pmap, in which case the cache syncs would have been
	 * skipped for the pages that were being unmapped. If the
	 * L2 table were then to be immediately re-allocated to
	 * the *current* pmap, it may well contain stale mappings
	 * which have not yet been cleared by a cache write-back
	 * and so would still be visible to the mmu.
	 */
	if (need_sync)
		PTE_SYNC_RANGE(l2, L2_TABLE_SIZE_REAL / sizeof(pt_entry_t));
#endif /* PMAP_INCLUDE_PTE_SYNC && PMAP_CACHE_VIVT */
	pool_cache_put_paddr(&pmap_l2ptp_cache, (void *)l2, pa);
}

/*
 * Returns a pointer to the L2 bucket associated with the specified pmap
 * and VA.
 *
 * If no L2 bucket exists, perform the necessary allocations to put an L2
 * bucket/page table in place.
 *
 * Note that if a new L2 bucket/page was allocated, the caller *must*
 * increment the bucket occupancy counter appropriately *before*
 * releasing the pmap's lock to ensure no other thread or cpu deallocates
 * the bucket/page in the meantime.
 */
struct l2_bucket *
pmap_alloc_l2_bucket(pmap_t pm, vaddr_t va)
{
	const size_t l1slot = l1pte_index(va);
	struct l2_dtable *l2;

	if ((l2 = pm->pm_l2[L2_IDX(l1slot)]) == NULL) {
		/*
		 * No mapping at this address, as there is
		 * no entry in the L1 table.
		 * Need to allocate a new l2_dtable.
		 */
		if ((l2 = pmap_alloc_l2_dtable()) == NULL)
			return (NULL);

		/*
		 * Link it into the parent pmap
		 */
		pm->pm_l2[L2_IDX(l1slot)] = l2;
	}

	struct l2_bucket * const l2b = &l2->l2_bucket[L2_BUCKET(l1slot)];

	/*
	 * Fetch pointer to the L2 page table associated with the address.
	 */
	if (l2b->l2b_kva == NULL) {
		pt_entry_t *ptep;

		/*
		 * No L2 page table has been allocated. Chances are, this
		 * is because we just allocated the l2_dtable, above.
		 */
		if ((ptep = pmap_alloc_l2_ptp(&l2b->l2b_pa)) == NULL) {
			/*
			 * Oops, no more L2 page tables available at this
			 * time. We may need to deallocate the l2_dtable
			 * if we allocated a new one above.
			 */
			if (l2->l2_occupancy == 0) {
				pm->pm_l2[L2_IDX(l1slot)] = NULL;
				pmap_free_l2_dtable(l2);
			}
			return (NULL);
		}

		l2->l2_occupancy++;
		l2b->l2b_kva = ptep;
		l2b->l2b_l1slot = l1slot;

#ifdef ARM_MMU_EXTENDED
		/*
		 * We know there will be a mapping here, so simply
		 * enter this PTP into the L1 now.
		 */
		pd_entry_t * const pdep = pmap_l1_kva(pm) + l1slot;
		pd_entry_t npde = L1_C_PROTO | l2b->l2b_pa
		    | L1_C_DOM(pmap_domain(pm));
		KASSERT(*pdep == 0);
		l1pte_setone(pdep, npde);
		PDE_SYNC(pdep);
#endif
	}

	return (l2b);
}

/*
 * One or more mappings in the specified L2 descriptor table have just been
 * invalidated.
 *
 * Garbage collect the metadata and descriptor table itself if necessary.
 *
 * The pmap lock must be acquired when this is called (not necessary
 * for the kernel pmap).
 */
void
pmap_free_l2_bucket(pmap_t pm, struct l2_bucket *l2b, u_int count)
{
	KDASSERT(count <= l2b->l2b_occupancy);

	/*
	 * Update the bucket's reference count according to how many
	 * PTEs the caller has just invalidated.
	 */
	l2b->l2b_occupancy -= count;

	/*
	 * Note:
	 *
	 * Level 2 page tables allocated to the kernel pmap are never freed
	 * as that would require checking all Level 1 page tables and
	 * removing any references to the Level 2 page table. See also the
	 * comment elsewhere about never freeing bootstrap L2 descriptors.
	 *
	 * We make do with just invalidating the mapping in the L2 table.
	 *
	 * This isn't really a big deal in practice and, in fact, leads
	 * to a performance win over time as we don't need to continually
	 * alloc/free.
	 */
	if (l2b->l2b_occupancy > 0 || pm == pmap_kernel())
		return;

	/*
	 * There are no more valid mappings in this level 2 page table.
	 * Go ahead and NULL-out the pointer in the bucket, then
	 * free the page table.
	 */
	const size_t l1slot = l2b->l2b_l1slot;
	pt_entry_t * const ptep = l2b->l2b_kva;
	l2b->l2b_kva = NULL;

	pd_entry_t * const pdep = pmap_l1_kva(pm) + l1slot;
	pd_entry_t pde __diagused = *pdep;

#ifdef ARM_MMU_EXTENDED
	/*
	 * Invalidate the L1 slot.
	 */
	KASSERT((pde & L1_TYPE_MASK) == L1_TYPE_C);
#else
	/*
	 * If the L1 slot matches the pmap's domain number, then invalidate it.
	 */
	if ((pde & (L1_C_DOM_MASK|L1_TYPE_MASK))
	    == (L1_C_DOM(pmap_domain(pm))|L1_TYPE_C)) {
#endif
		l1pte_setone(pdep, 0);
		PDE_SYNC(pdep);
#ifndef ARM_MMU_EXTENDED
	}
#endif

	/*
	 * Release the L2 descriptor table back to the pool cache.
	 */
#if defined(PMAP_INCLUDE_PTE_SYNC) && defined(PMAP_CACHE_VIVT)
	pmap_free_l2_ptp(!pmap_is_cached(pm), ptep, l2b->l2b_pa);
#else
	pmap_free_l2_ptp(ptep, l2b->l2b_pa);
#endif

	/*
	 * Update the reference count in the associated l2_dtable
	 */
	struct l2_dtable * const l2 = pm->pm_l2[L2_IDX(l1slot)];
	if (--l2->l2_occupancy > 0)
		return;

	/*
	 * There are no more valid mappings in any of the Level 1
	 * slots managed by this l2_dtable. Go ahead and NULL-out
	 * the pointer in the parent pmap and free the l2_dtable.
	 */
	pm->pm_l2[L2_IDX(l1slot)] = NULL;
	pmap_free_l2_dtable(l2);
}
#if 0
#endif


/*
 * Pool cache constructors for L2 descriptor tables, metadata and pmap
 * structures.
 */
static int
pmap_l2ptp_ctor(void *arg, void *v, int flags)
{
#ifndef PMAP_INCLUDE_PTE_SYNC
	vaddr_t va = (vaddr_t)v & ~PGOFSET;

	/*
	 * The mappings for these page tables were initially made using
	 * pmap_kenter_pa() by the pool subsystem. Therefore, the cache-
	 * mode will not be right for page table mappings. To avoid
	 * polluting the pmap_kenter_pa() code with a special case for
	 * page tables, we simply fix up the cache-mode here if it's not
	 * correct.
	 */
	if (pte_l2_s_cache_mode != pte_l2_s_cache_mode_pt) {
		const struct l2_bucket * const l2b =
		    pmap_get_l2_bucket(pmap_kernel(), va);
		KASSERTMSG(l2b != NULL, "%#lx", va);
		pt_entry_t * const ptep = &l2b->l2b_kva[l2pte_index(va)];
		const pt_entry_t opte = *ptep;

		if ((opte & L2_S_CACHE_MASK) != pte_l2_s_cache_mode_pt) {
			/*
			 * Page tables must have the cache-mode set correctly.
			 */
			const pt_entry_t npte = (opte & ~L2_S_CACHE_MASK)
			    | pte_l2_s_cache_mode_pt;
			l2pte_set(ptep, npte, opte);
			PTE_SYNC(ptep);
			cpu_tlb_flushD_SE(va);
			cpu_cpwait();
		}
	}
#endif

	memset(v, 0, L2_TABLE_SIZE_REAL);
	PTE_SYNC_RANGE(v, L2_TABLE_SIZE_REAL / sizeof(pt_entry_t));
	return (0);
}




static int
pmap_l2dtable_ctor(void *arg, void *v, int flags)
{

	memset(v, 0, sizeof(struct l2_dtable));
	return (0);
}

void
pmap_icache_sync_range(pmap_t pm, vaddr_t sva, vaddr_t eva)
{
	struct l2_bucket *l2b;
	pt_entry_t *ptep;
	vaddr_t next_bucket;
	vsize_t page_size = trunc_page(sva) + PAGE_SIZE - sva;

#if 0
	NPDEBUG(PDB_EXEC,
	    printf("pmap_icache_sync_range: pm %p sva 0x%lx eva 0x%lx\n",
	    pm, sva, eva));
#endif


#ifndef ARM_MMU_EXTENDED
	pmap_acquire_pmap_lock(pm);
#endif

	while (sva < eva) {
		next_bucket = L2_NEXT_BUCKET_VA(sva);
		if (next_bucket > eva)
			next_bucket = eva;

		l2b = pmap_get_l2_bucket(pm, sva);
		if (l2b == NULL) {
			sva = next_bucket;
			continue;
		}

		for (ptep = &l2b->l2b_kva[l2pte_index(sva)];
		     sva < next_bucket;
		     sva += page_size,
		     ptep += PAGE_SIZE / L2_S_SIZE,
		     page_size = PAGE_SIZE) {
			if (l2pte_valid_p(*ptep)) {
				cpu_icache_sync_range(sva,
				    min(page_size, eva - sva));
			}
		}
	}

#ifndef ARM_MMU_EXTENDED
	pmap_release_pmap_lock(pm);
#endif
}

/*
 * pmap_zero_page()
 *
 * Zero a given physical page by mapping it at a page hook point.
 * In doing the zero page op, the page we zero is mapped cachable, as with
 * StrongARM accesses to non-cached pages are non-burst making writing
 * _any_ bulk data very slow.
 */
#if (ARM_MMU_GENERIC + ARM_MMU_SA1 + ARM_MMU_V6 + ARM_MMU_V7) != 0
void
pmap_zero_page_generic(paddr_t pa)
{
#if defined(PMAP_CACHE_VIPT) || defined(DEBUG)
	struct vm_page *pg = PHYS_TO_VM_PAGE(pa);
//	struct vm_page_md *md = VM_PAGE_TO_MD(pg);
#endif
#if defined(PMAP_CACHE_VIPT)
	/* Choose the last page color it had, if any */
	const vsize_t va_offset = pmap_md_pagecolor(pg);
#else
	const vsize_t va_offset = 0;
#endif
#if defined(__HAVE_MM_MD_DIRECT_MAPPED_PHYS)
	/*
	 * Is this page mapped at its natural color?
	 * If we have all of memory mapped, then just convert PA to VA.
	 */
	bool okcolor = arm_pcache.dcache_type == CACHE_TYPE_PIPT
	   || va_offset == (pa & arm_cache_prefer_mask);
	const vaddr_t vdstp = okcolor
	    ? pmap_direct_mapped_phys(pa, &okcolor, cpu_cdstp(va_offset))
	    : cpu_cdstp(va_offset);
#else
	const bool okcolor = false;
	const vaddr_t vdstp = cpu_cdstp(va_offset);
#endif
	pt_entry_t * const ptep = cpu_cdst_pte(va_offset);

	KDASSERT();
#if 0
#ifdef DEBUG
	if (!SLIST_EMPTY(&md->pvh_list))
		panic("pmap_zero_page: page has mappings");
#endif
#endif

	KDASSERT((pa & PGOFSET) == 0);

	if (!okcolor) {
		/*
		 * Hook in the page, zero it, and purge the cache for that
		 * zeroed page. Invalidate the TLB as needed.
		 */
		const pt_entry_t npte = L2_S_PROTO | pa | pte_l2_s_cache_mode
		    | L2_S_PROT(PTE_KERNEL, VM_PROT_WRITE);
		l2pte_set(ptep, npte, 0);
		PTE_SYNC(ptep);
		cpu_tlb_flushD_SE(vdstp);
		cpu_cpwait();
#if defined(__HAVE_MM_MD_DIRECT_MAPPED_PHYS) && defined(PMAP_CACHE_VIPT) \
    && !defined(ARM_MMU_EXTENDED)
		/*
		 * If we are direct-mapped and our color isn't ok, then before
		 * we bzero the page invalidate its contents from the cache and
		 * reset the color to its natural color.
		 */
		cpu_dcache_inv_range(vdstp, PAGE_SIZE);
		md->pvh_attrs &= ~arm_cache_prefer_mask;
		md->pvh_attrs |= (pa & arm_cache_prefer_mask);
#endif
	}
	bzero_page(vdstp);
	if (!okcolor) {
		/*
		 * Unmap the page.
		 */
		l2pte_reset(ptep);
		PTE_SYNC(ptep);
		cpu_tlb_flushD_SE(vdstp);
#ifdef PMAP_CACHE_VIVT
		cpu_dcache_wbinv_range(vdstp, PAGE_SIZE);
#endif
	}



#ifndef ARM_MMU_EXTENDED
#ifdef PMAP_CACHE_VIPT
	/*
	 * This page is now cache resident so it now has a page color.
	 * Any contents have been obliterated so clear the EXEC flag.
	 */
	if (!pmap_is_page_colored_p(md)) {
		PMAPCOUNT(vac_color_new);
		md->pvh_attrs |= PVF_COLORED;
	}
	md->pvh_attrs |= PVF_DIRTY;
	if (PV_IS_EXEC_P(md->pvh_attrs)) {
		md->pvh_attrs &= ~PVF_EXEC;
		PMAPCOUNT(exec_discarded_zero);
	}
#endif
#endif
}
#endif /* (ARM_MMU_GENERIC + ARM_MMU_SA1 + ARM_MMU_V6) != 0 */

#if ARM_MMU_XSCALE == 1
void
pmap_zero_page_xscale(paddr_t pa)
{
#if 0
#ifdef DEBUG
	struct vm_page *pg = PHYS_TO_VM_PAGE(pa);
	struct vm_page_md *md = VM_PAGE_TO_MD(pg);

	KDASSERT();
	if (!SLIST_EMPTY(&md->pvh_list))
		panic("pmap_zero_page: page has mappings");
#endif
#endif

	KDASSERT((pa & PGOFSET) == 0);

	/*
	 * Hook in the page, zero it, and purge the cache for that
	 * zeroed page. Invalidate the TLB as needed.
	 */

	pt_entry_t npte = L2_S_PROTO | pa |
	    L2_S_PROT(PTE_KERNEL, VM_PROT_WRITE) |
	    L2_C | L2_XS_T_TEX(TEX_XSCALE_X);	/* mini-data */
	l2pte_set(cdst_pte, npte, 0);
	PTE_SYNC(cdst_pte);
	cpu_tlb_flushD_SE(cdstp);
	cpu_cpwait();
	bzero_page(cdstp);
	xscale_cache_clean_minidata();
	l2pte_reset(cdst_pte);
	PTE_SYNC(cdst_pte);
}
#endif /* ARM_MMU_XSCALE == 1 */

/* pmap_pageidlezero()
 *
 * The same as above, except that we assume that the page is not
 * mapped.  This means we never have to flush the cache first.  Called
 * from the idle loop.
 */
bool
pmap_pageidlezero(paddr_t pa)
{
	bool rv = true;
#if defined(PMAP_CACHE_VIPT) || defined(DEBUG)
	struct vm_page * const pg = PHYS_TO_VM_PAGE(pa);
//	struct vm_page_md *md = VM_PAGE_TO_MD(pg);
#endif
#ifdef PMAP_CACHE_VIPT
	/* Choose the last page color it had, if any */
	const vsize_t va_offset = pmap_md_pagecolor(pg);
#else
	const vsize_t va_offset = 0;
#endif
#ifdef __HAVE_MM_MD_DIRECT_MAPPED_PHYS
	bool okcolor = arm_pcache.dcache_type == CACHE_TYPE_PIPT
	   || va_offset == (pa & arm_cache_prefer_mask);
	const vaddr_t vdstp = okcolor
	    ? pmap_direct_mapped_phys(pa, &okcolor, cpu_cdstp(va_offset))
	    : cpu_cdstp(va_offset);
#else
	const bool okcolor = false;
	const vaddr_t vdstp = cpu_cdstp(va_offset);
#endif
	pt_entry_t * const ptep = cpu_cdst_pte(va_offset);


#ifdef DEBUG
	if (!SLIST_EMPTY(&md->pvh_list))
		panic("pmap_pageidlezero: page has mappings");
#endif

	KDASSERT((pa & PGOFSET) == 0);

	if (!okcolor) {
		/*
		 * Hook in the page, zero it, and purge the cache for that
		 * zeroed page. Invalidate the TLB as needed.
		 */
		const pt_entry_t npte = L2_S_PROTO | pa |
		    L2_S_PROT(PTE_KERNEL, VM_PROT_WRITE) | pte_l2_s_cache_mode;
		l2pte_set(ptep, npte, 0);
		PTE_SYNC(ptep);
		cpu_tlb_flushD_SE(vdstp);
		cpu_cpwait();
	}

	uint64_t *ptr = (uint64_t *)vdstp;
	for (size_t i = 0; i < PAGE_SIZE / sizeof(*ptr); i++) {
		if (sched_curcpu_runnable_p() != 0) {
			/*
			 * A process has become ready.  Abort now,
			 * so we don't keep it waiting while we
			 * do slow memory access to finish this
			 * page.
			 */
			rv = false;
			break;
		}
		*ptr++ = 0;
	}

#ifdef PMAP_CACHE_VIVT
	if (rv)
		/*
		 * if we aborted we'll rezero this page again later so don't
		 * purge it unless we finished it
		 */
		cpu_dcache_wbinv_range(vdstp, PAGE_SIZE);

#if 0
#ifndef ARM_MMU_EXTENDED
	pmap_impl_pageidlezero_done(pg);
#elif defined(PMAP_CACHE_VIPT)
	/*
	 * This page is now cache resident so it now has a page color.
	 * Any contents have been obliterated so clear the EXEC flag.
	 */
	if (!pmap_is_page_colored_p(md)) {
		PMAPCOUNT(vac_color_new);
		md->pvh_attrs |= PVF_COLORED;
	}
	if (PV_IS_EXEC_P(md->pvh_attrs)) {
		md->pvh_attrs &= ~PVF_EXEC;
		PMAPCOUNT(exec_discarded_zero);
	}
#endif
#endif
#endif
	/*
	 * Unmap the page.
	 */
	if (!okcolor) {
		l2pte_reset(ptep);
		PTE_SYNC(ptep);
		cpu_tlb_flushD_SE(vdstp);
	}

	return rv;
}

/*
 * pmap_copy_page()
 *
 * Copy one physical page into another, by mapping the pages into
 * hook points. The same comment regarding cachability as in
 * pmap_zero_page also applies here.
 */
#if (ARM_MMU_GENERIC + ARM_MMU_SA1 + ARM_MMU_V6 + ARM_MMU_V7) != 0
void
pmap_copy_page_generic(paddr_t src, paddr_t dst)
{
	struct vm_page * const src_pg = PHYS_TO_VM_PAGE(src);
	struct vm_page_md *src_md = VM_PAGE_TO_MD(src_pg);
	struct vm_page * const __diagused dst_pg = PHYS_TO_VM_PAGE(dst);
// 	struct vm_page_md *dst_md = VM_PAGE_TO_MD(dst_pg);
#ifdef PMAP_CACHE_VIPT
	const vsize_t src_va_offset = pmap_md_pagecolor(src_pg);
	const vsize_t dst_va_offset = pmap_md_pagecolor(dst_pg);
#else
	const vsize_t src_va_offset = 0;
	const vsize_t dst_va_offset = 0;
#endif
#if defined(__HAVE_MM_MD_DIRECT_MAPPED_PHYS)
	/*
	 * Is this page mapped at its natural color?
	 * If we have all of memory mapped, then just convert PA to VA.
	 */
	bool src_okcolor = arm_pcache.dcache_type == CACHE_TYPE_PIPT
	    || src_va_offset == (src & arm_cache_prefer_mask);
	bool dst_okcolor = arm_pcache.dcache_type == CACHE_TYPE_PIPT
	    || dst_va_offset == (dst & arm_cache_prefer_mask);
	const vaddr_t vsrcp = src_okcolor
	    ? pmap_direct_mapped_phys(src, &src_okcolor,
		cpu_csrcp(src_va_offset))
	    : cpu_csrcp(src_va_offset);
	const vaddr_t vdstp = pmap_direct_mapped_phys(dst, &dst_okcolor,
	    cpu_cdstp(dst_va_offset));
#else
	const bool src_okcolor = false;
	const bool dst_okcolor = false;
	const vaddr_t vsrcp = cpu_csrcp(src_va_offset);
	const vaddr_t vdstp = cpu_cdstp(dst_va_offset);
#endif
	pt_entry_t * const src_ptep = cpu_csrc_pte(src_va_offset);
	pt_entry_t * const dst_ptep = cpu_cdst_pte(dst_va_offset);

	KASSERT(PVLIST_EMPTY_P(dst_pg));

#if defined(PMAP_CACHE_VIPT) && !defined(ARM_MMU_EXTENDED)
	KASSERT(arm_cache_prefer_mask == 0 || src_md->pvh_attrs & (PVF_COLORED|PVF_NC));
#endif
	KDASSERT((src & PGOFSET) == 0);
	KDASSERT((dst & PGOFSET) == 0);

	/*
	 * Clean the source page.  Hold the source page's lock for
	 * the duration of the copy so that no other mappings can
	 * be created while we have a potentially aliased mapping.
	 */
	pmap_md_clean_page(src_md, true);

	/*
	 * Map the pages into the page hook points, copy them, and purge
	 * the cache for the appropriate page. Invalidate the TLB
	 * as required.
	 */
	if (!src_okcolor) {
		const pt_entry_t nsrc_pte = L2_S_PROTO
		    | src
#if defined(PMAP_CACHE_VIPT) && !defined(ARM_MMU_EXTENDED)
		    | ((src_md->pvh_attrs & PVF_NC) ? 0 : pte_l2_s_cache_mode)
#else // defined(PMAP_CACHE_VIVT) || defined(ARM_MMU_EXTENDED)
		    | pte_l2_s_cache_mode
#endif
		    | L2_S_PROT(PTE_KERNEL, VM_PROT_READ);
		l2pte_set(src_ptep, nsrc_pte, 0);
		PTE_SYNC(src_ptep);
		cpu_tlb_flushD_SE(vsrcp);
		cpu_cpwait();
	}
	if (!dst_okcolor) {
		const pt_entry_t ndst_pte = L2_S_PROTO | dst |
		    L2_S_PROT(PTE_KERNEL, VM_PROT_WRITE) | pte_l2_s_cache_mode;
		l2pte_set(dst_ptep, ndst_pte, 0);
		PTE_SYNC(dst_ptep);
		cpu_tlb_flushD_SE(vdstp);
		cpu_cpwait();
#ifndef ARM_MMU_EXTENDED
		// XXXNH maybe should provide indirect call here for ARM_MMU_EXTENDED ...
#if defined(__HAVE_MM_MD_DIRECT_MAPPED_PHYS) && defined(PMAP_CACHE_VIPT)
		/*
		 * If we are direct-mapped and our color isn't ok, then before
		 * we bcopy to the new page invalidate its contents from the
		 * cache and reset its color to its natural color.
		 */
		cpu_dcache_inv_range(vdstp, PAGE_SIZE);
		dst_md->pvh_attrs &= ~arm_cache_prefer_mask;
		dst_md->pvh_attrs |= (dst & arm_cache_prefer_mask);
#endif
#endif
	}
	bcopy_page(vsrcp, vdstp);
#ifdef PMAP_CACHE_VIVT
	cpu_dcache_inv_range(vsrcp, PAGE_SIZE);
	cpu_dcache_wbinv_range(vdstp, PAGE_SIZE);
#endif
	/*
	 * Unmap the pages.
	 */
	if (!src_okcolor) {
		l2pte_reset(src_ptep);
		PTE_SYNC(src_ptep);
		cpu_tlb_flushD_SE(vsrcp);
		cpu_cpwait();
	}
	if (!dst_okcolor) {
		l2pte_reset(dst_ptep);
		PTE_SYNC(dst_ptep);
		cpu_tlb_flushD_SE(vdstp);
		cpu_cpwait();
	}
#if 0
#ifndef ARM_MMU_EXTENDED
	pmap_impl_copypage_done(dst_pg);
#ifdef PMAP_CACHE_VIPT
	/*
	 * Now that the destination page is in the cache, mark it as colored.
	 * If this was an exec page, discard it.
	 */
	pmap_acquire_page_lock(dst_md);
	if (arm_pcache.cache_type == CACHE_TYPE_PIPT) {
		dst_md->pvh_attrs &= ~arm_cache_prefer_mask;
		dst_md->pvh_attrs |= (dst & arm_cache_prefer_mask);
	}
	if (!pmap_is_page_colored_p(dst_md)) {
		PMAPCOUNT(vac_color_new);
		dst_md->pvh_attrs |= PVF_COLORED;
	}
	dst_md->pvh_attrs |= PVF_DIRTY;
	if (PV_IS_EXEC_P(dst_md->pvh_attrs)) {
		dst_md->pvh_attrs &= ~PVF_EXEC;
		PMAPCOUNT(exec_discarded_copy);
	}
	pmap_release_page_lock(dst_md);
#endif
#endif
#endif
}
#endif /* (ARM_MMU_GENERIC + ARM_MMU_SA1 + ARM_MMU_V6) != 0 */

#if ARM_MMU_XSCALE == 1
void
pmap_copy_page_xscale(paddr_t src, paddr_t dst)
{
	struct vm_page *src_pg = PHYS_TO_VM_PAGE(src);
	struct vm_page_md *src_md = VM_PAGE_TO_MD(src_pg);
#ifdef DEBUG
	struct vm_page_md *dst_md = VM_PAGE_TO_MD(PHYS_TO_VM_PAGE(dst));

	if (!SLIST_EMPTY(&dst_md->pvh_list))
		panic("pmap_copy_page: dst page has mappings");
#endif

	KDASSERT((src & PGOFSET) == 0);
	KDASSERT((dst & PGOFSET) == 0);

	/*
	 * Clean the source page.  Hold the source page's lock for
	 * the duration of the copy so that no other mappings can
	 * be created while we have a potentially aliased mapping.
	 */

	pmap_md_clean_page(src_md, true);

	/*
	 * Map the pages into the page hook points, copy them, and purge
	 * the cache for the appropriate page. Invalidate the TLB
	 * as required.
	 */
	const pt_entry_t nsrc_pte = L2_S_PROTO | src
	    | L2_S_PROT(PTE_KERNEL, VM_PROT_READ)
	    | L2_C | L2_XS_T_TEX(TEX_XSCALE_X);	/* mini-data */
	l2pte_set(csrc_pte, nsrc_pte, 0);
	PTE_SYNC(csrc_pte);

	const pt_entry_t ndst_pte = L2_S_PROTO | dst
	    | L2_S_PROT(PTE_KERNEL, VM_PROT_WRITE)
	    | L2_C | L2_XS_T_TEX(TEX_XSCALE_X);	/* mini-data */
	l2pte_set(cdst_pte, ndst_pte, 0);
	PTE_SYNC(cdst_pte);

	cpu_tlb_flushD_SE(csrcp);
	cpu_tlb_flushD_SE(cdstp);
	cpu_cpwait();
	bcopy_page(csrcp, cdstp);
	xscale_cache_clean_minidata();
	l2pte_reset(csrc_pte);
	l2pte_reset(cdst_pte);
	PTE_SYNC(csrc_pte);
	PTE_SYNC(cdst_pte);
}
#endif /* ARM_MMU_XSCALE == 1 */



















/************************ Bootstrapping routines ****************************/

/*
 * pmap_bootstrap() is called from the board-specific initarm() routine
 * once the kernel L1/L2 descriptors tables have been set up.
 *
 * This is a somewhat convoluted process since pmap bootstrap is, effectively,
 * spread over a number of disparate files/functions.
 *
 * We are passed the following parameters
 *  - kernel_l1pt
 *    This is a pointer to the base of the kernel's L1 translation table.
 *  - vstart
 *    1MB-aligned start of managed kernel virtual memory.
 *  - vend
 *    1MB-aligned end of managed kernel virtual memory.
 *
 * We use the first parameter to build the metadata (struct l1_ttable and
 * struct l2_dtable) necessary to track kernel mappings.
 */
#define	PMAP_STATIC_L2_SIZE 16
void
pmap_bootstrap(vaddr_t vstart, vaddr_t vend)
{
	static struct l2_dtable static_l2[PMAP_STATIC_L2_SIZE];
#if 0
#ifndef ARM_MMU_EXTENDED
	static struct l1_ttable static_l1;
	struct l1_ttable *l1 = &static_l1;
#endif
#endif
	struct l2_dtable *l2;
	struct l2_bucket *l2b;
	pd_entry_t *l1pt = (pd_entry_t *) kernel_l1pt.pv_va;
	pmap_t pm = pmap_kernel();
	pt_entry_t *ptep;
	paddr_t pa;
	vsize_t size;
	int nptes, l2idx, l2next = 0;

#ifdef VERBOSE_INIT_ARM
	printf("kpm ");
#endif

	/*
	 * Initialise the kernel pmap object
	 */
	curcpu()->ci_pmap_cur = pm;

	pmap_impl_bootstrap();

#ifdef VERBOSE_INIT_ARM
	printf("l1pt (%p)", l1pt);
#endif
	/*
	 * Scan the L1 translation table created by initarm() and create
	 * the required metadata for all valid mappings found in it.
	 */
	for (size_t l1slot = 0;
	     l1slot < L1_TABLE_SIZE / sizeof(pd_entry_t);
	     l1slot++) {
		pd_entry_t pde = l1pt[l1slot];

		/*
		 * We're only interested in Coarse mappings.
		 * pmap_extract() can deal with section mappings without
		 * recourse to checking L2 metadata.
		 */
		if ((pde & L1_TYPE_MASK) != L1_TYPE_C)
			continue;

		printf("%s: pde %p\n", __func__, (void *)pde);
		/*
		 * Lookup the KVA of this L2 descriptor table
		 */
		pa = l1pte_pa(pde);
		ptep = (pt_entry_t *)kernel_pt_lookup(pa);
		if (ptep == NULL) {
			panic("pmap_bootstrap: No L2 for va 0x%x, pa 0x%lx",
			    (u_int)l1slot << L1_S_SHIFT, pa);
		}

		/*
		 * Fetch the associated L2 metadata structure.
		 * Allocate a new one if necessary.
		 */
		if ((l2 = pm->pm_l2[L2_IDX(l1slot)]) == NULL) {
			if (l2next == PMAP_STATIC_L2_SIZE)
				panic("pmap_bootstrap: out of static L2s");
			pm->pm_l2[L2_IDX(l1slot)] = l2 = &static_l2[l2next++];
		}

		/*
		 * One more L1 slot tracked...
		 */
		l2->l2_occupancy++;

		/*
		 * Fill in the details of the L2 descriptor in the
		 * appropriate bucket.
		 */
		l2b = &l2->l2_bucket[L2_BUCKET(l1slot)];
		l2b->l2b_kva = ptep;
		l2b->l2b_pa = pa;
		l2b->l2b_l1slot = l1slot;

		/*
		 * Establish an initial occupancy count for this descriptor
		 */
		for (l2idx = 0;
		    l2idx < (L2_TABLE_SIZE_REAL / sizeof(pt_entry_t));
		    l2idx++) {
			if ((ptep[l2idx] & L2_TYPE_MASK) != L2_TYPE_INV) {
				l2b->l2b_occupancy++;
			}
		}

		/*
		 * Make sure the descriptor itself has the correct cache mode.
		 * If not, fix it, but whine about the problem. Port-meisters
		 * should consider this a clue to fix up their initarm()
		 * function. :)
		 */
		if (pmap_set_pt_cache_mode(l1pt, (vaddr_t)ptep, 1)) {
			printf("pmap_bootstrap: WARNING! wrong cache mode for "
			    "L2 pte @ %p\n", ptep);
		}
	}

#ifdef VERBOSE_INIT_ARM
	printf("cache(l1pt) ");
#endif
	/*
	 * Ensure the primary (kernel) L1 has the correct cache mode for
	 * a page table. Bitch if it is not correctly set.
	 */
	if (pmap_set_pt_cache_mode(l1pt, kernel_l1pt.pv_va,
		    L1_TABLE_SIZE / L2_S_SIZE)) {
		printf("pmap_bootstrap: WARNING! wrong cache mode for "
		    "primary L1 @ 0x%lx\n", kernel_l1pt.pv_va);
	}

#ifdef PMAP_CACHE_VIVT
	cpu_dcache_wbinv_all();
	cpu_tlb_flushID();
	cpu_cpwait();
#endif

	/*
	 * now we allocate the "special" VAs which are used for tmp mappings
	 * by the pmap (and other modules).  we allocate the VAs by advancing
	 * virtual_avail (note that there are no pages mapped at these VAs).
	 *
	 * Managed KVM space start from wherever initarm() tells us.
	 */
	vaddr_t virtual_avail;
	vaddr_t virtual_end;
	virtual_avail = vstart;
	virtual_end = vend;

#ifdef VERBOSE_INIT_ARM
	printf("specials ");
#endif
#ifdef PMAP_CACHE_VIPT
	/*
	 * If we have a VIPT cache, we need one page/pte per possible alias
	 * page so we won't violate cache aliasing rules.
	 */
	virtual_avail = (virtual_avail + arm_cache_prefer_mask) & ~arm_cache_prefer_mask;
	nptes = (arm_cache_prefer_mask >> L2_S_SHIFT) + 1;
	nptes = roundup(nptes, PAGE_SIZE / L2_S_SIZE);
	if (arm_pcache.icache_type != CACHE_TYPE_PIPT
	    && arm_pcache.icache_way_size > nptes * L2_S_SIZE) {
		nptes = arm_pcache.icache_way_size >> L2_S_SHIFT;
		nptes = roundup(nptes, PAGE_SIZE / L2_S_SIZE);
	}
#else
	nptes = PAGE_SIZE / L2_S_SIZE;
#endif
#ifdef MULTIPROCESSOR
	cnptes = nptes;
	nptes *= arm_cpu_max;
#endif
	pmap_alloc_specials(&virtual_avail, nptes, &csrcp, &csrc_pte);
	pmap_set_pt_cache_mode(l1pt, (vaddr_t)csrc_pte, nptes);
	pmap_alloc_specials(&virtual_avail, nptes, &cdstp, &cdst_pte);
	pmap_set_pt_cache_mode(l1pt, (vaddr_t)cdst_pte, nptes);
	pmap_alloc_specials(&virtual_avail, nptes, &memhook, NULL);
	if (msgbufaddr == NULL) {
		pmap_alloc_specials(&virtual_avail,
		    round_page(MSGBUFSIZE) / PAGE_SIZE,
		    (void *)&msgbufaddr, NULL);
	}

	/*
	 * Allocate a range of kernel virtual address space to be used
	 * for L2 descriptor tables and metadata allocation in
	 * pmap_growkernel().
	 */
	size = ((virtual_end - pmap_curmaxkvaddr) + L1_S_OFFSET) / L1_S_SIZE;
	pmap_alloc_specials(&virtual_avail,
	    round_page(size * L2_TABLE_SIZE_REAL) / PAGE_SIZE,
	    &pmap_kernel_l2ptp_kva, NULL);

	size = (size + (L2_BUCKET_SIZE - 1)) / L2_BUCKET_SIZE;
	pmap_alloc_specials(&virtual_avail,
	    round_page(size * sizeof(struct l2_dtable)) / PAGE_SIZE,
	    &pmap_kernel_l2dtable_kva, NULL);

	pmap_impl_bootstrap_l1();

	pmap_impl_set_virtual_space(virtual_avail, virtual_end);

#ifndef ARM_HAS_VBAR
	/* Set up vector page L1 details, if necessary */
	if (vector_page < KERNEL_BASE) {
		pm->pm_pl1vec = pmap_l1_kva(pm) + l1pte_index(vector_page);
		l2b = pmap_get_l2_bucket(pm, vector_page);
printf("%s: vector_page %#"PRIxVADDR" l2b %p\n", __func__, vector_page, l2b);
		KDASSERT(l2b != NULL);
		pm->pm_l1vec = l2b->l2b_pa | L1_C_PROTO |
		    L1_C_DOM(pmap_domain(pm));
	} else
		pm->pm_pl1vec = NULL;
#endif

#ifdef VERBOSE_INIT_ARM
	printf("pools ");
#endif
	pmap_impl_bootstrap_pools();

	/*
	 * Initialize the L2 dtable pool and cache.
	 */
	pool_cache_bootstrap(&pmap_l2dtable_cache, sizeof(struct l2_dtable), 0,
	    0, 0, "l2dtblpl", NULL, IPL_NONE, pmap_l2dtable_ctor, NULL, NULL);

	/*
	 * Initialise the L2 descriptor table pool and cache
	 */
	pool_cache_bootstrap(&pmap_l2ptp_cache, L2_TABLE_SIZE_REAL, 0,
	    L2_TABLE_SIZE_REAL, 0, "l2ptppl", NULL, IPL_NONE,
	    pmap_l2ptp_ctor, NULL, NULL);

	mutex_init(&memlock, MUTEX_DEFAULT, IPL_NONE);

	cpu_dcache_wbinv_all();
}


/*static*/ bool
pmap_set_pt_cache_mode(pd_entry_t *kl1, vaddr_t va, size_t nptes)
{
#ifdef ARM_MMU_EXTENDED
	return false;
#else
	if (pte_l1_s_cache_mode == pte_l1_s_cache_mode_pt
	    && pte_l2_s_cache_mode == pte_l2_s_cache_mode_pt)
		return false;

	const vaddr_t eva = va + nptes * PAGE_SIZE;
	int rv = 0;

	while (va < eva) {
		/*
		 * Make sure the descriptor itself has the correct cache mode
		 */
		pd_entry_t * const pdep = &kl1[l1pte_index(va)];
		pd_entry_t pde = *pdep;

		if (l1pte_section_p(pde)) {
			__CTASSERT((L1_S_CACHE_MASK & L1_S_V6_SUPER) == 0);
			if ((pde & L1_S_CACHE_MASK) != pte_l1_s_cache_mode_pt) {
				*pdep = (pde & ~L1_S_CACHE_MASK) |
				    pte_l1_s_cache_mode_pt;
				PDE_SYNC(pdep);
				cpu_dcache_wbinv_range((vaddr_t)pdep,
				    sizeof(*pdep));
				rv = 1;
			}
			return rv;
		}
		vaddr_t pa = l1pte_pa(pde);
		pt_entry_t *ptep = (pt_entry_t *)kernel_pt_lookup(pa);
		if (ptep == NULL)
			panic("pmap_bootstrap: No PTP for va %#lx\n", va);

		ptep += l2pte_index(va);
		const pt_entry_t opte = *ptep;
		if ((opte & L2_S_CACHE_MASK) != pte_l2_s_cache_mode_pt) {
			const pt_entry_t npte = (opte & ~L2_S_CACHE_MASK)
			    | pte_l2_s_cache_mode_pt;
			l2pte_set(ptep, npte, opte);
			PTE_SYNC(ptep);
			cpu_dcache_wbinv_range((vaddr_t)ptep, sizeof(*ptep));
			rv = 1;
		}
		va += PAGE_SIZE;
	}

	return (rv);
#endif
}


static void
pmap_alloc_specials(vaddr_t *availp, int pages, vaddr_t *vap, pt_entry_t **ptep)
{
	vaddr_t va = *availp;
	struct l2_bucket *l2b;

	if (ptep) {
		l2b = pmap_get_l2_bucket(pmap_kernel(), va);
		if (l2b == NULL)
			panic("pmap_alloc_specials: no l2b for 0x%lx", va);

		if (ptep)
			*ptep = &l2b->l2b_kva[l2pte_index(va)];
	}

	*vap = va;
	*availp = va + (PAGE_SIZE * pages);
}








/*
 * pmap_postinit()
 *
 * This routine is called after the vm and kmem subsystems have been
 * initialised. This allows the pmap code to perform any initialisation
 * that can only be done once the memory allocation is in place.
 */
void
pmap_postinit(void)
{

	pool_cache_setlowat(&pmap_l2ptp_cache, (PAGE_SIZE / L2_TABLE_SIZE_REAL) * 4);
	pool_cache_setlowat(&pmap_l2dtable_cache,
	    (PAGE_SIZE / sizeof(struct l2_dtable)) * 2);

	pmap_impl_postinit();

#if 0
#ifndef ARM_MMU_EXTENDED
	extern paddr_t physical_start, physical_end;
	struct l1_ttable *l1;
	struct pglist plist;
	struct vm_page *m;
	pd_entry_t *pdep;
	vaddr_t va, eva;
	u_int loop, needed;
	int error;

	needed = (maxproc / PMAP_DOMAINS) + ((maxproc % PMAP_DOMAINS) ? 1 : 0);
	needed -= 1;

	l1 = kmem_alloc(sizeof(*l1) * needed, KM_SLEEP);

	for (loop = 0; loop < needed; loop++, l1++) {
		/* Allocate a L1 page table */
		va = uvm_km_alloc(kernel_map, L1_TABLE_SIZE, 0, UVM_KMF_VAONLY);
		if (va == 0)
			panic("Cannot allocate L1 KVM");

		error = uvm_pglistalloc(L1_TABLE_SIZE, physical_start,
		    physical_end, L1_TABLE_SIZE, 0, &plist, 1, 1);
		if (error)
			panic("Cannot allocate L1 physical pages");

		m = TAILQ_FIRST(&plist);
		eva = va + L1_TABLE_SIZE;
		pdep = (pd_entry_t *)va;

		while (m && va < eva) {
			paddr_t pa = VM_PAGE_TO_PHYS(m);

			pmap_kenter_pa(va, pa,
			    VM_PROT_READ|VM_PROT_WRITE, PMAP_KMPAGE|PMAP_PTE);

			va += PAGE_SIZE;
			m = TAILQ_NEXT(m, pageq.queue);
		}

#ifdef DIAGNOSTIC
		if (m)
			panic("pmap_alloc_l1pt: pglist not empty");
#endif	/* DIAGNOSTIC */

		pmap_init_l1(l1, pdep);
	}

#ifdef DEBUG
	printf("pmap_postinit: Allocated %d static L1 descriptor tables\n",
	    needed);
#endif
#endif /* !ARM_MMU_EXTENDED */
#endif
}






/*
 * Note that the following routines are used by board-specific initialisation
 * code to configure the initial kernel page tables.
 *
 * If ARM32_NEW_VM_LAYOUT is *not* defined, they operate on the assumption that
 * L2 page-table pages are 4KB in size and use 4 L1 slots. This mimics the
 * behaviour of the old pmap, and provides an easy migration path for
 * initial bring-up of the new pmap on existing ports. Fortunately,
 * pmap_bootstrap() compensates for this hackery. This is only a stop-gap and
 * will be deprecated.
 *
 * If ARM32_NEW_VM_LAYOUT *is* defined, these functions deal with 1KB L2 page
 * tables.
 */

/*
 * This list exists for the benefit of pmap_map_chunk().  It keeps track
 * of the kernel L2 tables during bootstrap, so that pmap_map_chunk() can
 * find them as necessary.
 *
 * Note that the data on this list MUST remain valid after initarm() returns,
 * as pmap_bootstrap() uses it to contruct L2 table metadata.
 */
SLIST_HEAD(, pv_addr) kernel_pt_list = SLIST_HEAD_INITIALIZER(kernel_pt_list);

static vaddr_t
kernel_pt_lookup(paddr_t pa)
{
	pv_addr_t *pv;

	SLIST_FOREACH(pv, &kernel_pt_list, pv_list) {
		if (pv->pv_pa == (pa & ~PGOFSET))
			return (pv->pv_va | (pa & PGOFSET));
	}
	return (0);
}

/*
 * pmap_map_section:
 *
 *	Create a single section mapping.
 */
void
pmap_map_section(vaddr_t l1pt, vaddr_t va, paddr_t pa, int prot, int cache)
{
	pd_entry_t * const pdep = (pd_entry_t *) l1pt;
	const size_t l1slot = l1pte_index(va);
	pd_entry_t fl;

	KASSERT(((va | pa) & L1_S_OFFSET) == 0);

	switch (cache) {
	case PTE_NOCACHE:
	default:
		fl = 0;
		break;

	case PTE_CACHE:
		fl = pte_l1_s_cache_mode;
		break;

	case PTE_PAGETABLE:
		fl = pte_l1_s_cache_mode_pt;
		break;
	}

	const pd_entry_t npde = L1_S_PROTO | pa |
	    L1_S_PROT(PTE_KERNEL, prot) | fl | L1_S_DOM(PMAP_DOMAIN_KERNEL);
	l1pte_setone(pdep + l1slot, npde);
	PDE_SYNC(pdep + l1slot);
}

/*
 * pmap_map_entry:
 *
 *	Create a single page mapping.
 */
void
pmap_map_entry(vaddr_t l1pt, vaddr_t va, paddr_t pa, int prot, int cache)
{
	pd_entry_t * const pdep = (pd_entry_t *) l1pt;
	const size_t l1slot = l1pte_index(va);
	pt_entry_t npte;
	pt_entry_t *ptep;

	KASSERT(((va | pa) & PGOFSET) == 0);

	switch (cache) {
	case PTE_NOCACHE:
	default:
		npte = 0;
		break;

	case PTE_CACHE:
		npte = pte_l2_s_cache_mode;
		break;

	case PTE_PAGETABLE:
		npte = pte_l2_s_cache_mode_pt;
		break;
	}

	if ((pdep[l1slot] & L1_TYPE_MASK) != L1_TYPE_C)
		panic("pmap_map_entry: no L2 table for VA 0x%08lx", va);

	ptep = (pt_entry_t *) kernel_pt_lookup(l1pte_pa(pdep[l1slot]));
	if (ptep == NULL)
		panic("pmap_map_entry: can't find L2 table for VA 0x%08lx", va);

	npte |= L2_S_PROTO | pa | L2_S_PROT(PTE_KERNEL, prot);
#ifdef ARM_MMU_EXTENDED
	if (prot & VM_PROT_EXECUTE) {
		npte &= ~L2_XS_XN;
	}
#endif
	ptep += l2pte_index(va);
	l2pte_set(ptep, npte, 0);
	PTE_SYNC(ptep);
}

/*
 * pmap_link_l2pt:
 *
 *	Link the L2 page table specified by "l2pv" into the L1
 *	page table at the slot for "va".
 */
void
pmap_link_l2pt(vaddr_t l1pt, vaddr_t va, pv_addr_t *l2pv)
{
	pd_entry_t * const pdep = (pd_entry_t *) l1pt + l1pte_index(va);

	KASSERT((va & ((L1_S_SIZE * (PAGE_SIZE / L2_T_SIZE)) - 1)) == 0);
	KASSERT((l2pv->pv_pa & PGOFSET) == 0);

	const pd_entry_t npde = L1_S_DOM(PMAP_DOMAIN_KERNEL) | L1_C_PROTO
	    | l2pv->pv_pa;

	l1pte_set(pdep, npde);
	PDE_SYNC_RANGE(pdep, PAGE_SIZE / L2_T_SIZE);

	SLIST_INSERT_HEAD(&kernel_pt_list, l2pv, pv_list);
}

/*
 * pmap_map_chunk:
 *
 *	Map a chunk of memory using the most efficient mappings
 *	possible (section, large page, small page) into the
 *	provided L1 and L2 tables at the specified virtual address.
 */
vsize_t
pmap_map_chunk(vaddr_t l1pt, vaddr_t va, paddr_t pa, vsize_t size,
    int prot, int cache)
{
	pd_entry_t * const pdep = (pd_entry_t *) l1pt;
	pt_entry_t f1, f2s, f2l;
	vsize_t resid;

	resid = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

	if (l1pt == 0)
		panic("pmap_map_chunk: no L1 table provided");

#ifdef VERBOSE_INIT_ARM
	printf("pmap_map_chunk: pa=0x%lx va=0x%lx size=0x%lx resid=0x%lx "
	    "prot=0x%x cache=%d\n", pa, va, size, resid, prot, cache);
#endif

	switch (cache) {
	case PTE_NOCACHE:
	default:
		f1 = 0;
		f2l = 0;
		f2s = 0;
		break;

	case PTE_CACHE:
		f1 = pte_l1_s_cache_mode;
		f2l = pte_l2_l_cache_mode;
		f2s = pte_l2_s_cache_mode;
		break;

	case PTE_PAGETABLE:
		f1 = pte_l1_s_cache_mode_pt;
		f2l = pte_l2_l_cache_mode_pt;
		f2s = pte_l2_s_cache_mode_pt;
		break;
	}

	size = resid;

	while (resid > 0) {
		const size_t l1slot = l1pte_index(va);
#if (ARM_MMU_V6 + ARM_MMU_V7) > 0
		/* See if we can use a supersection mapping. */
		if (L1_SS_PROTO && L1_SS_MAPPABLE_P(va, pa, resid)) {
			/* Supersection are always domain 0 */
			const pd_entry_t npde = L1_SS_PROTO | pa
#ifdef ARM_MMU_EXTENDED
			    | ((prot & VM_PROT_EXECUTE) ? 0 : L1_S_V6_XN)
			    | (va & 0x80000000 ? 0 : L1_S_V6_nG)
#endif
			    | L1_S_PROT(PTE_KERNEL, prot) | f1;
#ifdef VERBOSE_INIT_ARM
			printf("sS");
#endif
			l1pte_set(&pdep[l1slot], npde);
			PDE_SYNC_RANGE(&pdep[l1slot], L1_SS_SIZE / L1_S_SIZE);
			va += L1_SS_SIZE;
			pa += L1_SS_SIZE;
			resid -= L1_SS_SIZE;
			continue;
		}
#endif
		/* See if we can use a section mapping. */
		if (L1_S_MAPPABLE_P(va, pa, resid)) {
			const pd_entry_t npde = L1_S_PROTO | pa
#ifdef ARM_MMU_EXTENDED
			    | ((prot & VM_PROT_EXECUTE) ? 0 : L1_S_V6_XN)
			    | (va & 0x80000000 ? 0 : L1_S_V6_nG)
#endif
			    | L1_S_PROT(PTE_KERNEL, prot) | f1
			    | L1_S_DOM(PMAP_DOMAIN_KERNEL);
#ifdef VERBOSE_INIT_ARM
			printf("S");
#endif
			l1pte_set(&pdep[l1slot], npde);
			PDE_SYNC(&pdep[l1slot]);
			va += L1_S_SIZE;
			pa += L1_S_SIZE;
			resid -= L1_S_SIZE;
			continue;
		}

		/*
		 * Ok, we're going to use an L2 table.  Make sure
		 * one is actually in the corresponding L1 slot
		 * for the current VA.
		 */
		if ((pdep[l1slot] & L1_TYPE_MASK) != L1_TYPE_C)
			panic("%s: no L2 table for VA %#lx", __func__, va);

		pt_entry_t *ptep = (pt_entry_t *) kernel_pt_lookup(l1pte_pa(pdep[l1slot]));
		if (ptep == NULL)
			panic("%s: can't find L2 table for VA %#lx", __func__,
			    va);

		ptep += l2pte_index(va);

		/* See if we can use a L2 large page mapping. */
		if (L2_L_MAPPABLE_P(va, pa, resid)) {
			const pt_entry_t npte = L2_L_PROTO | pa
#ifdef ARM_MMU_EXTENDED
			    | ((prot & VM_PROT_EXECUTE) ? 0 : L2_XS_L_XN)
			    | (va & 0x80000000 ? 0 : L2_XS_nG)
#endif
			    | L2_L_PROT(PTE_KERNEL, prot) | f2l;
#ifdef VERBOSE_INIT_ARM
			printf("L");
#endif
			l2pte_set(ptep, npte, 0);
			PTE_SYNC_RANGE(ptep, L2_L_SIZE / L2_S_SIZE);
			va += L2_L_SIZE;
			pa += L2_L_SIZE;
			resid -= L2_L_SIZE;
			continue;
		}

#ifdef VERBOSE_INIT_ARM
		printf("P");
#endif
		/* Use a small page mapping. */
		pt_entry_t npte = L2_S_PROTO | pa
#ifdef ARM_MMU_EXTENDED
		    | ((prot & VM_PROT_EXECUTE) ? 0 : L2_XS_XN)
		    | (va & 0x80000000 ? 0 : L2_XS_nG)
#endif
		    | L2_S_PROT(PTE_KERNEL, prot) | f2s;
#ifdef ARM_MMU_EXTENDED
		npte &= ((prot & VM_PROT_EXECUTE) ? ~L2_XS_XN : ~0);
#endif
		l2pte_set(ptep, npte, 0);
		PTE_SYNC(ptep);
		va += PAGE_SIZE;
		pa += PAGE_SIZE;
		resid -= PAGE_SIZE;
	}
#ifdef VERBOSE_INIT_ARM
	printf("\n");
#endif
	return (size);
}

/********************** Static device map routines ***************************/

static const struct pmap_devmap *pmap_devmap_table;

/*
 * Register the devmap table.  This is provided in case early console
 * initialization needs to register mappings created by bootstrap code
 * before pmap_devmap_bootstrap() is called.
 */
void
pmap_devmap_register(const struct pmap_devmap *table)
{

	pmap_devmap_table = table;
}

/*
 * Map all of the static regions in the devmap table, and remember
 * the devmap table so other parts of the kernel can look up entries
 * later.
 */
void
pmap_devmap_bootstrap(vaddr_t l1pt, const struct pmap_devmap *table)
{
	int i;

	pmap_devmap_table = table;

	for (i = 0; pmap_devmap_table[i].pd_size != 0; i++) {
#ifdef VERBOSE_INIT_ARM
		printf("devmap: %08lx -> %08lx @ %08lx\n",
		    pmap_devmap_table[i].pd_pa,
		    pmap_devmap_table[i].pd_pa +
			pmap_devmap_table[i].pd_size - 1,
		    pmap_devmap_table[i].pd_va);
#endif
		pmap_map_chunk(l1pt, pmap_devmap_table[i].pd_va,
		    pmap_devmap_table[i].pd_pa,
		    pmap_devmap_table[i].pd_size,
		    pmap_devmap_table[i].pd_prot,
		    pmap_devmap_table[i].pd_cache);
	}
}

const struct pmap_devmap *
pmap_devmap_find_pa(paddr_t pa, psize_t size)
{
	uint64_t endpa;
	int i;

	if (pmap_devmap_table == NULL)
		return (NULL);

	endpa = (uint64_t)pa + (uint64_t)(size - 1);

	for (i = 0; pmap_devmap_table[i].pd_size != 0; i++) {
		if (pa >= pmap_devmap_table[i].pd_pa &&
		    endpa <= (uint64_t)pmap_devmap_table[i].pd_pa +
			     (uint64_t)(pmap_devmap_table[i].pd_size - 1))
			return (&pmap_devmap_table[i]);
	}

	return (NULL);
}

const struct pmap_devmap *
pmap_devmap_find_va(vaddr_t va, vsize_t size)
{
	int i;

	if (pmap_devmap_table == NULL)
		return (NULL);

	for (i = 0; pmap_devmap_table[i].pd_size != 0; i++) {
		if (va >= pmap_devmap_table[i].pd_va &&
		    va + size - 1 <= pmap_devmap_table[i].pd_va +
				     pmap_devmap_table[i].pd_size - 1)
			return (&pmap_devmap_table[i]);
	}

	return (NULL);
}

/********************** PTE initialization routines **************************/

/*
 * These routines are called when the CPU type is identified to set up
 * the PTE prototypes, cache modes, etc.
 *
 * The variables are always here, just in case modules need to reference
 * them (though, they shouldn't).
 */

pt_entry_t	pte_l1_s_cache_mode;
pt_entry_t	pte_l1_s_wc_mode;
pt_entry_t	pte_l1_s_cache_mode_pt;
pt_entry_t	pte_l1_s_cache_mask;

pt_entry_t	pte_l2_l_cache_mode;
pt_entry_t	pte_l2_l_wc_mode;
pt_entry_t	pte_l2_l_cache_mode_pt;
pt_entry_t	pte_l2_l_cache_mask;

pt_entry_t	pte_l2_s_cache_mode;
pt_entry_t	pte_l2_s_wc_mode;
pt_entry_t	pte_l2_s_cache_mode_pt;
pt_entry_t	pte_l2_s_cache_mask;

pt_entry_t	pte_l1_s_prot_u;
pt_entry_t	pte_l1_s_prot_w;
pt_entry_t	pte_l1_s_prot_ro;
pt_entry_t	pte_l1_s_prot_mask;

pt_entry_t	pte_l2_s_prot_u;
pt_entry_t	pte_l2_s_prot_w;
pt_entry_t	pte_l2_s_prot_ro;
pt_entry_t	pte_l2_s_prot_mask;

pt_entry_t	pte_l2_l_prot_u;
pt_entry_t	pte_l2_l_prot_w;
pt_entry_t	pte_l2_l_prot_ro;
pt_entry_t	pte_l2_l_prot_mask;

pt_entry_t	pte_l1_ss_proto;
pt_entry_t	pte_l1_s_proto;
pt_entry_t	pte_l1_c_proto;
pt_entry_t	pte_l2_s_proto;

void		(*pmap_copy_page_func)(paddr_t, paddr_t);
void		(*pmap_zero_page_func)(paddr_t);

#if (ARM_MMU_GENERIC + ARM_MMU_SA1 + ARM_MMU_V6 + ARM_MMU_V7) != 0
void
pmap_pte_init_generic(void)
{

	pte_l1_s_cache_mode = L1_S_B|L1_S_C;
	pte_l1_s_wc_mode = L1_S_B;
	pte_l1_s_cache_mask = L1_S_CACHE_MASK_generic;

	pte_l2_l_cache_mode = L2_B|L2_C;
	pte_l2_l_wc_mode = L2_B;
	pte_l2_l_cache_mask = L2_L_CACHE_MASK_generic;

	pte_l2_s_cache_mode = L2_B|L2_C;
	pte_l2_s_wc_mode = L2_B;
	pte_l2_s_cache_mask = L2_S_CACHE_MASK_generic;

	/*
	 * If we have a write-through cache, set B and C.  If
	 * we have a write-back cache, then we assume setting
	 * only C will make those pages write-through (except for those
	 * Cortex CPUs which can read the L1 caches).
	 */
	if (cpufuncs.cf_dcache_wb_range == (void *) cpufunc_nullop
#if ARM_MMU_V7 > 0
	    || CPU_ID_CORTEX_P(curcpu()->ci_arm_cpuid)
#endif
#if ARM_MMU_V6 > 0
	    || CPU_ID_ARM11_P(curcpu()->ci_arm_cpuid) /* arm116 errata 399234 */
#endif
	    || false) {
		pte_l1_s_cache_mode_pt = L1_S_B|L1_S_C;
		pte_l2_l_cache_mode_pt = L2_B|L2_C;
		pte_l2_s_cache_mode_pt = L2_B|L2_C;
	} else {
		pte_l1_s_cache_mode_pt = L1_S_C;	/* write through */
		pte_l2_l_cache_mode_pt = L2_C;		/* write through */
		pte_l2_s_cache_mode_pt = L2_C;		/* write through */
	}

	pte_l1_s_prot_u = L1_S_PROT_U_generic;
	pte_l1_s_prot_w = L1_S_PROT_W_generic;
	pte_l1_s_prot_ro = L1_S_PROT_RO_generic;
	pte_l1_s_prot_mask = L1_S_PROT_MASK_generic;

	pte_l2_s_prot_u = L2_S_PROT_U_generic;
	pte_l2_s_prot_w = L2_S_PROT_W_generic;
	pte_l2_s_prot_ro = L2_S_PROT_RO_generic;
	pte_l2_s_prot_mask = L2_S_PROT_MASK_generic;

	pte_l2_l_prot_u = L2_L_PROT_U_generic;
	pte_l2_l_prot_w = L2_L_PROT_W_generic;
	pte_l2_l_prot_ro = L2_L_PROT_RO_generic;
	pte_l2_l_prot_mask = L2_L_PROT_MASK_generic;

	pte_l1_ss_proto = L1_SS_PROTO_generic;
	pte_l1_s_proto = L1_S_PROTO_generic;
	pte_l1_c_proto = L1_C_PROTO_generic;
	pte_l2_s_proto = L2_S_PROTO_generic;

	pmap_copy_page_func = pmap_copy_page_generic;
	pmap_zero_page_func = pmap_zero_page_generic;
}

#if defined(CPU_ARM8)
void
pmap_pte_init_arm8(void)
{

	/*
	 * ARM8 is compatible with generic, but we need to use
	 * the page tables uncached.
	 */
	pmap_pte_init_generic();

	pte_l1_s_cache_mode_pt = 0;
	pte_l2_l_cache_mode_pt = 0;
	pte_l2_s_cache_mode_pt = 0;
}
#endif /* CPU_ARM8 */

#if defined(CPU_ARM9) && defined(ARM9_CACHE_WRITE_THROUGH)
void
pmap_pte_init_arm9(void)
{

	/*
	 * ARM9 is compatible with generic, but we want to use
	 * write-through caching for now.
	 */
	pmap_pte_init_generic();

	pte_l1_s_cache_mode = L1_S_C;
	pte_l2_l_cache_mode = L2_C;
	pte_l2_s_cache_mode = L2_C;

	pte_l1_s_wc_mode = L1_S_B;
	pte_l2_l_wc_mode = L2_B;
	pte_l2_s_wc_mode = L2_B;

	pte_l1_s_cache_mode_pt = L1_S_C;
	pte_l2_l_cache_mode_pt = L2_C;
	pte_l2_s_cache_mode_pt = L2_C;
}
#endif /* CPU_ARM9 && ARM9_CACHE_WRITE_THROUGH */
#endif /* (ARM_MMU_GENERIC + ARM_MMU_SA1 + ARM_MMU_V6) != 0 */

#if defined(CPU_ARM10)
void
pmap_pte_init_arm10(void)
{

	/*
	 * ARM10 is compatible with generic, but we want to use
	 * write-through caching for now.
	 */
	pmap_pte_init_generic();

	pte_l1_s_cache_mode = L1_S_B | L1_S_C;
	pte_l2_l_cache_mode = L2_B | L2_C;
	pte_l2_s_cache_mode = L2_B | L2_C;

	pte_l1_s_cache_mode = L1_S_B;
	pte_l2_l_cache_mode = L2_B;
	pte_l2_s_cache_mode = L2_B;

	pte_l1_s_cache_mode_pt = L1_S_C;
	pte_l2_l_cache_mode_pt = L2_C;
	pte_l2_s_cache_mode_pt = L2_C;

}
#endif /* CPU_ARM10 */

#if defined(CPU_ARM11) && defined(ARM11_CACHE_WRITE_THROUGH)
void
pmap_pte_init_arm11(void)
{

	/*
	 * ARM11 is compatible with generic, but we want to use
	 * write-through caching for now.
	 */
	pmap_pte_init_generic();

	pte_l1_s_cache_mode = L1_S_C;
	pte_l2_l_cache_mode = L2_C;
	pte_l2_s_cache_mode = L2_C;

	pte_l1_s_wc_mode = L1_S_B;
	pte_l2_l_wc_mode = L2_B;
	pte_l2_s_wc_mode = L2_B;

	pte_l1_s_cache_mode_pt = L1_S_C;
	pte_l2_l_cache_mode_pt = L2_C;
	pte_l2_s_cache_mode_pt = L2_C;
}
#endif /* CPU_ARM11 && ARM11_CACHE_WRITE_THROUGH */

#if ARM_MMU_SA1 == 1
void
pmap_pte_init_sa1(void)
{

	/*
	 * The StrongARM SA-1 cache does not have a write-through
	 * mode.  So, do the generic initialization, then reset
	 * the page table cache mode to B=1,C=1, and note that
	 * the PTEs need to be sync'd.
	 */
	pmap_pte_init_generic();

	pte_l1_s_cache_mode_pt = L1_S_B|L1_S_C;
	pte_l2_l_cache_mode_pt = L2_B|L2_C;
	pte_l2_s_cache_mode_pt = L2_B|L2_C;

	pmap_needs_pte_sync = 1;
}
#endif /* ARM_MMU_SA1 == 1*/

#if ARM_MMU_XSCALE == 1
#if (ARM_NMMUS > 1)
static u_int xscale_use_minidata;
#endif

void
pmap_pte_init_xscale(void)
{
	uint32_t auxctl;
	int write_through = 0;

	pte_l1_s_cache_mode = L1_S_B|L1_S_C;
	pte_l1_s_wc_mode = L1_S_B;
	pte_l1_s_cache_mask = L1_S_CACHE_MASK_xscale;

	pte_l2_l_cache_mode = L2_B|L2_C;
	pte_l2_l_wc_mode = L2_B;
	pte_l2_l_cache_mask = L2_L_CACHE_MASK_xscale;

	pte_l2_s_cache_mode = L2_B|L2_C;
	pte_l2_s_wc_mode = L2_B;
	pte_l2_s_cache_mask = L2_S_CACHE_MASK_xscale;

	pte_l1_s_cache_mode_pt = L1_S_C;
	pte_l2_l_cache_mode_pt = L2_C;
	pte_l2_s_cache_mode_pt = L2_C;

#ifdef XSCALE_CACHE_READ_WRITE_ALLOCATE
	/*
	 * The XScale core has an enhanced mode where writes that
	 * miss the cache cause a cache line to be allocated.  This
	 * is significantly faster than the traditional, write-through
	 * behavior of this case.
	 */
	pte_l1_s_cache_mode |= L1_S_XS_TEX(TEX_XSCALE_X);
	pte_l2_l_cache_mode |= L2_XS_L_TEX(TEX_XSCALE_X);
	pte_l2_s_cache_mode |= L2_XS_T_TEX(TEX_XSCALE_X);
#endif /* XSCALE_CACHE_READ_WRITE_ALLOCATE */

#ifdef XSCALE_CACHE_WRITE_THROUGH
	/*
	 * Some versions of the XScale core have various bugs in
	 * their cache units, the work-around for which is to run
	 * the cache in write-through mode.  Unfortunately, this
	 * has a major (negative) impact on performance.  So, we
	 * go ahead and run fast-and-loose, in the hopes that we
	 * don't line up the planets in a way that will trip the
	 * bugs.
	 *
	 * However, we give you the option to be slow-but-correct.
	 */
	write_through = 1;
#elif defined(XSCALE_CACHE_WRITE_BACK)
	/* force write back cache mode */
	write_through = 0;
#elif defined(CPU_XSCALE_PXA250) || defined(CPU_XSCALE_PXA270)
	/*
	 * Intel PXA2[15]0 processors are known to have a bug in
	 * write-back cache on revision 4 and earlier (stepping
	 * A[01] and B[012]).  Fixed for C0 and later.
	 */
	{
		uint32_t id, type;

		id = cpufunc_id();
		type = id & ~(CPU_ID_XSCALE_COREREV_MASK|CPU_ID_REVISION_MASK);

		if (type == CPU_ID_PXA250 || type == CPU_ID_PXA210) {
			if ((id & CPU_ID_REVISION_MASK) < 5) {
				/* write through for stepping A0-1 and B0-2 */
				write_through = 1;
			}
		}
	}
#endif /* XSCALE_CACHE_WRITE_THROUGH */

	if (write_through) {
		pte_l1_s_cache_mode = L1_S_C;
		pte_l2_l_cache_mode = L2_C;
		pte_l2_s_cache_mode = L2_C;
	}

#if (ARM_NMMUS > 1)
	xscale_use_minidata = 1;
#endif

	pte_l1_s_prot_u = L1_S_PROT_U_xscale;
	pte_l1_s_prot_w = L1_S_PROT_W_xscale;
	pte_l1_s_prot_ro = L1_S_PROT_RO_xscale;
	pte_l1_s_prot_mask = L1_S_PROT_MASK_xscale;

	pte_l2_s_prot_u = L2_S_PROT_U_xscale;
	pte_l2_s_prot_w = L2_S_PROT_W_xscale;
	pte_l2_s_prot_ro = L2_S_PROT_RO_xscale;
	pte_l2_s_prot_mask = L2_S_PROT_MASK_xscale;

	pte_l2_l_prot_u = L2_L_PROT_U_xscale;
	pte_l2_l_prot_w = L2_L_PROT_W_xscale;
	pte_l2_l_prot_ro = L2_L_PROT_RO_xscale;
	pte_l2_l_prot_mask = L2_L_PROT_MASK_xscale;

	pte_l1_ss_proto = L1_SS_PROTO_xscale;
	pte_l1_s_proto = L1_S_PROTO_xscale;
	pte_l1_c_proto = L1_C_PROTO_xscale;
	pte_l2_s_proto = L2_S_PROTO_xscale;

	pmap_copy_page_func = pmap_copy_page_xscale;
	pmap_zero_page_func = pmap_zero_page_xscale;

	/*
	 * Disable ECC protection of page table access, for now.
	 */
	auxctl = armreg_auxctl_read();
	auxctl &= ~XSCALE_AUXCTL_P;
	armreg_auxctl_write(auxctl);
}

/*
 * xscale_setup_minidata:
 *
 *	Set up the mini-data cache clean area.  We require the
 *	caller to allocate the right amount of physically and
 *	virtually contiguous space.
 */
void
xscale_setup_minidata(vaddr_t l1pt, vaddr_t va, paddr_t pa)
{
	extern vaddr_t xscale_minidata_clean_addr;
	extern vsize_t xscale_minidata_clean_size; /* already initialized */
	pd_entry_t *pde = (pd_entry_t *) l1pt;
	vsize_t size;
	uint32_t auxctl;

	xscale_minidata_clean_addr = va;

	/* Round it to page size. */
	size = (xscale_minidata_clean_size + L2_S_OFFSET) & L2_S_FRAME;

	for (; size != 0;
	     va += L2_S_SIZE, pa += L2_S_SIZE, size -= L2_S_SIZE) {
		const size_t l1slot = l1pte_index(va);
		pt_entry_t *ptep = (pt_entry_t *) kernel_pt_lookup(l1pte_pa(pde[l1slot]));
		if (ptep == NULL)
			panic("xscale_setup_minidata: can't find L2 table for "
			    "VA 0x%08lx", va);

		ptep += l2pte_index(va);
		pt_entry_t opte = *ptep;
		l2pte_set(ptep,
		    L2_S_PROTO | pa | L2_S_PROT(PTE_KERNEL, VM_PROT_READ)
		    | L2_C | L2_XS_T_TEX(TEX_XSCALE_X), opte);
	}

	/*
	 * Configure the mini-data cache for write-back with
	 * read/write-allocate.
	 *
	 * NOTE: In order to reconfigure the mini-data cache, we must
	 * make sure it contains no valid data!  In order to do that,
	 * we must issue a global data cache invalidate command!
	 *
	 * WE ASSUME WE ARE RUNNING UN-CACHED WHEN THIS ROUTINE IS CALLED!
	 * THIS IS VERY IMPORTANT!
	 */

	/* Invalidate data and mini-data. */
	__asm volatile("mcr p15, 0, %0, c7, c6, 0" : : "r" (0));
	auxctl = armreg_auxctl_read();
	auxctl = (auxctl & ~XSCALE_AUXCTL_MD_MASK) | XSCALE_AUXCTL_MD_WB_RWA;
	armreg_auxctl_write(auxctl);
}

/*
 * Change the PTEs for the specified kernel mappings such that they
 * will use the mini data cache instead of the main data cache.
 */
void
pmap_uarea(vaddr_t va)
{
	vaddr_t next_bucket, eva;

#if (ARM_NMMUS > 1)
	if (xscale_use_minidata == 0)
		return;
#endif

	eva = va + USPACE;

	while (va < eva) {
		next_bucket = L2_NEXT_BUCKET_VA(va);
		if (next_bucket > eva)
			next_bucket = eva;

		struct l2_bucket *l2b = pmap_get_l2_bucket(pmap_kernel(), va);
		KDASSERT(l2b != NULL);

		pt_entry_t * const sptep = &l2b->l2b_kva[l2pte_index(va)];
		pt_entry_t *ptep = sptep;

		while (va < next_bucket) {
			const pt_entry_t opte = *ptep;
			if (!l2pte_minidata_p(opte)) {
				cpu_dcache_wbinv_range(va, PAGE_SIZE);
				cpu_tlb_flushD_SE(va);
				l2pte_set(ptep, opte & ~L2_B, opte);
			}
			ptep += PAGE_SIZE / L2_S_SIZE;
			va += PAGE_SIZE;
		}
		PTE_SYNC_RANGE(sptep, (u_int)(ptep - sptep));
	}
	cpu_cpwait();
}
#endif /* ARM_MMU_XSCALE == 1 */


#if defined(CPU_ARM11MPCORE)

void
pmap_pte_init_arm11mpcore(void)
{

	/* cache mode is controlled by 5 bits (B, C, TEX) */
	pte_l1_s_cache_mask = L1_S_CACHE_MASK_armv6;
	pte_l2_l_cache_mask = L2_L_CACHE_MASK_armv6;
#if defined(ARM11MPCORE_COMPAT_MMU) || defined(ARMV6_EXTENDED_SMALL_PAGE)
	/* use extended small page (without APn, with TEX) */
	pte_l2_s_cache_mask = L2_XS_CACHE_MASK_armv6;
#else
	pte_l2_s_cache_mask = L2_S_CACHE_MASK_armv6c;
#endif

	/* write-back, write-allocate */
	pte_l1_s_cache_mode = L1_S_C | L1_S_B | L1_S_V6_TEX(0x01);
	pte_l2_l_cache_mode = L2_C | L2_B | L2_V6_L_TEX(0x01);
#if defined(ARM11MPCORE_COMPAT_MMU) || defined(ARMV6_EXTENDED_SMALL_PAGE)
	pte_l2_s_cache_mode = L2_C | L2_B | L2_V6_XS_TEX(0x01);
#else
	/* no TEX. read-allocate */
	pte_l2_s_cache_mode = L2_C | L2_B;
#endif
	/*
	 * write-back, write-allocate for page tables.
	 */
	pte_l1_s_cache_mode_pt = L1_S_C | L1_S_B | L1_S_V6_TEX(0x01);
	pte_l2_l_cache_mode_pt = L2_C | L2_B | L2_V6_L_TEX(0x01);
#if defined(ARM11MPCORE_COMPAT_MMU) || defined(ARMV6_EXTENDED_SMALL_PAGE)
	pte_l2_s_cache_mode_pt = L2_C | L2_B | L2_V6_XS_TEX(0x01);
#else
	pte_l2_s_cache_mode_pt = L2_C | L2_B;
#endif

	pte_l1_s_prot_u = L1_S_PROT_U_armv6;
	pte_l1_s_prot_w = L1_S_PROT_W_armv6;
	pte_l1_s_prot_ro = L1_S_PROT_RO_armv6;
	pte_l1_s_prot_mask = L1_S_PROT_MASK_armv6;

#if defined(ARM11MPCORE_COMPAT_MMU) || defined(ARMV6_EXTENDED_SMALL_PAGE)
	pte_l2_s_prot_u = L2_S_PROT_U_armv6n;
	pte_l2_s_prot_w = L2_S_PROT_W_armv6n;
	pte_l2_s_prot_ro = L2_S_PROT_RO_armv6n;
	pte_l2_s_prot_mask = L2_S_PROT_MASK_armv6n;

#else
	/* with AP[0..3] */
	pte_l2_s_prot_u = L2_S_PROT_U_generic;
	pte_l2_s_prot_w = L2_S_PROT_W_generic;
	pte_l2_s_prot_ro = L2_S_PROT_RO_generic;
	pte_l2_s_prot_mask = L2_S_PROT_MASK_generic;
#endif

#ifdef	ARM11MPCORE_COMPAT_MMU
	/* with AP[0..3] */
	pte_l2_l_prot_u = L2_L_PROT_U_generic;
	pte_l2_l_prot_w = L2_L_PROT_W_generic;
	pte_l2_l_prot_ro = L2_L_PROT_RO_generic;
	pte_l2_l_prot_mask = L2_L_PROT_MASK_generic;

	pte_l1_ss_proto = L1_SS_PROTO_armv6;
	pte_l1_s_proto = L1_S_PROTO_armv6;
	pte_l1_c_proto = L1_C_PROTO_armv6;
	pte_l2_s_proto = L2_S_PROTO_armv6c;
#else
	pte_l2_l_prot_u = L2_L_PROT_U_armv6n;
	pte_l2_l_prot_w = L2_L_PROT_W_armv6n;
	pte_l2_l_prot_ro = L2_L_PROT_RO_armv6n;
	pte_l2_l_prot_mask = L2_L_PROT_MASK_armv6n;

	pte_l1_ss_proto = L1_SS_PROTO_armv6;
	pte_l1_s_proto = L1_S_PROTO_armv6;
	pte_l1_c_proto = L1_C_PROTO_armv6;
	pte_l2_s_proto = L2_S_PROTO_armv6n;
#endif

	pmap_copy_page_func = pmap_copy_page_generic;
	pmap_zero_page_func = pmap_zero_page_generic;
	pmap_needs_pte_sync = 1;
}
#endif	/* CPU_ARM11MPCORE */


#if ARM_MMU_V7 == 1
void
pmap_pte_init_armv7(void)
{
	/*
	 * The ARMv7-A MMU is mostly compatible with generic. If the
	 * AP field is zero, that now means "no access" rather than
	 * read-only. The prototypes are a little different because of
	 * the XN bit.
	 */
	pmap_pte_init_generic();

	pmap_needs_pte_sync = 1;

	pte_l1_s_cache_mask = L1_S_CACHE_MASK_armv7;
	pte_l2_l_cache_mask = L2_L_CACHE_MASK_armv7;
	pte_l2_s_cache_mask = L2_S_CACHE_MASK_armv7;

	/*
	 * If the core support coherent walk then updates to translation tables
	 * do not require a clean to the point of unification to ensure
	 * visibility by subsequent translation table walks.  That means we can
	 * map everything shareable and cached and the right thing will happen.
	 */
        if (__SHIFTOUT(armreg_mmfr3_read(), __BITS(23,20))) {
		pmap_needs_pte_sync = 0;

		/*
		 * write-back, no write-allocate, shareable for normal pages.
		 */
		pte_l1_s_cache_mode |= L1_S_V6_S;
		pte_l2_l_cache_mode |= L2_XS_S;
		pte_l2_s_cache_mode |= L2_XS_S;
	}

	/*
	 * Page tables are just all other memory.  We can use write-back since
	 * pmap_needs_pte_sync is 1 (or the MMU can read out of cache).
	 */
	pte_l1_s_cache_mode_pt = pte_l1_s_cache_mode;
	pte_l2_l_cache_mode_pt = pte_l2_l_cache_mode;
	pte_l2_s_cache_mode_pt = pte_l2_s_cache_mode;

	/*
	 * Check the Memory Model Features to see if this CPU supports
	 * the TLBIASID coproc op.
	 */
	if (__SHIFTOUT(armreg_mmfr2_read(), __BITS(16,19)) >= 2) {
		arm_has_tlbiasid_p = true;
	} else if (__SHIFTOUT(armreg_mmfr2_read(), __BITS(12,15)) >= 2) {
		arm_has_tlbiasid_p = true;
	}

	pte_l1_s_prot_u = L1_S_PROT_U_armv7;
	pte_l1_s_prot_w = L1_S_PROT_W_armv7;
	pte_l1_s_prot_ro = L1_S_PROT_RO_armv7;
	pte_l1_s_prot_mask = L1_S_PROT_MASK_armv7;

	pte_l2_s_prot_u = L2_S_PROT_U_armv7;
	pte_l2_s_prot_w = L2_S_PROT_W_armv7;
	pte_l2_s_prot_ro = L2_S_PROT_RO_armv7;
	pte_l2_s_prot_mask = L2_S_PROT_MASK_armv7;

	pte_l2_l_prot_u = L2_L_PROT_U_armv7;
	pte_l2_l_prot_w = L2_L_PROT_W_armv7;
	pte_l2_l_prot_ro = L2_L_PROT_RO_armv7;
	pte_l2_l_prot_mask = L2_L_PROT_MASK_armv7;

	pte_l1_ss_proto = L1_SS_PROTO_armv7;
	pte_l1_s_proto = L1_S_PROTO_armv7;
	pte_l1_c_proto = L1_C_PROTO_armv7;
	pte_l2_s_proto = L2_S_PROTO_armv7;

}
#endif /* ARM_MMU_V7 */










#ifndef ARM_MMU_EXTENDED

#ifdef PMAP_STEAL_MEMORY
really? can probably be deleted
void
pmap_boot_pageadd(pv_addr_t *newpv)
{
	pv_addr_t *pv, *npv;

	if ((pv = SLIST_FIRST(&pmap_boot_freeq)) != NULL) {
		if (newpv->pv_pa < pv->pv_va) {
			KASSERT(newpv->pv_pa + newpv->pv_size <= pv->pv_pa);
			if (newpv->pv_pa + newpv->pv_size == pv->pv_pa) {
				newpv->pv_size += pv->pv_size;
				SLIST_REMOVE_HEAD(&pmap_boot_freeq, pv_list);
			}
			pv = NULL;
		} else {
			for (; (npv = SLIST_NEXT(pv, pv_list)) != NULL;
			     pv = npv) {
				KASSERT(pv->pv_pa + pv->pv_size < npv->pv_pa);
				KASSERT(pv->pv_pa < newpv->pv_pa);
				if (newpv->pv_pa > npv->pv_pa)
					continue;
				if (pv->pv_pa + pv->pv_size == newpv->pv_pa) {
					pv->pv_size += newpv->pv_size;
					return;
				}
				if (newpv->pv_pa + newpv->pv_size < npv->pv_pa)
					break;
				newpv->pv_size += npv->pv_size;
				SLIST_INSERT_AFTER(pv, newpv, pv_list);
				SLIST_REMOVE_AFTER(newpv, pv_list);
				return;
			}
		}
	}

	if (pv) {
		SLIST_INSERT_AFTER(pv, newpv, pv_list);
	} else {
		SLIST_INSERT_HEAD(&pmap_boot_freeq, newpv, pv_list);
	}
}

void
pmap_boot_pagealloc(psize_t amount, psize_t mask, psize_t match,
	pv_addr_t *rpv)
{
	pv_addr_t *pv, **pvp;
	struct vm_physseg *ps;
	size_t i;

	KASSERT(amount & PGOFSET);
	KASSERT((mask & PGOFSET) == 0);
	KASSERT((match & PGOFSET) == 0);
	KASSERT(amount != 0);

	for (pvp = &SLIST_FIRST(&pmap_boot_freeq);
	     (pv = *pvp) != NULL;
	     pvp = &SLIST_NEXT(pv, pv_list)) {
		pv_addr_t *newpv;
		psize_t off;
		/*
		 * If this entry is too small to satify the request...
		 */
		KASSERT(pv->pv_size > 0);
		if (pv->pv_size < amount)
			continue;

		for (off = 0; off <= mask; off += PAGE_SIZE) {
			if (((pv->pv_pa + off) & mask) == match
			    && off + amount <= pv->pv_size)
				break;
		}
		if (off > mask)
			continue;

		rpv->pv_va = pv->pv_va + off;
		rpv->pv_pa = pv->pv_pa + off;
		rpv->pv_size = amount;
		pv->pv_size -= amount;
		if (pv->pv_size == 0) {
			KASSERT(off == 0);
			KASSERT((vaddr_t) pv == rpv->pv_va);
			*pvp = SLIST_NEXT(pv, pv_list);
		} else if (off == 0) {
			KASSERT((vaddr_t) pv == rpv->pv_va);
			newpv = (pv_addr_t *) (rpv->pv_va + amount);
			*newpv = *pv;
			newpv->pv_pa += amount;
			newpv->pv_va += amount;
			*pvp = newpv;
		} else if (off < pv->pv_size) {
			newpv = (pv_addr_t *) (rpv->pv_va + amount);
			*newpv = *pv;
			newpv->pv_size -= off;
			newpv->pv_pa += off + amount;
			newpv->pv_va += off + amount;

			SLIST_NEXT(pv, pv_list) = newpv;
			pv->pv_size = off;
		} else {
			KASSERT((vaddr_t) pv != rpv->pv_va);
		}
		memset((void *)rpv->pv_va, 0, amount);
		return;
	}

	if (vm_nphysseg == 0)
		panic("pmap_boot_pagealloc: couldn't allocate memory");

	for (pvp = &SLIST_FIRST(&pmap_boot_freeq);
	     (pv = *pvp) != NULL;
	     pvp = &SLIST_NEXT(pv, pv_list)) {
		if (SLIST_NEXT(pv, pv_list) == NULL)
			break;
	}
	KASSERT(mask == 0);
	for (i = 0; i < vm_nphysseg; i++) {
		ps = VM_PHYSMEM_PTR(i);
		if (ps->avail_start == atop(pv->pv_pa + pv->pv_size)
		    && pv->pv_va + pv->pv_size <= ptoa(ps->avail_end)) {
			rpv->pv_va = pv->pv_va;
			rpv->pv_pa = pv->pv_pa;
			rpv->pv_size = amount;
			*pvp = NULL;
			pmap_map_chunk(kernel_l1pt.pv_va,
			     ptoa(ps->avail_start) + (pv->pv_va - pv->pv_pa),
			     ptoa(ps->avail_start),
			     amount - pv->pv_size,
			     VM_PROT_READ|VM_PROT_WRITE,
			     PTE_CACHE);
			ps->avail_start += atop(amount - pv->pv_size);
			/*
			 * If we consumed the entire physseg, remove it.
			 */
			if (ps->avail_start == ps->avail_end) {
				for (--vm_nphysseg; i < vm_nphysseg; i++)
					VM_PHYSMEM_PTR_SWAP(i, i + 1);
			}
			memset((void *)rpv->pv_va, 0, rpv->pv_size);
			return;
		}
	}

	panic("pmap_boot_pagealloc: couldn't allocate memory");
}

vaddr_t
pmap_steal_memory(vsize_t size, vaddr_t *vstartp, vaddr_t *vendp)
{
	pv_addr_t pv;

	pmap_boot_pagealloc(size, 0, 0, &pv);

	return pv.pv_va;
}
#endif /* PMAP_STEAL_MEMORY */
#endif










#if 0

SYSCTL_SETUP(sysctl_machdep_pmap_setup, "sysctl machdep.kmpages setup")
{
	sysctl_createv(clog, 0, NULL, NULL,
			CTLFLAG_PERMANENT,
			CTLTYPE_NODE, "machdep", NULL,
			NULL, 0, NULL, 0,
			CTL_MACHDEP, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
			CTLFLAG_PERMANENT,
			CTLTYPE_INT, "kmpages",
			SYSCTL_DESCR("count of pages allocated to kernel memory allocators"),
			NULL, 0, &pmap_kmpages, 0,
			CTL_MACHDEP, CTL_CREATE, CTL_EOL);
}

#endif




#ifdef PMAP_NEED_ALLOC_POOLPAGE
struct vm_page *
pmap_md_alloc_poolpage(int flags)
{
	/*
	 * On some systems, only some pages may be "coherent" for dma and we
	 * want to prefer those for pool pages (think mbufs) but fallback to
	 * any page if none is available.  But we can only fallback if we
	 * aren't direct mapping memory or all of memory can be direct-mapped.
	 * If that isn't true, pool changes can only come from direct-mapped
	 * memory.
	 */
	if (arm_poolpage_vmfreelist != VM_FREELIST_DEFAULT) {
		return uvm_pagealloc_strat(NULL, 0, NULL, flags,
		    UVM_PGA_STRAT_FALLBACK,
		    arm_poolpage_vmfreelist);
	}

	return uvm_pagealloc(NULL, 0, NULL, flags);
}
#endif

#if defined(ARM_MMU_EXTENDED) && defined(MULTIPROCESSOR)
void
pmap_md_tlb_info_attach(struct pmap_tlb_info *ti, struct cpu_info *ci)
{
        /* nothing */
}

int
pic_ipi_shootdown(void *arg)
{
#if PMAP_TLB_NEED_SHOOTDOWN
	pmap_tlb_shootdown_process();
#endif
	return 1;
}
#endif /* ARM_MMU_EXTENDED && MULTIPROCESSOR */


#ifdef __HAVE_MM_MD_DIRECT_MAPPED_PHYS
vaddr_t
pmap_direct_mapped_phys(paddr_t pa, bool *ok_p, vaddr_t va)
{
	bool ok = false;
	if (physical_start <= pa && pa < physical_end) {
#ifdef KERNEL_BASE_VOFFSET
		const vaddr_t newva = pa + KERNEL_BASE_VOFFSET;
#else
		const vaddr_t newva = KERNEL_BASE + pa - physical_start;
#endif
#ifdef ARM_MMU_EXTENDED
		if (newva >= KERNEL_BASE && newva < pmap_directlimit) {
#endif
			va = newva;
			ok = true;
#ifdef ARM_MMU_EXTENDED
		}
#endif
	}
	KASSERT(ok_p);
	*ok_p = ok;
	return va;
}

#endif /* __HAVE_MM_MD_DIRECT_MAPPED_PHYS */
