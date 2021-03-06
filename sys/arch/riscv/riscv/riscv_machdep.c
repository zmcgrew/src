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

#include <sys/cdefs.h>

#include "opt_modular.h"

__RCSID("$NetBSD: riscv_machdep.c,v 1.2 2017/03/16 16:13:21 chs Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cpu.h>
#include <sys/exec.h>
#include <sys/lwp.h>
#include <sys/sysctl.h>
#include <sys/kmem.h>
#include <sys/ktrace.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/reboot.h>
#include <sys/syscall.h>

#include <uvm/uvm_extern.h>

#include <riscv/locore.h>
#include <riscv/pte.h>
#include <riscv/umprintf.h>

int cpu_printfataltraps;
char machine[] = MACHINE;
char machine_arch[] = MACHINE_ARCH;

struct vm_map *phys_map;

struct trapframe cpu_ddb_regs;

struct cpu_info cpu_info_store = {
	.ci_cpl = IPL_HIGH,
	.ci_ddb_regs = &cpu_ddb_regs,
};

const pcu_ops_t * const pcu_ops_md_defs[PCU_UNIT_COUNT] = {
	[PCU_FPU] = &pcu_fpu_ops,
};

/* Used by PHYSTOV and VTOPHYS -- Will be set be BSS is zeroed so
 * keep it in data */
__uint64_t kern_vtopdiff __attribute__((__section__(".data")));

/* XXX Find a better way */
__uint64_t kern_vstart __attribute__((__section__(".data")));

SYSCTL_SETUP(sysctl_machdep_setup, "sysctl machdep subtree setup")
{
	sysctl_createv(clog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "machdep", NULL,
	    NULL, 0, NULL, 0,
	    CTL_MACHDEP, CTL_EOL);
}

void
delay(unsigned long us)
{
	const uint32_t cycles_per_us = curcpu()->ci_data.cpu_cc_freq / 1000000;
	const uint64_t cycles = (uint64_t)us * cycles_per_us;
	const uint64_t finish = riscvreg_cycle_read() + cycles;

	while (riscvreg_cycle_read() < finish) {
		/* spin, baby spin */
	}
}

#ifdef MODULAR
/*
 * Push any modules loaded by the boot loader.
 */
void
module_init_md(void)
{
}
#endif /* MODULAR */

/*
 * Set registers on exec.
 * Clear all registers except sp, pc, and t9.
 * $sp is set to the stack pointer passed in.  $pc is set to the entry
 * point given by the exec_package passed in, as is $t9 (used for PIC
 * code by the MIPS elf abi).
 */
void
setregs(struct lwp *l, struct exec_package *pack, vaddr_t stack)
{
	struct trapframe * const tf = l->l_md.md_utf;
	struct proc * const p = l->l_proc;

	memset(tf, 0, sizeof(struct trapframe));
	tf->tf_sp = (intptr_t)stack_align(stack);
	tf->tf_pc = (intptr_t)pack->ep_entry & ~1;
	tf->tf_sr = SR_USER;
	// Set up arguments for _start(obj, cleanup, ps_strings)
	tf->tf_a0 = 0;			// obj
	tf->tf_a1 = 0;			// cleanup
	tf->tf_a2 = p->p_psstrp;	// ps_strings
}

void
child_return(void *arg)
{
	struct lwp * const l = arg;
	struct trapframe * const tf = l->l_md.md_utf;

	tf->tf_a0 = 0;
	tf->tf_a1 = 1;
	/* tf->tf_sr &= ~SR_EF;		/\* Disable FP as we can't be them. *\/ */
	ktrsysret(SYS_fork, 0, 0);
}

void
cpu_spawn_return(struct lwp *l)
{
	userret(l);
}

/*
 * Start a new LWP
 */
void
startlwp(void *arg)
{
	ucontext_t * const uc = arg;
	lwp_t * const l = curlwp;
	int error __diagused;

	error = cpu_setmcontext(l, &uc->uc_mcontext, uc->uc_flags);
	KASSERT(error == 0);

	kmem_free(uc, sizeof(ucontext_t));
	userret(l);
}

// We've worked hard to make sure struct reg and __gregset_t are the same.
// Ditto for struct fpreg and fregset_t.

CTASSERT(sizeof(struct reg) == sizeof(__gregset_t));
CTASSERT(sizeof(struct fpreg) == sizeof(__fregset_t));

void
cpu_getmcontext(struct lwp *l, mcontext_t *mcp, unsigned int *flags)
{
	const struct trapframe * const tf = l->l_md.md_utf;

	/* Save register context. */
	*(struct reg *)mcp->__gregs = tf->tf_regs;

	mcp->__private = (intptr_t)l->l_private;

	*flags |= _UC_CPU | _UC_TLSBASE;

	/* Save floating point register context, if any. */
	KASSERT(l == curlwp);
	if (fpu_valid_p(l)) {
		/*
		 * If this process is the current FP owner, dump its
		 * context to the PCB first.
		 */
		fpu_save(l);

		struct pcb * const pcb = lwp_getpcb(l);
		*(struct fpreg *)mcp->__fregs = pcb->pcb_fpregs;
		*flags |= _UC_FPU;
	}
}

int
cpu_mcontext_validate(struct lwp *l, const mcontext_t *mcp)
{
	/*
	 * Verify that at least the PC and SP are user addresses.
	 */
	if ((intptr_t) mcp->__gregs[_REG_PC] < 0
	    || (intptr_t) mcp->__gregs[_REG_SP] < 0
	    || (mcp->__gregs[_REG_PC] & 1))
		return EINVAL;

	return 0;
}

int
cpu_setmcontext(struct lwp *l, const mcontext_t *mcp, unsigned int flags)
{
	struct trapframe * const tf = l->l_md.md_utf;
	struct proc * const p = l->l_proc;
	const __greg_t * const gr = mcp->__gregs;
	int error;

	/* Restore register context, if any. */
	if (flags & _UC_CPU) {
		error = cpu_mcontext_validate(l, mcp);
		if (error)
			return error;

		/* Save register context. */
		tf->tf_regs = *(const struct reg *)gr;
	}

	/* Restore the private thread context */
	if (flags & _UC_TLSBASE) {
		lwp_setprivate(l, (void *)(intptr_t)mcp->__private);
	}

	/* Restore floating point register context, if any. */
	if (flags & _UC_FPU) {
		KASSERT(l == curlwp);
		/* Tell PCU we are replacing the FPU contents. */
		fpu_replace(l);

		/*
		 * The PCB FP regs struct includes the FP CSR, so use the
		 * proper size of fpreg when copying.
		 */
		struct pcb * const pcb = lwp_getpcb(l);
		pcb->pcb_fpregs = *(const struct fpreg *)mcp->__fregs;
	}

	mutex_enter(p->p_lock);
	if (flags & _UC_SETSTACK)
		l->l_sigstk.ss_flags |= SS_ONSTACK;
	if (flags & _UC_CLRSTACK)
		l->l_sigstk.ss_flags &= ~SS_ONSTACK;
	mutex_exit(p->p_lock);

	return (0);
}

void
cpu_need_resched(struct cpu_info *ci, int flags)
{
	struct lwp * const l = ci->ci_data.cpu_onproc;
#ifdef MULTIPROCESSOR
	struct cpu_info * const cur_ci = curcpu();
#endif

	KASSERT(kpreempt_disabled());

	ci->ci_want_resched |= flags;

	if (__predict_false((l->l_pflag & LP_INTR) != 0)) {
		/*
		 * No point doing anything, it will switch soon.
		 * Also here to prevent an assertion failure in
		 * kpreempt() due to preemption being set on a
		 * soft interrupt LWP.
		 */
		return;
	}

	if (__predict_false(l == ci->ci_data.cpu_idlelwp)) {
#ifdef MULTIPROCESSOR
		/*
		 * If the other CPU is idling, it must be waiting for an
		 * interrupt.  So give it one.
		 */
		if (__predict_false(ci != cur_ci))
			cpu_send_ipi(ci, IPI_NOP);
#endif
		return;
	}

#ifdef MULTIPROCESSOR
	atomic_or_uint(&ci->ci_want_resched, flags);
#else
	ci->ci_want_resched |= flags;
#endif

	if (flags & RESCHED_KPREEMPT) {
#ifdef __HAVE_PREEMPTION
		atomic_or_uint(&l->l_dopreempt, DOPREEMPT_ACTIVE);
		if (ci == cur_ci) {
			softint_trigger(SOFTINT_KPREEMPT);
                } else {
                        cpu_send_ipi(ci, IPI_KPREEMPT);
                }
#endif
		return;
	}
	l->l_md.md_astpending = 1;		/* force call to ast() */
#ifdef MULTIPROCESSOR
	if (ci != cur_ci && (flags & RESCHED_IMMED)) {
		cpu_send_ipi(ci, IPI_AST);
	}
#endif
}

void
cpu_signotify(struct lwp *l)
{
	KASSERT(kpreempt_disabled());
#ifdef __HAVE_FAST_SOFTINTS
	KASSERT(lwp_locked(l, NULL));
#endif
	KASSERT(l->l_stat == LSONPROC || l->l_stat == LSRUN || l->l_stat == LSSTOP);

	l->l_md.md_astpending = 1; 		/* force call to ast() */
}

void
cpu_need_proftick(struct lwp *l)
{
	KASSERT(kpreempt_disabled());
	KASSERT(l->l_cpu == curcpu());

	l->l_pflag |= LP_OWEUPC;
	l->l_md.md_astpending = 1;		/* force call to ast() */
}

void
cpu_set_curpri(int pri)
{
	kpreempt_disable();
	curcpu()->ci_schedstate.spc_curpriority = pri;
	kpreempt_enable();
}

void
cpu_reboot(int how, char *bootstr)
{
	for (;;) {
	}
}

void
cpu_dumpconf(void)
{
	// TBD!!
}

void
cpu_startup(void)
{
	vaddr_t minaddr, maxaddr;
	char pbuf[10];	/* "999999 MB" -- But Sv39 is max 512GB */


	/*
	 * Good {morning,afternoon,evening,night}.
	 */
	printf("%s%s", copyright, version);
	format_bytes(pbuf, sizeof(pbuf), ctob(physmem));
	printf("total memory = %s\n", pbuf);

	minaddr = 0;
	/*
	 * Allocate a submap for physio.
	 */
	phys_map = uvm_km_suballoc(kernel_map, &minaddr, &maxaddr,
	    VM_PHYS_SIZE, 0, FALSE, NULL);

	format_bytes(pbuf, sizeof(pbuf), ptoa(uvmexp.free));
	printf("avail memory = %s\n", pbuf);
}

paddr_t
init_mmu(paddr_t dtb, paddr_t end)
{
	extern paddr_t virt_map;
	virt_map = (paddr_t)virt_map - (paddr_t)&virt_map;
	extern __uint64_t l1_pte[512];
	extern __uint64_t l2_pte[512];
	extern __uint64_t l2_dtb[512];
	__uint64_t phys_base = VM_MIN_KERNEL_ADDRESS - virt_map;
	__uint64_t phys_base_2mb_chunk = phys_base >> 21;
	__uint64_t l2_perms = PTE_V | PTE_D | PTE_A | PTE_R | PTE_W | PTE_X;
	__uint64_t i = l1pde_index(VM_MIN_KERNEL_ADDRESS);
	

	end = (end + 0x200000 - 1) & -0x200000;

	/* Global used later for VTOPHYS and PHYSTOV */
	kern_vtopdiff = VM_MAX_KERNEL_ADDRESS - 0x80000000ULL;
	kern_vstart = VM_MIN_KERNEL_ADDRESS - phys_base + end + 0x200000;

	/* L1 PTE with entry for Kernel VA, pointing to L2 PTE */
	l1_pte[i] = (((paddr_t)&l2_pte >> PAGE_SHIFT) << PTE_PPN0_S) | PTE_V;

	/* Map all of memory into the last gig */
	/* XXX THIS IS SUPER, SUPER WRONG. */
	l1_pte[l1pde_index(VM_MAX_KERNEL_ADDRESS)] = ((0x80000000ULL >> PAGE_SHIFT) << PTE_PPN0_S) | l2_perms;

	/* L1 PTE with entry for Kernel PA, pointing to L2 PTE */
	/* i = ((paddr_t)&start >> L1_SHIFT) & Ln_ADDR_MASK; */
	/* l1_pte[i] = (((paddr_t)&l2_pte >> PAGE_SHIFT) << PTE_PPN0_S) | PTE_V; */

	/* XXX: This is the same index as the Kernel PA */

	/* L1 PTE with entry for L2_DTB */
	/* i = ((paddr_t)&l2_dtb >> L1_SHIFT) & Ln_ADDR_MASK; */
	/* umprintf("i = %d\n", i); */
	/* l1_pte[i] = (((paddr_t)&l2_dtb >> PAGE_SHIFT) << PTE_PPN0_S) | PTE_V; */
	/* umprintf("l1_pte[%d]: 0x%x\n", i, l1_pte[i]); */

	/* Build the L2 Page Table we just pointed to */
	for (i = 0; ((phys_base_2mb_chunk + i) << 21) < end; ++i) {
		l2_pte[i] = ((phys_base_2mb_chunk + i) << PTE_PPN1_S)
		    | l2_perms;
	}

	/* umprintf("DTB: 0x%x\n", dtb); */

	/* Put the DTB in the L2_DTB table */
	/* i = ((paddr_t)dtb >> L1_SHIFT) & Ln_ADDR_MASK; */
	/* l2_dtb[i] = (dtb << PTE_PPN0_S) | PTE_V | PTE_A | PTE_R; */

	return phys_base;
}

void
riscv_init_lwp0_uarea(void)
{
	extern char lwp0uspace[];

	uvm_lwp_setuarea(&lwp0, (vaddr_t)lwp0uspace);
	memset(&lwp0.l_md, 0, sizeof(lwp0.l_md));
	memset(lwp_getpcb(&lwp0), 0, sizeof(struct pcb));

	struct trapframe *tf = (struct trapframe *)(lwp0uspace + USPACE) - 1;
	memset(tf, 0, sizeof(struct trapframe));
	/* tf->tf_spsr = SPSR_M_EL0T; */
	lwp0.l_md.md_utf = lwp0.l_md.md_ktf = tf;
}

void
init_riscv(register_t hartid, paddr_t dtb, paddr_t kernstart, paddr_t kernend)
{
	/* Main screen turn on */
	consinit();

	/* SPAM me while testing */
	boothowto |= AB_DEBUG;

	/* Just pretend we have a gig of ram until FDT is implemented */
	pmap_bootstrap(0x80000000ULL, 0xc0000000ULL, kern_vstart, kernend);

	/* Finish setting up lwp0 on our end before we call main() */
	riscv_init_lwp0_uarea();

}
