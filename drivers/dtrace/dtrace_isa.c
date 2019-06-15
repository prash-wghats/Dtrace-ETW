/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * $FreeBSD: release/10.0.0/sys/cddl/dev/dtrace/i386/dtrace_isa.c 211608 2010-08-22 10:53:32Z rpaulo $
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/dtrace_misc.h>
#include <sys/dtrace_win32.h>
#include <sys/dtrace_impl.h>
#include <strsafe.h>
#include <stddef.h>
#include <sys/regset.h>
#include "dtrace_private.h"
#include "etw.h"

uintptr_t
dtrace_getreg(void *regs, uint_t reg)
{
	struct reg *rp = (struct reg *)regs;
#if defined(__amd64)
	int regmap[] = {
		REG_GS,		/* GS */
		REG_FS,		/* FS */
		REG_ES,		/* ES */
		REG_DS,		/* DS */
		REG_RDI,	/* EDI */
		REG_RSI,	/* ESI */
		REG_RBP,	/* EBP */
		REG_RSP,	/* ESP */
		REG_RBX,	/* EBX */
		REG_RDX,	/* EDX */
		REG_RCX,	/* ECX */
		REG_RAX,	/* EAX */
		REG_TRAPNO,	/* TRAPNO */
		REG_ERR,	/* ERR */
		REG_RIP,	/* EIP */
		REG_CS,		/* CS */
		REG_RFL,	/* EFL */
		REG_RSP,	/* UESP */
		REG_SS		/* SS */
	};

	if (reg <= SS) {
		if (reg >= sizeof (regmap) / sizeof (int)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return (0);
		}

		reg = regmap[reg];
	} else {
		reg -= SS + 1;
	}

	switch (reg) {
	case REG_RDI:
		return (rp->r_rdi);
	case REG_RSI:
		return (rp->r_rsi);
	case REG_RDX:
		return (rp->r_rdx);
	case REG_RCX:
		return (rp->r_rcx);
	case REG_R8:
		return (rp->r_r8);
	case REG_R9:
		return (rp->r_r9);
	case REG_RAX:
		return (rp->r_rax);
	case REG_RBX:
		return (rp->r_rbx);
	case REG_RBP:
		return (rp->r_rbp);
	case REG_R10:
		return (rp->r_r10);
	case REG_R11:
		return (rp->r_r11);
	case REG_R12:
		return (rp->r_r12);
	case REG_R13:
		return (rp->r_r13);
	case REG_R14:
		return (rp->r_r14);
	case REG_R15:
		return (rp->r_r15);
	case REG_DS:
		return (rp->r_ds);
	case REG_ES:
		return (rp->r_es);
	case REG_FS:
		return (rp->r_fs);
	case REG_GS:
		return (rp->r_gs);
	case REG_TRAPNO:
		return (rp->r_trapno);
	case REG_ERR:
		return (rp->r_err);
	case REG_RIP:
		return (rp->r_rip);
	case REG_CS:
		return (rp->r_cs);
	case REG_SS:
		return (rp->r_ss);
	case REG_RFL:
		return (rp->r_rflags);
	case REG_RSP:
		return (rp->r_rsp);
	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return (0);
	}

#else
	if (reg > SS) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return (0);
	}

	return ((&rp->r_gs)[reg]);
#endif
}

void
dtrace_getpcstack(pc_t *pcstack, int pcstack_limit, int aframes, uint32_t *intrpc)
{
	int depth = 0;
	uintptr_t ebp;
	struct frame *frame;
	uintptr_t callpc;
	pc_t caller = (pc_t) CPU[curcpu].cpu_dtrace_caller;
	CONTEXT Context;

	if ((depth = dtrace_etw_get_stack(pcstack, pcstack_limit, 0)) > 0) {
		goto zerok;
	}
	
	zerok:
	for (; depth < pcstack_limit; depth++) {
		pcstack[depth] = 0;
	}
}

static int
dtrace_getustack_common(uint64_t *pcstack, int pcstack_limit, uintptr_t pc,
    uintptr_t sp)
{
#ifdef notyet
	proc_t *p = curproc;
	uintptr_t oldcontext = lwp->lwp_oldcontext; /* XXX signal stack. */
	size_t s1, s2;
#endif
	volatile uint16_t *flags =
	    (volatile uint16_t *)&cpu_core[curcpu].cpuc_dtrace_flags;
	int ret = 0;

	ASSERT(pcstack == NULL || pcstack_limit > 0);

#ifdef notyet /* XXX signal stack. */
	if (p->p_model == DATAMODEL_NATIVE) {
		s1 = sizeof (struct frame) + 2 * sizeof (long);
		s2 = s1 + sizeof (siginfo_t);
	} else {
		s1 = sizeof (struct frame32) + 3 * sizeof (int);
		s2 = s1 + sizeof (siginfo32_t);
	}
#endif

	while (pc != 0) {
		ret++;
		if (pcstack != NULL) {
			*pcstack++ = (uint64_t)pc;
			pcstack_limit--;
			if (pcstack_limit <= 0)
				break;
		}
		if (sp == 0)
			break;

#if defined(sun) 	 /* XXX signal stack. */
		if (oldcontext == sp + s1 || oldcontext == sp + s2) {
			if (p->p_model == DATAMODEL_NATIVE) {
				ucontext_t *ucp = (ucontext_t *)oldcontext;
				greg_t *gregs = ucp->uc_mcontext.gregs;

				sp = dtrace_fulword(&gregs[REG_FP]);
				pc = dtrace_fulword(&gregs[REG_PC]);

				oldcontext = dtrace_fulword(&ucp->uc_link);
			} else {
				ucontext32_t *ucp = (ucontext32_t *)oldcontext;
				greg32_t *gregs = ucp->uc_mcontext.gregs;

				sp = dtrace_fuword32(&gregs[EBP]);
				pc = dtrace_fuword32(&gregs[EIP]);

				oldcontext = dtrace_fuword32(&ucp->uc_link);
			}
		} else {
			if (p->p_model == DATAMODEL_NATIVE) {
				struct frame *fr = (struct frame *)sp;

				pc = dtrace_fulword(&fr->fr_savpc);
				sp = dtrace_fulword(&fr->fr_savfp);
			} else {
				struct frame32 *fr = (struct frame32 *)sp;

				pc = dtrace_fuword32(&fr->fr_savpc);
				sp = dtrace_fuword32(&fr->fr_savfp);
			}
		}
#else
		pc = dtrace_fuword32((void *)(sp + 4));
		sp = dtrace_fuword32((void *)sp);

#endif
		/*
		 * This is totally bogus:  if we faulted, we're going to clear
		 * the fault and break.  This is to deal with the apparently
		 * broken Java stacks on x86.
		 */
		if (*flags & CPU_DTRACE_FAULT) {
			*flags &= ~CPU_DTRACE_FAULT;
			break;
		}
	}
	return (ret);
}

#ifdef __i386__
#define	r_rax	r_eax
#define	r_rbx	r_ebx
#define	r_rip	r_eip
#define	r_rflags r_eflags
#define	r_rsp	r_esp
#define r_rbp   r_ebp
#endif

void
dtrace_getupcstack(uint64_t *pcstack, int pcstack_limit)
{
	proc_t *p = curproc;
	thread_t *td = curthread;
	struct reg *tf;
	uintptr_t pc, sp, fp, stack[25];
	volatile uint16_t *flags =
	    (volatile uint16_t *)&cpu_core[curcpu].cpuc_dtrace_flags;
	int n = 0;
	CONTEXT ct;

	if (*flags & CPU_DTRACE_FAULT)
		return;

	if (pcstack_limit <= 0)
		return;

	if ((n = dtrace_etw_get_stack(pcstack+1, --pcstack_limit, 1)) > 0) {
		*pcstack++ = (uint64_t)p->pid;
		pcstack_limit -= n;
		pcstack += n;
		goto zero;
	}
	
	/*
	 * If there's no user context we still need to zero the stack.
	 */
	if (p == NULL || (tf = td->tf) == NULL)
		goto zero;

	*pcstack++ = (uint64_t)p->pid;
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

#ifdef __amd64
	if (p->model == DATAMODEL_NATIVE && td->context) {
		winos_reg_to_context(&ct, tf);
		n = winos_unwind_user_stack(td, td->context, pcstack_limit, (uintptr_t) pcstack);
		pcstack = &pcstack[n];
		pcstack_limit -= n;
	} else {
#endif // i386
		pc = tf->r_rip;
		fp = tf->r_rbp;
		sp = tf->r_rsp;

		if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
			/*
			 * In an entry probe.  The frame pointer has not yet been
			 * pushed (that happens in the function prologue).  The
			 * best approach is to add the current pc as a missing top
			 * of stack and back the pc up to the caller, which is stored
			 * at the current stack pointer address since the call
			 * instruction puts it there right before the branch.
			 */

			*pcstack++ = (uint64_t)pc;
			pcstack_limit--;
			if (pcstack_limit <= 0)
				return;

			pc = dtrace_fuword32((void *) sp);
		}

		n = dtrace_getustack_common(pcstack, pcstack_limit, pc, fp);
		ASSERT(n >= 0);
		ASSERT(n <= pcstack_limit);

		pcstack += n;
		pcstack_limit -= n;

#ifdef __amd64
	}
#endif

	zero:
	while (pcstack_limit-- > 0)
		*pcstack++ = 0;
}

int
dtrace_getustackdepth(void)
{
	proc_t *p = curproc;
	struct reg *tf;
	uintptr_t pc, fp, sp;
	int n = 0;
	uint64_t pcstack[100];
	int pcstack_limit = 100;

	if ((n=dtrace_etw_get_stack(pcstack, pcstack_limit, 1)) > 0) {
		return n;
	}

	if (p == NULL || (tf = curthread->tf) == NULL)
		return (0);

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT))
		return (-1);

#ifdef __amd64
	if (p->model == DATAMODEL_NATIVE) {
		CONTEXT ct;

		winos_reg_to_context(&ct, tf);
		n += winos_unwind_user_stack(curthread, &ct, pcstack_limit, (uintptr_t) pcstack);
	} else {
#endif // i386
		pc = tf->r_rip;
		fp = tf->r_rbp;
		sp = tf->r_rsp;

		if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
			/*
			 * In an entry probe.  The frame pointer has not yet been
			 * pushed (that happens in the function prologue).  The
			 * best approach is to add the current pc as a missing top
			 * of stack and back the pc up to the caller, which is stored
			 * at the current stack pointer address since the call
			 * instruction puts it there right before the branch.
			 */

			pc = dtrace_fuword32((void *) sp);
			n++;
		}

		n += dtrace_getustack_common(NULL, 0, pc, fp);
#ifdef __amd64
	}
#endif
	return (n);
}


void
dtrace_getufpstack(uint64_t *pcstack, uint64_t *fpstack, int pcstack_limit)
{
	proc_t *p = curproc;
	thread_t *td = curthread;

	struct reg *tf;
	uintptr_t pc, sp, fp;

	volatile uint16_t *flags =
	    (volatile uint16_t *)&cpu_core[curcpu].cpuc_dtrace_flags;
	int n = 0;
	CONTEXT ct;

	if (*flags & CPU_DTRACE_FAULT)
		return;

	if (pcstack_limit <= 0)
		return;

	/*
	 * If there's no user context we still need to zero the stack.
	 */
	if (p == NULL || (tf = td->tf) == NULL)
		goto zero;

	*pcstack++ = (uint64_t)p->pid;
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

#ifdef __amd64
	if (p->model == DATAMODEL_NATIVE) {
		winos_reg_to_context(&ct, tf);
		n = winos_unwind_user_stack(td, &ct, pcstack_limit, (uintptr_t) pcstack);
		pcstack = &pcstack[n];
		pcstack_limit -= n;
	} else {
#endif // i386
		pc = tf->r_rip;
		fp = tf->r_rbp;
		sp = tf->r_rsp;

#ifdef notyet /* XXX signal stack */
		oldcontext = lwp->lwp_oldcontext;

		if (p->p_model == DATAMODEL_NATIVE) {
			s1 = sizeof (struct frame) + 2 * sizeof (long);
			s2 = s1 + sizeof (siginfo_t);
		} else {
			s1 = sizeof (struct frame32) + 3 * sizeof (int);
			s2 = s1 + sizeof (siginfo32_t);
		}
#endif

		if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
			*pcstack++ = (uint64_t)pc;
			*fpstack++ = 0;
			pcstack_limit--;
			if (pcstack_limit <= 0)
				return;

			pc = dtrace_fuword32((void *)sp);
		}

		while (pc != 0) {
			*pcstack++ = (uint64_t)pc;
			*fpstack++ = fp;
			pcstack_limit--;
			if (pcstack_limit <= 0)
				break;

			if (fp == 0)
				break;

#ifdef notyet /* XXX signal stack */
			if (oldcontext == sp + s1 || oldcontext == sp + s2) {
				if (p->p_model == DATAMODEL_NATIVE) {
					ucontext_t *ucp = (ucontext_t *)oldcontext;
					greg_t *gregs = ucp->uc_mcontext.gregs;

					sp = dtrace_fulword(&gregs[REG_FP]);
					pc = dtrace_fulword(&gregs[REG_PC]);

					oldcontext = dtrace_fulword(&ucp->uc_link);
				} else {
					ucontext_t *ucp = (ucontext_t *)oldcontext;
					greg_t *gregs = ucp->uc_mcontext.gregs;

					sp = dtrace_fuword32(&gregs[EBP]);
					pc = dtrace_fuword32(&gregs[EIP]);

					oldcontext = dtrace_fuword32(&ucp->uc_link);
				}
			} else
#endif /* XXX */
			{
				pc = dtrace_fuword32((void *)(fp + 4));
				fp = dtrace_fuword32((void *)fp);
			}

			/*
			 * This is totally bogus:  if we faulted, we're going to clear
			 * the fault and break.  This is to deal with the apparently
			 * broken Java stacks on x86.
			 */
			if (*flags & CPU_DTRACE_FAULT) {
				*flags &= ~CPU_DTRACE_FAULT;
				break;
			}
		}
#ifdef __amd64
	}
#endif

	zero:
	while (pcstack_limit-- > 0)
		*pcstack++ = 0;
	return;
}

int
dtrace_getstackdepth(int aframes)
{
	int depth = 0;
	struct frame *frame;
	uintptr_t ebp;
	uintptr_t callpc;
	thread_t *td = curthread;
#if defined(windows)
	int pcstack_limit = 100;
	uint64_t pcstack[100];
#endif

	if ((depth=dtrace_etw_get_stack(pcstack, pcstack_limit, 0)) > 0) {
		return depth;
	}
	ebp = td->ebp;
	frame = (struct frame *)ebp;
	depth++;

#ifdef __amd64
	depth += RtlCaptureStackBackTrace(0, pcstack_limit, (PVOID) pcstack, NULL);
#else
	for(;;) {
		if ((uintptr_t)frame < td->klimit ||
		    (uintptr_t) ((char *) frame - sizeof(struct frame)) >= td->kbase)
				break;
		depth++;
		callpc = frame->f_retaddr;

		if (!INKERNEL(callpc))
			break;

		frame = frame->f_frame;
	}
#endif
	if (depth < aframes)
		return 0;
	else
		return depth - aframes;
}

uint64_t
dtrace_getarg(int arg, int aframes)
{
	UNREFERENCED_PARAMETER(arg);
	UNREFERENCED_PARAMETER(aframes);
	return 0;
}

static int
dtrace_copycheck(uintptr_t uaddr, uintptr_t kaddr, size_t size)
{
	return (1);
}

void
dtrace_copyin(uintptr_t uaddr, uintptr_t kaddr, size_t size, volatile uint16_t *flags)
{
	if (pcopyin(uaddr, kaddr, size)) {
		*flags |= CPU_DTRACE_FAULT;
	}
}


void
dtrace_copyinstr(uintptr_t uaddr, uintptr_t kaddr, size_t size,
    volatile uint16_t *flags)
{
	if (pcopyin(uaddr, kaddr, size)) {
		*flags |= CPU_DTRACE_FAULT;
	}
}


void
dtrace_copyoutstr(uintptr_t kaddr, uintptr_t uaddr, size_t size, volatile uint16_t *flags)
{
	int len = strlen(kaddr)+1;

	if (len > size || pcopyout(kaddr, uaddr, len)) {
		*flags |= CPU_DTRACE_FAULT;
	}
}

void
dtrace_copyout(uintptr_t kaddr, uintptr_t uaddr, size_t size,
    volatile uint16_t *flags)
{
	if (pcopyout(kaddr, uaddr, size)) {
		*flags |= CPU_DTRACE_FAULT;
	}
}

uint8_t
dtrace_fuword8(void *uaddr)
{
	return (dtrace_fuword8_nocheck(uaddr));
}

uint16_t
dtrace_fuword16(void *uaddr)
{
	return (dtrace_fuword16_nocheck(uaddr));
}


uint32_t
dtrace_fuword32(void *uaddr)
{
	return (dtrace_fuword32_nocheck(uaddr));
}

uintptr_t
dtrace_fulword(void *addr)
{
	uintptr_t ret;

	RtlCopyMemory(&ret, addr, sizeof(uintptr_t));
	return ret;
}

uint64_t
dtrace_fuword64(void *uaddr)
{
	return (dtrace_fuword64_nocheck(uaddr));
}
