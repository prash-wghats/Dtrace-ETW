/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 */

#include <sys/dtrace_misc.h>
#include <sys/fasttrap_impl.h>
#include "etw.h"
#include "fasttrap_win32.h"
#include "inject.h"

__declspec(dllimport) cpu_core_t *cpu_core;

int fasttrap_ioctl(void *arg,  int cmd);
int fasttrap_close();
int fasttrap_open();
int fasttrap_load();
int fasttrap_unload();
static void FasttrapUnload();
#define	STATUS_SUCCESS 0

#if !defined(STATIC)
BOOL APIENTRY
DllMain(HMODULE hmodule, DWORD  reason, LPVOID notused)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return (TRUE);
}
#endif

NTSTATUS
FasttrapClose()
{
	fasttrap_close();

	return (STATUS_SUCCESS);
}

NTSTATUS
FasttrapOpen()
{
	fasttrap_load();
	fasttrap_open();

	return (STATUS_SUCCESS);
}

static void
FasttrapUnload()
{
	fasttrap_unload();
}

int
FasttrapInterrupt(CONTEXT *ct, pid_t pid, pid_t tid);

int
FasttrapIoctl(HANDLE DevObj, int cmd, void *addr)
{
	int st = 0, t;

	if (addr == NULL)
		st =  (0x0000000 | ENOMEM);
	else {
		if (cmd == FASTTRAPIOC_INTRPTCB) {
			*((uintptr_t *) addr) = FasttrapInterrupt;
			t = 0;
		} else {
			t = fasttrap_ioctl(addr, cmd);
		}
		if (t)
			st = 0x0000000 | t;
	}

	return (st);
}

/* return 0 on success */
int
fasttrap_copyout(void * kaddr, void * uaddr, int len)
{
	proc_t *p = curproc;
	int err = 0;

	err = uwrite(p, kaddr, len, uaddr);
	return (err);
}

/* Fetches 32 bits of data from the user-space address base */
int32_t
fuword32(const void *base)
{
	proc_t *p = curproc;
	uint32_t kaddr;
	int err = 0;

	err = uread(p, &kaddr, sizeof (int32_t), base);
	return (err == 0 ? kaddr : -1);
}

/* Fetches 64 bits of data from the user-space address base */
int64_t
fuword64(const void *base)
{
	proc_t *p = curproc;
	uint64_t kaddr;
	int err = 0;

	err = uread(p, &kaddr, sizeof (int64_t), base);
	return (err == 0 ? kaddr : -1);
}

/* Stores 32 bits of data to the user-space address base */
int
suword32(void *base, int32_t word)
{
	proc_t *p = curproc;
	int err;

	err = uwrite(p, &word, sizeof (int32_t), base);
	return (err ? -1 : 0);
}

/* Stores 64 bits of data to the user-space address base */
int
suword64(void *base, int64_t word)
{
	proc_t *p = curproc;
	int err;

	err = uwrite(p, &word, sizeof (int64_t), base);
	return (err ? -1 : 0);
}


/* timeout functions */

static void CALLBACK
TimerProc(void* data, BOOLEAN TimerOrWaitFired)
{
	void (*func)(void *) = data;
	(void) (func)(NULL);
}

timeout_id_t
timeout(void (*func)(void *), void* unused, hrtime_t nano)
{
	HANDLE t;
	DWORD time = nano / 1000000;

	CreateTimerQueueTimer(&t, NULL, TimerProc, func,
	    time, 0, WT_EXECUTEINTIMERTHREAD);

	return ((timeout_id_t) t);
}

void
untimeout(timeout_id_t id)
{
	DeleteTimerQueueTimer(NULL, id, NULL);
}

void
fasttrap_winsig(pid_t pid, uintptr_t addr)
{
	/* terminate process */
}

#ifdef __i386__
#define	r_pc	r_eip
#else
#define	r_pc	r_rip
#endif

int
dtrace_user_probe(struct reg *rp)
{
	int ret = 0;
	thread_t *td = curthread;

	td->ebp = 0;
	if (rp->r_trapno == T_DTRACE_RET) {
		uint8_t step = td->t_dtrace_step;
		uint8_t ret = td->t_dtrace_ret;
		uintptr_t npc = td->t_dtrace_npc;

		if (td->t_dtrace_ast) {
#ifdef illumos
			aston(curthread);
			curthread->t_sig_check = 1;
#endif
			dprintf("dtrace_user_mode() t_dtrace_ast = %d\n",
			    td->t_dtrace_ast);
		}

		/*
		 * Clear all user tracing flags.
		 */
		td->t_dtrace_ft = 0;

		/*
		 * If we weren't expecting to take a return probe trap, kill
		 * the process as though it had just executed an unassigned
		 * trap instruction.
		 */
		if (step == 0) {
#ifdef illumos
			tsignal(curthread, SIGILL);
#endif
			dprintf("dtrace_user_mode():"
			    "Not expecting a return probe\n");
			return (1);
		}

		/*
		 * If we hit this trap unrelated to a return probe, we're
		 * just here to reset the AST flag since we deferred a signal
		 * until after we logically single-stepped the instruction we
		 * copied out.
		 */
		if (ret == 0) {
			rp->r_pc = npc;
			return (0);
		}

		/*
		 * We need to wait until after we've called the
		 * dtrace_return_probe_ptr function pointer to set %pc.
		 */
		td->tf = rp;
		(void) fasttrap_return_probe(rp);
		td->tf = NULL;
		rp->r_pc = npc;

	} else if (rp->r_trapno == T_DTRACE_PROBE) {
		;
	} else if (rp->r_trapno == T_BPTFLT) {
		uint8_t instr;

		/*
		 * The DTrace fasttrap provider uses the breakpoint trap
		 * (int 3). We let DTrace take the first crack at handling
		 * this trap; if it's not a probe that DTrace knowns about,
		 * we call into the trap() routine to handle it like a
		 * breakpoint placed by a conventional debugger.
		 */
		td->tf = rp;
		ret = fasttrap_pid_probe(rp);
		td->tf = NULL;
#ifdef illumos
		/*
		 * If the instruction that caused the breakpoint trap doesn't
		 * look like an int 3 anymore, it may be that this tracepoint
		 * was removed just after the user thread executed it. In
		 * that case, return to user land to retry the instuction.
		 */
		if (fuword8((void *)(rp->r_pc - 1), &instr) == 0 &&
		    instr != FASTTRAP_INSTR) {
			rp->r_pc--;
			return;
		}

		trap(rp, addr, cpuid);
#endif
	} else {
#ifdef illumos
		trap(rp, addr, cpuid);
#endif
	}
	return (ret);
}

void
ft_setreg(struct reg *rp, CONTEXT *ct)
{
#if defined(__amd64)
	rp->r_rax = ct->Rax;
	rp->r_rbx = ct->Rbx;
	rp->r_rcx = ct->Rcx;
	rp->r_rdx = ct->Rdx;
	rp->r_rsi = ct->Rsi;
	rp->r_rdi = ct->Rdi;
	rp->r_r8 =  ct->R8;
	rp->r_r9 =  ct->R9;
	rp->r_r10 = ct->R10;
	rp->r_r11 = ct->R11;
	rp->r_r12 = ct->R12;
	rp->r_r13 = ct->R13;
	rp->r_r14 = ct->R14;
	rp->r_r15 = ct->R15;
	rp->r_trapno = T_DTRACE_FASTTRAP;
	rp->r_err = 0;
	rp->r_rbp = ct->Rbp;
	rp->r_rip = ct->Rip;
	rp->r_rsp = ct->Rsp;
	rp->r_rflags = ct->EFlags;
#else
	rp->r_eax = ct->Eax;
	rp->r_ebx = ct->Ebx;
	rp->r_ecx = ct->Ecx;
	rp->r_edx = ct->Edx;
	rp->r_esi = ct->Esi;
	rp->r_edi = ct->Edi;
	rp->r_trapno = T_DTRACE_FASTTRAP;
	rp->r_err = 0;
	rp->r_ebp = ct->Ebp;
	rp->r_eip = ct->Eip;
	rp->r_esp = ct->Esp;
	rp->r_eflags = ct->EFlags;
#endif
}

void
ft_setcontext(CONTEXT *ct, struct reg *rp)
{
#if defined(__amd64)
	ct->Rax = rp->r_rax;
	ct->Rbx = rp->r_rbx;
	ct->Rcx = rp->r_rcx;
	ct->Rdx = rp->r_rdx;
	ct->Rsi = rp->r_rsi;
	ct->Rdi = rp->r_rdi;
	ct->R8 = rp->r_r8;
	ct->R9 = rp->r_r9;
	ct->R10 = rp->r_r10;
	ct->R11 = rp->r_r11;
	ct->R12 = rp->r_r12;
	ct->R13 = rp->r_r13;
	ct->R14 = rp->r_r14;
	ct->R15 = rp->r_r15;
	ct->Rbp = rp->r_rbp;
	ct->Rip = rp->r_rip;
	ct->Rsp  = rp->r_rsp;
	ct->EFlags = rp->r_rflags;
#else
	ct->Eax = rp->r_eax;
	ct->Ebx = rp->r_ebx;
	ct->Ecx = rp->r_ecx;
	ct->Edx = rp->r_edx;
	ct->Esi = rp->r_esi;
	ct->Edi = rp->r_edi;
	ct->Ebp = rp->r_ebp;
	ct->Eip = rp->r_eip;
	ct->Esp  = rp->r_esp;
	ct->EFlags = rp->r_eflags;
#endif
}

/* send message to traced process */
static int
fasttrap_fpid_msg(proc_t *p, int msgid, uetwptr_t faddr,
    uetwptr_t pc, int ftype)
{
	dt_pmsg_t *e = NULL;
	int size;
	dt_pmsg_t *msg;
	dt_msg_func_t *mfunc = msg->data;

	size = offsetof(dt_pmsg_t, data) + sizeof (dt_msg_func_t);
	msg = malloc(size);
	msg->id = msgid;
	msg->size = size;

	mfunc = msg->data;
	mfunc->addr = pc;
	mfunc->faddr = faddr;
	mfunc->type = ftype;

	e = dt_pipe_sndrcv(p->pipe, msg);

	free(msg);

	return ((e && e->id == PIPE_DONE) ? 0: -1);
}

static int
ft_etw_process(pid_t pid, pid_t tid, uetwptr_t pc, uetwptr_t *stack, int ssz,
    uetwptr_t *args, uetwptr_t rax, uint64_t ts, uint32_t cpuno)
{
	fasttrap_tracepoint_t *tp;
	fasttrap_bucket_t *bucket;
	fasttrap_id_t *id;

	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	/*
	 * Lookup the tracepoint that the process just hit.
	 */
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    tp->ftt_proc->ftpc_acount != 0)
			break;
	}

	/*
	 * If we couldn't find a matching tracepoint, either a tracepoint has
	 * been inserted without using the pid<pid> ioctl interface (see
	 * fasttrap_ioctl), or somehow we have mislaid this tracepoint.
	 */
	if (tp == NULL) {
		dprintf("FastTrapCB: missed pid %d tid %d pc %p\n",
		    pid, tid, pc);
		return (-1);
	}

	dtrace_set_ft_stack(stack, ssz);

	for (id = tp->ftt_ids; id != NULL; id = id->fti_next) {
		if (id->fti_ptype == DTFTP_ENTRY) {
			HANDLE *lock = dtrace_etw_set_cur(pid, tid,
			    ts, cpuno);
			dtrace_etw_probe(id->fti_probe->ftp_id, args[0],
			    args[1], args[2], args[3], args[4], 1);
			dtrace_etw_reset_cur(lock);
		} else {
			ASSERT(0);
		}
	}

	if (tp->ftt_retids != NULL) {
		for (id = tp->ftt_retids; id != NULL; id = id->fti_next) {
			if (id->fti_ptype == DTFTP_RETURN) {
				dtrace_etw_probe(id->fti_probe->ftp_id,
				    pc - id->fti_probe->ftp_faddr,
				    rax, 0, 0, 0, 1);
			} else {
				ASSERT(0);
			}
		}
	}
}

int
FasttrapInterrupt(pid_t pid, pid_t tid, int mode, void *arg)
{
	HANDLE *lock;
	struct reg regs, *rp;
	int r = 0, size = 0;

	if (mode == PSYS_FUNC) {
		/* 0xcc trap */
		CONTEXT *ct = (CONTEXT *) arg;
		thread_t *td = dtrace_etw_td_find(pid, tid, ETW_SET_CURRENT);
		rp = &regs;
		td->context = ct;
		ft_setreg(rp, ct);
		lock = dtrace_etw_set_cur(pid, tid, 0, -1);
		r = dtrace_user_probe(rp);
		dtrace_etw_reset_cur(lock);
		ft_setcontext(ct, rp);
	} else if (mode == PSYS_SYM_HANDLE) {
		/* dbghelp handle for stack trace */
		proc_t *proc = dtrace_etw_proc_find(pid, ETW_PROC_FIND);
		if (proc)
			proc->symhandle = (HANDLE) arg;
	} else if (mode == PSYS_FPID_QUEUE_CLEAR) {
		/* enable all hooks */
		proc_t *p = dtrace_etw_proc_find(pid, ETW_PROC_FIND);

		if (p == NULL || p->pipe == NULL)
			return (-1);

		fasttrap_fpid_msg(p, PIPE_QUEUE_CLEAR, 0, 0, 0);
		dprintf("FasttrapInterrupt functions init %d hooked %d\n",
		    p->mini, p->mque);
		p->mini = p->mque = 0;
	} else if (mode == PSYS_FPID_TID) {
		/* return agent thread id */
		proc_t *p = dtrace_etw_proc_find(pid, ETW_PROC_FIND);
		dt_pmsg_t *msg;
		dt_pmsg_t *e;

		if (p == NULL || p->pipe == NULL)
			return (-1);

		size = offsetof(dt_pmsg_t, data);
		msg = malloc(size);
		msg->id = PIPE_WAIT_TID;
		msg->size = size;
		e = dt_pipe_sndrcv(p->pipe, msg);
		dprintf("FasttrapInterrupt: agent thread id %d\n", e->id);
		free(msg);

		return (e->id);
	} else if (mode == PSYS_RELEASE_PROC) {
		/*
		 * unload agent dll from injected process,
		 * and close the pipe.
		 */
		proc_t *p = dtrace_etw_proc_find(pid, ETW_PROC_FIND);
		if (p->pipe == NULL)
			return (-1);

		fasttrap_fpid_msg(p, PIPE_CLOSE, 0, 0, 0);

	} else if (mode == PSYS_PROC_DEAD) {
		/* update process status (exited) */
		proc_t *p = dtrace_etw_proc_find(pid, ETW_PROC_FIND);
		if (p)
			p->dead = 1;
	}

	return (r);
}

int
FastTrapCB(PEVENT_RECORD ev, void *data)
{
	uintptr_t pc;
	uint32_t pid = ev->EventHeader.ProcessId;
	uint32_t tid = ev->EventHeader.ThreadId;

	if (ev->EventHeader.EventDescriptor.Id == 1 ||
	    ev->EventHeader.EventDescriptor.Id == 2) {
		struct etwft *ft = (struct etwft *) ev->UserData;

		ASSERT(ft->addr > 0);

		pc = ft->addr;
		ft_etw_process(pid, tid, pc, ft->stack,
		    (ft->stacksz / sizeof (uintptr_t)), &ft->arg0,
		    ft->ax, ev->EventHeader.TimeStamp.QuadPart,
		    ev->BufferContext.ProcessorNumber);
	} else if (ev->EventHeader.EventDescriptor.Id == 3) {
		struct etwft0 *ft = (struct etwft0 *) ev->UserData;
		etw_event_t *tmp = &ft->arr[0], *tmpr;
		int samp = ft->count, j = 0, co = 0;

		ASSERT(ev->UserDataLength >= ft->count);

		while (samp >= (int) sizeof (etw_event_t)) {
			/*
			 * TODO: sanity check the packet
			 */
			ft_etw_process(pid, tid, tmp->addr, tmp->stack,
			    tmp->stacksz, &tmp->arg0, tmp->ax,
			    tmp->time, tmp->cpuno);
			tmpr = tmp;
			tmp = &(tmp->stack[tmp->stacksz+1]);
			samp -= ((char *)tmp - (char *)tmpr);
			co++;
		}
	} else if (ev->EventHeader.EventDescriptor.Id == 4) {
		;
	}

	return (0);
}

/*
 * inject the tracing module, and initialize ETW
 * return 0 on failure.
 */
int
fasttrap_inject_fpid(proc_t *p)
{
	WCHAR  buf0[MAX_SYM_NAME] = {0};
	WCHAR  buf1[MAX_PATH] = {0};
	WCHAR *sagent = NULL;
	wchar_t *last0, *last1, *last;
	DWORD len = GetModuleFileNameW(NULL, buf0, MAX_SYM_NAME-1);
	dt_pipe_t *pipe;
	int e;
	FILE *dum;

	if (len == 0) {
		e = GetLastError();
		return (0);
	}

	len = GetFullPathNameW(buf0, MAX_PATH, buf1, NULL);
	last0 = wcsrchr(buf1, L'\\');
	last1 = wcsrchr(buf1, L'/');
	last = last0 > last1? last0:last1;
	if (last == NULL)
		return (0);

	if (p->model) {
		sagent = AGENTDLL64;
	} else {
		sagent = AGENTDLL32;
	}

	len = wcslen(sagent);
	wcscpy(last+1, sagent);

	if ((dum = _wfopen(buf1, "r")) == NULL) {
		fprintf(stderr, "fasttrap_inject_fpid: agent not found (%ws) \n",
		    sagent);
		return (0);
	} else {
		fclose(dum);
	}

	pipe = dt_create_pipe(p->pid, 1024, NULL);
	if (pipe == NULL)
		return (0);
	if (dt_injectdll(p->pid, buf1) == 0)
		return (0);

	p->pipe = pipe;
	if (p->withstacks) {
		fasttrap_fpid_msg(p, PIPE_WITH_STACKS, 0, 0, 0);
	}
	dtrace_etw_enable_ft(&FastTrapGuid, 0, 0);
	dtrace_etw_hook_event(&FastTrapGuid, FastTrapCB, NULL,
	    ETW_EVENTCB_ORDER_ANY);

	return (1);
}

/*ARGSUSED*/
int
fasttrap_tracepoint_init_fpid(proc_t *p, fasttrap_probe_t *probe,
    fasttrap_tracepoint_t *tp, uintptr_t pc, fasttrap_probe_type_t type)
{
	int err = 0, rc = fasttrap_tracepoint_init(p, tp, pc, type);

	if (rc != 0)
		return (rc);

	p->mini++;		/* diagnostics */

	if (p->agent_loaded == 0) {
		p->agent_loaded = fasttrap_inject_fpid(p);
		if (p->agent_loaded == 0) {
			return (-1);
		}
	}
	err = fasttrap_fpid_msg(p, PIPE_HOOK_FUNC,
	    probe->ftp_faddr, tp->ftt_pc,
	    type == DTFTP_ENTRY ? PIPE_FUNC_ENTER: PIPE_FUNC_RETURN);

	return (err);
}

int
fasttrap_tracepoint_install_fpid(proc_t *p, fasttrap_probe_t *probe,
    fasttrap_tracepoint_t *tp)
{
	int err = 0;

	p->mque++;		/* diagnostics */
	err = fasttrap_fpid_msg(p, PIPE_FUNC_ENABLE,
	    probe->ftp_faddr, tp->ftt_pc, 0);
	return (err);
}

int
fasttrap_tracepoint_remove_fpid(proc_t *p, fasttrap_probe_t *probe,
    fasttrap_tracepoint_t *tp)
{
	int err;

	err = fasttrap_fpid_msg(p, PIPE_FUNC_DISABLE,
	    probe->ftp_faddr, tp->ftt_pc, 0);
	if (p->p_dtrace_count == 1) {
		fasttrap_fpid_msg(p, PIPE_QUEUE_CLEAR, 0, 0, 0);
		fasttrap_fpid_msg(p, PIPE_CLOSE, 0, 0, 0);
	}

	return (err);
}
