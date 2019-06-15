/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENDtrace.LICENSE
 * or http://www.openDtrace.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENDtrace.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

#include <sys/dtrace_misc.h>
#include <sys/dtrace_win32.h>
#include <sys/dtrace_impl.h>
#include <strsafe.h>
#include <dbghelp.h>

pri_t maxclsyspri;
dtrace_cacheid_t dtrace_predcache_id;
int panic_quiesce;

int xcall_cpu = -1;		/* current cross call cpu */
/* per cpu lock, to serialize access to dtrace buffer, between xcall and probe context */
kmutex_t *intr_cpu;		
hrtime_t Hertz;
cpu_data_t *CPU;
cpu_core_t *cpu_core;
struct modctl *modules;

int
dtrace_wcstombs(char *dest, wchar_t *src, int size)
{
	volatile uint16_t *flags = (volatile uint16_t *)
	    &cpu_core[curcpu].cpuc_dtrace_flags;
	int len = 0;

	__try {
		/*
		 * if the destination utf8 string buffer, is not enought to convert
		 * the wchar string, truuncate it.
		 */
		//len = WideCharToMultiByte(CP_UTF8, 0, src, -1, dest, size, NULL, NULL );
		wcstombs_s(&len, dest, size, src, _TRUNCATE);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		*flags |= CPU_DTRACE_FAULT;
	}
	return len;
}

/* XXX should return the size of wchar string, returned by dtrace_wcstombs */
size_t
dtrace_wstrlen(const wchar_t *s, size_t lim)
{
	volatile uint16_t *flags = (volatile uint16_t *)
	    &cpu_core[curcpu].cpuc_dtrace_flags;
	size_t sz = 0;

	__try {
		/*
		 * INCOMPLETE: TODO
		 * does not take into account that a wide char can be 1,2 or 3 bytes.
		 */
		sz = wcsnlen_s(s, lim);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		*flags |= CPU_DTRACE_FAULT;
		sz = 0;
	}
	return sz;
}
int
GetCurrentIrql()
{
	return 1;
}

int
ncpus()
{
	static int ncpu = 0;
	
	if (ncpu == 0) {
		ncpu = dtrace_etw_nprocessors();
	}

	return ncpu;
}

int
_curcpu()
{
	int cpu = dtrace_etw_current_cpu();

	if (cpu == -1)
		return 0;
	else
		return cpu;
}

dtrace_user_module_t *user_modules = NULL;

#if defined(__amd64__)

int
winos_user_module_mdl(pid_t pid, dtrace_user_module_t *mod)
{
	SIZE_T co = 0;

	dtrace_user_module_t *p = kmem_zalloc(sizeof(dtrace_user_module_t), 0);
	p->mdl = 0;
	proc_t *pr = dtrace_etw_proc_find(pid, ETW_PROC_CREATE_LIVE);
	// memcpy(p->buf, p->imgbase, mod->size);
	p->imgbase = mod->imgbase;
	strcpy(p->name, mod->name);
	p->size = mod->size;
	p->pid = mod->pid;
	p->buf = kmem_alloc(mod->size, 0);
	ReadProcessMemory(pr->handle, p->imgbase, p->buf, mod->size, &co);

	p->next = NULL;

	if (user_modules == NULL) {
		user_modules = p;
	} else {
		p->next = user_modules;
		user_modules = p;
	}
	return 0;
}

dtrace_user_module_t *
winos_find_user_module(uintptr_t pc)
{
	dtrace_user_module_t *ctl;

	if (!INKERNEL(pc)) {
		for (ctl=user_modules; ctl!= NULL; ctl = ctl->next) {
			if (pc >= ctl->imgbase && pc < (ctl->imgbase + ctl->size)) {
				return ctl;
			}
		}
	}

	return NULL;
}

int
winos_unwind_user_stack(thread_t *td, CONTEXT *ct, int frame, uintptr_t out)
{
	DWORD MachineType = 0;
	uint64_t *pcstack = out;
	int count = 0;
	CONTEXT Context = *ct, Context0;
	// Stack frame
	if (td->handle == NULL) {
		td->handle = OpenThread(THREAD_ALL_ACCESS, FALSE, td->tid);
	}
	if (td->handle == NULL || td->proc->symhandle == NULL)
		return 0;
	Context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(td->handle, &Context);

	STACKFRAME64 StackFrame;
	memset( &StackFrame, 0, sizeof(StackFrame) );
	MachineType                 = IMAGE_FILE_MACHINE_AMD64;
	StackFrame.AddrPC.Offset    = Context.Rip;
	StackFrame.AddrPC.Mode      = AddrModeFlat;
	StackFrame.AddrReturn.Offset = Context.Rsp;
	StackFrame.AddrReturn.Mode   = AddrModeFlat;
	StackFrame.AddrFrame.Offset = Context.Rsp;
	StackFrame.AddrFrame.Mode   = AddrModeFlat;
	StackFrame.AddrStack.Offset = Context.Rsp;
	StackFrame.AddrStack.Mode   = AddrModeFlat;

	while (count < frame ) {
		if ( ! StackWalk64(
		        MachineType,
		        td->proc->symhandle,
		        td->handle,
		        &StackFrame,
		        MachineType == IMAGE_FILE_MACHINE_I386
		        ? NULL
		        : &Context,
		        NULL,
		        SymFunctionTableAccess64,
		        SymGetModuleBase64,
		        NULL ) ) {
			break;
		}

		if (StackFrame.AddrPC.Offset != 0 ) {
			*pcstack++  = StackFrame.AddrPC.Offset;
			count++;
		} else {
			break;
		}
	}

	return count;
}

void
winos_reg_to_context(CONTEXT *ct, struct reg *rp)
{
	ZeroMemory(ct, sizeof(CONTEXT));

	ct->Rax = rp->r_rax;
	ct->Rbx = rp->r_rbx;
	ct->Rcx = rp->r_rcx;
	ct->Rdx = rp->r_rdx;
	ct->Rsp = rp->r_rsp;
	ct->Rbp = rp->r_rbp;
	ct->Rsi = rp->r_rsi;
	ct->Rdi = rp->r_rdi;
	ct->Rip = rp->r_rip;
	ct->R8 = rp->r_r8;
	ct->R9 = rp->r_r9;
	ct->R10 = rp->r_r10;
	/*ct->R11 = r->R11;
	ct->R12 = r->R12;
	ct->R13 = r->R13;
	ct->R14 = r->R14;
	ct->R15 = r->R15;*/

}
#endif

/*
 * taskq implementation
 */
typedef struct funcptr {
	task_func_t *f;
} funcptr_t;

funcptr_t taskfunc;


VOID CALLBACK
apc_function_1(ULONG_PTR dwParam)
{
	funcptr_t *g = (funcptr_t *) dwParam;
	g->f();
}

DWORD WINAPI
thread_function(LPVOID lpParameter)
{
	while (1) {
		SleepEx(INFINITE,TRUE);
	}
}

taskq_t *
taskq_create(const char *name, int nthreads, pri_t pri, int minalloc, int maxalloc, uint_t flags)
{

	UNREFERENCED_PARAMETER(name);
	UNREFERENCED_PARAMETER(nthreads);
	UNREFERENCED_PARAMETER(pri);
	UNREFERENCED_PARAMETER(minalloc);
	UNREFERENCED_PARAMETER(maxalloc);
	UNREFERENCED_PARAMETER(flags);

	WORD thread_id;
	HANDLE thread_handle = CreateThread(NULL,0,thread_function,NULL,0,&thread_id);

	if (!thread_handle) {
		dprintf("dtrace.sys: tasq_create() failed\n");
		return NULL;
	}

	return (taskq_t *) thread_handle;
}

taskqid_t
taskq_dispatch(taskq_t *pdpc, task_func_t func, void *args, uint_t i)
{
	UNREFERENCED_PARAMETER(i);

	taskfunc.f = func;

	QueueUserAPC(apc_function_1, (HANDLE) pdpc, (ULONG_PTR)&taskfunc);
	return 0;
}

void
taskq_destroy(taskq_t *pdpc)
{
	CloseHandle((HANDLE) pdpc);
}

/*
 * Memory allocation
 */
void *
kmem_alloc(size_t size, int kmflag)
{
	void *p;
	UNREFERENCED_PARAMETER(kmflag);

	p = malloc(size);
	if (p == NULL)
		dprintf("dtrace.sys: kmem_alloc failed %d\n", size);
	return p;
}

void *
kmem_zalloc(size_t size, int kmflag)
{
	void *p;
	UNREFERENCED_PARAMETER(kmflag);

	p = malloc(size);
	if (p == NULL)
		dprintf("dtrace.sys: kmem_zalloc failed %d\n", size);
	else
		ZeroMemory(p, size);
	return p;
}

void
kmem_free(void *buf, size_t size)
{
	if (buf == NULL || size == 0)
		return;
	free(buf);
}

/*
 * atomic functions
 */
uint32_t
dtrace_cas32(uint32_t *target, uint32_t cmp, uint32_t new)
{
	LONG tmp;
	tmp = InterlockedCompareExchange((volatile LONG *)target, (LONG)new, (LONG)cmp);
	if (tmp != *target)
		return cmp;
	else
		return ~cmp;
}

void *
dtrace_casptr(volatile void *target, volatile void *cmp, volatile void *new)
{
	ULONG *tmp;
	
	tmp = InterlockedCompareExchangePointer((VOID **)target, new, cmp);
	if (tmp != *(ULONG **)target)
		return cmp;
	else
		return (void *) (~(uintptr_t)cmp);
}

/*
 * interprocessor interrupt (IPI) or cross-call
 * dtrace_xcall
 */

void
dtrace_init_xcall()
{
	int i;

	intr_cpu = kmem_zalloc(sizeof(kmutex_t) * NCPU, KM_SLEEP);
	CPU_FOREACH(i) {
		mutex_init(&intr_cpu[i]);
	}
}

void
dtrace_xcall(processorid_t cpu, dtrace_xcall_t func, void *arg)
{
	int i;
	if (cpu == DTRACE_CPUALL) {
		CPU_FOREACH(i) {
			xcall_cpu = i;
			func(arg);
		}
	} else {
		xcall_cpu = cpu;
		func(arg);
	}
	xcall_cpu = -1;
}

int
copyin(void * uaddr, void * kaddr, int len)
{
	RtlCopyMemory((void *)kaddr, (void *)uaddr, len);
	return 0;
}

int
copyout(void * kaddr, void * uaddr, int len)
{
	RtlCopyMemory((void *)uaddr, (void *)kaddr, len);
	return 0;
}

/*
 * copyin copies LEN bytes from a user-space address uaddr to a
 * kernel-space address kaddr
 * return 0 on success
 */
int
pcopyin(void *uaddr, void *kaddr, int len)
{
	proc_t *p = curproc;
	return uread(p, kaddr, len, uaddr);
}

/*
 * copyout copies LEN bytes from a kernel-space address kaddr to a
 * user-space address uaddr
 */
int
pcopyout(void *kaddr, void *uaddr, int len)
{
	proc_t *p = curproc;
	return uwrite(p, kaddr, len, uaddr);
}

/*
 * copyinstr copies a null-terminated string of at most LEN bytes from
 * a user-space address USERSRC to a kernel-space address DEST, and
 * returns the actual length of string found in GOT. DEST is always
 * null-terminated on success. LEN and GOT include the null terminator
 * *  return ENAMETOOLONG if the string is longer than len bytes.
 */
int
copyinstr(void *uaddr, void *kaddr, int len)
{
	return pcopyin(uaddr, kaddr, len);
}

/*
 * copyoutstr copies a null-terminated string of at most LEN bytes from
 * a kernel-space address SRC to a user-space address USERDEST, and
 * returns the actual length of string found in GOT. DEST is always
 * null-terminated on success. LEN and GOT include the null terminator.
 */
int
copyoutstr(void *uaddr, void *kaddr, int len)
{
	return pcopyout(uaddr, kaddr, len);
}

/* 
 * read 64,32,16,8 bits from user process
 */
uint64_t
dtrace_fuword64_nocheck(void *uaddr)
{
	uint64_t kaddr;
	proc_t *p = curproc;
	uread(p, &kaddr, sizeof(int64_t), uaddr);

	return kaddr;
}

uint32_t
dtrace_fuword32_nocheck(void *uaddr)
{
	uint32_t kaddr;
	proc_t *p = curproc;
	uread(p, &kaddr, sizeof(int32_t), uaddr);

	return kaddr;
}

uint16_t
dtrace_fuword16_nocheck(void *uaddr)
{
	uint16_t kaddr;
	proc_t *p = curproc;
	uread(p, &kaddr, sizeof(uint16_t), uaddr);

	return kaddr;
}

uint8_t
dtrace_fuword8_nocheck(void *uaddr)
{
	uint8_t kaddr;
	proc_t *p = curproc;
	uread(p, &kaddr, sizeof(int8_t), uaddr);

	return kaddr;
}

/*
 * callout implementaion
 */
static void CALLBACK
TimerProc(void* data, BOOLEAN TimerOrWaitFired)
{
	struct callout *cyc = (struct callout *) data;
	dtrace_state_t *s = (dtrace_state_t *) cyc->state;

	(void) (cyc->func)(s);
}

void
callout_init(struct callout *cyc, HANDLE dev)
{
	cyc->Queue = NULL;
}

void
callout_reset(struct callout *cyc, int64_t nano)
{
	HANDLE t;
	DWORD time = nano / 1000000;

	cyc->time = time;
	CreateTimerQueueTimer(&t, cyc->Queue, TimerProc,
	    cyc, time, time, WT_EXECUTEINTIMERTHREAD);
	cyc->Timer = t;
}

void
callout_stop(struct callout *cyc)
{
	DeleteTimerQueueTimer(cyc->Queue, cyc->Timer, NULL);
}

/*
 * mutex implementaion
 */
void
mutex_init(kmutex_t *m)
{
	HANDLE h;

	h = CreateMutex(NULL, FALSE, NULL);
	*m = h;
}

void
mutex_enter(kmutex_t *m)
{
	DWORD r;
	HANDLE h = *m;

	r = WaitForSingleObject(h, INFINITE);
	if (r == WAIT_FAILED)
		r = GetLastError();
}

void
mutex_exit(kmutex_t *m)
{
	ReleaseMutex(*m);
}

void
mutex_destroy(kmutex_t *m)
{
	CloseHandle(*m);
}

int
mutex_owned(kmutex_t *m)
{
	DWORD r = WaitForSingleObject(*m, 0);
	if (r == WAIT_OBJECT_0 || r == WAIT_ABANDONED) {
		ReleaseMutex(*m);
		return 1;
	}
	return 0;
}

int
bcmp(const void *s1, const void *s2, size_t n)
{
	return memcmp(s1, s2, n);
}

void
vcmn_err(int ce, const char *fmt, va_list adx)
{
	char buf[256];
	const char *prefix;

	prefix = NULL; /* silence unwitty compilers */
	switch (ce) {
	case CE_CONT:
		prefix = "Dtrace(cont): ";
		break;
	case CE_NOTE:
		prefix = "Dtrace: NOTICE: ";
		break;
	case CE_WARN:
		prefix = "Dtrace: WARNING: ";
		break;
	case CE_PANIC:
		prefix = "Dtrace(panic): ";
		break;
	case CE_IGNORE:
		break;
	default:
		panic("Dtrace: unknown severity level");
	}
	if (ce == CE_PANIC) {
		vsnprintf(buf, sizeof(buf), fmt, adx);
		panic("%s%s", prefix, buf);
	}
	if (ce != CE_IGNORE) {
		printf("%s", prefix);
		vprintf(fmt, adx);
		printf("\n");
	}
}

void
cmn_err(int type, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vcmn_err(type, fmt, ap);
	va_end(ap);
}

/*
 * current process
 */
proc_t *
_curproc()
{
	proc_t *p = dtrace_etw_curproc();

	return p;
}

/*
 * current thread
 */
thread_t *
_curthread()
{
	thread_t *td = dtrace_etw_curthread();

	return td;
}

/* 
 * find process (pid), if it exits
 */
proc_t *
fasttrap_pfind(pid_t id)
{
	proc_t *p;
	p = dtrace_etw_proc_find(id, ETW_PROC_FIND);

	return p == NULL || p->dead ? NULL: p;
}

/* 
 * find process (pid), if not found create new entry 
 */
proc_t *
pfind(pid_t id)
{
	proc_t *p = NULL;
	p = dtrace_etw_proc_find(id, ETW_PROC_CREATE_LIVE);

	return p;

}

/*
 * functions to read and write to process
 */

int
uread(proc_t *p, void *kaddr, size_t len, uintptr_t uaddr)
{
	int err = 0;
	SIZE_T ret;

	if (p->handle == NULL) {
		p->handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
		        PROCESS_VM_WRITE, FALSE, p->pid);
		if (p->handle == NULL) {
			dprintf("dtrace.sys: uread, OpenProcess() pid (%d)  error (%d)\n",
			    p->pid, (err = GetLastError()));
			return (err);
		}
	}

	if (ReadProcessMemory(p->handle, (PVOID) uaddr, kaddr, len, &ret) == FALSE) {
		dprintf("dtrace.sys:, ReadProcessMemory() pid (%d) addr (%x)"
		    " size (%d) error (%d)\n", p->pid, uaddr, len, (err = GetLastError()));
	}

	return (err);
}

int
uwrite(proc_t *p, void *kaddr, size_t len, uintptr_t uaddr)
{
	int err = 0;
	SIZE_T ret;

	if (p->handle == NULL) {
		p->handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
		        PROCESS_VM_WRITE, FALSE, p->pid);
		if (p->handle == NULL) {
			dprintf("uwrite, OpenProcess() pid (%d) "
			    "error (%d)\n", p->pid, (err = GetLastError()));
			return (err);
		}
	}

	if (WriteProcessMemory(p->handle, (PVOID) uaddr, kaddr, len, &ret) == FALSE) {
		dprintf("uwrite(), WriteProcessMemory() pid (%d) addr (%x) "
		    "size (%d) error (%d)\n", p->pid, uaddr, len, (err = GetLastError()));
	} else {
		FlushInstructionCache(p->handle, (PVOID) uaddr, len);
	}

	return (err);
}

/* 
 * fasttrap thread local memory for instruction execution
 */
#define FTT_PAGE_UNITS 64
#define FTT_SCRATCH_SIZE 64

typedef struct mem_page {
	uintptr_t addr;
	int free_co;
	SIZE_T size;
	int bsize;
	struct mem_page *next;
	int free_list[1];
} mem_page_t;

PVOID scr_allocate(proc_t *p);

PVOID
scr_alloc_mem(proc_t *p)
{
	mem_page_t *page;
	uintptr_t vm = 0;
	int i, count, units = 0;
	mem_page_t *scr_mem;

	if (p->scr_mem == 0) {
		scr_allocate(p);
	}
	scr_mem = (mem_page_t *) p->scr_mem;

	if (scr_mem != NULL) {
		page = scr_mem;
		do {
			if (page->free_co) {
				vm = page->addr + page->free_list[0]*page->bsize;
				page->free_co--;
				for (i = 0; i < page->free_co; i++)
					page->free_list[i] = page->free_list[i+1];
				units = page->size/page->bsize;
				break;
			}
		} while ((page = page->next) != NULL);
	}

	if (vm != 0) {
		page = (mem_page_t *) p->scr_mem;
		count = 0;
		do
			count += page->free_co;
		while ((page = page->next) != NULL);

		return (PVOID) vm;
	}

	return NULL;

}

PVOID
scr_allocate(proc_t *p)
{
	mem_page_t *page;
	SIZE_T mem_size = FTT_PAGE_UNITS * FTT_SCRATCH_SIZE;
	uintptr_t mem = 0, vm = 0;
	int i;
	char *mem_base = NULL;
	DWORD oldprot = 0;

	ASSERT(p != NULL);

	if (p->handle == NULL) {
		p->handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
		        PROCESS_VM_WRITE, FALSE, p->pid);
		if (p->handle == NULL) {
			dprintf("scr_allocate: failed to open process pid (%d) err (%d)\n", 
				p->pid, GetLastError());
			return NULL;
		}
	}
	
	mem = VirtualAllocEx(p->handle, (PVOID) mem_base, mem_size,
	        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (mem == 0 ||
	    VirtualProtectEx(p->handle, mem, mem_size,
	        PAGE_EXECUTE_READWRITE, &oldprot) == 0) {
		dprintf("dtrace.sys: scr_allocate() ZwAllocateVirtualMemory failed %x\n",
		    GetLastError());
		goto end;
	}

	page = malloc(sizeof(mem_page_t)
	        + (sizeof(int) * ((mem_size/FTT_SCRATCH_SIZE)-1)));
	if (page == NULL) {
		goto end;
	}
	vm = page->addr = (uintptr_t) mem;
	page->size = mem_size;
	page->bsize = FTT_SCRATCH_SIZE;
	for (i = 0; i < (page->size / page->bsize) ; i++)
		page->free_list[i] = i;

	page->free_co = i;
	page->next = NULL;

	if (p->scr_mem == 0)
		p->scr_mem = (uintptr_t) page;
	else {
		page->next = (mem_page_t *) p->scr_mem;
		p->scr_mem = (uintptr_t) page;
	}
	end:
	dprintf("scr_allocate: allocated mem (%p)\n", vm);
	return (PVOID) vm;
}

void
scr_rel_mem(proc_t *p, PVOID addr1)
{
	mem_page_t *page;
	int j;
	uintptr_t addr = (uintptr_t) addr1;

	page = (mem_page_t *) p->scr_mem;

	while (page != NULL) {
		if (addr >= page->addr && addr < (page->addr + page->size)) {
			j = (addr - page->addr) / page->bsize;
			page->free_list[page->free_co] = j;
			page->free_co++;
			break;
		}
		page = page->next;
	}
}

void
scr_rel_page(proc_t *p)
{
	BOOL st;
	mem_page_t *page, *temp;

	if (p->scr_mem != 0) {
		page = (mem_page_t *) p->scr_mem;
		do {
			st = VirtualFreeEx(p->handle, (PVOID ) page->addr,
			        page->size, MEM_RELEASE);
			if (st == FALSE)
				dprintf("scr_rel_page(): "
				    "VirtualFreeEx failed %x\n", st);
			temp = page;
			page = page->next;
			free(temp);
		} while (page != NULL);

		p->scr_mem = 0;
	}
}

void
uprintf(const char *format, ...)
{
	DWORD sz = 0;
	static char *modulename = NULL;

	if (1) {
		va_list alist;

		va_start(alist, format);
		(void) vfprintf(stderr, format, alist);
		va_end(alist);
	}
}

void
vuprintf(const char *format, va_list alist)
{
	char str[256];

	StringCbVPrintfA(str, 256, format, alist);
	uprintf(str);
}