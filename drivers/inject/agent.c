/*
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
 * DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Copyright (C) 2019, PK.
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <winnt.h>
#include <evntprov.h>
#include "MinHook.h"
#include "inject.h"
#include "ftetw.h"


#if defined(_M_X64) || defined(__x86_64__)
typedef struct Context64 Context;
#else
typedef struct Context32 Context;
#endif

#if defined(_M_X64) || defined(__x86_64__)
#define	AGENT_DLL "agent64"
#else
#define	AGENT_DLL "agent32"
#endif

#define	MAX_PAYLOAD_DESCRIPTORS  9
#define	MAX_SIZE 7000

/* thread info */
#define	MAX_THREADS 1024
struct Tls {
	DWORD in;
	DWORD tid;
	struct Tls *next;
} tidtls[MAX_THREADS] = {0};

static int ETWTYPE = 1;
static int tlsmax = 0;
static REGHANDLE RegHandle = NULL;
static HMODULE agentdll;
static DWORD _agent_tid, _proc_pid, _stackon;

typedef struct etw_evarc {
	uint64_t addr[MAX_SIZE];
	uint64_t end;
	uint64_t off;
	int co;
	struct etw_evarc *next;
} etw_evarc_t;

static etw_evarc_t *event_add_list;
static etw_evarc_t *event_send_list, *event_passive_list;
static HANDLE agent_add_lock, test_lock;

static int StackTrace(uint64_t *pcstack, uintptr_t ip,
    uintptr_t sp, int limit, int aframes);

static int blobevents, dropped, blobsent, lllen, events, eventsent;
static int _debug = 0;
static int thread_lock = 0;

#define DIAG(st)	if (_debug) { if (st != ERROR_SUCCESS) dropped++; eventsent++; events++; }

dt_pipe_t *proc_func(dt_pipe_t *pipe);

static void
dprintf(char *fmt, ...)
{
	va_list args;
	if (_debug) {
		va_start(args, fmt);
		fputs("AGENT.DLL DEBUG: ", stderr);
		vfprintf(stderr, fmt, args);
		va_end(args);
	}
}

int
d_msg_count(intptr_t addr, int size)
{
	struct ftetw_blob *ft = (struct ftetw_blob *) addr;
	ftetw_msg_t *tmp = addr, *tmpr;
	int samp = size, j = 0;
	int evco = 0;

	while (samp >= (int) sizeof (ftetw_msg_t)) {
		evco++;
		tmpr = tmp;
		tmp = &(tmp->stack[tmp->stacksz + 1]);
		samp -= ((char *)tmp - (char *)tmpr);
	}

	return evco;
}

static int _malloc = 0, spin = 0;
static struct Tls *freelist = NULL, *hotlist = NULL;
void
init_alloc()
{
	int i;
	struct Tls *tmp = malloc(sizeof(struct Tls) * MAX_THREADS);
	freelist = tmp;
	for (i = 0; i < MAX_THREADS - 1; i++) {
		tmp[i].next = &tmp[i + 1];
	}
	tmp[i].next = NULL;
}

/* lookup thread data, for the current thread */
static struct Tls *
lookup_tid(DWORD tid)
{
	DWORD ind, inc;
	struct Tls *tmp = NULL, *prev = NULL;

	for (tmp = hotlist; tmp != NULL; tmp = tmp->next) {
		if (tmp->tid == tid) {
			return tmp;
		}
	}
	///while (InterlockedCompareExchange(&_malloc, 1, 0) != 0)
	///   spin++;

	for (tmp = hotlist; tmp != NULL; tmp = tmp->next) {
		if (InterlockedCompareExchange(&tmp->tid, tid, 0) == 0) {
			//if (tmp->tid == 0) {
			tmp->tid = tid;
			///InterlockedExchange(&_malloc, 0);
			return tmp;
		}
		prev = tmp;
	}

	assert(freelist != NULL);

	do {
		tmp = freelist;
		//freelist = tmp->next;
	} while (InterlockedCompareExchangePointer(&freelist, tmp->next, tmp) != tmp);
	tmp->tid = tid;
	tmp->in = 0;
	tmp->next = NULL;
	if (prev == NULL)
		hotlist = tmp;
	else
		prev->next = tmp;

	lllen++;

	return tmp;

	/*
	    for (int i = 0; i < tlsmax; i++) {
	        if (tidtls[i].tid == tid) {
	            return (&tidtls[i]);
	        }
	    }

	    do {
	        ind = tlsmax;
	        inc = ind + 1;
	    } while (InterlockedCompareExchange(&tlsmax, inc, ind) != ind);

	    if (ind >= MAX_THREADS) {
	        dprintf("agent: threads > MAX_THREADS?\n");
	        return (NULL);
	    }

	    tidtls[ind].tid = tid;

	    return (&tidtls[ind]);
	*/
}

/*
 * Returns nanoseconds since boot.
 */
#define	NANOSEC		1000000000
#define	ONE0MSEC	10000000
typedef LONG64 hrtime_t;

static hrtime_t
gethrtime()
{
	hrtime_t ret;
	LARGE_INTEGER Frequency = {0}, StartingTime;
	static hrtime_t frequency = 0;

	if (frequency == 0) {
		QueryPerformanceFrequency(&Frequency);
		frequency = NANOSEC / Frequency.QuadPart;
	}
	QueryPerformanceCounter(&StartingTime);
	ret = StartingTime.QuadPart * frequency;

	return (ret);
}

static void
deinit()
{
	MH_Uninitialize();
}

/* MUTEX */
static void
etw_mutex_init(HANDLE *m)
{
	HANDLE h;

	h = CreateMutex(NULL, FALSE, NULL);
	*m = h;
}

static void
etw_mutex_enter(HANDLE *m)
{
	DWORD r;
	HANDLE h = *m;
	r = WaitForSingleObject(h, INFINITE);
	if (r == WAIT_FAILED)
		r = GetLastError();
}

static void
etw_mutex_exit(HANDLE *m)
{
	ReleaseMutex(*m);
}

static void
etw_mutex_destroy(HANDLE *m)
{
	CloseHandle(*m);
}

/* memory */
static void *
ag_zalloc(size_t size)
{
	void *p;

	p = malloc(size);
	if (p == NULL)
		dprintf("ag_zalloc, failed %lld\n", size);
	else
		ZeroMemory(p, size);

	return (p);
}

static void
ag_free(void *buf)
{
	if (buf == NULL)
		return;

	free(buf);
}

static int
ag_init_evarc()
{
	etw_evarc_t *tmp = NULL;

	etw_mutex_init(&agent_add_lock);
	etw_mutex_init(&test_lock);
	tmp = (etw_evarc_t *) ag_zalloc(sizeof (etw_evarc_t));
	tmp->end = &tmp->addr[MAX_SIZE];
	tmp->off = &tmp->addr[0];
	tmp->next = NULL;
	event_add_list = tmp;

	tmp = (etw_evarc_t *) ag_zalloc(sizeof (etw_evarc_t));
	tmp->end = &tmp->addr[MAX_SIZE];
	tmp->off = &tmp->addr[MAX_SIZE];
	tmp->next = NULL;
	tmp->co = MAX_SIZE;
	event_passive_list = tmp;

	return (0);
}

static BOOL
ag_init()
{
	DWORD status;
	dt_pipe_t *pipe;
	HANDLE td;
	MH_STATUS st;

	_debug = getenv("AGENT_DEBUG") != NULL;

	status = EventRegister(
	    &ProviderGuid,	/* GUID that identifies the provider */
	    NULL,
	    NULL,
	    &RegHandle);
	if (ERROR_SUCCESS != status) {
		dprintf("ag_init, EventRegister() failed with (%lu)\n", status);
		return (FALSE);
	}

	/* increment the module count, so that it is not unloaded */
	agentdll = GetModuleHandle(AGENT_DLL);

	dprintf("%s.dll loaded in process: pid (%d)\n",
	    AGENT_DLL, GetCurrentProcessId());

	/* Initialize MinHook. */
	if ((st = MH_Initialize()) != MH_OK) {
		dprintf("ag_init, failed to initialize MinHook (%d)\n", st);
		return (FALSE);
	}

	pipe = dt_create_pipe(0, 1024, proc_func);
	td = dt_pipe_wait(pipe);
	_agent_tid = GetThreadId(td);
	_proc_pid = GetCurrentProcessId();
	ag_init_evarc();
	init_alloc();
	return (TRUE);
}

static int
swap_evarc(etw_evarc_t *add_list, uintptr_t offset)
{
	etw_evarc_t *temp;

	send_events(event_add_list);
	memset(event_add_list->addr, 0, sizeof(event_add_list->addr));
	event_add_list->co = 0;
	event_add_list->off = &event_add_list->addr[0];

	return (0);
}

static void
purge_events()
{
	swap_evarc(event_add_list, event_add_list->off);
}

#define	MAX_PAYLOAD_DESCRIPTORS0 3

static int
send_events(etw_evarc_t *send)
{
	EVENT_DATA_DESCRIPTOR Descriptors[MAX_PAYLOAD_DESCRIPTORS0];
	int size =  send->off - (uint64_t) &send->addr[0];
	ULONG st = 0, co = 0;

	EventDataDescCreate(&Descriptors[0], &send->co, sizeof (UINT32));
	EventDataDescCreate(&Descriptors[1], &size, sizeof (UINT32));
	EventDataDescCreate(&Descriptors[2], send->addr, size);

	st = EventWrite(RegHandle, &Events, 3, Descriptors);

	if (_debug) {
		if (st != ERROR_SUCCESS) {
			dropped++; 		/* diagnostics */
			return (-1);
		}
		blobsent++;
		blobevents += d_msg_count(send->addr, size);
	}

	return (0);
}

static int
ev_addarc(uintptr_t paddr, uint32_t id, uintptr_t arg0,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4, uintptr_t ax, int32_t tid, int32_t cpuno, hrtime_t time,
    uint64_t *stack,
    int stsz, int type)
{
	int noff = 0, i;
	etw_evarc_t *temp;
	uint64_t *addr, *tmp, noffp;
	ftetw_msg_t *ev;
	LARGE_INTEGER  Time;

	//noff = (stsz + FT_ETW_EVENT_SIZE) * sizeof (uint64_t);
	//stsz += type;
	noff = (stsz + type) * sizeof (uint64_t) + sizeof(ftetw_msg_t);
	while (InterlockedCompareExchange(&thread_lock, 1, 0) != 0)
		;
	//etw_mutex_enter(&test_lock);
	while (1) {

		addr = event_add_list->off;
		noffp = (uint64_t) addr + noff;
		if (noffp >= event_add_list->end) {
			if (swap_evarc(event_add_list, addr) < 0) {
				return (-1);
			}
			continue;
		}

		event_add_list->off = noffp;
		break;
	}

	ev = addr;
	ev->type = type;
	ev->time = time;
	ev->addr = paddr;
	ev->pid = _proc_pid;
	ev->tid = tid;
	ev->cpuno = cpuno;
	ev->stacksz = stsz + type;
	if (type == INJ_ENTRY_TYPE) {
		ev->stack[0] = arg0;
		ev->stack[1] = arg1;
		ev->stack[2] = arg2;
		ev->stack[3] = arg3;
		ev->stack[4] = arg4;
	} else {
		ev->stack[0] = ax;
	}

	tmp = &ev->stack[type];

	for (i = 0; i < stsz; i++) {
		tmp[i] = stack[i];
	}
	tmp[i] = 0;

	event_add_list->co++;
	//etw_mutex_exit(&test_lock);
	InterlockedExchange(&thread_lock, 0);
	return (0);
}

#ifdef _WIN64

/* http://www.nynaeve.net/Code/StackWalk64.cpp */
#define	UNW_FLAG_NHANDLER 0x0

static int
StackTrace(uint64_t *pcstack, uintptr_t ip, uintptr_t sp,
    int limit, int aframes)
{
	CONTEXT Context;
	KNONVOLATILE_CONTEXT_POINTERS NvContext;
	UNWIND_HISTORY_TABLE UnwindHistoryTable;
	PRUNTIME_FUNCTION RuntimeFunction;
	PVOID HandlerData;
	ULONG64 EstablisherFrame;
	ULONG64 ImageBase;
	int depth = 0;

	__try {
		RtlCaptureContext(&Context);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return (0);
	}

	RtlZeroMemory(&UnwindHistoryTable, sizeof (UNWIND_HISTORY_TABLE));

	/*
	 * This unwind loop intentionally skips the first call frame,
	 * as it shall correspond to the call to StackTrace64,
	 * which we aren't interested in.
	 */
	while (depth < limit) {
		/* Try to look up unwind metadata for the current function. */
		RuntimeFunction = RtlLookupFunctionEntry(Context.Rip,
		    &ImageBase, &UnwindHistoryTable);
		RtlZeroMemory(&NvContext,
		    sizeof (KNONVOLATILE_CONTEXT_POINTERS));

		if (!RuntimeFunction) {
			/*
			 * If we don't have a RUNTIME_FUNCTION, then
			 * we've encountered a leaf function.
			 * Adjust the stack approprately.
			 */
			__try {
				Context.Rip  =
				(ULONG64)(*(PULONG64)Context.Rsp);
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				return (depth);
			}
			Context.Rsp += 8;
		} else {
			/* call RtlVirtualUnwind to execute the unwind for us */
			__try {
				RtlVirtualUnwind(UNW_FLAG_NHANDLER, ImageBase,
				    Context.Rip, RuntimeFunction, &Context,
				    &HandlerData, &EstablisherFrame,
				    &NvContext);
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				return (depth);
			}
		}

		/*
		 * If we reach an RIP of zero, this means that we've walked
		 * off the end of the call stack and are done.
		 */
		if (!Context.Rip)
			break;
		if (aframes > 0) {
			aframes--;
			if ((aframes == 0) && (ip != 0)) {
				pcstack[depth++] = ip;
			}
		} else {
			pcstack[depth++] = Context.Rip;
		}
	}

	return (depth);
}
#else
struct frame {
	struct frame *f_frame;
	uintptr_t f_retaddr;
};

static int
StackTrace(uint64_t *pcstack, uintptr_t ip, uintptr_t sp,
    int limit, int aframes)
{
	CONTEXT Context;
	struct frame *frames;
	uintptr_t callpc;
	int depth = 0;

	RtlCaptureContext(&Context);
	frames = (struct frame *) Context.Ebp;
	while (frames && depth < limit) {
		__try {
			callpc = frames->f_retaddr;
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			break;
		}

		if (aframes > 0) {
			aframes--;
			if ((aframes == 0) && (ip != 0)) {
				pcstack[depth++] = ip;
			}
		} else {
			pcstack[depth++] = callpc;
		}
		frames = frames->f_frame;
	}

	return (depth);
}
#endif

/*
 * CaptureStackBackTrace, will not work, beacause the
 * injected trampoline code is not within loaded module range.
 * http://win32easy.blogspot.com/2011/03/rtlcapturestackbacktrace-in-managed.html
 */

enum {
	STACKSIZE = 256,
};

void
Etw(void* funcaddr, Context* ct, unsigned a_ContextSize, int type)
{
	struct Tls *tls = NULL;
	EVENT_DATA_DESCRIPTOR Descriptors[MAX_PAYLOAD_DESCRIPTORS];
	DWORD id = 0, n = 0, size = 0, st;
	uint64_t stacks[STACKSIZE], s5 = 0;
	static hrtime_t ts = 0;
	hrtime_t ts0;
	int32_t cpuno;
	LARGE_INTEGER Time;
	DWORD tid = GetCurrentThreadId();

	if (tid == _agent_tid ||  (tls = lookup_tid(tid)) == NULL || tls->in) {
		return;
	}

	tls->in = 1;

	if (ETWTYPE) {
		ts0 = gethrtime();
		if (ts && (ts0 - ts) < ONE0MSEC) {
			ETWTYPE = 0;
		}
		ts = ts0;
	}

	if (_stackon) {
#if defined(_M_X64) || defined(__x86_64__)
		n = StackTrace(stacks, funcaddr, &ct->m_RET, STACKSIZE, 3);
#else
		n = StackTrace(stacks, funcaddr, &ct->m_RET, STACKSIZE, 2);
#endif
	}
	size = n * sizeof (uintptr_t);

#if defined(_M_X64) || defined(__x86_64__)
	if (ETWTYPE == 1) {
		if (type == INJ_ENTRY_TYPE) {
			EventDataDescCreate(&Descriptors[0], &size, sizeof (UINT32));
			EventDataDescCreate(&Descriptors[1], &funcaddr, sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[2], &ct->m_RCX, sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[3], &ct->m_RDX, sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[4], &ct->m_R8, sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[5], &ct->m_R9, sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[6], &s5, sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[7], stacks, size);
			st = EventWrite(RegHandle, &Entry, 8, Descriptors);
		} else {
			EventDataDescCreate(&Descriptors[0], &size, sizeof (UINT32));
			EventDataDescCreate(&Descriptors[1], &funcaddr, sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[2], &ct->m_RAX, sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[3], stacks, size);
			st = EventWrite(RegHandle, &Return, 4, Descriptors);
		}
		DIAG(st)
	} else {
		QueryPerformanceCounter(&Time);
		cpuno = GetCurrentProcessorNumber();

		ev_addarc((uintptr_t) funcaddr, id, ct->m_RCX,
		    ct->m_RDX, ct->m_R8, ct->m_R9, s5, ct->m_RAX, tid, cpuno, Time.QuadPart, stacks,
		    n, type);
	}
#else
	uint32_t *stack = (uint32_t *) &ct->m_RET;

	if (ETWTYPE == 1) {
		if (type == INJ_ENTRY_TYPE) {
			EventDataDescCreate(&Descriptors[0], &size, sizeof (UINT32));
			EventDataDescCreate(&Descriptors[1], &funcaddr, sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[2], &stack[1], sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[3], &stack[2], sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[4], &stack[3], sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[5], &stack[4], sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[6], &stack[5], sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[7], stacks, size);

			st = EventWrite(RegHandle, &Entry, 8, Descriptors);
		} else {
			EventDataDescCreate(&Descriptors[0], &size, sizeof (UINT32));
			EventDataDescCreate(&Descriptors[1], &funcaddr, sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[2], &(ct->m_EAX), sizeof (uint64_t));
			EventDataDescCreate(&Descriptors[3], stacks, size);

			st = EventWrite(RegHandle, &Return, 9, Descriptors);
		}

		DIAG(st)
	} else {

		QueryPerformanceCounter(&Time);
		cpuno = GetCurrentProcessorNumber();
		ev_addarc((uintptr_t) funcaddr, id, stack[1], 
		    stack[2], stack[3], stack[4], stack[5],
		    ct->m_EAX, tid, cpuno, Time.QuadPart, stacks, n, type);
	}
#endif

	tls->in = 0;
	tls->tid = 0;
}

void
PrologEtw(void* funcaddr, Context* ct, unsigned a_ContextSize)
{
	Etw(funcaddr, ct, a_ContextSize, INJ_ENTRY_TYPE);
}

void
EpilogEtw(void* funcaddr, Context* ct, unsigned a_ContextSize)
{
	Etw(funcaddr, ct, a_ContextSize, INJ_RETURN_TYPE);
}

dt_pipe_t *
proc_func(dt_pipe_t *pipe)
{
	dt_pmsg_t rmsg = {0}, *msg;
	MH_STATUS st = MH_OK;

	msg = (dt_pmsg_t *) pipe->hmap;

	rmsg.id = PIPE_DONE;
	rmsg.size = sizeof (dt_pmsg_t);

	switch (msg->id) {
	case PIPE_HOOK_FUNC: {
		dt_msg_func_t *f = (dt_msg_func_t *) msg->data;

		if (f->type == PIPE_FUNC_ENTER) {
			st = MH_Orbit_CreateHookPrologEpilog((LPVOID) f->addr,
			    f->faddr, PrologEtw, NULL, NULL, 0);
		} else {
			st = MH_Orbit_CreateHookPrologEpilog((LPVOID) f->addr,
			    f->faddr, EpilogEtw /* EpilogEtw64 */,
			    NULL, NULL, 0);
		}
		break;
	}
	case PIPE_FUNC_ENABLE: {
		dt_msg_func_t *f = (dt_msg_func_t *)  msg->data;
		st = MH_QueueEnableHook((LPVOID) f->addr);
		break;
	}
	case PIPE_FUNC_DISABLE: {
		dt_msg_func_t *f = (dt_msg_func_t *)  msg->data;
		st = MH_QueueDisableHook((LPVOID) f->addr);
		break;
	}
	case PIPE_QUEUE_CLEAR: {
		dt_msg_func_t *f = (dt_msg_func_t *)  msg->data;
		st = MH_ApplyQueued();
		break;
	}
	case PIPE_WAIT_TID: {
		rmsg.id = _agent_tid;
		break;
	}
	case PIPE_WITH_STACKS: {
		_stackon = 1;
		break;
	}
	case PIPE_CLOSE: {
		dprintf("Freeing library and existing thread\n");
		memcpy((void *) pipe->hmap, &rmsg, rmsg.size);
		dt_unload_msg(pipe);
		FreeLibraryAndExitThread(agentdll, 0);
		break;
	}
	default:
		break;
	}

	if (st != MH_OK) {
		rmsg.id = PIPE_ERROR;
	}

	memcpy((void *) pipe->hmap, &rmsg, rmsg.size);

	return (pipe);
}

BOOL WINAPI
DllMain(HMODULE DllHandle, DWORD Reason, PVOID Reserved)
{
	UNREFERENCED_PARAMETER(DllHandle);
	UNREFERENCED_PARAMETER(Reserved);

	if (DLL_PROCESS_ATTACH == Reason) {
		return (ag_init());
	} else if (DLL_THREAD_DETACH == Reason) {
		return (TRUE);
	} else if (DLL_PROCESS_DETACH == Reason) {
		EVENT_DATA_DESCRIPTOR Descriptors[1];
		UINT32 status = 0;

		if (ETWTYPE == 0)
			purge_events();

		EventDataDescCreate(&Descriptors[0], &status, sizeof (UINT32));
		EventWrite(RegHandle, &Status, 1, Descriptors);
		EventUnregister(RegHandle);
		dprintf("Events (%d) Packets (%d) Dropped (%d) linked list length (%d)\n",
		    blobevents + events, blobsent + eventsent, dropped, lllen);

		return (TRUE);
	} else {
		return (TRUE);
	}
}