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
 * Copyright (C) 2019, PK
 */

#define	INITGUID  // Include this #define to use SystemTraceControlGuid in Evntrace.h.

#include <sys/dtrace_misc.h>
#include <libelf.h>
#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <stdint.h>
#include <signal.h>
#include <wmistr.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <Shlwapi.h>
#include "common.h"
#include <etw.h>
#include "etw_struct.h"
#include "etw_private.h"

#include <functional>

#define LOGGER_NAME_SIZE	256
#define LOGGER_FILENAME_SIZE 1024

struct etw_sessioninfo *dtrace_etw_sessions[DT_ETW_MAX_SESSION] = {0};
/*
 * ETW processing thread data
 */
__declspec(thread) static struct sessioninfo *sessinfo = NULL;
__declspec(thread) static thread_t missing_thread = {0};
__declspec(thread) static proc_t missing_proc = {0};

static HANDLE etw_eventcb_lock;
static HANDLE etw_cur_lock;
static HANDLE etw_proc_lock;
static HANDLE etw_thread_lock;
static HANDLE etw_start_lock;

static int (*etw_diag_cb) (PEVENT_RECORD, void *) = NULL;
static uint32_t etw_diag_flags = 0;

static etw_dbg_t pdbsyms = {0};		/* dbghelp link of modules with pdb */
static etw_dbg_t nopdbsyms = {0};	/* dbghelp link of modules without pdb */

uint64_t kernellmts[2][2] = {
	{0x7FFFFFFF, 0xFFFFFFFF},
	{0x7ffffffeffff, ~(0)}
};

#define FILESESSION(sess)	((sess)->flags & SESSINFO_ISFILE)

/* specialized hash function for unordered_map keys */
struct hash_fn {
	std::size_t
	operator() (const GUID &guid) const {
		std::size_t h1 = std::hash<ULONG>()(guid.Data1);
		std::size_t h2 = std::hash<ULONG>()(guid.Data2);

		return (h1 ^ h2);
	}
};

static unordered_map<GUID, Functions, hash_fn> eventfuncs;	/* event cb map */
static unordered_map<pid_t, proc_t *> proclist;				/* etw process map */
static unordered_map<pid_t, thread_t *> threadlist;			/* etw thread map */
static unordered_map<wstring, etw_module_t *> modlist;		/* etw loaded modules */
static map<wstring, wstring, std::greater<wstring>>
devmap;	/* device path to pathname */
static unordered_map<uetwptr_t, uintptr_t> fileiomap;		/* open files */
static unordered_map<GUID, cvpdbinfo_t *, hash_fn>
cvinfolist; /* modules pdb info */
static map<uint32_t, etw_jitsym_map_t> pid_jit_symtable;		/* jit symbol map */

#define	ETW_PROC_MISSING_NAME "<not yet>"

static int sdt_temp_size = 1024 * 1024;

/*
 * map jitted module, module ID = module name
 */
static etw_jit_module_t *
etw_add_jit_module(pid_t pid, etw_jit_module_t *mod, int len)
{
	etw_jitsym_map_t& symmap = pid_jit_symtable[pid];
	int len0 = wcslen((wchar_t *) &mod->ModuleILPath);
	wchar_t *modn = (wchar_t *) mem_zalloc((len0 + 1) * sizeof (wchar_t));
	wcscpy(modn, (wchar_t *) &mod->ModuleILPath);
	symmap.jit_modules[mod->ModuleID] = modn;

	return (mod);
}

/*
 * add jitted function to map
 */
static etw_jit_symbol_t *
etw_add_jit_sym(pid_t pid, etw_jit_symbol_t *sym, int len)
{
	etw_jit_symbol_t *tsym = (etw_jit_symbol_t *) mem_zalloc(len);

	memcpy(tsym, sym, len);
	etw_jitsym_map_t& symmap = pid_jit_symtable[pid];
	symmap.jit_syms.push_back(tsym);
	symmap.sorted = 0;

	return (tsym);
}

/*
 * ETW event callback for MSDotNETRuntimeRundown provider
 * for jitted module and functions
 */
int
clr_jitted_rd_func(PEVENT_RECORD ev, void *data)
{
	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId,
	    MSDotNETRuntimeRundownGuid));

	USHORT eventid = ev->EventHeader.EventDescriptor.Id;

	if (eventid == 143) { /* Method */
		etw_add_jit_sym(ev->EventHeader.ProcessId,
		    (etw_jit_symbol_t *) ev->UserData,
		    ev->UserDataLength);
	} else if (eventid == 153) { /* Module */
		etw_add_jit_module(ev->EventHeader.ProcessId,
		    (etw_jit_module_t *) ev->UserData,
		    ev->UserDataLength);
	}
	return (0);
}

/*
 * ETW event callback for MSDotNETRuntime provider
 * for jitted module and functions
 */
static int
clr_jitted_func(PEVENT_RECORD ev, void *data)
{
	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, MSDotNETRuntimeGuid));
	USHORT eventid = ev->EventHeader.EventDescriptor.Id;

	if (eventid == 143) { /* Method */
		etw_add_jit_sym(ev->EventHeader.ProcessId,
		    (etw_jit_symbol_t *) ev->UserData,
		    ev->UserDataLength);
	} else if (eventid == 152) { /* Module */
		etw_add_jit_module(ev->EventHeader.ProcessId,
		    (etw_jit_module_t *) ev->UserData,
		    ev->UserDataLength);
	} else if (eventid == 82) { /* Stack ? native or .net */
		struct netstack82 *sw = (struct netstack82 *) ev->UserData;
		etw_sessioninfo_t *sess = sessinfo->etw;
		int cpuno = ev->BufferContext.ProcessorNumber;
		etw_stack_t *stackp =
		    (etw_stack_t *) lookuphm(&sess->Q.map[ev->BufferContext.ProcessorNumber],
		    sw->clr_instid, hashint64, cmpint64);
		for (uint32_t i = 0; i < sess->ncpus && stackp == NULL; i++) {
			stackp =
			    (etw_stack_t *) lookuphm(&sess->Q.map[i], sw->clr_instid, hashint64, cmpint64);
			cpuno = i;
		}

		if (stackp == NULL) {
			if (etw_diag_flags & ~SDT_DIAG_NSTACK_EVENTS) {
				etw_diag_cb(ev,  (void *) SDT_DIAG_NSTACK_EVENTS);
			}
			return (0);
		}

		ASSERT(stackp != NULL);
		int ptrsz = stackp->dprobe.proc->model == 0 ? 4 : 8;
		int offset = (sizeof (struct netstack82) - ptrsz);
		int depth = (ev->UserDataLength - offset) / ptrsz;
		if (depth + stackp->stacklen > ETW_MAX_STACK) {
			depth = ETW_MAX_STACK - stackp->stacklen;
		}

		if (depth) {
			int j = stackp->stacklen;
			if (ptrsz == 4) {
				uint32_t *pc = (uint32_t *) ((char *)ev->UserData + offset);
				for (int i = 0 ; i < depth; i++)
					stackp->stack[j++] = (uint64_t) pc[i];
			} else {
				uint64_t *pc = (uint64_t *) ((char *)ev->UserData + offset);
				for (int i = 0 ; i < depth; i++)
					stackp->stack[j++] = pc[i];
			}

			stackp->stacklen += depth;
			stackp->stackready = 1;
		}
		erasehm(&sess->Q.map[cpuno], stackp->key, hashint64,
		    cmpint64);
		stackp->key = 0;
	}

	return (0);
}

int
dtrace_dnet_stack_func(PEVENT_RECORD ev, void *data)
{
	return clr_jitted_func(ev, data);
}

static bool
jit_sym_cmp(etw_jit_symbol_t *sym0, etw_jit_symbol_t *sym1)
{
	return (sym0->MethodStartAddress < sym1->MethodStartAddress);
}

static proc_t *
etw_get_proc(pid_t pid, int create)
{
	proc_t *p = NULL;

	if (!FILESESSION(dtrace_etw_sessions[0]))
		wmutex_enter(&etw_proc_lock);

	p = proclist[pid];
	if (p == NULL && create) {
		switch (create) {
		case ETW_PROC_CREATE_LIVE: {
			p = (proc_t *) mem_zalloc(sizeof (proc_t));
			p->pid = pid;
			p->handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
			    PROCESS_VM_WRITE, FALSE, pid);
			if (p->handle) {
				BOOL wow = 0;
				IsWow64Process(p->handle, &wow);
				p->model = !wow;
			} else {
				p->model = 1;
			}
			HMODULE hMod;
			DWORD cbNeeded;
			char *szProcessName = (char *) mem_zalloc(MAX_PATH);

			if (EnumProcessModules(p->handle, &hMod, sizeof (hMod),
			    &cbNeeded)) {
				GetModuleBaseNameA(p->handle, hMod, szProcessName,
				    sizeof (szProcessName) / sizeof (char));
				p->name = _strlwr(szProcessName);
			}

			proclist[pid] = p;
			break;
		}
		case ETW_PROC_TEMP: {
			ZeroMemory(&missing_proc, sizeof (proc_t));
			missing_proc.pid = pid;
			missing_proc.name = ETW_PROC_MISSING_NAME;
			p = &missing_proc;
			break;
		}
		case ETW_PROC_CREATE: {
			p = (proc_t *) mem_zalloc(sizeof (proc_t));
			p->pid = pid;
			p->name = ETW_PROC_MISSING_NAME;
			proclist[pid] = p;
			break;
		}
		default:
			p = NULL;
			break;
		}
	}
	if (!FILESESSION(dtrace_etw_sessions[0]))
		wmutex_exit(&etw_proc_lock);

	return (p);
}

static thread_t *
etw_get_td(pid_t tid, pid_t pid, int create)
{
	thread_t *td = NULL;

	if (!FILESESSION(dtrace_etw_sessions[0]))
		wmutex_enter(&etw_thread_lock);
	td = threadlist[tid];

	if (td && pid != -1 && td->pid != pid) {
		td->pid = pid;
		td->proc = etw_get_proc(pid, ETW_PROC_CREATE);
	}

	if (td == NULL && create) {
		if (create == ETW_THREAD_CREATE) {
			td = (thread_t *) mem_zalloc(sizeof (thread_t));
			td->pid = pid;
			td->tid = tid;
			td->proc = etw_get_proc(pid, ETW_PROC_CREATE);
			threadlist[tid] = td;
		} else if (create == ETW_THREAD_TEMP) {
			ZeroMemory(&missing_thread, sizeof (thread_t));
			missing_thread.tid = tid;
			missing_thread.pid = pid;
			missing_thread.proc = etw_get_proc(pid, ETW_PROC_TEMP);
			td = &missing_thread;
		} else {
			td = NULL;
		}
	}

	if (!FILESESSION(dtrace_etw_sessions[0]))
		wmutex_exit(&etw_thread_lock);

	return (td);
}

/*
 *	set the current parameters
 */
static HANDLE *
etw_set_cur(pid_t pid, pid_t tid, hrtime_t tm, int cpuno)
{
	/* wmutex_enter(&etw_cur_lock); */
	sessinfo->timestamp = tm;
	sessinfo->cpuno = cpuno;
	sessinfo->pid = pid;
	sessinfo->tid = tid;
	sessinfo->td = etw_get_td(tid, pid, ETW_THREAD_TEMP);
	if (sessinfo->td) {
		sessinfo->td->cpu = cpuno;
	}
	sessinfo->proc = sessinfo->td->proc ? sessinfo->td->proc :
	    etw_get_proc(pid, ETW_PROC_TEMP);

	return (&etw_cur_lock);
}

static void
etw_reset_cur(HANDLE *lock)
{
	/* wmutex_exit(lock); */
}

/*
 * Matches the event to the stack, before sending to dtrace
 */
static void
etw_send_dprobe(etw_stack_t *stackp)
{
	etw_dprobe_t *dprobes;
	HANDLE *lock;

dprobes = &stackp->dprobe;

lock = etw_set_cur(dprobes->pid, dprobes->tid, dprobes->ts,
	    dprobes->cpuno);

	sessinfo->etw->dtrace_probef(dprobes->id, dprobes->args[0],
	    dprobes->args[1], dprobes->args[2],
	    dprobes->args[3], dprobes->args[4]);

	etw_reset_cur(lock);
}

void
send_probe(etw_sessioninfo_t *sess)
{
	etw_stack_t *stackp;
	stackp = sess->Q.queue.front();
	sess->stackinfo = stackp;
	sess->Q.queue.pop();
	erasehm(&sess->Q.map[stackp->dprobe.cpuno], stackp->key, hashint64,
	    cmpint64);
	etw_send_dprobe(stackp);
	esfree(stackp);
}

/*
 * Send all pending events to dtrace, without waiting for stack
 * events
 */
static void
etw_event_purge()
{
	etw_stack_t *stackp;
	etw_sessioninfo_t *sess = sessinfo->etw;

	while (InterlockedExchange(&sess->Q.lock, TRUE) == TRUE)
		Sleep(1);

	while (sess->Q.queue.size()) {
		send_probe(sess);
	}
	InterlockedExchange(&sess->Q.lock, FALSE);
}

/*
 * Event callback helper routines
 */

static Functions&
evfuncsforguid(const GUID *pguid)
{
	wmutex_enter(&etw_eventcb_lock);
	Functions& vf = eventfuncs[*pguid];
	wmutex_exit(&etw_eventcb_lock);

	return (vf);
}

/*
 * Add event callback function to the cb map, in the place
 * specified within the event cb array.
 * Returns 0 on success
 */
static int
etw_hook_event(const GUID *guid, Function efunc, void *data,
    int place, BOOL isntlog)
{
	wmutex_enter(&etw_eventcb_lock);

	Functions& vf = eventfuncs[*guid];
	Functions::iterator iter = vf.begin();

	while (iter != vf.end()) {
		Pair ef = *iter;
		if (ef.first == efunc && ef.second == data) {
			wmutex_exit(&etw_eventcb_lock);
			dprintf("etw_hook_event, cb already present: cb %p, arg %p\n", efunc,
			    data);
			return (-1);
		}
		iter++;
	}

	Pair func = std::make_pair(efunc, data);

	if (place == ETW_EVENTCB_ORDER_ANY) {
		if (vf.begin() == vf.end())
			vf.push_back(func);
		else
			vf.insert(++vf.begin(), func);
	} else if (place == ETW_EVENTCB_ORDER_FRIST) {
		vf.insert(vf.begin(), func);
	} else {
		vf.push_back(func);
	}
	wmutex_exit(&etw_eventcb_lock);
	dprintf("etw_hook_event, added cb (%p) arg (%p)\n", efunc, data);

	return (0);
}

/*
 * Remove event cb from the cb map
 */
static int
etw_unhook_event(const GUID *guid, Function efunc, void *data,
    BOOL all)
{
	wmutex_enter(&etw_eventcb_lock);

	Functions& vf = eventfuncs[*guid];
	Functions::iterator iter = vf.begin();


	while (iter != vf.end()) {
		Pair ef = *iter;
		if (all) {
			dprintf("etw_unhook_event, removed cb %p arg %p\n", ef.first,
			    ef.second);
			vf.erase(iter);
			iter = vf.begin();
			continue;
		}
		if (ef.first == efunc && ef.second == data) {
			vf.erase(iter);
			dprintf("etw_unhook_event, removed cb %p arg %p\n", efunc, data);
			wmutex_exit(&etw_eventcb_lock);
			return (0);
		}
		iter++;
	}

	wmutex_exit(&etw_eventcb_lock);
	if (!all)
		dprintf("etw_unhook_event, failed to remove cb %p arg %p\n",
		    efunc, data);

	return (-1);
}

void
etw_stop_ft()
{
	etw_unhook_event(&FastTrapGuid, NULL, NULL, TRUE);
	//dtrace_etw_sessions[DT_ETW_FT_SESSION] = NULL;
}

/*
 * timebase and scaling factor to convert etw event timestamp to nanosec timestamp.
 * https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header
 */
static void
etw_event_timebase(etw_sessioninfo_t *sess, hrtime_t starttime, hrtime_t ts)
{
	sess->starttime = starttime;

	switch (sess->clctype) {
	case 1: /* QPC */
		sess->timescale = 10000000.0 / sess->perffreq;
		sess->timebase = sess->starttime - (sess->timescale * ts);
		break;
	case 2: /* SYSTEM TIME */
		sess->timebase = 0;
		sess->timescale = 1.0;
		break;
	case 3:
		sess->timescale = 10 / sess->cpumhz;
		sess->timebase = sess->starttime - (sess->timescale * ts);
		break;
	default:
		ASSERT(0);
	}
}

static void
event_cb(Functions& funcs, PEVENT_RECORD ev)
{
	sessioninfo stmp = {0};
	Functions::iterator end, iter = funcs.begin();

	end = iter;

	sessinfo->timestamp = ev->EventHeader.TimeStamp.QuadPart;
	sessinfo->cpuno = ev->BufferContext.ProcessorNumber;
	sessinfo->tid = ev->EventHeader.ThreadId;
	sessinfo->pid = ev->EventHeader.ProcessId;
	sessinfo->td = etw_get_td(sessinfo->tid, sessinfo->pid,
	    ETW_THREAD_TEMP);
	sessinfo->proc = etw_get_proc(sessinfo->pid, ETW_PROC_TEMP);
	sessinfo->payload = 0;

	memcpy(&stmp, sessinfo, sizeof(sessioninfo));
	while (iter != funcs.end()) {
		memcpy(sessinfo, &stmp, sizeof(sessioninfo));
		((*iter).first)(ev, (*iter).second);
		iter++;
	}

	/* diagnostic event provider for etw. */
	if (end == iter) {
		/*
		 * if any event not caught by any probes,
		 * send to diag provider.
		 */
		if (etw_diag_flags & ~SDT_DIAG_IGNORED_EVENTS) {
			memcpy(sessinfo, &stmp, sizeof(sessioninfo));
			etw_diag_cb(ev, (void *) SDT_DIAG_IGNORED_EVENTS);
		}
	} else {
		sessinfo->etw->hb++;
	}

	if (etw_diag_flags & ~SDT_DIAG_ALL_EVENTS) {
		memcpy(sessinfo, &stmp, sizeof(sessioninfo));
		etw_diag_cb(ev, (void *) SDT_DIAG_ALL_EVENTS);
	}
}

/*
 * Only called for the first time, to get initial start time of the
 * trace, which is used in calculate the actual time for the subsequent
 * events.
 */
static void
first_event_cb(Functions& funcs, PEVENT_RECORD ev)
{
	if (ev->EventHeader.TimeStamp.QuadPart == 0) {
		ASSERT(FILESESSION(sessinfo->etw) == 0);
		return;
	}

	if (FILESESSION(sessinfo->etw) == 0) {
		ASSERT(ev->EventHeader.TimeStamp.QuadPart != 0);

		etw_event_timebase(sessinfo->etw, sessinfo->etw->starttime,
		    ev->EventHeader.TimeStamp.QuadPart);
	} else {
		TRACE_LOGFILE_HEADER *hd = (TRACE_LOGFILE_HEADER *) ev->UserData;
		etw_event_timebase(sessinfo->etw, hd->StartTime.QuadPart,
		    ev->EventHeader.TimeStamp.QuadPart);
	}
	sessinfo->timestamp = ev->EventHeader.TimeStamp.QuadPart;
	sessinfo->cpuno = ev->BufferContext.ProcessorNumber;
	sessinfo->tid = ev->EventHeader.ThreadId;
	sessinfo->pid = ev->EventHeader.ProcessId;


	wmutex_exit(&etw_eventcb_lock);
	wmutex_enter(&etw_start_lock);
	wmutex_exit(&etw_start_lock);
	wmutex_enter(&etw_eventcb_lock);
	sessinfo->etw->evcb = event_cb;
	sessinfo->etw->evcb(funcs, ev);
}

/*
 * ETW helper thread.
 */
static DWORD WINAPI
etw_event_thread(void* data)
{
	int notyet = 0, id = 0;
	ULONG error;
	sessioninfo_t *tsinfo;
	static int frmfile = dtrace_etw_sessions[0] == NULL ||
	    FILESESSION(dtrace_etw_sessions[0]);

	etw_sessioninfo_t *sinfo = (etw_sessioninfo_t *) data;
	tsinfo = (sessioninfo_t *) mem_zalloc(sizeof (sessioninfo_t));
	tsinfo->etw = sinfo;
	sinfo->sessinfo = tsinfo;
	sessinfo = tsinfo;
	sinfo->evcb = first_event_cb;
	sinfo->flags |= SESSINFO_ISLIVE;
	error = ProcessTrace(&sinfo->psession, 1, 0, 0);
	sinfo->flags &= ~SESSINFO_ISLIVE;

	if (error != ERROR_SUCCESS) {
		eprintf("etw_event_thread, ProcessTrace failed: session (%ls) error (%d)\n",
		    sinfo->sessname, error);
		return (-1);
	}
	/* process all pending events, without waiting for stacks */
	etw_event_purge();

	/* if reading from a file send stop signal to dtrace, to end dtrace session */
	for (int i = 0; i < DT_ETW_MAX_SESSION; i++) {
		if (dtrace_etw_sessions[i] != NULL) {
			if (dtrace_etw_sessions[i] == sinfo) {
				sinfo->flags |= SESSINFO_DONE;
			} else {
				if ((sinfo->flags & SESSINFO_DONE) == 0)
					notyet = 1;
			}
		}
	}

	if (!notyet && frmfile) {
		raise(2);
	}

	return (0);
}

/*
 * ETW event callback processing function.
 */

/*
 * etw event cb
 */
static void WINAPI
etw_event_cb(PEVENT_RECORD ev)
{
	wmutex_enter(&etw_eventcb_lock);
	/* copy of funcs, callback can remove itself */
	Functions funcs = eventfuncs[ev->EventHeader.ProviderId];

	sessinfo->etw->ev = ev;
	sessinfo->etw->evcb(funcs, ev);
	wmutex_exit(&etw_eventcb_lock);
}

/*
 * ETW parameter setting functions
 */

static proc_t *
etw_add_proc(pid_t pid, proc_t *p)
{
	wmutex_enter(&etw_proc_lock);
	proclist[pid] = p;
	wmutex_exit(&etw_proc_lock);

	return (p);
}

static thread_t *
etw_add_thread(pid_t tid, thread_t *td)
{
	wmutex_enter(&etw_thread_lock);
	threadlist[tid] = td;
	wmutex_exit(&etw_thread_lock);

	return (td);
}

static etw_module_t *
etw_add_module(etw_module_t *mod, wstring wstr)
{
	modlist[wstr] = mod;

	return (mod);
}

static wchar_t *
etw_get_fname(uetwptr_t fobj)
{
	if (fileiomap.find(fobj) == fileiomap.end())
		return (NULL);

	return ((wchar_t *) fileiomap[fobj]);
}

/*
 * Normalize pathnames
 */
static wchar_t *
etw_rep_dev_to_path(wchar_t *str)
{
	size_t l0, l1, len;
	int fnd = 0;

	for (map<wstring, wstring>::iterator iter = devmap.begin();
	    iter != devmap.end(); iter++) {

		l0 =  wcslen(&iter->first[0]);
		if (wcsncmp(str, &iter->first[0], l0) == 0) {
			l1 = wcslen(&iter->second[0]);
			if (l0 > l1) {
				wcsncpy(str, &iter->second[0], l1);
				if (*(str + (l0)) == L'\\')
					l0 += 1;
				wcscpy(str + l1, str + l0);
			} else {
				wchar_t tmp[MAX_PATH] = {0};
				wcscpy(tmp, str);
				len = wcslen(str) + 1 + (l1 - l0);
				wcsncpy(str, &iter->second[0], l1);
				wcscpy(str + l1, tmp + l0);
			}
			fnd = 1;
			break;
		}
	}

	// path name begining with \\ instead of drive letter
	// skip \\Device (\\HarddiskVolumeShadowCopy)
	int cmp = wcsncmp(L"\\Device", str, 7);
	if (!fnd && str[0] == L'\\' && cmp) {
		DWORD drive = GetLogicalDrives();
		WCHAR dl = L'A';
		DWORD mask = 1;
		WCHAR path[MAX_PATH];
		while (drive) {
			if (drive & mask) {
				path[0] = dl;
				path[1] = L':';
				wcscpy(path + 2, str);
				if (PathFileExistsW(path)) {
					wcscpy(str, path);
					break;
				}
			}
			drive = drive & (~mask);
			mask <<= 1;
			dl++;
		}
	}

	return (str);
}

/*
 * Returns nanoseconds since boot.
 */
static hrtime_t
sys_gethrtime()
{
	hrtime_t ret;
	LARGE_INTEGER Frequency;
	LARGE_INTEGER StartingTime, Time;
	static hrtime_t frequency = 0;

	if (frequency == 0) {
		QueryPerformanceFrequency(&Frequency);
		frequency = NANOSEC / Frequency.QuadPart;
	}
	QueryPerformanceCounter(&StartingTime);
	ret = (StartingTime.QuadPart) * frequency;

	return (ret);
}

/* system time in nanoseconds */
static hrtime_t
sys_gethrestime(void)
{
	ULARGE_INTEGER SystemTime;
	FILETIME FileTime;
	hrtime_t ret;

	GetSystemTimeAsFileTime(&FileTime);
	SystemTime.LowPart = FileTime.dwLowDateTime;
	SystemTime.HighPart = FileTime.dwHighDateTime;
	ret = ((SystemTime.QuadPart - PTW32_TIMESPEC_TO_FILETIME_OFFSET) *
	    100UL);

	return (ret);
}

static wchar_t *
etw_add_fname(uetwptr_t fobj, wchar_t *fname)
{
	wchar_t *name = etw_rep_dev_to_path(fname);

	fileiomap[fobj] = (uintptr_t) fname;
	return (fname);
}

/*
 * convert etw event timestamp to nanosec timestamp
 * or epoch 1970 time.
 */
static hrtime_t
etw_event_timestamp(hrtime_t TimeStamp)
{
	hrtime_t tm = (hrtime_t) (sessinfo->etw->timebase +
	    (sessinfo->etw->timescale * TimeStamp));
	return (tm ? ((tm - PTW32_TIMESPEC_TO_FILETIME_OFFSET) * 100UL) : 0);
}

etw_pmc_t *
dtrace_etw_pmc_info(ulong_t *count, ulong_t *maxpmc)
{
	ULONG error, len, i = 1, j = 0;;
	PROFILE_SOURCE_INFO *profsrc, *tmp;
	TRACE_PROFILE_INTERVAL interval = {0};
	etw_pmc_t *epmc;

	*count = 0;
	error = TraceQueryInformation(0, TraceProfileSourceListInfo,
	    NULL, 0, &len);
	if (len > 0) {
		profsrc = (PROFILE_SOURCE_INFO *) malloc(len);
		error = TraceQueryInformation(0, TraceProfileSourceListInfo,
		    profsrc, len, NULL);
		if (error != ERROR_SUCCESS) {
			eprintf("dtrace_etw_pmc_info, failed to get PMC source info (%x)\n",
			    error);
			return (NULL);
		}
		for(tmp = profsrc; tmp->NextEntryOffset != 0;
		    tmp = (PROFILE_SOURCE_INFO *) ((char *) tmp + tmp->NextEntryOffset)) {
			i++;
		}
		epmc = (etw_pmc_t *) malloc(sizeof(etw_pmc_t) * i);
		tmp = profsrc;
		for(tmp = profsrc; ;
		    tmp = (PROFILE_SOURCE_INFO *) ((char *) tmp + tmp->NextEntryOffset)) {
			epmc[j].srcid = tmp->Source;
			WideCharToMultiByte(CP_UTF8, 0, tmp->Description, -1, epmc[j].name,
			    DTRACE_FUNCNAMELEN, NULL, NULL);
			strlwr(epmc[j].name);
			epmc[j].minint = tmp->MinInterval;
			epmc[j].maxint = tmp->MaxInterval;
			interval.Source = tmp->Source;
			error = TraceQueryInformation(0, TraceSampledProfileIntervalInfo,
			    &interval, sizeof(TRACE_PROFILE_INTERVAL), NULL);
			epmc[j].interval = interval.Interval;
			j++;
			if (tmp->NextEntryOffset == 0)
				break;
		}
		*count = j;
		error = TraceQueryInformation(0, TraceMaxPmcCounterQuery,
		    maxpmc, sizeof(ulong_t), NULL);
	}

	return (epmc);
}

struct {
	TRACEHANDLE handle;
	CLASSIC_EVENT_ID cid[64];
	ulong_t ids[64];
	ulong_t idssys[64];
	int cco, ico, sco;
} hpmcev[DT_ETW_MAX_SESSION] = {0};

void
dtrace_etw_pmc_samples(ulong_t *ids, TRACE_PROFILE_INTERVAL *tpintrval,
    int length)
{
	ULONG error, dup = 0;

	for (int i = 0; i < length; i++) {
		error = TraceSetInformation(0, TraceSampledProfileIntervalInfo,
		    &tpintrval[i], sizeof(TRACE_PROFILE_INTERVAL));
		if (error != ERROR_SUCCESS) {
			eprintf("dtrace_etw_pmc_samples, failed to set PMC sample intervals info (%x)\n",
			    error);
			return;
		}
	}
	for (int i = 0; i < length; i++) {
		for (int j = 0; j < hpmcev[0].sco; j++) {
			if (hpmcev[0].idssys[j] == ids[i]) {
				dup = 1;
			}
		}
		if (dup == 0)
			hpmcev[0].idssys[hpmcev[0].sco++] = ids[i];
		dup = 0;
	}
}

int
etw_pmc_samples()
{
	ULONG error;
	/* maximum source == 8 ? */
	if (hpmcev[0].sco <= 0)
		return (0);

	error = TraceSetInformation(0, TraceProfileSourceConfigInfo,
	    hpmcev[0].idssys, sizeof(ulong_t) * hpmcev[0].sco);
	if (error != ERROR_SUCCESS) {
		printf("dtrace_etw_pmc_samples, failed to set PMC sources (%x)\n",
		    error);
		return (0);
	}
	return(0);
}

int
etw_pmc_counters()
{
	ULONG error;
	for (int i = 0; i < DT_ETW_MAX_SESSION; i++) {
		if (hpmcev[i].handle == 0)
			continue;
		error = TraceSetInformation(hpmcev[i].handle, TracePmcCounterListInfo,
		    hpmcev[i].ids, sizeof(ulong_t) * hpmcev[i].ico);
		if (error != ERROR_SUCCESS) {
			printf("dtrace_etw_pmc_count, failed to set PMC event counters (%d)\n", error);
			return (-1);
		}

		error = TraceSetInformation(hpmcev[i].handle, TracePmcEventListInfo,
		    hpmcev[i].cid, sizeof(CLASSIC_EVENT_ID) * hpmcev[i].cco);
		if (error != ERROR_SUCCESS) {
			printf("dtrace_etw_pmc_count, failed to set PMC events (%d)\n", error);
			return (-1);
		}
	}
	return (0);
}

void
dtrace_etw_pmc_counters(int sid, ulong_t *ids, CLASSIC_EVENT_ID *events,
    int length)
{
	int dup = 0;
	if (sid == -1)
		return;

	hpmcev[sid].handle = dtrace_etw_sessions[sid]->hsession;

	for (int i = 0; i < length; i++) {
		for (int j = 0; j < hpmcev[sid].cco; j++) {
			if (memcmp(&hpmcev[sid].cid[j], &events[i], sizeof(CLASSIC_EVENT_ID)) == 0) {
				dup = 1;
			}
		}
		if (dup == 0)
			memcpy(&hpmcev[sid].cid[hpmcev[sid].cco++], &events[i],
			    sizeof(CLASSIC_EVENT_ID));
		dup = 0;

		for (int j = 0; j < hpmcev[sid].ico; j++) {
			if (hpmcev[sid].ids[j] == ids[i]) {
				dup = 1;
			}
		}
		if (dup == 0)
			hpmcev[sid].ids[hpmcev[sid].ico++] = ids[i];
	}

	return;
}

struct {
	TRACEHANDLE handle;
	ulong_t group_mask[8] = {0};
} hgroup_mask[DT_ETW_MAX_SESSION];

void
dtrace_etw_prov_enable_gm(int sid, ulong_t mask, int level)
{
	hgroup_mask[sid].handle = dtrace_etw_sessions[sid]->hsession;

	hgroup_mask[sid].group_mask[level] |= mask;
}

int
etw_prov_enable_gm()
{
	ULONG error;
	ULONG SystemTraceFlags[8];
	TRACEHANDLE h;
	for (int i = 0; i < DT_ETW_MAX_SESSION; i++) {
		if ((h = hgroup_mask[i].handle) == 0)
			continue;
		error = TraceQueryInformation(h,
		    TraceSystemTraceEnableFlagsInfo,
		    SystemTraceFlags, sizeof(SystemTraceFlags), NULL);
		if (error != ERROR_SUCCESS) {
			eprintf("dtrace_etw_prov_enable_gm, \
				failed to get TraceSystemTraceEnableFlagsInfo (%x)\n",
			    error);
			return (-1);
		}
		for (int j = 0; j < 8; j++)
			SystemTraceFlags[j] |= hgroup_mask[i].group_mask[j];
		error = TraceSetInformation(h,
		    TraceSystemTraceEnableFlagsInfo,
		    SystemTraceFlags, sizeof(SystemTraceFlags));
		if (error != ERROR_SUCCESS) {
			eprintf("dtrace_etw_prov_enable_gm, \
				failed to set PMC event raceSystemTraceEnableFlagsInfo (%x)\n",
			    error);
			return (-1);
		}
	}
	return (0);
}

static int
etw_finalize_start()
{
	if (etw_pmc_counters() != 0 || etw_pmc_samples() != 0 ||
	    etw_prov_enable_gm() != 0)
		return (0);
	return (1);
}


/*
 * set the profile sampling frequency,
 * using TraceSetInformation().
 * freq = samples/sec
 */
static int
etw_set_freqTSI(int freq)
{
	ULONG error;
	TRACE_PROFILE_INTERVAL interval = {0};
	interval.Interval = (ULONG) (10000.f * (1000.f / freq));

	error = TraceSetInformation(0, TraceSampledProfileIntervalInfo,
	    (void*)&interval, sizeof (TRACE_PROFILE_INTERVAL));

	if (error != ERROR_SUCCESS) {
		eprintf("etw_set_freqTSI, failed to set profile timer (%x) interval (%d)\n",
		    error, interval.Interval);
		return (-1);
	}

	return (0);
}

// https://github.com/Microsoft/BPerf/blob/master/CPUSamplesCollector/Program.cpp

enum EVENT_TRACE_INFORMATION_CLASS {
	EventTraceTimeProfileInformation = 3,
	EventTraceStackCachingInformation = 16
};

enum SYSTEM_INFORMATION_CLASS {
	SystemPerformanceTraceInformation = 31
};

typedef struct _EVENT_TRACE_TIME_PROFILE_INFORMATION {
	EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
	ULONG ProfileInterval;
} EVENT_TRACE_TIME_PROFILE_INFORMATION;

static int
etw_set_freqNT(int interval)
{
	typedef int(__stdcall * PNtSetSystemInformation) (
	    int SystemInformationClass,
	    void *SystemInformation, int SystemInformationLength);
	EVENT_TRACE_TIME_PROFILE_INFORMATION timeInfo;
	HMODULE ntdll = LoadLibrary(L"ntdll.dll");
	HRESULT hr;
	PNtSetSystemInformation addr;

	addr = (PNtSetSystemInformation) GetProcAddress(ntdll,
	    "NtSetSystemInformation");

	timeInfo.EventTraceInformationClass =
	    EventTraceTimeProfileInformation;

	timeInfo.ProfileInterval = interval;
	hr = addr(SystemPerformanceTraceInformation, &timeInfo,
	    sizeof (EVENT_TRACE_TIME_PROFILE_INFORMATION));

	if (hr != ERROR_SUCCESS) {
		eprintf("etw_set_freqNT, failed to set profile timer (%x) interval (%ld)\n",
		    hr, interval);
		return (-1);
	}

	return (0);
}

/*
 * check OS for Windows 8 or greater
 */
static BOOL
etw_win8_or_gt()
{
	DWORD Version = ::GetVersion();
	WORD MajorVersion = (DWORD)(LOBYTE(LOWORD(Version)));
	WORD MinorVersion = (DWORD)(HIBYTE(LOWORD(Version)));

	return ((MajorVersion >= 6) && (MinorVersion >= 2));
}

/*
 * set etw stacktrace for id[] events
 */
static int
etw_set_kernel_stacktrace(TRACEHANDLE session,
    CLASSIC_EVENT_ID id[], int len)
{
	ULONG error = TraceSetInformation(session, TraceStackTracingInfo,
	    (void*)id, (sizeof (CLASSIC_EVENT_ID)) * len);

	if (error != ERROR_SUCCESS) {
		eprintf("etw_set_kernl_stacktrace, failed (%x) session (%llu) \n",
		    error, session);
		return (-1);
	}
	return (0);
}

/*
 * Set (flags) kernel providers for the current session
 * Return 0 on success.
 */
static int
etw_enable_kernel_prov(TRACEHANDLE shandle, WCHAR *sname, ULONG flags,
    BOOL enable)
{
	EVENT_TRACE_PROPERTIES *prop;
	ULONG status, iflags = 0, len = 0;
	size_t sz = 0;

	sz = (ULONG) sizeof (EVENT_TRACE_PROPERTIES) +
	    LOGGER_NAME_SIZE + LOGGER_FILENAME_SIZE;

	prop = (EVENT_TRACE_PROPERTIES*) mem_zalloc(sz);
	prop->Wnode.BufferSize = (DWORD) sz;
	prop->LoggerNameOffset = sizeof (EVENT_TRACE_PROPERTIES);
	prop->LogFileNameOffset = sizeof (EVENT_TRACE_PROPERTIES) + LOGGER_NAME_SIZE;
	status = ControlTrace(shandle, sname, prop,
	    EVENT_TRACE_CONTROL_QUERY);
	if (status != ERROR_SUCCESS) {
		eprintf("etw_enable_kernel_prov, ControlTrace"
		    "(EVENT_TRACE_CONTROL_QUERY) failed (%x)\n", status);
		return (-1);
	}

	if (enable) {
		prop->EnableFlags |= flags;
	} else {
		prop->EnableFlags &= ~flags;
	}

	prop->LogFileNameOffset = 0;

	status = ControlTrace(shandle, sname, prop,
	    EVENT_TRACE_CONTROL_UPDATE);
	if (status != ERROR_SUCCESS) {
		eprintf("etw_enable_kernel_prov, ControlTrace"
		    "(EVENT_TRACE_CONTROL_UPDATE) failed (%x)\n", status);
		return (-1);
	}

	return (0);
}

/*
 * Create device name to normalized name MAP
 */
static int
etw_devname_to_path(map<wstring, wstring, std::greater<wstring>>
    &devmap)
{
	WCHAR volname[MAX_PATH] = L"";
	WCHAR  devname[MAX_PATH] = L"";
	HANDLE vh = INVALID_HANDLE_VALUE;
	size_t ind;
	DWORD co, error = 0;

	//
	//  Enumerate all volumes in the system.
	vh = FindFirstVolumeW(volname, ARRAYSIZE(volname));
	if (vh == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "FindFirstVolumeW failed with error code %d\n",
		    GetLastError());
		return (-1);
	}

	for (;;) {
		//  Skip the \\?\ prefix and remove the trailing backslash.
		ind = wcslen(volname) - 1;

		if (volname[0] != L'\\' ||
		    volname[1] != L'\\' ||
		    volname[2] != L'?'  ||
		    volname[3] != L'\\' ||
		    volname[ind] != L'\\') {
			error = ERROR_BAD_PATHNAME;
			fprintf(stderr, "FindFirstVolumeW/FindNextVolumeW \
				returned a bad path: %ls\n", volname);
			break;
		}

		//  QueryDosDeviceW does not allow a trailing backslash,
		//  so temporarily remove it.
		volname[ind] = L'\0';

		co = QueryDosDeviceW(&volname[4], devname, ARRAYSIZE(devname));
		if (co == 0) {
			error = GetLastError();
			fprintf(stderr, "QueryDosDeviceW failed with error code %d\n", error);
			break;
		}
		volname[ind] = L'\\';

		co = MAX_PATH + 1;
		PWCHAR pnames = NULL;
		BOOL fnd   = FALSE;

		for (;;) {
			//
			//  Allocate a buffer to hold the paths.
			pnames = (PWCHAR) mem_zalloc(co * sizeof(WCHAR));

			if (!pnames) {
				goto pcleanup;
			}

			//  Obtain all of the paths for this volume.
			if ((fnd = GetVolumePathNamesForVolumeNameW(volname, pnames, co,
			    &co)) ||
			    GetLastError() != ERROR_MORE_DATA) {
				break;
			}
			//  Try again with the new suggested size.
			free(pnames);
		}
		if (fnd) {
			//pnames  = null terminated strings of path names
			devmap[wstring(&devname[0])] = wstring(pnames);
		} else {
			fprintf(stderr, "GetVolumePathNamesForVolumeNameW %d %d %ls\n",
			    co, GetLastError(), pnames);
		}
		fnd = FindNextVolumeW(vh, volname, ARRAYSIZE(volname));

		if (!fnd) {
			error = GetLastError();
			if (error != ERROR_NO_MORE_FILES) {
				fprintf(stderr, "FindNextVolumeW failed with error code %d\n", error);
				break;
			}

			//  Finished iterating through all the volumes.
			error = ERROR_SUCCESS;
			break;
		}
	}
	pcleanup:
	FindVolumeClose(vh);
	DWORD sz = 0;
	wchar_t buf[MAX_PATH];
	wchar_t *env;

	sz = GetEnvironmentVariable(L"SystemRoot", buf, MAX_PATH);
	if (sz > MAX_PATH || sz == 0)
		return (error);

	env = (wchar_t *) mem_zalloc(sz + 2 + 2);
	wcsncpy(env, buf, sz);
	wcsncpy(env + sz, L"\\", 2);

	devmap[L"\\SystemRoot\\"] = env;

	sz = GetEnvironmentVariable(L"windir", buf, MAX_PATH);
	if (sz > MAX_PATH || sz == 0)
		return (error);
	env = (wchar_t *) mem_zalloc(sz + 2 + 2);
	wcsncpy(env, buf, sz);
	wcsncpy(env + sz, L"\\", 2);

	devmap[L"\\Windows\\"] = env;
	devmap[L"\\??\\"] = L"";

	return (error);
}

static HANDLE
etw_init_dbg(HANDLE h)
{
	DWORD Options = SymGetOptions();
	Options |= SYMOPT_DEFERRED_LOADS;
	Options |= SYMOPT_DEBUG;
	SymSetOptions(Options);

	init_symbols(h, FALSE, NULL);

	return (h);
}

static void
etw_initialize()
{
	HANDLE t;
	char *s;

	missing_thread.proc = &missing_proc;
	missing_thread.tid = -1;
	missing_thread.pid = -1;
	missing_proc.pid = -1;
	missing_proc.ppid = 0;
	missing_proc.name = "notyet";
	missing_proc.cmdline = L"\0";

	s = set_syms_path(NULL);
	if (s) {
		/* fprintf(stderr, "Symbols Search path: %s\n", s); */
	}

	pdbsyms.h = etw_init_dbg((HANDLE) 999);
	pdbsyms.endaddr = 0x1000;
	nopdbsyms.h = etw_init_dbg((HANDLE) 9999);
	nopdbsyms.endaddr = 0x1000;

}

/*
 * ETW session management functions
 */
/*
 * Timestamp confusion
 * StartTrace = QPC, Opentrace = PROCESS_TRACE_MODE_RAW_TIMESTAMP
 * 		PEVENT_RECORD->TimeStamp = raw timestamp, StackWalk->EventTimeStamp = raw timestamp
 * StartTrace = QPC, Opentrace = !PROCESS_TRACE_MODE_RAW_TIMESTAMP
 * 		PEVENT_RECORD->TimeStamp = system time, StackWalk->EventTimeStamp = raw timestamp
 * StartTrace = SYSTEM, Opentrace = PROCESS_TRACE_MODE_RAW_TIMESTAMP
 * 		PEVENT_RECORD->TimeStamp = system time, StackWalk->EventTimeStamp = system time
 * StartTrace = QPC, Opentrace = !PROCESS_TRACE_MODE_RAW_TIMESTAMP
 * 		PEVENT_RECORD->TimeStamp = system time, StackWalk->EventTimeStamp = system time
 */

static void
etw_end_session(etw_sessioninfo_t *sinfo, WCHAR *sname)
{
	EVENT_TRACE_PROPERTIES properties;
	ULONG st;

	if (sinfo) {
		if (FILESESSION(sinfo)) {
			if (sinfo->psession) {
				st = CloseTrace(sinfo->psession);
			}
		} else {
			ZeroMemory(&properties, sizeof (EVENT_TRACE_PROPERTIES));
			properties.Wnode.BufferSize = sizeof (EVENT_TRACE_PROPERTIES);
			st = ControlTrace(sinfo->hsession, sinfo->hsession ? NULL : sinfo->sessname, &properties,
			    EVENT_TRACE_CONTROL_STOP);
		}
	} else if (sname) {
		ZeroMemory(&properties, sizeof (EVENT_TRACE_PROPERTIES));
		properties.Wnode.BufferSize = sizeof (EVENT_TRACE_PROPERTIES);
		st = ControlTrace(0, sname, &properties, EVENT_TRACE_CONTROL_STOP);
	}
}

/*
 * Initialize ETW by calling StartTrace, with the logmode.
 * currently only logmode == EVENT_TRACE_REAL_TIME_MODE supported
 */
static TRACEHANDLE
etw_init_session(WCHAR *sname, GUID sguid, ULONG clctype,
    ULONG logmode, hrtime_t *sts)
{
	TRACEHANDLE hsession = 0;
	EVENT_TRACE_PROPERTIES* prop = NULL;
	size_t sz = 0, sesssz = 0, fnlen = 0, fsz = 0;
	ULONG status = ERROR_SUCCESS;
	WCHAR *fname = NULL;

	/* close any open session with same name */
	etw_end_session(NULL, sname);
	sesssz = wcslen(sname) * 2 + 2;

	/* Even if  EVENT_TRACE_FILE_MODE_NONE and loggername is present logging
	 * takes place */
	if (logmode & (EVENT_TRACE_FILE_MODE_SEQUENTIAL |
	    EVENT_TRACE_FILE_MODE_CIRCULAR)) {
		fname = sesstofile(sname, &fsz);
		fnlen = wcslen(fname) * 2 + 2;
	}
	sz = sizeof (EVENT_TRACE_PROPERTIES) + LOGGER_NAME_SIZE + LOGGER_FILENAME_SIZE;
	prop = (EVENT_TRACE_PROPERTIES*) mem_zalloc(sz);
	if (prop == NULL) {
		eprintf("etw_init_session, mem_zalloc() failed for size (%lld)\n", sz);
		return (0);
	}

	ZeroMemory(prop, sz);
	prop->Wnode.BufferSize = (DWORD) sz;
	prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	prop->Wnode.ClientContext = clctype;
	prop->Wnode.Guid = sguid;
	prop->BufferSize = 1024;
	prop->LogFileMode = logmode;
	prop->MinimumBuffers = 300;
	prop->FlushTimer = 1;
	prop->LoggerNameOffset = sizeof (EVENT_TRACE_PROPERTIES);
	StringCbCopy((LPWSTR)((CHAR*)prop + prop->LoggerNameOffset),
	    (wcslen(sname) * 2 + 2), sname);

	prop->MaximumFileSize = fsz;
	prop->LogFileNameOffset = sizeof (EVENT_TRACE_PROPERTIES) + LOGGER_NAME_SIZE;
	StringCbCopy((LPWSTR)((CHAR*)prop + prop->LogFileNameOffset),
	    fnlen, fname);

	/* starttime for real time, walltimestamp */
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	*sts = ((LARGE_INTEGER *) &ft)->QuadPart;

	status = StartTrace((PTRACEHANDLE)&hsession, sname, prop);

	if (status != ERROR_SUCCESS) {
		eprintf("etw_init_session, StartTrace() failed with (%lx)\n", status);
		return (0);
	}

	return (hsession);
}

/*
 * Start etw trace.
 * if nothread is set than, dont create the helper thread for the session yet.
 * returns the created thread handle or tracehandle in case of nothread
 */
static HANDLE
etw_start_trace(etw_sessioninfo_t *sinfo, PEVENT_RECORD_CALLBACK cb,
    LPTHREAD_START_ROUTINE tfunc, int nothread)
{
	ULONG status = ERROR_SUCCESS;
	EVENT_TRACE_LOGFILE trace;
	TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
	TRACEHANDLE handle;
	HANDLE thread = 0;

	if (sinfo->psession == 0) {
		ZeroMemory(&trace, sizeof (EVENT_TRACE_LOGFILE));
		if ((FILESESSION(sinfo)) == 0) {
			trace.LoggerName = sinfo->sessname;
			trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
			    PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
		} else {
			trace.LogFileName = sinfo->etlfile;
			trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD |
			    PROCESS_TRACE_MODE_RAW_TIMESTAMP;
		}

		trace.EventRecordCallback = cb;
		handle = OpenTrace(&trace);
		if (INVALID_PROCESSTRACE_HANDLE == handle) {
			eprintf("etw_enable_trace, OpenTrace() failed with (%lx)\n",
			    GetLastError());
			return (NULL);
		}

		sinfo->psession = handle;
		sinfo->flags |= (trace.LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE) ?
		    SESSINFO_ISUSERMODE : 0;

		sinfo->flags |= (trace.ProcessTraceMode & PROCESS_TRACE_MODE_RAW_TIMESTAMP) ?
		    SESSINFO_RAWTIME : 0;
		sinfo->ncpus = trace.LogfileHeader.NumberOfProcessors;
		sinfo->boottime = trace.LogfileHeader.BootTime.QuadPart;

		//ASSERT(!((sinfo->flags & SESSINFO_FILE_ENABLE_ALL) &&
		//    trace.LogfileHeader.ReservedFlags == 0));

		sinfo->clctype = trace.LogfileHeader.ReservedFlags;
		sinfo->perffreq = trace.LogfileHeader.PerfFreq.QuadPart;
		sinfo->ptrsz = trace.LogfileHeader.PointerSize;

		sinfo->timerres = trace.LogfileHeader.TimerResolution;
		sinfo->cpumhz = trace.LogfileHeader.CpuSpeedInMHz;
		sinfo->Q.map = (Hashmap *) malloc(sizeof(Hashmap) * sinfo->ncpus);
		memset(sinfo->Q.map, 0, sizeof(Hashmap) * sinfo->ncpus);
	}

	if (nothread == 0) {
		thread = CreateThread(NULL, 0, tfunc, (void *) sinfo, 0, &sinfo->id);
		if (thread == NULL) {
			eprintf("etw_start_trace, CreateThread() failed with (%lu)\n",
			    GetLastError());
			CloseTrace(handle);
			return (NULL);
		}
		//SetThreadPriority(thread, THREAD_PRIORITY_HIGHEST);
	} else {
		return ((HANDLE) handle);
	}

	return (thread);
}

etw_sessioninfo_t *
newsessinfo()
{
	static int i = 0;
	etw_sessioninfo_t *sinfo = new etw_sessioninfo_t();
	sinfo->thrid = i++;
	return sinfo;

}
static etw_sessioninfo_t *
etw_new_session(WCHAR *sname, const GUID *sguid, ULONG clctype, ULONG flags,
    etw_dtrace_probe_t probef, etw_dtrace_ioctl_t ioctlf, int nothread)
{
	TRACEHANDLE handle = 0, hsession = 0;
	HANDLE thread = 0;
	etw_sessioninfo_t *sinfo;
	hrtime_t sts = 0;

	if ((hsession =
	    etw_init_session(sname, *sguid, clctype, flags, &sts)) == 0) {
		etw_end_session(NULL, sname);
		return (NULL);
	}

	sinfo = newsessinfo();
	sinfo->starttime = sts;
	sinfo->flags &= ~SESSINFO_ISFILE;
	sinfo->sessname = sname;
	sinfo->sessguid = (GUID *) sguid;
	sinfo->hsession = hsession;
	sinfo->dtrace_probef = probef;
	sinfo->dtrace_ioctlf = ioctlf;

	if ((thread = etw_start_trace(sinfo, etw_event_cb, etw_event_thread,
	    nothread)) == 0) {
		free(sinfo);
		etw_end_session(sinfo, NULL);
		return (NULL);
	}

	return (sinfo);
}

static void
etw_end_trace(WCHAR *sname, GUID sguid)
{
	EVENT_TRACE_PROPERTIES *properties;
	ULONG status;
	int sz = sizeof (EVENT_TRACE_PROPERTIES) + LOGGER_NAME_SIZE +
	    LOGGER_FILENAME_SIZE;

	properties = (EVENT_TRACE_PROPERTIES *) mem_zalloc(sz);
	ZeroMemory(properties, sz);
	properties->Wnode.BufferSize = sz;
	properties->Wnode.Guid = sguid;
	status = StopTrace(0, sname, properties);
	if (status != ERROR_SUCCESS) {
		eprintf("etw_end_trace, failed (%x)\n", status);
	}
}

static int
etw_enable_user(TRACEHANDLE hsession, GUID *guid, int kw, int level,
    int enablestack, int capture)
{
	ENABLE_TRACE_PARAMETERS EnableParameters;

	ZeroMemory(&EnableParameters, sizeof (EnableParameters));
	EnableParameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

	if (enablestack) {
		EnableParameters.EnableProperty =
		    EVENT_ENABLE_PROPERTY_STACK_TRACE;
	}
	DWORD status = EnableTraceEx2(hsession, (LPCGUID)guid,
	    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
	    level, kw, 0, 0, &EnableParameters);
	if (capture && status == ERROR_SUCCESS) {
		status = EnableTraceEx2(hsession, (LPCGUID)guid,
		    EVENT_CONTROL_CODE_CAPTURE_STATE,
		    level, kw, 0, 0, &EnableParameters);
	}
	if (ERROR_SUCCESS != status) {
		//eprintf("etw_enable_user, EnableTraceEx() failed (%lu)\n", status);
		return (status);
	}

	return (0);
}

static DWORDLONG
etw_file_chksum(wchar_t *modname)
{
	HANDLE file, map;
	void *base;
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_OPTIONAL_HEADER64 ohdr64;
	PIMAGE_OPTIONAL_HEADER32 ohdr32;
	DWORD sum = 0;

	file = CreateFileW(modname, GENERIC_READ, FILE_SHARE_READ, NULL,
	    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return (0);
	}

	map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (map == NULL) {
		CloseHandle(file);
		return (0);
	}
	base = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
	if (base == NULL) {
		CloseHandle(map);
		CloseHandle(file);
		return (0);
	}

	dos = (PIMAGE_DOS_HEADER) base;
	nthdr = (PIMAGE_NT_HEADERS) ((char *)base + dos->e_lfanew);
	hdr = &nthdr->FileHeader;
	if (hdr->Machine == IMAGE_FILE_MACHINE_I386) {

		ohdr32 = (PIMAGE_OPTIONAL_HEADER32) &nthdr->OptionalHeader;
		sum = ohdr32->CheckSum;
	} else if (hdr->Machine == IMAGE_FILE_MACHINE_AMD64) {

		ohdr64 = (PIMAGE_OPTIONAL_HEADER64) &nthdr->OptionalHeader;
		sum = ohdr64->CheckSum;
	}
	CloseHandle(map);
	CloseHandle(file);

	return (sum);
}

/*
 * Get PDB info for the given module
 * ngen image, first = ni pdb, last = il pdb
 */
static cvpdbinfo_t *
etw_pdb_info(wchar_t *modname)
{
	cvpdbinfo_t *cv = NULL;
	HANDLE file, map;
	void *base;
	DWORD size;
	PIMAGE_DEBUG_DIRECTORY dbase;

	file = CreateFileW(modname, GENERIC_READ, FILE_SHARE_READ, NULL,
	    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return (NULL);
	}

	map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (map == NULL) {
		CloseHandle(file);
		return (NULL);
	}

	base = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
	if (base == NULL) {
		CloseHandle(map);
		CloseHandle(file);
		return (NULL);
	}

	dbase = (PIMAGE_DEBUG_DIRECTORY)
	    ImageDirectoryEntryToDataEx(base, FALSE,
	    IMAGE_DIRECTORY_ENTRY_DEBUG, &size, NULL);
	if (dbase) {
		size_t count = size / sizeof (IMAGE_DEBUG_DIRECTORY);

		for (size_t i = 0; i < count; ++i) {
			if (dbase[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
				cvpdbinfo_t *cv0 = (cvpdbinfo_t *) ((char *) base +
				    dbase[i].PointerToRawData);
				if (cv0->cvsig == 0x53445352) {	/* RSDS */
					cv = (cvpdbinfo_t *) mem_zalloc(dbase[i].SizeOfData);
					memcpy(cv, (void *) ((char *) base +
					    dbase[i].PointerToRawData), dbase[i].SizeOfData);
					break;
				}
			}
		}
	}

	CloseHandle(map);
	CloseHandle(file);

	return (cv);
}

static int
etw_create_ni_pdb(char *image, char *dir)
{
	char cmd[1024];
	char path[MAX_PATH];
	int  n = 0;
	int arch = 0, isnet = 0, code;

	if (filetype(image, &arch, &isnet) < 0) {
		eprintf("etw_create_ni_pdb, unknown file type (%s)\n", image);
		return (0);
	}

	if ((n = ngenpath(path, MAX_PATH, 1,
	    isnet > 0 ? isnet - 1 : 0)) <= 0) {
		eprintf("etw_create_ni_pdb(), failed to get NGEN path (%x)\n",
		    GetLastError());
		return (0);
	}

	sprintf(cmd, "%s %s %s %s", path, "createPDB", image, dir);

	if ((code = runcmd(cmd)) < 0) {
		eprintf("etw_create_ni_pdb, failed to run cmd (%s) (%x)\n", cmd,
		    GetLastError());
		return (0);
	}

	return (code);
}

/*
 * check if pdb file for the ngened module exists
 * in dbghelp search path. If not create one.
 * ex. _NT_SYMBOL_PATH=srv*c:\symbols*http://msdl.microsoft.com/download/symbols;e:\sym
 */
#define	SYMBOLS_PATH "SRV*c:\\symbols*https://msdl.microsoft.com/download/symbols"

char *
crtsymfld(char *buf, int size)
{
	char tmp[MAX_PATH];

	int sz = GetSystemDirectoryA(buf, size);
	ASSERT(sz <= size);
	char *f = strchr(buf, ':');
	strcpy(++f, "\\Symbols");

	return buf;
}

static cvpdbinfo_t *
etw_find_ni_syms(cvpdbinfo_t *cv, etw_module_t *mod)
{
	char SYMPATH[MAX_PATH];
	char pdbdir[MAX_PATH];
	char fn[MAX_PATH];
	char nifn[MAX_PATH];
	char *tmp1 = SYMPATH, *tmp0, *symdir = NULL;
	int fnd = 0;
	size_t r = 0;

	getenv_s(&r, SYMPATH, 256, "_NT_SYMBOL_PATH");
	ASSERT(r != 0);

	tmp0 = tmp1 = SYMPATH;

	for ( ; *tmp0; ++tmp0) *tmp0 = tolower(*tmp0);

	sprintf(pdbdir,
	    "\\%s\\%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%x\\%s",
	    cv->pdbname,
	    cv->sig.Data1, cv->sig.Data2,
	    cv->sig.Data3, cv->sig.Data4[0], cv->sig.Data4[1], cv->sig.Data4[2],
	    cv->sig.Data4[3], cv->sig.Data4[4], cv->sig.Data4[5],
	    cv->sig.Data4[6],
	    cv->sig.Data4[7], cv->age, cv->pdbname);

	wcstombs_d(nifn, mod->name, MAX_PATH);
	if (r == 0)
		symdir = crtsymfld(SYMPATH, MAX_PATH);
	else do {
			tmp0 = tmp1;
			tmp1 = strchr(tmp1, ';');
			if (tmp1 != NULL) {
				*tmp1 = 0;
				++tmp1;
			}
			if (strstr(tmp0, "cache")) {
				continue;
			}
			if (strstr(tmp0, "srv")) {
				char *s0 = strchr(tmp0, '*');
				char *s1 = strchr(++s0, '*');
				if (s1 != NULL) {
					s1[0] = 0;
				}
				symdir = s0;
				strcpy(fn, s0);
				strcpy(fn + strlen(s0), pdbdir);
				if (PathFileExistsA(fn)) {
					fnd = 1;
					break;
				}
			}
		} while (tmp1 != NULL);

	if (fnd == 0) {
		etw_create_ni_pdb(nifn, symdir);
	}

	return (cv);
}

/*
 * if pdb info is missing for the module, try to extract
 * it from the source file. First try matching with the file
 * from the host os.
 * If no match found in the host machine and datetime is present
 * try to download the source file from MS server, and then extract
 * the pdb info from the downloaded file.
 */
static cvpdbinfo_t *
etw_match_datatime(HANDLE h, etw_module_t *mod, uetwptr_t base)
{
	char filen[MAX_PATH] = {0};
	char dest[MAX_PATH + 1] = {0};
	DWORD date, size, three = 0, flags = SSRVOPT_DWORDPTR;
	SYMSRV_INDEX_INFO info = {0};
	BOOL r;
	int flag = 0;

	wcstombs_d(filen, mod->name, MAX_PATH);
	info.sizeofstruct = sizeof (SYMSRV_INDEX_INFO);

	/* check for the module on the host machine */
	if ((r = SymSrvGetFileIndexInfo(filen, &info, flag)) == TRUE) {
		DWORD head = 0, chksum = 0;
		if (mod->tmstamp == 0) {
			chksum = etw_file_chksum(mod->name);
			if (mod->chksum == chksum) {
				mod->tmstamp = info.timestamp;
			}
		}
		if (info.timestamp == mod->tmstamp &&
		    info.size == mod->size) {
			if (wcsstr(mod->name, L".ni.") == NULL) {
				int len = strlen(info.pdbfile) + 1;
				cvpdbinfo_t *cv0 =
				    (cvpdbinfo_t *) mem_zalloc(sizeof (cvpdbinfo_t) + len);
				cv0->age = info.age;
				cv0->cvsig = 0x53445352;
				cv0->sig = info.guid;
				strcpy((char *) &cv0->pdbname, info.pdbfile);
				return (cv0);
			} else {
				cvpdbinfo_t *cv = etw_pdb_info(mod->name);
				return (etw_find_ni_syms(cv, mod));
			}
		}
	} else {
		eprintf("SymSrvGetFileIndexInfo failed (%d)\n", GetLastError());
	}

	if (mod->tmstamp == 0) {
		eprintf("etw_match_datatime, timestamp == 0 (%s)\n", filen);
		return (NULL);
	}

	/*
	 * DATETIME  value is represented in the number of seconds
	 * elapsed since midnight (00:00:00), January 1, 1970,
	 * Universal Coordinated Time.
	 */
	date = mod->tmstamp;
	size = mod->size;

	wcstombs_d(filen, mod->name, MAX_PATH);

	fprintf(stderr, "[#] Locating module (%s)\r", filen);
	if (SymFindFileInPath(h, NULL, filen, &date, size, three,
	    flags, dest, NULL, NULL) == 0) {
		eprintf("SymFindFileInPath failed for (%s) - (%d)\n", filen,
		    GetLastError());
		return (NULL);
	}
	fprintf(stderr, "%90s\r\t      ", "");

	wchar_t wdest[MAX_PATH + 1] = {0};
	mbstowcs(wdest, dest, MAX_PATH);
	cvpdbinfo_t *cv = etw_pdb_info(wdest);

	return (cv);
}

/*
 * Match the etw process pdb info events, with the module
 * DbgID_RSDS base == struct Image ImageBase ??? XXX
 */
static cvpdbinfo_t *
etw_match_cvinfo(etw_proc_cvinfo *lcvinfo, etw_module_t *mod,
    uetwptr_t base)
{
	char nmod[MAX_PATH] = {0}, mname[MAX_PATH];

	wcstombs_d(mname, mod->name, MAX_PATH);

	/* extract lowercase module name without extention */
	_splitpath(mname, NULL, NULL, nmod, NULL);

	if (nmod[0] == '\0')
		return (NULL);
	_strlwr(nmod);

	while (lcvinfo) {
		char npdb[MAX_PATH] = {0};
		/* extract lowercase pdb name without extention */
		_splitpath((char *) lcvinfo->cv->pdbname, NULL, NULL, npdb, NULL);
		if (npdb[0] == '\0')
			return (NULL);
		_strlwr(npdb);

		if (strcmp(nmod, npdb) == 0)
			return (lcvinfo->cv);
		else if (lcvinfo->base == base)
			return (lcvinfo->cv);
		lcvinfo = lcvinfo->next;
	}
	return (NULL);
}


static etw_jit_symbol_t *
etw_lookup_jit_sym(pid_t pid, uetwptr_t addr)
{
	etw_jitsym_map_t& symmap = pid_jit_symtable[pid];
	etw_jit_symbol_t *tsym = NULL;
	int low, high, mid, size;

	if (symmap.sorted == 0) {
		std::sort(symmap.jit_syms.begin(), symmap.jit_syms.end(),
		    jit_sym_cmp);
		symmap.sorted = 1;
	}

	size = symmap.jit_syms.size();
	low  =  0;
	high  =  size  -  1;
	while (low  <=  high) {
		mid  =  (low  +  high)  /  2;
		tsym = symmap.jit_syms[mid];
		if (addr < tsym->MethodStartAddress)
			high = mid - 1;
		else if (addr >= tsym->MethodStartAddress + tsym->MethodSize)
			low = mid + 1;
		else {
			return (tsym);
		}
	}
	return (NULL);
}

/*
 * get keyword information of a provider
 */
static etw_provkw_t *
etw_prov_kw(GUID *pguid, int *nkw)
{
	DWORD status = ERROR_SUCCESS;
	PROVIDER_FIELD_INFOARRAY* penum = NULL, *ptemp = NULL;
	DWORD BufferSize = 0;
	etw_provkw_t *etwp = NULL;
	int num = 0;

	*nkw = 0;

	status = TdhEnumerateProviderFieldInformation(pguid,
	    EventKeywordInformation, penum, &BufferSize);
	if (ERROR_INSUFFICIENT_BUFFER == status) {
		ptemp = (PROVIDER_FIELD_INFOARRAY*) realloc(penum, BufferSize);
		if (ptemp == NULL) {
			eprintf("Allocation failed (size=%lu).\n", BufferSize);
			status = ERROR_OUTOFMEMORY;
			goto cleanup0;
		}
		penum = ptemp;
		// Retrieve the information for the field type.

		status = TdhEnumerateProviderFieldInformation(pguid,
		    EventKeywordInformation, penum, &BufferSize);
	}

	// The first call can fail with ERROR_NOT_FOUND if none of the provider's event
	// descriptions contain the requested field type information.

	if (ERROR_SUCCESS != status) {
		goto cleanup0;
	}

	num = penum->NumberOfElements;
	etwp = (etw_provkw_t *) mem_zalloc(sizeof (etw_provkw_t) * (num + 1));
	// Loop through the list of field information and print the field's name,
	// description (if it exists), and value.
	int count = 0;
	for (DWORD j = 0; j < num; j++) {
		wchar_t *wtmp =  (PWCHAR)((PBYTE)(penum) +
		    penum->FieldInfoArray[j].NameOffset);
		/* remove channel kw. providername/channeltye */
		if (wcschr(wtmp, L'/') != NULL)
			continue;

		char *s = (char *) mem_zalloc(256);
		wcstombs_d(s, wtmp, 256);
		int len = strlen(s);
		for (int i = 0; i < len; i++) {
			if (s[i] == ' ' || s[i] == ';' || s[i] == ':')
				s[i] = '_';
		}
		etwp[count].kwn = strlwr(s);
		etwp[count].kwv =  penum->FieldInfoArray[j].Value;
		count++;
	}

	etwp[count].kwn = NULL;
	*nkw = count;

	cleanup0:

	if (penum) {
		free(penum);
		penum = NULL;
	}

	return (etwp);
}

/*
 * enumerate etw providers
 */
static etw_provinfo_t *
etw_provlist(int *nprov)
{
	DWORD status = ERROR_SUCCESS;
	PROVIDER_ENUMERATION_INFO* penum = NULL, *ptemp = NULL;
	DWORD BufferSize = 0, i;
	etw_provinfo_t *lprov = NULL;

	BufferSize = 1024 * 256;
	penum = (PROVIDER_ENUMERATION_INFO*) malloc(BufferSize);

	*nprov = 0;
	/* Retrieve the required buffer size. */
	status = TdhEnumerateProviders(penum, &BufferSize);

	while (ERROR_INSUFFICIENT_BUFFER == status) {
		ptemp = (PROVIDER_ENUMERATION_INFO*) realloc(penum, BufferSize);
		if (NULL == ptemp) {
			eprintf("Allocation failed (size=%lu).\n", BufferSize);
			break;
		}
		penum = ptemp;
		status = TdhEnumerateProviders(penum, &BufferSize);
	}

	lprov = (etw_provinfo_t *) mem_zalloc((penum->NumberOfProviders + 1) *
	    sizeof (etw_provinfo_t));

	for (i = 0; i < penum->NumberOfProviders; i++) {
		char *s = (char *) mem_zalloc(256);
		GUID *g = (GUID *) mem_zalloc(sizeof(GUID));
		int nkw = 0;
		wchar_t *wtmp = (LPWSTR)((PBYTE)(penum) +
		    penum->TraceProviderInfoArray[i].ProviderNameOffset);

		wcstombs_d(s, wtmp, 256);

		int len = strlen(s);
		for (int j = 0; j < len; j++) {
			if (s[j] == ' ' || s[j] == ';' ||
			    s[j] == ':' || s[j] == '(' ||
			    s[j] == ')')
				s[j] = '-';
		}
		lprov[i].provn = strlwr(s);
		lprov[i].provg = penum->TraceProviderInfoArray[i].ProviderGuid;
		lprov[i].src = penum->TraceProviderInfoArray[i].SchemaSource;
		lprov[i].provkw = etw_prov_kw(&lprov[i].provg, &nkw);
		lprov[i].provnkw = nkw;
	}
	lprov[i].provn = NULL;
	*nprov = i;

	return (lprov);
}

/*
 * cache the list of providers and its keyword in a
 * file "dt_provlist.dat", in dtrace binary directory.
 * sudsequent calls to dtrace will read this file to get the
 * provider list. If you need dtrace to refresh the provider list, then
 * delete this file.
 */

/*
 * FILE FORMAT
 * I 4bytes, II 8bytes, S null terminated string, G sizeof(GUID)
 * I<number of providers>
 * S<provider0 name>G<provider0 GUID>
 *  I<schema type, flags >
 * 	I<number of keywords >
 * 		S<keyword00 name>II<keyword00 value>
 * 		S<keyword01 name>II<keyword01 value>
 * 		.....
 * 		S<keyword0m name>II<keyword0m value>
 * S<provider1 name>G<provider1 GUID>
 * 	....
 * 	....
 * S<providern name>G<providern GUID>
 *  I<schema type, flags >
 * 	I<number of keywords >
 * 		S<keywordn0 name>II<keywordn0 value>
 * 		S<keywordn1 name>II<keywordn1 value>
 * 		.....
 * 		S<keywordnm name>II<keywordnm value>
 */
static int
etw_provlist_tofile(char *fn, etw_provinfo_t *lprov, int nprov)
{
	etw_provkw_t *lkw;
	int i, j;
	FILE *fp = fopen(fn, "wb");

	fwrite(&nprov, sizeof (int), 1, fp);

	for (i = 0; i < nprov; i++) {
		lkw = lprov[i].provkw;
		fwrite(lprov[i].provn, sizeof (char), strlen(lprov[i].provn) + 1, fp);
		fwrite(&lprov[i].provg, sizeof (GUID), 1, fp);
		fwrite(&lprov[i].src, sizeof (int), 1, fp);
		fwrite(&lprov[i].provnkw, sizeof (int), 1, fp);
		for (j = 0; j < lprov[i].provnkw; j++) {
			fwrite(lkw[j].kwn, sizeof (char), strlen(lkw[j].kwn) + 1, fp);
			fwrite(&lkw[j].kwv, sizeof (uint64_t), 1, fp);
		}
	}
	fclose(fp);

	return (1);
}

/*
 * get the list of etw providers and their keywords from the
 * cached file "dt_provlist.dat".
 */
static etw_provinfo_t *
etw_provlist_ffile(char *fprov, int *nprov)
{
	etw_provinfo_t *lprov;
	etw_provkw_t *lkw;
	DWORD i, j, k, l, nkw, num = 0, flags;
	ULONG64 val = 0;
	char provn[MAX_PATH], kwn[MAX_PATH], *s, *skw;
	GUID g;
	int c, sum = 0;
	FILE *fp = fopen(fprov, "rb");

	if (fp == NULL)
		return (NULL);

	*nprov = 0;

	fread(&num, sizeof (int), 1, fp);
	ASSERT(num != 0);
	lprov = (etw_provinfo_t *) mem_zalloc((num + 1) *
	    sizeof (etw_provinfo_t));
	sum = (num + 1) * sizeof (etw_provinfo_t);
	for (i = 0, j = 0; i < num; i++, j = 0) {
		do {
			c = fgetc(fp);
			provn[j++] = c;
		} while (c != '\0');

		s = (char *) mem_zalloc(j);
		memcpy(s, provn, j);
		fread(&g, sizeof (GUID), 1, fp);
		fread(&flags, sizeof (int), 1, fp);
		fread(&nkw, sizeof (int), 1, fp);
		lkw = (etw_provkw_t *) mem_zalloc((nkw + 1) *
		    sizeof (etw_provkw_t));
		sum += (nkw + 1) * sizeof (etw_provkw_t);
		for (k = 0, l = 0; k < nkw; k++, l = 0) {
			do {
				c = fgetc(fp);
				kwn[l++] = c;
			} while (c != '\0');
			skw = (char *) mem_zalloc(l);
			sum += l;
			memcpy(skw, kwn, l);
			fread(&val, sizeof (uint64_t), 1, fp);
			lkw[k].kwn = strlwr(skw);
			lkw[k].kwv = val;
		}
		lkw[k].kwn = NULL;

		lprov[i].provn = strlwr(s);
		lprov[i].provg = g;
		lprov[i].src = flags;
		lprov[i].provnkw = nkw;
		lprov[i].provkw = lkw;
	}
	lprov[i].provn = NULL;
	*nprov = num;
	fclose(fp);

	return (lprov);
}

static void *
etw_get_providers()
{
	char path[MAX_PATH];
	DWORD st = GetModuleFileNameA(NULL, path, MAX_PATH);
	BOOL b = PathRemoveFileSpecA(path);
	char *fprov = strcpy(path + strlen(path), "\\dt_provlist.dat");
	FILE *fp = fopen(fprov, "rb");
	etw_provinfo_t *lprov;
	int nprov;

	if ((lprov = etw_provlist_ffile(path, &nprov)) == NULL) {
		lprov = etw_provlist(&nprov);
		etw_provlist_tofile(path, lprov, nprov);
	}

	return (lprov);
}

/*
 * ETW Event processing function
 * Common to all providers
 */

/*
 * FileIO CB Name
 * create a map of all open files during startup
 */
static int
fileio_func(PEVENT_RECORD ev, void *data)
{
	size_t len;
	wchar_t *fname;
	int ptrsz = ARCHETW(ev) ? 8 : 4; //sessinfo->etw->ptrsz;
	char *ud = (char *) ev->UserData;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, FileIoGuid));

	switch (ev->EventHeader.EventDescriptor.Opcode) {
	case 0:
	case 32:
	case 35:
	case 36:
		len = wcslen((wchar_t *) (ud + ptrsz));
		fname = (wchar_t *) mem_zalloc((len + 2) * sizeof (wchar_t));
		wcsncpy(fname, (const wchar_t *) (ud + ptrsz), len);
		fname[len] = L'\0';
		etw_add_fname(ptrsz == 4 ? * (uint32_t *) ud : * (uint64_t *) ud, fname);
		break;
	default:
		return (0);
	}

	return (0);
}
//pid, ppid, SID, flags, exitval, addr, pageaddr, session id
struct ProcessTypeGroupOff {
	int pid, ppid, SID, id, es, base, uniq, flags, exittm;
} poff[2][6] = {
	{
		{0, 4, 8, -1, -1, -1, -1, -1, -1},
		{4, 8, 20, 12, 16, 0, -1, -1, -1},
		{4, 8, 20, 12, 16, -1, 0, -1, -1},
		{4, 8, 24, 12, 16, 20, 0, -1, -1},
		{4, 8, 28, 12, 16, 20, 0, 24, -1},
		{4, 8, 28, 12, 16, 20, 0, 24, -8}
	},
	{
		{0, 4, 8, -1, -1, -1, -1, -1, -1},
		{8, 12, 24, 16, 20, 0, -1, -1, -1},
		{8, 12, 24, 16, 20, -1, 0, -1, -1},
		{8, 12, 32, 16, 20, 24, 0, -1, -1},
		{8, 12, 36, 16, 20, 24, 0, 32, -1},
		{8, 12, 36, 16, 20, 24, 0, 32, -8}
	}
};


/* process event processing function */
#define	SeLengthSid(Sid) \
	(8 + (4 * ((SID *)Sid)->SubAuthorityCount))
static proc_t *
process_event(char *data, int dlen, int arch, int ver)
{
	proc_t *p = (proc_t *) mem_zalloc(sizeof (proc_t));
	wchar_t *wstr;
	char *str;
	size_t len;
	struct ProcessTypeGroupOff *lpoff = &poff[arch][ver];

	if (p == NULL)
		return (NULL);
	ZeroMemory(p, sizeof (proc_t));
	p->ppid = *(uint32_t *) (data + lpoff->ppid);
	p->pid = *(uint32_t *) (data + lpoff->pid);
	len = arch ? 16 : 8;
	ULONG* sid = (ULONG *) (data + lpoff->SID);
	if (*sid == 0) {
		str = (char *) ((data + lpoff->SID + len));
	} else {
		SID *sid = (SID *) (data + lpoff->SID + len);
		len = SeLengthSid(sid);
		str = (char *) ((char *) sid + len);
	}

	if ((str - (char *)data) >= dlen)
		return (p);
	str = _strlwr(str);
	len = strlen(str) + 1;
	p->name = (char *) mem_zalloc(len);
	strcpy(p->name, str);
	if (ver < 2)
		return (p);
	wstr = (wchar_t *) (str + len);
	len = wcslen(wstr) * 2 + 2;
	p->cmdline = (wchar_t *) mem_zalloc(len);
	wcscpy(p->cmdline,  wstr);

	return (p);
}

/*
 * last cb function to run for process event
 * doesnt do anything yet. remove defunct/exit process
 */
static int
process_func_last(PEVENT_RECORD ev, void *data)
{
	pid_t pid = ev->EventHeader.ProcessId;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, ProcessGuid));

	switch (ev->EventHeader.EventDescriptor.Opcode) {
	case 2:
	case 4:
		/* remove from proclist ?? */
		return (0);
	}
	return (1);
}

/* first cb function to run for process event */
static int
process_func_first(PEVENT_RECORD ev, void *data)
{
	proc_t *p = NULL, *p0 = NULL;
	uint32_t st, pid;
	int ver = ev->EventHeader.EventDescriptor.Version;
	int arch = ARCHETW(ev);//arch = sessinfo->etw->ptrsz == 4 ? 0 : 1;
	char *ud = (char *) ev->UserData;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, ProcessGuid));
	ASSERT(ver < 6);

	switch (ev->EventHeader.EventDescriptor.Opcode) {
	case 1:	//start
	case 3:	//start rundown
	case 4:	//end rundown
		p = process_event(ud, ev->UserDataLength, arch, ver);
		break;
	case 2:	//exit
	case 39: {  //defunct
		pid = *(uint32_t *) (ud + poff[arch][ver].pid);
		st = *(uint32_t *) (ud + poff[arch][ver].es);

		p0 = etw_get_proc(pid, ETW_PROC_FIND);
		if (p0) {
			p0->exitval = st;
			p0->dead = 1;
		}
		return (0);
	}
	default:
		return (-1);
	}

	p->sessid = poff[arch][ver].id == -1 ? p->sessid :
	    *(uint32_t *) (ud + poff[arch][ver].id);
	p->exitval = poff[arch][ver].es == -1 ? p->exitval :
	    *(uint32_t *) (ud + poff[arch][ver].es);
	p->pageaddr = poff[arch][ver].base == -1 ? p->pageaddr : (
	    !arch ? * (uint32_t *) (ud + poff[arch][ver].base) :
	    * (uint64_t *) (ud + poff[arch][ver].base));
	p->addr = poff[arch][ver].uniq == -1 ? p->addr : (
	    !arch ? * (uint32_t *) (ud + poff[arch][ver].uniq) :
	    * (uint64_t *) (ud + poff[arch][ver].uniq));
	p->model = poff[arch][ver].flags == -1 ? 1 : *(uint32_t *) (
	    ud + poff[arch][ver].flags); /* flags == 2 WOW64 ?? */
	p->model = p->model == 2 ? 0 : 1;
	if (ev->EventHeader.EventDescriptor.Opcode == 1) {
		sessinfo->proc = p;
		sessinfo->pid = p->pid;
	}

	p0 = etw_get_proc(p->pid, ETW_PROC_FIND);

	if (!p0) {
		etw_add_proc(p->pid, p);
	} else {
		ASSERT(p->pid == p0->pid);

		p0->ppid = p->ppid;
		p0->name = p->name;
		/* p0->p_model = p->p_model; */
		p0->cmdline = p->cmdline;
		p0->sessid = p->sessid;
		p0->exitval = p->exitval;
		p0->pageaddr = p->pageaddr;
		p0->addr = p->addr;

		free(p);
	}
	return (0);
}

static void
print_proclist()
{
	unordered_map<pid_t, proc_t *>::iterator iter = proclist.begin();
	int i = 0;

	while (iter != proclist.end()) {
		printf("%d - %s %S\n", i++, iter->second->name,
		    iter->second->cmdline);
		iter++;
	}
}

struct ThreadTypeGroup1 {
	int pid, tid, stkb, stksz, usktb, ustlsz, staddr, win32, teb, tag, prib, prip,
	    priio, flags, name;
} toff[2][4] = {
	{
		{0, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
		{0, 4, 8, 12, 16, 20, 24, 28, -1, -1, 32, -1, -1, -1, -1},
		{0, 4, 8, 12, 16, 20, 24, 28, 32, 36, -1, -1, -1, -1, -1},
		{0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 41, 42, 43, 44}
	},
	{

		{0, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
		{0, 4, 8, 16, 24, 32, 40, 48, -1, -1, 56, -1, -1, -1, -1},
		{0, 4, 8, 16, 24, 32, 40, 48, 56, 64, -1, -1, -1, -1, -1},
		{0, 4, 8, 16, 24, 32, 40, 48, 56, 64, 72, 73, 74, 75, 76}
	}
};

/* thread event processing function */
static thread_t *
thread_event(struct ThreadTypeGroup1 *off, char *data, int dlen, int arch,
	    int version)
{
	thread_t *td = (thread_t *) mem_zalloc(sizeof (thread_t));
	proc_t *p;
	int pid = *(int *) data, tid = *(int *) (data + 4);

	ASSERT(pid != -1);

	if (td == NULL)
		return (NULL);

	p = etw_get_proc(pid, ETW_PROC_CREATE);

	td->pid = pid;
	td->tid = tid;
	if (p != NULL) {
		td->ppid = p->ppid;
		td->proc = p;
	}
	td->kbase = off->stkb == -1 ? td->kbase : (
	    !arch ? * (uint32_t *) (data + off->stkb) : * (uint64_t *) (data + off->stkb));
	td->klimit = off->stksz == -1 ? td->klimit : (
	    !arch ? * (uint32_t *) (data + off->stksz) : * (uint64_t *) (
	    data + off->stksz));
	td->ubase = off->usktb == -1 ? td->ubase : (
	    !arch ? * (uint32_t *) (data + off->usktb) : * (uint64_t *) (
	    data + off->usktb));
	td->ulimit = off->ustlsz == -1 ? td->ulimit : (
	    !arch ? * (uint32_t *) (data + off->ustlsz) : * (uint64_t *) (
	    data + off->ustlsz));

	return (td);
}

/* first cb function to run for thread event */
static int
thread_func_first(PEVENT_RECORD ev, void *data)
{
	thread_t *td, *t0;
	int len;
	int arch = ARCHETW(ev);
	int ver = ev->EventHeader.EventDescriptor.Version;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, ThreadGuid));

	switch (ev->EventHeader.EventDescriptor.Opcode) {
	case 1:
	case 3:
	case 4: {
		td = thread_event(&toff[arch][ver], (char *) ev->UserData, ev->UserDataLength,
		    arch, ver);
		if (ev->EventHeader.EventDescriptor.Opcode == 1) {
			sessinfo->td = td;
			sessinfo->tid = td->tid;
			sessinfo->proc = td->proc;
			sessinfo->pid = td->pid;
		}

		t0 = etw_get_td(td->tid, td->pid, ETW_THREAD_FIND);

		if (!t0) {
			etw_add_thread(td->tid, td);
		} else {
			if (t0->tid != td->tid) {
				int off = offsetof(thread_t, kbase);
				memcpy((char *)td + off, (char *)t0 + off,
				    sizeof (thread_t) - off);
				free(t0);
				etw_add_thread(td->tid, td);
			}
		}
		break;
	}
	case 72: {// SetName
		struct Thread_V2_SetName *tsn = (struct Thread_V2_SetName *) ev->UserData;
		td = etw_get_td(tsn->TThreadId, tsn->ProcessId, ETW_THREAD_CREATE);
		wcstombs_d(td->t_name, &tsn->ThreadName[0], MAX_PATH_NAME);
		break;
	}
	case 2:	//exit thread
	case 36: //context switch
	case 50: //readythread
	case 66: //???
	case 67: //???
	case 68: //???
		break;
	default:
		ASSERT("ThreadGuid Undefined Opcode" == 0);
	}

	return (0);
}

/*
 * last cb function to run for thread event
 * doesnt do anything yet. remove defunct/exit threads
 */
static int
thread_func_last(PEVENT_RECORD ev, void *data)
{
	pid_t tid;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, ThreadGuid));

	switch (ev->EventHeader.EventDescriptor.Opcode) {
	case 2:
		switch (ev->EventHeader.EventDescriptor.Version) {
		case 0:
			tid = *((uint32_t *) ev->UserData);
			break;
		case 1:
		case 2:
		case 3:
			tid = *((uint32_t *) ((char *)ev->UserData + 4));
			break;
		default:
			return (-1);
		}
	default:
		return (-1);
	}

	return (0);
}

static void
print_threadlist()
{
	unordered_map<pid_t, thread_t *>::iterator iter = threadlist.begin();
	int i = 0;

	while (iter != threadlist.end()) {
		printf("%d - %s %lld\n", i++,
		    iter->second->proc ? iter->second->proc->name : "",
		    iter->second->tid);
		iter++;
	}
}

/* first cb function to run for profile (perfinfo) event */
static int
profile_func_first(PEVENT_RECORD ev, void *data)
{
	char *ud = (char *) ev->UserData;
	int arch = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
	if (ev->EventHeader.EventDescriptor.Opcode != 46)
		return (0);

	if (ev->UserDataLength != 0) {
		//SampledProfile *sample = (SampledProfile *) ev->UserData;
		sessinfo->tid = *(uint32_t *) (ud + arch);
		sessinfo->td = etw_get_td(sessinfo->tid, -1, ETW_THREAD_CREATE);
		sessinfo->proc = sessinfo->td->proc;
		return (0);
	}
	return (-1);
}


/*
 * xperf synthetic image events
 * creates a list of pdb info for each process
 * having this events
 */
static int
xperf_image_events(PEVENT_RECORD ev, void *data)
{
	//struct DbgID_RSDS *dbg;
	int fnd = 0;
	size_t size = 0;
	cvpdbinfo_t *cv = NULL;
	proc_t *proc;
	int ptrsz = ARCHETW(ev) ? 8 : 4; //sessinfo->etw->ptrsz;
	uetwptr_t base;
	int pid, age;
	GUID *sid;
	char *p = (char *) ev->UserData;
	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId,
	    KernelTraceControlGuid));

	if (ev->EventHeader.EventDescriptor.Opcode == 36 ||
	    ev->EventHeader.EventDescriptor.Opcode == 37) {
		//dbg = (struct DbgID_RSDS *)  ev->UserData;
		if (ptrsz == 4) {
			base = *(uint32_t *) p;
		} else {
			base = *(uint64_t *) p;
		}
		p += ptrsz;
		pid = *(int *) p;
		p += sizeof(int);
		sid = (GUID *) p;
		p += sizeof(GUID);
		age = *(int *) p;
		p += sizeof(int);
		ASSERT(ev->EventHeader.ProcessId == pid);

		proc = etw_get_proc(pid, ETW_PROC_CREATE);

		if ((cv = cvinfolist[*sid]) == NULL) {
			size_t len = strlen((char *)p);
			size = (int) offsetof(cvpdbinfo_t, pdbname)
			    + len + 1;
			cv = (cvpdbinfo_t *) mem_zalloc(size);
			cv->cvsig = 0x53445352;
			cv->sig = *sid;
			cv->age = age;
			strcpy((char *) &cv->pdbname[0], (char *) p);
			cv->pdbname[len] = 0;
			cvinfolist[cv->sig] = cv;
		} else {
			/*
			 * if we have already received this event,
			 * ex for a different process, dont create a new cvpdbinfo_t.
			 * Check whether it is linked with existing process.
			 */
			etw_proc_cvinfo_t *tmp = (etw_proc_cvinfo_t *) proc->cvinfo;
			while (tmp) {
				if (tmp->cv == cv)
					return (0);
				tmp = tmp->next;
			}
			size_t len = strlen((char *)cv->pdbname);
			size = (int) offsetof(cvpdbinfo_t, pdbname) + len + 1;
		}

		etw_proc_cvinfo_t * cvinfo =
		    (etw_proc_cvinfo_t *) mem_zalloc(sizeof (etw_proc_cvinfo_t));
		cvinfo->cv = cv;
		cvinfo->base = base;
		cvinfo->size = size;
		cvinfo->next = (etw_proc_cvinfo_t *) proc->cvinfo;
		proc->cvinfo = cvinfo;
	} else if (ev->EventHeader.EventDescriptor.Opcode == 0) {
		;
	}

	return (0);
}

/* image load */
static void
print_modulelist()
{
	unordered_map<wstring, etw_module_t *>::iterator iter =
	    modlist.begin();
	int i = 0;
	fprintf(stderr, "Module list\n");
	while (iter != modlist.end()) {
		printf("%ls\n", iter->second->name);
		iter++;
	}
}

struct ImageLoad etw_imgload[2][4] = {
	{
		{ 0, 4, -1, -1, -1, -1, 8 },
		{ 0, 4, 8, -1, -1, -1, 12 },
		{ 24, 4, 8, 12, 16, 0, 44 },
		{ 24, 4, 8, 12, 16, 0, 44 }
	},
	{
		{ 0, 8, -1, -1, -1, -1, 16 },
		{ 0, 8, 16, -1, -1, -1, 20 },
		{ 32, 8, 16, 20, 24, 0, 56 },
		{ 32, 8, 16, 20, 24, 0, 56 }
	}
};

int
dtrace_etwloadinfo(int arch, int ver, char *p, int len, etw_module_t *mod,
    int32_t *pid, uint64_t *pbase)
{
	struct ImageLoad *off = &etw_imgload[arch][ver];

	mod->base = arch ? *(uint64_t *) (p + off->base) : *(uint32_t *) (
	    p + off->base);
	*pbase = off->dbase == -1 ? mod->base :
	    (arch ? * (uint64_t *) (p + off->dbase) : * (uint32_t *) (p + off->dbase));
	mod->size = arch ? *(uint64_t *) (p + off->size) : *(uint32_t *) (
	    p + off->size);
	mod->chksum = off->chksum == -1 ? 0 : *(uint32_t *) (p + off->chksum);
	mod->tmstamp = off->tmstamp == -1 ? 0 : *(uint32_t *) (p + off->tmstamp);
	wcscpy(mod->name, (wchar_t *) (p + off->wname));
	*pid = off->pid == -1 ? 0 : *(uint32_t *) (p + off->pid);

	return (0);
}

/* processing for module load event */
static int
image_load_func(PEVENT_RECORD ev, void *data)
{
	proc_t *proc;
	int32_t pid = 0;
	etw_proc_module_t *pmod;
	uetwptr_t pbase;
	Image *img;
	wchar_t *pstr;
	wstring wstr;
	int fnd = 0;
	char *p = (char *) ev->UserData;
	int ver = ev->EventHeader.EventDescriptor.Version;
	int arch = ARCHETW(ev);
	struct ImageLoad *off = &etw_imgload[arch][ver];

	etw_module_t *fmod, *mod =
	    (etw_module_t *) mem_zalloc(sizeof (etw_module_t));

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, ImageLoadGuid));
	ASSERT(ev->EventHeader.EventDescriptor.Opcode != 1);

	memset(mod, 0, sizeof (etw_module_t));
	switch (ev->EventHeader.EventDescriptor.Opcode) {
	case 10: 	/* Load */
		fnd = 0;
	case 3:		/* DCStartLoad */
	case 4:		/* DCEndUnLoad */
		dtrace_etwloadinfo(arch, ver, p, ev->UserDataLength, mod, &pid, &pbase);
		break;
	case 2:		/* UnLoad */
		return (0);
		break;
	default:
		dprintf("(%s), unknown event (%d) version (%d)\n", __func__,
		    ev->EventHeader.EventDescriptor.Opcode,
		    ev->EventHeader.EventDescriptor.Version);
		return (0);
		break;
	}

	etw_rep_dev_to_path(mod->name);	/* Normalize pathname */
	_wcslwr(mod->name);
	wstr = wstring((wchar_t *) mod->name);

	if ((fmod = modlist[wstr]) == NULL) {
		mod->cvinfo = NULL;	/* etw_pdb_info(mod->name); */
		etw_add_module(mod, wstr);
	} else {
		/*
		 * timestamp is zero for rundowns,
		 * only has value for load & unload events.
		 */
		if (fmod->tmstamp == 0 && mod->tmstamp > 0)
			fmod->tmstamp = mod->tmstamp;
		free(mod);
		mod = fmod;
	}

	if (pid != -1) {
		pmod = (etw_proc_module_t *) mem_zalloc(sizeof (etw_proc_module_t));
		pmod->mod =  mod;
		pmod->base = pbase;
		proc = etw_get_proc(pid, ETW_PROC_FIND);
		if (proc != NULL) {
			pmod->next = (etw_proc_module_t *) proc->mod;
			proc->mod = pmod;
		}
	}

	return (0);
}

/*
 * etw user stack event processing
 * this are additional stacks whick were not included in the
 * user event extended data stack.
 * (ex. kernel stack trace of the user event)
 */
static int
ustack_func(PEVENT_RECORD ev, void *data)
{
	int i = 0;
	etw_sessioninfo_t *sess = sessinfo->etw;
	int size = 0, psize = 0;
	ULONG64 matchid = 0;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, KernelEventTracing));

	if (ev->EventHeader.EventDescriptor.Id != 18) {
		return (0);
	}

	if (ev->ExtendedDataCount) {
		do {
			if (ev->ExtendedData[i].ExtType ==
			    EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
				psize = sizeof (ULONG64);
				size = (ev->ExtendedData[i].DataSize - sizeof (ULONG64)) / psize;
			} else if (ev->ExtendedData[i].ExtType ==
			    EVENT_HEADER_EXT_TYPE_STACK_TRACE32) {
				psize = sizeof (ULONG);
				size = (ev->ExtendedData[i].DataSize - sizeof (ULONG64)) / psize;
			} else {
				continue;
			}
			matchid = *((ULONG64 *)ev->ExtendedData[i].DataPtr);

			intptr_t out[5];
			int osz = 5;
			etw_stack_t *stackp = NULL;
			int r = lookupallhm(&sess->Q.map[ev->BufferContext.ProcessorNumber],
			    matchid, out, osz, hashint64, cmpint64);

			/*
			 * processor number in the event and its stackwalk
			 * may not match. so check for the event in all the cpu.
			 */
			if (r == NULL) {
				for (uint32_t i = 0; i < sess->ncpus && stackp == NULL && r == 0; i++) {
					r = lookupallhm(&sess->Q.map[i], matchid, out,
					    osz, hashint64, cmpint64);
				}
			}
			if (r == 0) {
				if (etw_diag_flags & ~SDT_DIAG_ZUSTACK_EVENTS) {
					etw_diag_cb(ev,  (void *) SDT_DIAG_ZUSTACK_EVENTS);
				}
				return (-1);
				//assert(0);
			}
			/*
			 * events can match more than one probe (etw keywords)
			 */
			for (int j = 0; j < r; j++) {
				stackp = (etw_stack_t *)out[j];
				int del = stackp->stacklen;
				memcpy((char *) stackp->stack + (stackp->stacklen * psize),
				    (char *) ev->ExtendedData[i].DataPtr + sizeof (ULONG64),
				    size * psize);

				stackp->stacklen += size;
				stackp->stackready = 1;
			}
		} while (++i < ev->ExtendedDataCount);
	}
	return (0);
}

/* Stack */
static int
stack_func(PEVENT_RECORD ev, void *data)
{
	struct ETWStackWalk *sw = (struct ETWStackWalk *) ev->UserData;
	etw_sessioninfo_t *sess = sessinfo->etw;
	int ptrsz = ARCHETW(ev) ? 8 : 4; //sess->ptrsz; /* XXXX */
	int offset = (sizeof (struct ETWStackWalk) - ptrsz);
	int depth = (ev->UserDataLength - offset) / ptrsz;

	etw_stack_t *stackp =
	    (etw_stack_t *) lookuphm(&sess->Q.map[ev->BufferContext.ProcessorNumber],
	    sw->EventTimeStamp, hashint64, cmpint64);

	/*
	 * processor number in the event and its stackwalk
	 * may not match. so check for the event in all the cpu.
	 */
	if ((stackp == NULL) || (stackp->dprobe.tid != -1 &&
	    (stackp->dprobe.tid != sw->StackThread))) {
		stackp = NULL;
		for (uint32_t i = 0; i < sess->ncpus && stackp == NULL; i++) {
			stackp = (etw_stack_t *) lookuphm(&sess->Q.map[i],
			    sw->EventTimeStamp, hashint64, cmpint64);
			if (stackp && (stackp->dprobe.tid != sw->StackThread &&
			    stackp->dprobe.tid != -1))
				stackp = NULL;
		}
	}

	if (stackp == NULL) {
		if (etw_diag_flags & ~SDT_DIAG_ZSTACK_EVENTS) {
			sessinfo->timestamp = sw->EventTimeStamp;
			etw_diag_cb(ev,  (void *) SDT_DIAG_ZSTACK_EVENTS);
		}
		return (-1);
	}

	ASSERT(stackp->dprobe.ts == sw->EventTimeStamp);
	ASSERT(stackp->dprobe.tid == sw->StackThread ||
	    stackp->dprobe.tid == -1);

	/*
	 * if the initial events process id or thread id is equal to -1
	 * update it here
	 */
	stackp->dprobe.pid = sw->StackProcess;
	if (stackp->dprobe.tid == -1) {
		stackp->dprobe.tid = sw->StackThread;
	}

	if (depth + stackp->stacklen > ETW_MAX_STACK) {
		depth = ETW_MAX_STACK - stackp->stacklen;
	}

	if (depth) {
		int j = stackp->stacklen;
		if (ptrsz == 4) {
			uint32_t *pc = (uint32_t *) ((char *)ev->UserData + offset);
			for (int i = 0 ; i < depth; i++)
				stackp->stack[j++] = (uint64_t) pc[i];
		} else {
			uint64_t *pc = (uint64_t *) ((char *)ev->UserData + offset);
			for (int i = 0 ; i < depth; i++)
				stackp->stack[j++] = pc[i];
		}

		stackp->stacklen += depth;
		stackp->stackready = 1;
	}

	return (0);
}

int
dtrace_stack_func(PEVENT_RECORD ev, void *data)
{
	return stack_func(ev, data);
}

/* lost event - opcode = 32 */
static int
lost_event_func(PEVENT_RECORD ev, void *data)
{
	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, RTLostEvent));
	dprintf("Lost Events\n");

	return (0);
}

static int
etw_set_stackid(etw_sessioninfo_t *sess, CLASSIC_EVENT_ID id[], int len)
{
	int fnd = 0;
	int err;

	if (FILESESSION(sess))
		return (0);
	ASSERT(sess->stackidlen + len < ETW_MAX_STACKID);

	for (int i = 0; i < len; i++) {
		for (int j = 0; j < sess->stackidlen; j++) {
			if (sess->stackid[j].EventGuid == id[i].EventGuid &&
			    sess->stackid[j].Type == id[i].Type) {
				fnd = 1;
				break;
			}
		}
		if (fnd == 0) {
			sess->stackid[sess->stackidlen].EventGuid = id[i].EventGuid;
			sess->stackid[sess->stackidlen].Type = id[i].Type;
			sess->stackidlen++;
		}
	}

	err = etw_set_kernel_stacktrace(sess->hsession,
	    sess->stackid, sess->stackidlen);
	return (err);
}

/*
 * Return the linked list of modules loaded for the process
 */
etw_proc_module_t *
dtrace_etw_pid_modules(pid_t pid)
{
	proc_t *p = NULL;

	p = etw_get_proc(pid, ETW_PROC_FIND);

	return ((etw_proc_module_t *) (p ? p->mod : NULL));
}

char *
dtrace_etw_lookup_jit_module(pid_t pid, uetwptr_t addr, char *buf,
    size_t size)
{
	etw_jitsym_map_t& symmap = pid_jit_symtable[pid];
	wchar_t *tmod = NULL;
	etw_jit_symbol_t *tsym = etw_lookup_jit_sym(pid, addr);

	if (tsym == NULL) {
		buf[0] = 0;
		return (buf);
	}
	tmod = symmap.jit_modules[tsym->ModuleID];
	if (tmod == NULL) {
		buf[0] = 0;
		return (buf);
	}
	wchar_t name[MAX_PATH];
	_wsplitpath(tmod, NULL, NULL, name, NULL);
	wcstombs_d(buf, name, size);

	return (buf);
}

int
dtrace_etw_lookup_jit_addr(pid_t pid, uetwptr_t addr, char *buf,
    size_t size, GElf_Sym *symp)
{
	etw_jit_symbol_t *jsym = etw_lookup_jit_sym(pid, addr);
	int ls, lw;
	wchar_t wbuf[256];

	if (jsym) {
		if (symp != NULL) {
			symp->st_name = 0;
			symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
			symp->st_other = 0;
			symp->st_shndx = 1;
			symp->st_value = jsym->MethodStartAddress;
			symp->st_size = jsym->MethodSize;
		}
		if (buf != NULL && size > 0) {
			wcscpy(wbuf, jsym->MethodFullName);
			ls = wcslen(wbuf);
			wbuf[ls++] = L'.';
			wcscpy(wbuf + ls, jsym->MethodFullName + ls);
			ls = wcstombs_d(buf, wbuf, size);
		}

		return (0);
	}

	return (-1);
}

/*
 * lookup symbol for the given address, by looking at the etw loaded
 * modules. modules are initialized with dbghelp as and when needed.
 * when initialzing with dbghelp, they are loaded at next free address.
 * when looking for a symbol within this module, the sym address is converted
 * to match the base address registred with dbghelp, and if a symbol
 * is found, reversed  to get the actual address.
 */
int
dtrace_etw_lookup_addr(etw_proc_module_t *pmod, pid_t pid,
    uetwptr_t addr,
    char *buf, size_t size, GElf_Sym *symp)
{
	int fnd = 0;
	proc_t *p;
	etw_module_t *mod;
	cvpdbinfo_t *cv;
	uint64_t base;
	uetwptr_t tmpa;
	int arch = (sessinfo == NULL ?
	    dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]->sessinfo :
	    sessinfo)->etw->ptrsz == 4 ? 0 : 1; //XXX

	if (pmod == NULL) {
		p = etw_get_proc(pid, ETW_PROC_FIND);
		if (p) {
			pmod = (etw_proc_module_t *) p->mod;
		}
	}

	NTKERNEL:
	while (pmod) {
		mod = pmod->mod;
		base = pmod->base ? pmod->base : mod->base;
		ASSERT(mod != NULL);

		if (addr >= base && addr < base + mod->size) {
			if (pmod->symloaded) {
				ASSERT(mod->sym != NULL);
				fnd = 1;
				break;
			}

			if (mod->sym == &pdbsyms) {
				pmod->symloaded = 1;
				fnd = 1;
				break;
			} else if (mod->sym == &nopdbsyms) {
				/*
				 * if module previously loaded in dbghelp without
				 * pdb info. try again with this process pdb info
				 * collection.
				 */
				p = etw_get_proc(pid, ETW_PROC_FIND);
				if (p->cvinfo) {
					cv = etw_match_cvinfo((etw_proc_cvinfo *) p->cvinfo,
					    mod, pmod->base);
				}
				if (cv == NULL) {
					pmod->symloaded = 1;
					fnd = 1;
					break;
				}
			}

			if (cv == NULL || (cv = mod->cvinfo) == NULL) {
				p = etw_get_proc(pid, ETW_PROC_FIND);
				if (p->cvinfo) {
					cv = mod->cvinfo =
					    etw_match_cvinfo((etw_proc_cvinfo *) p->cvinfo,
					    mod, pmod->base);
				} else {
					cv = mod->cvinfo =
					    etw_match_datatime(pdbsyms.h, mod, pmod->base);
				}
			}

			if (cv == NULL) {
				/*
				 * No symbol file found. load anyway into dbghelp
				 * at the next free address.
				 */
				wchar_t *ws0 = PathFindFileNameW(mod->name);
				if (INKERNEL_ETW(pmod->base, arch)) {
					uint64_t base0 = SymLoadModuleExW(nopdbsyms.h, 0, ws0, NULL,
					    pmod->base, (DWORD) mod->size, NULL, 0);
					mod->dbgbase = pmod->base;
				} else {
					uint64_t base0 = SymLoadModuleExW(nopdbsyms.h, 0, ws0, NULL,
					    nopdbsyms.endaddr, (DWORD) mod->size, NULL, 0);
					mod->dbgbase = nopdbsyms.endaddr;
					nopdbsyms.endaddr += mod->size;
				}
				mod->sym = &nopdbsyms;
				pmod->symloaded = 1;
				fnd = 1;
				break;
			}

			size_t len = strlen((char *)cv->pdbname);
			size_t size = offsetof(cvpdbinfo_t, pdbname)
			    + len + 1;
			size_t sz = sizeof (MODLOAD_CVMISC) + size;

			MODLOAD_CVMISC * cvmisc = (MODLOAD_CVMISC *) mem_zalloc(sz);
			cvmisc->oCV = sizeof (MODLOAD_CVMISC);
			cvmisc->cCV = size;
			cvmisc->oMisc = 0;
			cvmisc->cMisc = 0;
			cvmisc->dtImage = 0;
			cvmisc->cImage = 0;
			memcpy((char *) cvmisc + sizeof (MODLOAD_CVMISC), cv, size);

			MODLOAD_DATA md = {0};
			md.ssize = sizeof (md);
			md.ssig = DBHHEADER_CVMISC;
			md.data = cvmisc;
			md.size = (DWORD) sz;
			wchar_t *ws = PathFindFileNameW(mod->name);
			/* load into dbghelp at the next free address */
			if (INKERNEL_ETW(addr, arch)) {
				base = SymLoadModuleExW(pdbsyms.h, 0, ws, NULL,
				    pmod->base, (DWORD) mod->size, &md, 0);
				mod->dbgbase = pmod->base;
			} else {
				base = SymLoadModuleExW(pdbsyms.h, 0, ws, NULL,
				    pdbsyms.endaddr, (DWORD) mod->size, &md, 0);
				mod->dbgbase = pdbsyms.endaddr;
				pdbsyms.endaddr += mod->size;
			}
			pmod->symloaded = 1;
			mod->sym = &pdbsyms;
			fnd = 1;
			break;
		}
		pmod = pmod->next;
	}
	/* for kernel address, search in pid 0 (idle) and pid 4 (system) process */
	if (pid == 0 && fnd == 0) {
		pid = 4;
		p = etw_get_proc(pid, ETW_PROC_FIND);
		if (p) {
			goto NTKERNEL;
		}
	}
	/* not found, try with jitted functions */
	if (fnd == 0) {
		return (dtrace_etw_lookup_jit_addr(pid, addr, buf, size, symp));
	}

	SYMBOL_INFO *s;
	s = (SYMBOL_INFO *) malloc(sizeof (SYMBOL_INFO) + size - 1);
	if (s == NULL)
		return (-1);
	ZeroMemory(s, sizeof (SYMBOL_INFO) + size - 1);
	s->SizeOfStruct = sizeof (SYMBOL_INFO);
	s->MaxNameLen = size;
	int64_t fac =  ((uint64_t) mod->dbgbase - pmod->base) ;
	tmpa = addr + fac;
	if (SymFromAddr(mod->sym->h, tmpa, 0, s) == TRUE) {
		if (symp != NULL) {
			symp->st_name = 0;
			symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
			symp->st_other = 0;
			symp->st_shndx = 1;
			symp->st_value = s->Address - fac;
			symp->st_size = s->Size;
		}
		if (buf != NULL && size > 0)
			strncpy(buf, s->Name, size);
		return (0);
	}

	return (-1);
}

char *
dtrace_etw_objname(etw_proc_module_t *pmod, pid_t pid, uetwptr_t addr,
    char *buffer, size_t bufsize)
{
	int fnd = 0;
	etw_module_t *mod;

	while (pmod) {
		mod = pmod->mod;

		ASSERT(mod != NULL);

		if (addr >= pmod->base && addr < pmod->base + mod->size) {
			wchar_t *ws = PathFindFileNameW(mod->name);
			WideCharToMultiByte(CP_UTF8, 0, ws, -1, buffer, bufsize, NULL, NULL);
			buffer[bufsize - 1] = 0;
			return (buffer);
		}
		pmod = pmod->next;
	}
	return (dtrace_etw_lookup_jit_module(pid, addr, buffer, bufsize));
}

etw_proc_module_t *
dtrace_etw_pid_symhandle(pid_t pid)
{
	proc_t *p;
	p = etw_get_proc(pid, ETW_PROC_FIND);
	if (p) {
		return ((etw_proc_module_t *) (p->mod));
	}
	return (0);
}

/*
 * Get process of pid from process map. If not found, add
 * to the map, and return.
 */
proc_t *
dtrace_etw_proc_find(pid_t pid, int create)
{
	proc_t *p = NULL;

	p = etw_get_proc(pid, create);

	return (p);
}

/*
 * Get thread of tid from thread map. If not found, add
 * to the map, and return.
 */
thread_t *
dtrace_etw_td_find(pid_t pid, pid_t tid, int current)
{
	thread_t *td = NULL;

	td = etw_get_td(tid, pid, ETW_THREAD_CREATE);

	if (current) {
		if (sessinfo == NULL) {
			sessioninfo_t *tmp = (sessioninfo_t *) mem_zalloc(
			    sizeof (sessioninfo_t));
			sessinfo = tmp;
		}
		sessinfo->td = td;
		sessinfo->tid = tid;
		sessinfo->pid = td->pid;
		sessinfo->proc = td->proc;
	}

	return (td);
}

/*
 * Return NULL if kernel session doesnt exist
 */
int
dtrace_etw_session_on(etw_sessions_t *sinfo)
{
	return (int)
	    dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]->psession;
}

int
dtrace_set_ft_stack(uetwptr_t *stack, uint32_t size)
{
	sessinfo->etw->ftstack = stack;
	sessinfo->etw->ftsize = size;

	return (0);
}

/*
 * wait for ft etw provider to deliver all events
 * before ending the session
 */
int
dtrace_etw_session_ft_on(etw_sessions_t *sinfo)
{
	etw_sessioninfo_t *sess = NULL;
	int hb = 0, loop = 40;

	while ((sess = dtrace_etw_sessions[DT_ETW_FT_SESSION]) && loop) {
		Sleep(2000);
		if (sess->hb == hb) {
			etw_stop_ft();
			return (0);
		}
		hb = sess->hb;
		loop--;
	}
	etw_stop_ft();

	return (0);
}

/*
 * Returns the thread which generated the ETW event
 */
thread_t *
dtrace_etw_curthread()
{
	if (sessinfo) {
		return (sessinfo->td);
	} else {
		thread_t *td = etw_get_td(GetCurrentThreadId(),
		    GetCurrentProcessId(), ETW_THREAD_CREATE);
		return (td);
	}
}

/*
 * Returns the process which generated the ETW event
 */
proc_t *
dtrace_etw_curproc()
{
	if (sessinfo) {
		return (sessinfo->proc);
	} else {
		proc_t *p = etw_get_proc(GetCurrentProcessId(), ETW_PROC_CREATE);
		return (p);
	}
}

int
dtrace_etw_current_cpu()
{
	if (sessinfo) {
		return (sessinfo->cpuno);
	} else {
		return (-1);
	}
}

/*
 * Returns the structure containing information off all the
 * etw providers found
 */
void *
dtrace_etw_user_providers()
{
	return dtrace_etw_sessions[DT_ETW_KERNEL_SESSION] == NULL ?
	    NULL : dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]->data;
}
void
dtrace_etw_probe(dtrace_id_t id, uetwptr_t arg0, uetwptr_t arg1,
    uetwptr_t arg2, uetwptr_t arg3, uetwptr_t arg4)
{
	dtrace_etw_probe_sdt(id, arg0, arg1, arg2, arg3, arg4, 0, 0, 0);
}

/*
 * stacktrace of a kernel event may come any time after the event, in
 * a seperate stack event, in more than one event packet.
 * Here we wait for ETW_QUEUE_SIZE events before sending the event.
 * If stacktrace for the event comes after ETW_QUEUE_SIZE events, then
 * the trace is lost.
 */
void
dtrace_etw_probe_sdt(dtrace_id_t id, uetwptr_t arg0, uetwptr_t arg1,
    uetwptr_t arg2, uetwptr_t arg3, uetwptr_t arg4, uetwptr_t stackid, uetwptr_t pl,
    uetwptr_t epl)
{
	HANDLE *lock = 0;
etw_stack_t *del, *stackp;
etw_dprobe_t *dprobe;
int size = 0, psize = 0, matchid = 0, i = 0;

stackp = esalloc();
	stackp->stacklen = 0;
	stackp->stackready = 0;
	dprobe = &stackp->dprobe;

	dprobe->id = id;
	dprobe->args[0] = arg0;
	dprobe->args[1] = arg1;
	dprobe->args[2] = arg2;
	dprobe->args[3] = arg3;
	dprobe->args[4] = arg4;
	dprobe->ts = sessinfo->timestamp;
	dprobe->cpuno = sessinfo->cpuno;
	dprobe->proc = sessinfo->proc;
	dprobe->td = sessinfo->td;
	dprobe->pid = sessinfo->pid;
	dprobe->tid = sessinfo->tid;
	dprobe->payload = pl;
	dprobe->extpayload = epl;
	dprobe->thrid = sessinfo->etw->thrid;

	while (InterlockedExchange(&sessinfo->etw->Q.lock, TRUE) == TRUE)
		Sleep(1);

	sessinfo->etw->Q.queue.push(stackp);

	/* user mode ETW stacktrace */
	if (sessinfo->etw->ev && sessinfo->etw->ev->ExtendedDataCount) {
		PEVENT_RECORD ev = sessinfo->etw->ev;

		if (ev->ExtendedDataCount) {
			do {
				if (ev->ExtendedData[i].ExtType ==
				    EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
					psize = sizeof (ULONG64);
					size = (ev->ExtendedData[i].DataSize - sizeof (ULONG64)) / psize;
				} else if (ev->ExtendedData[i].ExtType ==
				    EVENT_HEADER_EXT_TYPE_STACK_TRACE32) {
					psize = sizeof (ULONG);
					size = (ev->ExtendedData[i].DataSize - sizeof (ULONG64)) / psize;
				} else {
					continue;
				}

				memcpy((char *) stackp->stack + (stackp->stacklen * psize),
				    (char *) ev->ExtendedData[i].DataPtr + sizeof (ULONG64),
				    size * psize);
				stackp->stacklen += size;
				stackp->stackready = 1;
				matchid = *((ULONG64 *)ev->ExtendedData[i].DataPtr);

				/* if matchid == 0 both kernel and user stack complete; */
				if (matchid != 0) {
					stackp->key = matchid;
					addhm(&sessinfo->etw->Q.map[dprobe->cpuno], matchid, (uintptr_t) stackp,
					    hashint64);
				}
			} while (++i < ev->ExtendedDataCount);
		}
	}
	if (stackid) {
		replacehm(&sessinfo->etw->Q.map[dprobe->cpuno], stackid, (uintptr_t) stackp,
		    hashint64, cmpint64);
		stackp->key = stackid;
	} else if (sessinfo->etw->ftsize) {
		memcpy(stackp->stack, sessinfo->etw->ftstack,
		    sessinfo->etw->ftsize * sizeof (uetwptr_t));
		stackp->stacklen = sessinfo->etw->ftsize;
		sessinfo->etw->ftsize = 0;
		stackp->stackready = 1;
	} else if (matchid == 0) {
		addhm(&sessinfo->etw->Q.map[dprobe->cpuno], dprobe->ts, (uintptr_t) stackp,
		    hashint64);
		stackp->key = dprobe->ts;
	}

	del = stackp;
	int co = sessinfo->etw->Q.queue.size();
	static hrtime_t lasttm = ~0L;
	if (co > ETW_QUEUE_SIZE) {
		send_probe(sessinfo->etw);
	} else if (dprobe->ts - lasttm > 1000000 && --co > 0) {
		for (int i = 0; i < co; i++) {
			send_probe(sessinfo->etw);
		}
	}
	lasttm = dprobe->ts;
	InterlockedExchange(&sessinfo->etw->Q.lock, FALSE);
}

void
dtrace_etw_reset_cur(HANDLE *lock)
{
	return (etw_reset_cur(lock));
}

HANDLE *
dtrace_etw_set_cur(pid_t pid, pid_t tid, hrtime_t tm, int cpuno)
{
	return (etw_set_cur(pid, tid, tm, cpuno));
}

/*
 * Dtrace etw helper functions
 */
int
dtrace_etw_samplerate(int interval)
{
	return (etw_set_freqNT(interval));
}

/*
 * Get the stacktrace for current event,
 * returns stack depth
 */
int
dtrace_etw_get_stack(uint64_t *pcstack, int pcstack_limit,
    int usermode)
{
	int n = pcstack_limit;
	etw_stack_t *stackp;
	int arch;

	if (!sessinfo || sessinfo->etw == NULL)
		return (0);

	arch = sessinfo->etw->ptrsz == 4 ? 0 : 1; //XXX
	stackp = sessinfo->etw->stackinfo;

	if (!stackp || stackp->stackready == 0) {
		return (0);
	}

	if (usermode) {
		for (int i = 0; i < stackp->stacklen && pcstack_limit; i++) {
			if (!INKERNEL_ETW(stackp->stack[i], arch)) {
				*pcstack++ = (uint64_t)stackp->stack[i];
				pcstack_limit--;
			}
		}
	} else {
		for (int i = 0; i < stackp->stacklen && pcstack_limit; i++) {
			if (INKERNEL_ETW(stackp->stack[i], arch)) {
				*pcstack++ = (uint64_t)stackp->stack[i];
				pcstack_limit--;
			}
		}
	}

	return (n - pcstack_limit);
}

hrtime_t
dtrace_etw_gethrtime()
{
	int tmp;
	hrtime_t ts = 0;
	etw_sessioninfo *etw;

	sessinfo = sessinfo == NULL ?
	    dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]->sessinfo : sessinfo;

	if (sessinfo && sessinfo->etw) {
		tmp = sessinfo->etw->timescale * 100UL;
		ts = sessinfo->timestamp * tmp;
	}
	return (ts == 0 ? sys_gethrtime() : ts);
}

hrtime_t
dtrace_etw_gethrestime(void)
{
	sessinfo = sessinfo == NULL ?
	    dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]->sessinfo : sessinfo;
	hrtime_t ts = sessinfo && sessinfo->timestamp ?
	    etw_event_timestamp(sessinfo->timestamp) : sys_gethrestime();

	return (ts);
}

int
dtrace_etw_hook_event(const GUID *guid, Function efunc, void *data,
    int place)
{
	return (etw_hook_event(guid, efunc, data, place, TRUE));
}

int
dtrace_etw_unhook_event(const GUID *guid, Function efunc, void *data)
{
	return (etw_unhook_event(guid, efunc, data, FALSE));
}

int
dtrace_etw_nprocessors()
{
	int ncpus = 0;
	if (!sessinfo) {
		if (dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]) {
			ncpus = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]->ncpus;
		}
	} else {
		ncpus = sessinfo->etw->ncpus;
	}
	if (ncpus == 0) {
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		ncpus = si.dwNumberOfProcessors;
	}
	ASSERT(ncpus > 0);
	return (ncpus);
}

wchar_t *
dtrace_etw_get_fname(uetwptr_t fobj)
{
	return (etw_get_fname(fobj));
}

int
dtrace_etw_kernel_stack_enable(CLASSIC_EVENT_ID id[], int len)
{
	etw_sessioninfo_t *sess = NULL;
	int nlen = 0, ret;
	CLASSIC_EVENT_ID *nid = (CLASSIC_EVENT_ID *)
	    mem_zalloc(sizeof(CLASSIC_EVENT_ID) * len);

	if (etw_win8_or_gt()) {
		for (int i = 0; i < len; i++) {
			switch (id[i].Type) {
			case 35:
			case 36:
			case 47:
			case 50:

			case 66:
			case 68:
			case 69:

			case 67:
			case 51:
			case 52:
				nid[nlen].EventGuid = id[i].EventGuid;
				nid[nlen++].Type = id[i].Type;

				id[i].Type = 0;
				break;
			default:
				break;
			}
		}
		if (nlen && (sess = dtrace_etw_sessions[DT_ETW_HFREQ_SESSION]) != NULL) {
			ret = etw_set_stackid(sess, nid, nlen);
			//if (nlen != len)
			//	ASSERT(0);

			return ret;
		}
	}

	sess = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	return (etw_set_stackid(sess, id, len));
}

int
dtrace_etw_profile_enable(hrtime_t interval, int type)
{
	etw_sessioninfo_t *sess = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];
	CLASSIC_EVENT_ID  id[1];

	etw_hook_event(&PerfInfoGuid, profile_func_first, NULL,
	    ETW_EVENTCB_ORDER_FRIST, TRUE);

	if (FILESESSION(sess))
		return (0);

	id[0].EventGuid = PerfInfoGuid;
	id[0].Type = 46;

	etw_set_stackid(sess, id, 1);

	dtrace_etw_samplerate((int)(interval / 100.0));

	if (etw_enable_kernel_prov(NULL, sess->sessname,
	    EVENT_TRACE_FLAG_PROFILE, TRUE) != 0) {
		dprintf("dtrace_etw_profile_enable, failed\n ");
		return (0);
	}

	return (1);
}

int
dtrace_etw_profile_disable()
{
	etw_sessioninfo_t *sess = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	if (!sess || (FILESESSION(sess)))
		return (0);

	if (etw_enable_kernel_prov(NULL, sess->sessname,
	    EVENT_TRACE_FLAG_PROFILE, FALSE) != 0) {
		eprintf("dtrace_etw_profile_disable, failed\n ");
		return (-1);
	}
	return (1);
}

/*
 * Enable (flags) kernel provider
 */
int
dtrace_etw_prov_enable(int flags)
{
	etw_sessioninfo_t *fsess, *sess = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];
	int nflags = 0;
	if (FILESESSION(sess))
		return (-1);

	if (etw_win8_or_gt()) {
		if (flags & EVENT_TRACE_FLAG_CSWITCH)
			nflags |= EVENT_TRACE_FLAG_CSWITCH;
		if (flags & EVENT_TRACE_FLAG_DISPATCHER)
			nflags |= EVENT_TRACE_FLAG_DISPATCHER;
		if (flags & EVENT_TRACE_FLAG_DPC)
			nflags |= EVENT_TRACE_FLAG_DPC;
		if (flags & EVENT_TRACE_FLAG_INTERRUPT)
			nflags |= EVENT_TRACE_FLAG_INTERRUPT;
		if (flags & EVENT_TRACE_FLAG_DPC)
			nflags |= EVENT_TRACE_FLAG_DPC;
		if (flags & EVENT_TRACE_FLAG_SYSTEMCALL)
			nflags |= EVENT_TRACE_FLAG_SYSTEMCALL;
		if ((flags & PERF_PMC_PROFILR_GM1) == PERF_PMC_PROFILR_GM1)
			nflags |= PERF_PMC_PROFILR_GM1;
		if (nflags) {
			ULONG eflags = !(sess->flags & SESSINFO_LIVEFILE) ?
			    EVENT_TRACE_REAL_TIME_MODE :
			    (sess->flags & SESSINFO_FILE_ENABLE_ALL) ?
			    (EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_REAL_TIME_MODE) :
			    EVENT_TRACE_FILE_MODE_SEQUENTIAL;
			eflags |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
			if ((fsess = dtrace_etw_sessions[DT_ETW_HFREQ_SESSION]) == NULL) {
				fsess = etw_new_session(DTRACE_SESSION_NAME_HFREQ,
				    &DtraceSessionGuidHFREQ, ETW_TS_QPC, eflags,
				    sess->dtrace_probef, sess->dtrace_ioctlf,
				    (eflags & EVENT_TRACE_REAL_TIME_MODE) ? 0 : 1);
				dtrace_etw_sessions[DT_ETW_HFREQ_SESSION] = fsess;
				//relog_single(fsess, DT_ETW_HFREQ_SESSION);
			}

			if (nflags & PERF_PMC_PROFILR_GM1) {
				nflags &= ~PERF_PMC_PROFILR_GM1;
				flags &= ~PERF_PMC_PROFILR_GM1;
				dtrace_etw_prov_enable_gm(fsess == NULL ? DT_ETW_KERNEL_SESSION :
				    DT_ETW_HFREQ_SESSION, PERF_PMC_PROFILR_GM1, 1);
			}
			if (fsess == NULL)
				goto oldsession;
			if (nflags) {
				if (etw_enable_kernel_prov(NULL, fsess->sessname,
				    nflags, TRUE) != 0) {
					eprintf("dtrace_etw_prov_enable, failed for session %s flags (%d)\n ",
					    fsess->sessname, flags);
					return (-1);
				}
			}
			if ((flags = flags ^ nflags) == 0)
				return (DT_ETW_HFREQ_SESSION);
		}
	}

	oldsession:
	if (etw_enable_kernel_prov(NULL, sess->sessname,
	    flags, TRUE) != 0) {
		eprintf("dtrace_etw_prov_enable, failed for session %s flags (%d)\n ",
		    sess->sessname, flags);
		return (-1);
	}
	return (DT_ETW_KERNEL_SESSION);
}

/*
 * Disable (flags) kernel provider
 */
int
dtrace_etw_prov_disable(int flags)
{
	etw_sessioninfo_t *sess = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	if (sess == NULL || (FILESESSION(sess)))
		return (0);

	if (etw_enable_kernel_prov(NULL, sess->sessname,
	    flags, FALSE) != 0) {
		eprintf("dtrace_etw_prov_disable, failed for flags (%d)\n ",
		    flags);
		return (-1);
	}
	return (0);
}

int
dtrace_etw_uprov_enable(GUID *pguid, uint64_t keyword,
    uint32_t eventno, int level, int estack, int capture)
{
	if (dtrace_etw_sessions[DT_ETW_USER_SESSION]) {
		return etw_enable_user(
		    dtrace_etw_sessions[DT_ETW_USER_SESSION]->hsession,
		    pguid, keyword, level, estack, capture);
	} else if (FILESESSION(dtrace_etw_sessions[DT_ETW_KERNEL_SESSION])) {
		return (0);
	}

	return (-1);
}

int
etwfileexist(wchar_t *file)
{
	DWORD att = GetFileAttributes(file);

	return (att != INVALID_FILE_ATTRIBUTES &&
	    !(att & FILE_ATTRIBUTE_DIRECTORY));
}

HANDLE etwfile_start(etw_sessions_t *dummy);

/*
 * Initialize ETW to read from a etl file
 */
etw_sessions_t *
dtrace_etwfile_init(etw_dtrace_probe_t probef,
    etw_dtrace_ioctl_t ioctlf, wchar_t *etlfile, uint32_t flags)
{
	int iskevent = 0;
	etw_sessioninfo_t *sinfo;

	if (!etwfileexist(etlfile))
		return dtrace_etw_init(probef, ioctlf, etlfile, flags);
	etw_initialize();
	sinfo = newsessinfo();

	sinfo->dtrace_probef = probef;
	sinfo->dtrace_ioctlf = ioctlf;
	sinfo->flags |= SESSINFO_ISFILE;
	sinfo->etlfile = etlfile;

	wmutex_init(&etw_eventcb_lock);
	wmutex_init(&etw_cur_lock);
	wmutex_init(&etw_proc_lock);
	wmutex_init(&etw_thread_lock);
	wmutex_init(&etw_start_lock);

	etw_devname_to_path(devmap);

	etw_hook_event(&ProcessGuid, process_func_first, NULL, 1, iskevent);
	etw_hook_event(&ProcessGuid, process_func_last, NULL, 2, iskevent);
	etw_hook_event(&ThreadGuid, thread_func_first, NULL, 1, iskevent);
	etw_hook_event(&ThreadGuid, thread_func_last, NULL, 2, iskevent);
	/* etw_hook_event(&PerfInfoGuid, profile_func_first, NULL, 1, iskevent); */
	etw_hook_event(&StackWalkGuid, stack_func, NULL, 0, iskevent);
	etw_hook_event(&ImageLoadGuid, image_load_func, NULL, 0, iskevent);
	etw_hook_event(&FileIoGuid, fileio_func, NULL, 0, iskevent);
	/* etw_hook_event(&RTLostEvent, lost_event_func, NULL, 0, iskevent); */
	etw_hook_event(&KernelTraceControlGuid, xperf_image_events, NULL, 0,
	    iskevent);
	etw_hook_event(&MSDotNETRuntimeRundownGuid, clr_jitted_rd_func, NULL,
	    1, iskevent);
	etw_hook_event(&MSDotNETRuntimeGuid, clr_jitted_func, NULL, 1,
	    iskevent);
	etw_hook_event(&KernelEventTracing, ustack_func, NULL, 0, iskevent);

	dtrace_etw_sessions[DT_ETW_KERNEL_SESSION] = sinfo;

	if (etw_start_trace(sinfo, etw_event_cb, 0, 1) == 0) {
		etw_end_session(sinfo, NULL);
		delete sinfo;
		return (NULL);
	}
	wmutex_enter(&etw_start_lock);

	etwfile_start(NULL);
	sinfo->data = etw_get_providers();

	return (dtrace_etw_sessions);
}

etw_sessioninfo_t *
etw_session_add_fileext(etw_sessioninfo_t *sess, wchar_t *ext, int id)
{
	int len;
	len = (wcslen(sess->etlfile) + wcslen(ext) + 1) * 2;
	wchar_t *etlrdfile, *dot;
	etw_sessioninfo_t *sinfo;

	etlrdfile = (wchar_t *) mem_zalloc(len);
	wcscpy(etlrdfile, sess->etlfile);
	dot = wcsrchr(etlrdfile, L'.');
	wcscpy(++dot, ext);

	if (!PathFileExistsW(etlrdfile))
		return (NULL);

	sinfo = newsessinfo();

	sinfo->flags |= SESSINFO_ISFILE;
	sinfo->etlfile = etlrdfile;
	if ((etw_start_trace(sinfo, etw_event_cb, etw_event_thread, 0)) == 0) {
		etw_end_session(sinfo, NULL);
		delete sinfo;
		return (NULL);
	}
	sinfo->dtrace_ioctlf = sess->dtrace_ioctlf;
	sinfo->dtrace_probef = sess->dtrace_probef;
	dtrace_etw_sessions[id] = sinfo;

	return (sinfo);
}


HANDLE
dtrace_etwfile_start(etw_sessions_t *dummy)
{
	HANDLE ret = HANDLE (1);
	etw_sessioninfo_t *session =
	    dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	if (FILESESSION(session) == 0) {
		ret = (HANDLE) etw_finalize_start();
	}

	wmutex_exit(&etw_start_lock);

	return ret;
}

/*
 * Start etw trace from a etl file
 */
HANDLE
etwfile_start(etw_sessions_t *dummy)
{
	HANDLE thr = 0;
	etw_sessioninfo_t *session =
	    dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	/* perfview trace file */
	etw_session_add_fileext(session, L"kernel.etl", DT_ETW_HFREQ_SESSION);
	etw_session_add_fileext(session, L"clrRundown.etl",
	    DT_ETW_CLR_SESSION);

	if ((thr = etw_start_trace(session, etw_event_cb, etw_event_thread, 0)) == 0) {
		etw_end_session(session, NULL);
		return (0);
	}

	return (thr);
}

/*
 * missed events and missed stack
 */
int
dtrace_etw_set_diagnostic(int (*cb) (PEVENT_RECORD, void *),
    uint32_t id)
{
	etw_diag_cb = cb;
	etw_diag_flags |= ~id;

	return (0);
}

/*
 * Enable user mode etl providers
 */
int
dtrace_etw_enable_ft(GUID *guid, int kw, int enablestack)
{
	etw_sessioninfo_t * sinfo, *ksinfo;

	ksinfo = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];
	ULONG eflags = !(ksinfo->flags & SESSINFO_LIVEFILE) ? EVENT_TRACE_REAL_TIME_MODE :
	    (EVENT_TRACE_FILE_MODE_CIRCULAR | EVENT_TRACE_REAL_TIME_MODE);
	if (!dtrace_etw_sessions[DT_ETW_FT_SESSION]) {
		sinfo = etw_new_session(DTRACE_SESSION_NAME_FT, &DtraceSessionGuidFT,
		    ETW_TS_QPC, eflags,
		    ksinfo->dtrace_probef, ksinfo->dtrace_ioctlf, 0);
		if (sinfo == NULL) {
			return (0);
		}
		dtrace_etw_sessions[DT_ETW_FT_SESSION] = sinfo;
	}

	return etw_enable_user(
	    dtrace_etw_sessions[DT_ETW_FT_SESSION]->hsession, guid,
	    kw, TRACE_LEVEL_VERBOSE, enablestack, 0);
}

/*
 * Initialize ETW for real time events
 */
etw_sessions_t *
dtrace_etw_init(etw_dtrace_probe_t probef, etw_dtrace_ioctl_t ioctlf,
    wchar_t *oetlfile, uint32_t flags)
{
	ULONG etwflags = EVENT_TRACE_FLAG_PROCESS |
	    EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_THREAD |
	    EVENT_TRACE_FLAG_DISK_FILE_IO;
	ULONG iflags = 0;
	TRACEHANDLE handle = 0, hsession = 0;
	HANDLE thread = 0;
	int iskevent;
	const GUID *sguid;
	void (WINAPI * cb)(PEVENT_RECORD ev);
	wchar_t *sname;
	etw_sessioninfo_t *sinfo;
	hrtime_t sts = 0;
	uint32_t tflags = 0;

	etw_initialize();

	wmutex_init(&etw_eventcb_lock);
	wmutex_init(&etw_cur_lock);
	wmutex_init(&etw_proc_lock);
	wmutex_init(&etw_thread_lock);

	etw_devname_to_path(devmap);

	tempfiles(oetlfile);

	tflags |= oetlfile == NULL ? 0 :
	    (flags & 1) ? SESSINFO_LIVEFILE | SESSINFO_FILE_ENABLE_ALL : SESSINFO_LIVEFILE;

	if (etw_win8_or_gt()) {
		iskevent = FALSE;
		sname = DTRACE_SESSION_NAME;
		sguid = &DtraceSessionGuid;
		cb = etw_event_cb;
		iflags = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE |
		    (tflags ? EVENT_TRACE_FILE_MODE_SEQUENTIAL : 0);
	} else {
		iskevent = FALSE;
		sname = KERNEL_LOGGER_NAME;
		sguid = &SystemTraceControlGuid;
		cb = etw_event_cb;
		iflags =  EVENT_TRACE_REAL_TIME_MODE |
		    (tflags ? EVENT_TRACE_FILE_MODE_SEQUENTIAL : 0);
	}

	etw_hook_event(&ProcessGuid, process_func_first, NULL, 1, iskevent);
	etw_hook_event(&ProcessGuid, process_func_last, NULL, 2, iskevent);
	etw_hook_event(&ThreadGuid, thread_func_first, NULL, 1, iskevent);
	etw_hook_event(&ThreadGuid, thread_func_last, NULL, 2, iskevent);
	/* etw_hook_event(&PerfInfoGuid, profile_func_first, NULL, 1, iskevent); */
	etw_hook_event(&StackWalkGuid, stack_func, NULL, 0, iskevent);
	etw_hook_event(&ImageLoadGuid, image_load_func, NULL, 0, iskevent);
	etw_hook_event(&FileIoGuid, fileio_func, NULL, 0, iskevent);
	/* etw_hook_event(&RTLostEvent, lost_event_func, NULL, 0, iskevent); */
	etw_hook_event(&MSDotNETRuntimeRundownGuid, clr_jitted_rd_func, NULL,
	    1, 0);
	etw_hook_event(&MSDotNETRuntimeGuid, clr_jitted_func, NULL, 1, 0);
	etw_hook_event(&KernelEventTracing, ustack_func, NULL, 0, iskevent);
	if ((hsession =
	    etw_init_session(sname, *sguid, ETW_TS_QPC, iflags, &sts)) == 0) {
		etw_end_session(NULL, sname);
		return (NULL);
	}

	/*
	 * Get rundown of all the open files
	 * Slows down the startup
	 */
	LONG result = EnableTraceEx(&KernelRundownGuid_I, NULL, hsession, 1,
	    0, 0x10, 0, 0, NULL);

	if (result != ERROR_SUCCESS) {
		eprintf("dtrace_etw_init, failed to get rundown of open files (%x)\n",
		    result);
	}

	if (etw_enable_kernel_prov(hsession, sname, etwflags, TRUE) != 0) {
		etw_end_session(NULL, sname);
		return (NULL);
	}

	sinfo = newsessinfo();
	sinfo->starttime = sts;
	sinfo->dtrace_probef = probef;
	sinfo->dtrace_ioctlf = ioctlf;
	sinfo->flags &= ~SESSINFO_ISFILE;
	//sinfo->flags |= oetlfile != NULL ? SESSINFO_LIVEFILE : 0;
	//sinfo->flags |= oetlfile == NULL || (flags & 1) ? SESSINFO_FILE_ENABLE_ALL : 0;
	sinfo->flags |= tflags;

	sinfo->etlfile = oetlfile;
	sinfo->sessname = sname;
	sinfo->sessguid = (GUID *) sguid;
	sinfo->hsession = hsession;

	if ((thread = etw_start_trace(sinfo, cb, etw_event_thread, 0)) == 0) {
		free(sinfo);
		etw_end_session(sinfo, NULL);
		return (NULL);
	}

	dtrace_etw_sessions[DT_ETW_KERNEL_SESSION] = sinfo;
	sinfo->data = etw_get_providers();

	ULONG eflags = !(sinfo->flags & SESSINFO_LIVEFILE) ?
	    EVENT_TRACE_REAL_TIME_MODE :
	    (sinfo->flags & SESSINFO_FILE_ENABLE_ALL) ?
	    (EVENT_TRACE_FILE_MODE_CIRCULAR | EVENT_TRACE_REAL_TIME_MODE) :
	    EVENT_TRACE_FILE_MODE_CIRCULAR;

	sinfo = etw_new_session(DTRACE_SESSION_NAME_USER, &DtraceSessionGuidUser,
	    ETW_TS_QPC, eflags, probef, ioctlf,
	    (eflags & EVENT_TRACE_REAL_TIME_MODE) ? 0 : 1);
	dtrace_etw_sessions[DT_ETW_USER_SESSION] = sinfo;

	/*eflags = !(dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]->flags & SESSINFO_LIVEFILE) ?
		EVENT_TRACE_REAL_TIME_MODE :
	    (EVENT_TRACE_FILE_MODE_CIRCULAR | EVENT_TRACE_REAL_TIME_MODE);

	sinfo = etw_new_session(DTRACE_SESSION_NAME_CLR, &DtraceSessionGuidCLR,
	    ETW_TS_QPC, eflags, probef, ioctlf, 0);
	dtrace_etw_sessions[DT_ETW_CLR_SESSION] = sinfo;*/

	result = EnableTraceEx(&MSDotNETRuntimeRundownGuid, NULL,
	    sinfo->hsession, 1, 0, 0x58, 0, 0, NULL);
	if (result != ERROR_SUCCESS) {
		eprintf("dtrace_etw_init, failed to get rundown of \
			.net jitted methods (%x)\n", result);
	}
	result = EnableTraceEx(&MSDotNETRuntimeGuid, NULL,
	    sinfo->hsession, 1, 0, 0x18, 0, 0, NULL);
	if (result != ERROR_SUCCESS) {
		eprintf("dtrace_etw_init, failed to get event fot jit methods (%x)\n",
		    result);
	}

	//relog(dtrace_etw_sessions, DT_ETW_MAX_SESSION, oetlfile);

	return (dtrace_etw_sessions);
}

void
dtrace_etw_stop(etw_sessions_t *sinfo)
{
	ULONG status[DT_ETW_MAX_SESSION] = {0};

	for (int i = 0; i < DT_ETW_MAX_SESSION; i++) {
		if (dtrace_etw_sessions[i]) {
			status[i] = CloseTrace(dtrace_etw_sessions[i]->psession);
			dtrace_etw_sessions[i]->psession = 0;
		}
	}

	for (int i = 0; i < DT_ETW_MAX_SESSION; i++) {
		if (status[i] == ERROR_CTX_CLOSE_PENDING) {
			while(dtrace_etw_sessions[i]->flags & SESSINFO_ISLIVE)
				Sleep(100);
			//break;
		}
	}

}

void
dtrace_etw_close(etw_sessions_t *sinfo)
{
	wmutex_exit(&etw_start_lock);
	for (int i = 0; i < DT_ETW_MAX_SESSION; i++) {
		if (dtrace_etw_sessions[i] &&
		    dtrace_etw_sessions[i]->sessname != NULL) {
			etw_end_session(dtrace_etw_sessions[i], NULL);
		}
	}
	for (int i = 0; i < DT_ETW_MAX_SESSION; i++) {
		if (dtrace_etw_sessions[i]) {
			while(dtrace_etw_sessions[i]->flags & SESSINFO_ISLIVE)
				Sleep(100);
			//break;
		}
	}

	etw_merge_etlfiles();
}

unsigned int
hashint64(uint64_t key)
{
	uint64_t *p;
	unsigned int h = (key * (uint64_t) 2654435761) % NHASH;

	return (h);
}

int
cmpint64(uint64_t a, uint64_t b)
{
	return (a == b ? 0 : -1);
}

intptr_t
lookuphm(Hashmap *hash, uint64_t key, uint_t (*hashfn)(uint64_t key),
    int (*cmp)(uint64_t, uint64_t))
{
	int h;
	unsigned int uh;
	Hashblk *st, **hashmap = hash->buckets;

	uh = hashfn(key);
	h = uh;
	for (st = hashmap[h]; st != NULL; st = st->next) {
		if (cmp(st->key, key) == 0)
			return (st->value);
	}

	return (0);
}

int
lookupallhm(Hashmap *hash, uint64_t key, intptr_t *ret, int sz,
    uint_t (*hashfn)(uint64_t key), int (*cmp)(uint64_t, uint64_t))
{
	int h, fnd = 0;
	unsigned int uh;
	Hashblk *st, **hashmap = hash->buckets;

	uh = hashfn(key);
	h = uh;
	for (st = hashmap[h]; st != NULL; st = st->next) {
		if (cmp(st->key, key) == 0) {
			ret[fnd++] = st->value;
			if (fnd == sz)
				break;
		}
	}

	return (fnd);
}

#define HB_MALLOC(st)	\
	if (sessinfo->etw->freelist == NULL) st = (Hashblk *) malloc(sizeof(Hashblk)); \
	else { st = sessinfo->etw->freelist; sessinfo->etw->freelist = st->next; }

Hashblk *
replacehm(Hashmap *hash, uint64_t key, uint64_t value,
    uint_t (*hashfn)(uint64_t key),
    int (*cmp)(uint64_t, uint64_t))
{
	unsigned int h;
	Hashblk *st, **hashmap = hash->buckets;

	h = hashfn(key);
	for (st = hashmap[h]; st != NULL; st = st->next) {
		if (cmp(st->key, key) == 0) {

			etw_stack_t *tmp = (etw_stack_t *) st->value;
			st->value = value;
			return (st);
		}
	}
	return (addhm(hash, key, value, hashfn));
}


Hashblk *
addhm(Hashmap *hash, uint64_t key, uint64_t value,
    uint_t (*hashfn)(uint64_t key))
{
	int h;
	Hashblk *st, **hashmap = hash->buckets, *tmp;

	h = hashfn(key);

	if (sessinfo->etw->freelist == NULL)
		st = (Hashblk *) malloc(sizeof(Hashblk));
	else {
		st = sessinfo->etw->freelist;
		sessinfo->etw->freelist = st->next;
	}

	st->key = key;
	st->value = value;
	tmp = hashmap[h];
	st->next = hashmap[h];
	hashmap[h] = st;
	tmp = hashmap[h];

	return (st);
}

Hashblk *
erasehm(Hashmap *hash, uint64_t key, uint_t (*hashfn)(uint64_t key),
    int (*cmp)(uint64_t, uint64_t))
{
	int h;
	Hashblk *st, *prev = NULL, **hashmap = hash->buckets;
	h = hashfn(key);

	st = hashmap[h];
	while (st != NULL) {
		if (cmp(st->key, key) == 0) {
			Hashblk *tmp = st;

			if (prev == NULL) {
				hashmap[h] = st->next;
				st = hashmap[h];
			} else {
				prev->next = st->next;
				st = st->next;
			}
			tmp->next = sessinfo->etw->freelist;
			sessinfo->etw->freelist = tmp;

			continue;
		}
		prev = st;
		st = st->next;
	}

	return (NULL);
}

etw_stack_t*
esalloc()
{
	etw_stack_t *tmp;

	if (sessinfo->etw->freelistetw == NULL) {
		tmp = (etw_stack_t *) mem_zalloc(sizeof(etw_stack_t));
		return (tmp);
	}

	tmp = sessinfo->etw->freelistetw;
	sessinfo->etw->freelistetw = tmp->next;
	memset(tmp, 0, sizeof(etw_stack_t));

	return (tmp);
}

void
esfree(etw_stack_t *f)
{
	sdtmem_free(sessinfo->etw->sdtmem, f->dprobe.payload, false, f->dprobe.thrid);
	sdtmem_free(sessinfo->etw->sdtmem, f->dprobe.extpayload, false,
	    f->dprobe.thrid);
	f->next = sessinfo->etw->freelistetw;
	sessinfo->etw->freelistetw = f;
}

int
dtrace_sdtmem_free(intptr_t sz)
{
	sessinfo->payload = 0;
	return (sdtmem_free(sessinfo->etw->sdtmem, sz, true, sessinfo->etw->thrid));
}

int
sdtmem_free(sdtmem_t *sdtmem, intptr_t sz, bool reclaim, int thr)
{
	sdtmem_t *tmps;
	void *mem = NULL;
	int debug = 0;
	uintptr_t ptail = 0;

	if (sz == 0)
		return (0);

	for (tmps = sdtmem; tmps != NULL; tmps = tmps->next) {
		debug = 0;
		if (sz >= tmps->buffer && sz < tmps->max) {
			if (reclaim) {
				tmps->head = sz;
				tmps->prevsz = tmps->rcsz;
				break;
			}
			ptail = tmps->tail;
			if (sz < tmps->tail) {
				assert(tmps->tail == tmps->end);
				assert(sz == tmps->buffer);
				tmps->tail = sz;
				tmps->end = 0;
				break;
			}

			tmps->tail = sz;
			break;
		}

		debug = -1;
	}
	assert(!(tmps->end == 0 && tmps->head <= tmps->tail));
	assert(!(tmps->end != 0 && tmps->head > tmps->tail));

	assert(debug != -1);
	return (0);
}

void *
dtrace_sdtmem_alloc(int sz)
{
	sessinfo->payload = (uintptr_t) sdtmem_alloc(sz);
	return ((void *) sessinfo->payload);
}

void *
sdtmem_alloc(int sz)
{
	sdtmem_t *tmps, *sdtmem = sessinfo->etw->sdtmem;
	intptr_t mem = NULL;
	int thr = sessinfo->etw->thrid;

	if (sz == 0)
		return (0);
	assert (sz < sdt_temp_size);
	for (tmps = sdtmem; tmps != NULL; tmps = tmps->next) {
		if (tmps->end == 0) {
			if (tmps->max - tmps->head >= sz) {
				mem = tmps->head;
				tmps->head += sz;
				break;
			} else {
				tmps->end = tmps->head - tmps->prevsz;
				tmps->head = tmps->buffer;
				if (tmps->tail - tmps->head > sz) {
					mem = tmps->head;
					tmps->head += sz;
					break;
				}
			}
		} else if (tmps->end != 0) {
			if (tmps->tail - tmps->head >= sz) {
				mem = tmps->head;
				tmps->head += sz;
				break;
			}
		}
	}

	if (mem == NULL) {
		if (sdtmem == NULL) {
			sdtmem = (sdtmem_t *) malloc(sizeof(sdtmem_t));
			tmps = sdtmem;
			sessinfo->etw->sdtmem = sdtmem;
		} else {
			for (tmps = sdtmem; tmps->next != NULL; tmps = tmps->next)
				;
			tmps->next = (sdtmem_t *) malloc(sizeof(sdtmem_t));
			tmps = tmps->next;
		}
		tmps->buffer = (uintptr_t) malloc(sdt_temp_size);
		tmps->max = tmps->buffer + sdt_temp_size;
		tmps->head = tmps->buffer;
		tmps->tail = 0;
		tmps->end = 0;
		tmps->prevsz = 0;
		//tmps->a = ALPHA++;
		tmps->next = NULL;
		mem = tmps->head;
		tmps->head += sz;
	}
	tmps->rcsz = tmps->prevsz;
	tmps->prevsz = sz;

	memset((void *) mem, 0, sz);

	assert(tmps->head <= tmps->max);
	assert(!(tmps->end == 0 && tmps->head <= tmps->tail));
	assert(mem >= tmps->buffer && mem + sz <= tmps->max);

	return ((char *) mem);
}
