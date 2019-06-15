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

#define INITGUID  // Include this #define to use SystemTraceControlGuid in Evntrace.h.

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

struct etw_sessioninfo *dtrace_etw_sessions[DT_ETW_MAX_SESSION] = {0};
/*
 * ETW processing thread data
 */
__declspec(thread) static struct sessioninfo *sessinfo = NULL;	

static thread_t missing_thread = {0};
static proc_t missing_proc = {0};

static HANDLE etw_eventcb_lock;
static HANDLE etw_cur_lock;
static HANDLE etw_proc_lock;
static HANDLE etw_thread_lock;
static int (*etw_diag_cb) (PEVENT_RECORD, void *) = NULL;
static uint32_t etw_diag_id = 0;

static etw_dbg_t pdbsyms = {0};		/* dbghelp link of modules with pdb */
static etw_dbg_t nopdbsyms = {0};	/* dbghelp link of modules without pdb */

// specialized hash function for unordered_map keys
struct hash_fn {
	std::size_t
	operator() (const GUID &guid) const {
		std::size_t h1 = std::hash<ULONG>()(guid.Data1);
		std::size_t h2 = std::hash<ULONG>()(guid.Data2);

		return h1 ^ h2;
	}
};

static unordered_map<GUID, Functions, hash_fn> eventfuncs;	/* event cb map */
static unordered_map<pid_t, proc_t *> proclist;			/* etw process map */
static unordered_map<pid_t, thread_t *> threadlist;		/* etw thread map */
static unordered_map<wstring, etw_module_t *> modlist;		/* etw loaded modules */
static map<wstring, wstring, std::greater<wstring>> devmap;						/* device path to pathname */
static unordered_map<uetwptr_t, uintptr_t> fileiomap;		/* open files */
static unordered_map<GUID, cvpdbinfo_t *, hash_fn> cvinfolist; /* modules pdb info */
static map<uint32_t, etw_jitsym_map_t> pid_jit_symtable;		/* jit symbol map */

#define ETW_PROC_MISSING_NAME "<not yet>"

/*
 * map jitted module, module ID = module name
 */
static etw_jit_module_t *
etw_add_jit_module(pid_t pid, etw_jit_module_t *mod, int len)
{
	etw_jitsym_map_t& symmap = pid_jit_symtable[pid];
	int len0 = wcslen((wchar_t *) &mod->ModuleILPath);
	wchar_t *modn = (wchar_t *) mem_zalloc((len0+1) * sizeof(wchar_t));
	wcscpy(modn, (wchar_t *) &mod->ModuleILPath);
	symmap.jit_modules[mod->ModuleID] = modn;

	return mod;
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

	return tsym;
}

/*
 * ETW event callback for MSDotNETRuntimeRundown provider
 * for jitted module and functions
 */
int
clr_jitted_rd_func(PEVENT_RECORD ev, void *data)
{
	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, MSDotNETRuntimeRundownGuid));
	struct Etw_Clr_143 *sym = (Etw_Clr_143 *) ev->UserData;
	USHORT eventid = ev->EventHeader.EventDescriptor.Id;

	if (eventid == 144) { //Method
		etw_add_jit_sym(ev->EventHeader.ProcessId, (etw_jit_symbol_t *) ev->UserData,
		    ev->UserDataLength);
	} else if (eventid == 154) { //Module
		etw_add_jit_module(ev->EventHeader.ProcessId, (etw_jit_module_t *) ev->UserData,
		    ev->UserDataLength);
	}
	return 0;
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

	if (eventid == 143) { //Method
		struct Etw_Clr_143 *sym = (Etw_Clr_143 *) ev->UserData;
		etw_add_jit_sym(ev->EventHeader.ProcessId, (etw_jit_symbol_t *) ev->UserData,
		    ev->UserDataLength);
	} else if (eventid == 152) { //Module
		etw_add_jit_module(ev->EventHeader.ProcessId, (etw_jit_module_t *) ev->UserData,
		    ev->UserDataLength);
	}

	return 0;
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

	wmutex_enter(&etw_proc_lock);

	p = proclist[pid];
	if (p == NULL && create) {
		switch (create) {
		case ETW_PROC_CREATE_LIVE: {
			p = (proc_t *) mem_zalloc(sizeof(proc_t));
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
			char *szProcessName  = (char *) mem_zalloc(MAX_PATH);

			if ( EnumProcessModules( p->handle, &hMod, sizeof(hMod),
			        &cbNeeded) ) {
				GetModuleBaseNameA( p->handle, hMod, szProcessName,
				    sizeof(szProcessName)/sizeof(char) );
				p->name = _strlwr(szProcessName);
			}

			proclist[pid] = p;
			break;
		}
		case ETW_PROC_TEMP: {
			ZeroMemory(&missing_proc, sizeof(proc_t));
			missing_proc.pid = pid;
			missing_proc.name = ETW_PROC_MISSING_NAME;
			p = &missing_proc;
			break;
		}
		case ETW_PROC_CREATE: {
			p = (proc_t *) mem_zalloc(sizeof(proc_t));
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
	wmutex_exit(&etw_proc_lock);

	return (p);
}

static thread_t *
etw_get_td(pid_t tid, pid_t pid, int create)
{
	thread_t *td = NULL;

	wmutex_enter(&etw_thread_lock);
	td = threadlist[tid];

	if (td && pid != -1 && td->pid != pid) {
		td->pid = pid;
		td->proc = etw_get_proc(pid, ETW_PROC_CREATE);
	}

	if (td == NULL && create) {
		if (create == ETW_THREAD_CREATE) {
			td = (thread_t *) mem_zalloc(sizeof(thread_t));
			td->pid = pid;
			td->tid = tid;
			td->proc = etw_get_proc(pid, ETW_PROC_CREATE);
			threadlist[tid] = td;
		} else if (create == ETW_THREAD_TEMP) {
			ZeroMemory(&missing_thread, sizeof(thread_t));
			missing_thread.tid = tid;
			missing_thread.pid = pid;
			missing_thread.proc = etw_get_proc(pid, ETW_PROC_TEMP);
			td = &missing_thread;
		} else {
			td = NULL;
		}
	}

	wmutex_exit(&etw_thread_lock);

	return (td);
}

/*
 *	set the current parameters
 */
static HANDLE *
etw_set_cur(pid_t pid, pid_t tid, hrtime_t tm, int cpuno)
{
	//wmutex_enter(&etw_cur_lock);

	sessinfo->timestamp = tm;
	sessinfo->cpuno = cpuno;
	sessinfo->pid = pid;
	sessinfo->tid = tid;
	sessinfo->td = etw_get_td(tid, pid, ETW_THREAD_TEMP);
	if (sessinfo->td) {
		sessinfo->td->cpu = cpuno;
	}
	sessinfo->proc = sessinfo->td->proc ? sessinfo->td->proc:
	    etw_get_proc(pid, ETW_PROC_TEMP);

	return &etw_cur_lock;
}

static void
etw_reset_cur(HANDLE *lock)
{
	;//wmutex_exit(lock);
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

lock = etw_set_cur(dprobes->pid, dprobes->tid, dprobes->ts, dprobes->cpuno);

	sessinfo->etw->dtrace_probef(dprobes->id, dprobes->args[0], dprobes->args[1],
	    dprobes->args[2], dprobes->args[3],dprobes->args[3]);

	etw_reset_cur(lock);
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

	while(InterlockedExchange(&sess->Q.lock, TRUE) == TRUE)
		Sleep(1);

	while (sess->Q.queue.size()) {
		stackp = sess->Q.queue.front();
		sess->stackinfo = stackp;
		sess->Q.queue.pop();
		sess->Q.map[stackp->dprobe.cpuno].erase(stackp->dprobe.ts);
		etw_send_dprobe(stackp);
		free(stackp); 
	}
	InterlockedExchange(&sess->Q.lock, FALSE);
}


void CALLBACK
TimerProc(void* data, BOOLEAN TimerOrWaitFired)
{
	static int qsz[DT_ETW_MAX_SESSION];
	etw_stack_t *stackp;
	etw_sessioninfo_t *sess;

	for (int i=0; i < DT_ETW_MAX_SESSION; i++) {
		if (dtrace_etw_sessions[i] != NULL) {
			sess = dtrace_etw_sessions[i];
			if (sess->Q.queue.size() > 0 &&
			    sess->Q.queue.size() <= ETW_QUEUE_SIZE &&
			    InterlockedExchange(&sess->Q.lock, TRUE) == FALSE) {
				if (sessinfo == NULL) {
					sessioninfo_t *tmp = (sessioninfo_t *)
					    mem_zalloc(sizeof(sessioninfo_t));
					sessinfo = tmp;
				}
				ASSERT(sessinfo != NULL);
				sessinfo->etw = sess;
				stackp = sess->Q.queue.front();
				sess->stackinfo = stackp;
				sess->Q.queue.pop();
				sess->Q.map[stackp->dprobe.cpuno].erase(stackp->dprobe.ts);

				etw_send_dprobe(stackp);
				free(stackp); 
				InterlockedExchange(&sess->Q.lock, FALSE);
			}
		}
	}
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
	return vf;

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
			dprintf("etw_hook_event, cb already present: cb %p, arg %p\n", efunc, data);
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
etw_unhook_event(const GUID *guid, Function efunc, void *data, BOOL all)
{
	wmutex_enter(&etw_eventcb_lock);

	Functions& vf = eventfuncs[*guid];
	Functions::iterator iter = vf.begin();

	
	while (iter != vf.end()) {
		Pair ef = *iter;
		if (all) {
			dprintf("etw_unhook_event, removed cb %p arg %p\n", ef.first, ef.second);
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
		dprintf("etw_unhook_event, failed to remove cb %p arg %p\n", efunc, data);

	return (-1);
}

void etw_stop_ft()
{
	etw_unhook_event(&FastTrapGuid, NULL, NULL, TRUE);
	dtrace_etw_sessions[DT_ETW_FT_SESSION] = NULL;
}

/*
 * timebase and scaling factor to convert etw event timestamp to nanosec timestamp.
 */
static void
etw_event_timebase(PEVENT_RECORD ev)
{
	etw_sessioninfo_t *sess = sessinfo->etw;

	switch (sess->clctype) {
	case 1: //QPC
		sess->timescale = 10000000.0 / sess->perffreq;
		sess->timebase = sess->boottime;
		break;
	case 2: //SYSTEM TIME
		sess->timebase = 0;
		sess->timescale = 1.0;
		break;
	case 3:
		sess->timescale = 10 / sess->cpumhz;
		sess->timebase = sess->boottime;
		break;
	default:
		ASSERT(0);
	}
	return;
}

static void
event_cb(Functions& funcs, PEVENT_RECORD ev)
{
	Functions::iterator iter = funcs.begin();

	sessinfo->timestamp = ev->EventHeader.TimeStamp.QuadPart;
	sessinfo->cpuno = ev->BufferContext.ProcessorNumber;
	sessinfo->tid = ev->EventHeader.ThreadId;
	sessinfo->pid = ev->EventHeader.ProcessId;
	sessinfo->td = etw_get_td(sessinfo->tid, sessinfo->pid, ETW_THREAD_TEMP);
	sessinfo->proc = etw_get_proc(sessinfo->pid, ETW_PROC_TEMP);

	if (iter != funcs.end())
		sessinfo->etw->hb++;
	else {
		/* diagnostic event provider for etw.
		   if any event not caught by any probes,
		   send to diag provider.
		 */
		if (etw_diag_cb)
			etw_diag_cb(ev, (void *) etw_diag_id);
	}

	while (iter != funcs.end()) {
		((*iter).first)(ev, (*iter).second);
		iter++;
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
	etw_event_timebase(ev);
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
	    dtrace_etw_sessions[0]->isfile;

	etw_sessioninfo_t *sinfo = (etw_sessioninfo_t *) data;
	tsinfo = (sessioninfo_t *) mem_zalloc(sizeof(sessioninfo_t));
	tsinfo->etw = sinfo;
	sessinfo = tsinfo;
	sinfo->evcb = first_event_cb;

	error = ProcessTrace(&sinfo->psession, 1, 0, 0 );
	if( error != ERROR_SUCCESS ) {
		dprintf("etw_event_thread, ProcessTrace failed: session (%ls) error (%d)\n",
		    sinfo->sessname, error);
		return (-1);
	}
	/* process all pending events, without waiting for stacks */
	etw_event_purge();

	Sleep(1000); //XXXX

	/* if reading from a file send stop signal to dtrace, to end dtrace session */
	for (int i=0; i < DT_ETW_MAX_SESSION; i++) {
		if (dtrace_etw_sessions[i] != NULL) {
			if (dtrace_etw_sessions[i] == sinfo) {
				dtrace_etw_sessions[i] = NULL;
			} else {
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
	// copy of funcs, callback can remove itself
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

	return p;
}

static thread_t *
etw_add_thread(pid_t tid, thread_t *td)
{
	wmutex_enter(&etw_thread_lock);
	threadlist[tid] = td;
	wmutex_exit(&etw_thread_lock);
	return td;
}

static etw_module_t *
etw_add_module(etw_module_t *mod, wstring wstr)
{
	modlist[wstr] = mod;

	return mod;
}

/* XXX */
static wchar_t *
etw_get_fname(uetwptr_t fobj)
{
	if (fileiomap.find(fobj) == fileiomap.end())
		return NULL;

	return (wchar_t *) fileiomap[fobj];
}

/*
 * Normalize pathnames
 */
static wchar_t *
etw_rep_dev_to_path(wchar_t *str)
{
	size_t l0, l1, len;
	int fnd = 0;

	for(map<wstring, wstring>::iterator iter = devmap.begin();
	    iter != devmap.end(); iter++) {

		l0 =  wcslen(&iter->first[0]);
		if (wcsncmp(str, &iter->first[0], l0) == 0) {
			l1 = wcslen(&iter->second[0]);
			if (l0 > l1) {
				wcsncpy(str, &iter->second[0], l1);
				if (*(str+(l0)) == L'\\')
					l0 += 1;
				wcscpy(str+l1, str+l0);
			} else {
				wchar_t tmp[MAX_PATH] = {0};
				wcscpy(tmp, str);
				len = wcslen(str)+1+(l1-l0);
				wcsncpy(str, &iter->second[0], l1);
				wcscpy(str+l1, tmp+l0);
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
		while(drive) {
			if (drive & mask) {
				path[0] = dl;
				path[1] = L':';
				wcscpy(path+2, str);
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

	return str;
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

	return ret;
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
	ret = ((SystemTime.QuadPart - PTW32_TIMESPEC_TO_FILETIME_OFFSET) * 100UL);
	return ret;
}

static wchar_t *
etw_add_fname(uetwptr_t fobj, wchar_t *fname)
{
	wchar_t *name = etw_rep_dev_to_path(fname);

	fileiomap[fobj] = (uintptr_t) fname;
	return fname;
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
	return tm ? ((tm - PTW32_TIMESPEC_TO_FILETIME_OFFSET) * 100UL): 0;
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
	interval.Interval =  (ULONG) (10000.f * (1000.f / freq)) ;

	error = TraceSetInformation(0, TraceSampledProfileIntervalInfo,
	        (void*)&interval, sizeof( TRACE_PROFILE_INTERVAL ) );

	if (error != ERROR_SUCCESS) {
		dprintf("etw_set_freqTSI, failed to set profile timer (%x) interval (%d)\n",
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
	typedef int(__stdcall *PNtSetSystemInformation) (int SystemInformationClass,
	    void *SystemInformation, int SystemInformationLength);
	EVENT_TRACE_TIME_PROFILE_INFORMATION timeInfo;
	HMODULE ntdll = LoadLibrary(L"ntdll.dll");
	HRESULT hr;
	PNtSetSystemInformation addr;

	addr = (PNtSetSystemInformation) GetProcAddress(ntdll, "NtSetSystemInformation");

	timeInfo.EventTraceInformationClass = EventTraceTimeProfileInformation;

	timeInfo.ProfileInterval = interval;
	hr = addr(SystemPerformanceTraceInformation, &timeInfo,
	        sizeof(EVENT_TRACE_TIME_PROFILE_INFORMATION));

	if (hr != ERROR_SUCCESS) {
		dprintf("etw_set_freqNT, failed to set profile timer (%x) interval (%ld)\n",
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
	DWORD dwVersion = ::GetVersion();
	WORD wMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	WORD wMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	return (wMajorVersion >= 6) && (wMinorVersion >= 2);
}

/*
 * set etw stacktrace for id[] events
 */
static int
etw_set_kernel_stacktrace(TRACEHANDLE session,
    CLASSIC_EVENT_ID id[], int len)
{
	ULONG error = TraceSetInformation(session, TraceStackTracingInfo,
	        (void*)id, (sizeof(CLASSIC_EVENT_ID))*len);

	if (error != ERROR_SUCCESS) {
		dprintf("etw_set_kerenl_stacktrace, failed (%x) session (%llu) \n", error, session);
		return (-1);
	}
	return (0);
}

/*
 * Set (flags) kernel providers for the current session
 * Return 0 on success.
 */
static int
etw_enable_kernel_prov(TRACEHANDLE shandle, WCHAR *sname, ULONG flags, BOOL enable)
{
	EVENT_TRACE_PROPERTIES *prop;
	ULONG status, iflags = 0, len = 0;
	size_t sz = 0;

	sz = (ULONG) sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(sname)*2+2) + 8; //XXXX

	prop = (EVENT_TRACE_PROPERTIES*) mem_zalloc(sz);
	prop->Wnode.BufferSize = (DWORD) sz;
	status = ControlTrace(shandle, sname, prop, EVENT_TRACE_CONTROL_QUERY);
	if (status != ERROR_SUCCESS) {
		dprintf("etw_enable_kernel_prov, ControlTrace"
		    "(EVENT_TRACE_CONTROL_QUERY) failed (%x)\n", status);
		return (-1);
	}

	if (enable) {
		prop->EnableFlags |= flags;
	} else {
		prop->EnableFlags &= ~flags;
	}

	status = ControlTrace(shandle, sname, prop, EVENT_TRACE_CONTROL_UPDATE);
	if (status != ERROR_SUCCESS) {
		dprintf("etw_enable_kernel_prov, ControlTrace"
		    "(EVENT_TRACE_CONTROL_UPDATE) failed (%x)\n", status);
		return (-1);
	}

	return (0);
}

/*
 * Create device name to normalized name MAP
 */
static int
etw_devname_to_path(map<wstring, wstring, std::greater<wstring>> &devmap)
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
		fprintf(stderr, "FindFirstVolumeW failed with error code %d\n", GetLastError());
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
			if ((fnd = GetVolumePathNamesForVolumeNameW(volname, pnames, co, &co)) ||
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
			    co,GetLastError(), pnames);
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

	sz = GetEnvironmentVariable(L"SystemRoot", buf, MAX_PATH);
	if (sz > MAX_PATH || sz == 0) return (error); //XXXX
	wchar_t *env = (wchar_t *) mem_zalloc(sz + 2 + 2);
	wcsncpy(env, buf, sz);
	wcsncpy(env+sz, L"\\", 2);

	devmap[L"\\SystemRoot\\"] = env;

	sz = GetEnvironmentVariable(L"windir", buf, MAX_PATH);
	if (sz > MAX_PATH || sz == 0)
		return (error); //XXXX
	env = (wchar_t *) mem_zalloc(sz + 2 + 2);
	wcsncpy(env, buf, sz);
	wcsncpy(env+sz, L"\\", 2);

	devmap[L"\\Windows\\"] = env;
	devmap[L"\\??\\"] = L"";

	return (error);
}

static HANDLE
etw_init_dbg(HANDLE h)
{
	DWORD Options = SymGetOptions();
	Options |= SYMOPT_DEFERRED_LOADS;
	Options |= SYMOPT_DEBUG ;
	SymSetOptions(Options);

	init_symbols(h, FALSE, NULL);
	return h;
}

static void
etw_initialize()
{
	missing_thread.proc = &missing_proc;
	missing_thread.tid = -1;
	missing_thread.pid = -1;
	missing_proc.pid = -1;
	missing_proc.ppid = 0;
	missing_proc.name = "notyet";
	missing_proc.cmdline = L"\0";

	char *s= set_syms_path(NULL);
	if (s) {
		;//fprintf(stderr, "Symbols Search path: %s\n", s);
	}
	
	pdbsyms.h = etw_init_dbg((HANDLE) 999);
	pdbsyms.endaddr = 0x1000;
	nopdbsyms.h = etw_init_dbg((HANDLE) 9999);
	nopdbsyms.endaddr = 0x1000;

	HANDLE t;
	DWORD  time = 2000, due = 2000;
	
	CreateTimerQueueTimer(&t, NULL, TimerProc, NULL, due,
	    time, WT_EXECUTEINTIMERTHREAD);
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
 *
 */

static void
etw_end_session(etw_sessioninfo_t *sinfo, WCHAR *sname)
{
	EVENT_TRACE_PROPERTIES properties;
	ULONG st;

	if (sinfo) {
		if (sinfo->etlfile) {
			// Opentrace
			if (sinfo->psession) {
				st = CloseTrace(sinfo->psession);
			}
		} else {
			ZeroMemory(&properties, sizeof(EVENT_TRACE_PROPERTIES));
			properties.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES);
			// starttrace
			ControlTrace(sinfo->hsession, sinfo->sessname, &properties, EVENT_TRACE_CONTROL_STOP);
		}
	} else if (sname) {
		ZeroMemory(&properties, sizeof(EVENT_TRACE_PROPERTIES));
			properties.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES);
			// starttrace
			ControlTrace(0, sname, &properties, EVENT_TRACE_CONTROL_STOP);
	}
}

/*
 * Initialize ETW by calling StartTrace, with the logmode.
 * currently only logmode == EVENT_TRACE_REAL_TIME_MODE supported
 */
static TRACEHANDLE
etw_init_session(WCHAR *sname, GUID sguid, ULONG clctype, ULONG logmode)
{
	TRACEHANDLE hsession = 0;
	EVENT_TRACE_PROPERTIES* prop = NULL;
	size_t sz = 0;
	ULONG status = ERROR_SUCCESS;

	/* close any open session with same name */
	etw_end_session(NULL, sname);

	sz = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(sname)*2+2);
	prop = (EVENT_TRACE_PROPERTIES*) mem_zalloc(sz);
	if (prop == NULL) {
		dprintf("etw_init_session, mem_zalloc() failed for size (%lld)\n", sz);
		return 0;
	}

	ZeroMemory(prop, sz);
	prop->Wnode.BufferSize = (DWORD) sz;
	prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	prop->Wnode.ClientContext = clctype;
	prop->Wnode.Guid = sguid;
	prop->BufferSize = 1000;
	prop->LogFileMode = logmode;
	prop->MinimumBuffers = 300;
	prop->FlushTimer = 1;
	prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	StringCbCopy((LPWSTR)((WCHAR*)prop + prop->LogFileNameOffset),
	    (wcslen(sname)*2+2), sname);

	status = StartTrace((PTRACEHANDLE)&hsession, sname, prop);

	if (status != ERROR_SUCCESS) {
		dprintf("etw_init_session, StartTrace() failed with (%lx)\n", status);
		return 0;
	}

	return hsession;
}

/*
 * Start etw trace.
 * if nothread is set than, dont create the helper thread for the session yet.
 * returns the created thread handle or tracehandle in case of nothread
 */
static HANDLE
etw_start_trace(etw_sessioninfo_t *sinfo, BOOL isreal, PEVENT_RECORD_CALLBACK cb,
    LPTHREAD_START_ROUTINE tfunc, int nothread)
{
	ULONG status = ERROR_SUCCESS;
	EVENT_TRACE_LOGFILE trace;
	TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
	TRACEHANDLE handle;
	HANDLE thread = 0;

	if (sinfo->psession == 0) {
		ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
		if (sinfo->isfile == 0) {
			trace.LoggerName = sinfo->sessname;
			trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
			    PROCESS_TRACE_MODE_EVENT_RECORD|PROCESS_TRACE_MODE_RAW_TIMESTAMP;
		} else {
			trace.LogFileName = sinfo->etlfile;
			trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD |
			    PROCESS_TRACE_MODE_RAW_TIMESTAMP;
		}

		trace.EventRecordCallback = cb;
		handle = OpenTrace(&trace);
		if (INVALID_PROCESSTRACE_HANDLE == handle) {
			dprintf("etw_enable_trace, OpenTrace() failed with (%lx)\n", GetLastError());
			return (NULL);
		}

		sinfo->psession = handle;
		sinfo->isusermode = trace.LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;
		sinfo->ncpus = trace.LogfileHeader.NumberOfProcessors;
		sinfo->boottime = trace.LogfileHeader.BootTime.QuadPart;

		ASSERT(trace.LogfileHeader.ReservedFlags != 0);

		sinfo->clctype = trace.LogfileHeader.ReservedFlags;
		sinfo->perffreq = trace.LogfileHeader.PerfFreq.QuadPart;
		sinfo->ptrsz = trace.LogfileHeader.PointerSize;
		sinfo->starttime = trace.LogfileHeader.BootTime.QuadPart;
		sinfo->israwtime = trace.ProcessTraceMode & PROCESS_TRACE_MODE_RAW_TIMESTAMP;
		sinfo->timerres = trace.LogfileHeader.TimerResolution;
		sinfo->cpumhz = trace.LogfileHeader.CpuSpeedInMHz;

		sinfo->Q.map = new map<hrtime_t, etw_stack_t *>[sinfo->ncpus];
	}

	if (nothread == 0) {
		thread = CreateThread(NULL, 0, tfunc, (void *) sinfo, 0, &sinfo->id);

		if (thread == NULL) {
			dprintf("etw_start_trace, CreateThread() failed with (%lu)\n", 
				GetLastError());
			CloseTrace(handle);
			(NULL);
		}
	} else {
		return (HANDLE) handle;
	}

	return thread;
}

static etw_sessioninfo_t *
etw_new_session(WCHAR *sname, const GUID *sguid, ULONG clctype, ULONG flags,
    etw_dtrace_probe_t probef, etw_dtrace_ioctl_t ioctlf)
{
	TRACEHANDLE handle = 0, hsession = 0;
	HANDLE thread = 0;
	etw_sessioninfo_t *sinfo;

	if ((hsession =
	            etw_init_session(sname, *sguid, clctype, flags)) == 0) {

		etw_end_session(NULL, sname);
		return (NULL);
	}

	sinfo = new etw_sessioninfo_t();

	sinfo->isfile = 0;
	sinfo->sessname = sname;
	sinfo->sessguid = (GUID *) sguid;
	sinfo->hsession = hsession;
	sinfo->dtrace_probef = probef;
	sinfo->dtrace_ioctlf = ioctlf;

	if ((thread = etw_start_trace(sinfo, TRUE, etw_event_cb,
	                etw_event_thread, 0)) == 0) {
		free(sinfo);
		etw_end_session(sinfo, NULL);
		return (NULL);
	}

	return sinfo;
}


static void
etw_end_trace(WCHAR *sname, GUID sguid)
{
	EVENT_TRACE_PROPERTIES *properties;
	ULONG status;
	int sz = sizeof(EVENT_TRACE_PROPERTIES)*2;

	properties = (EVENT_TRACE_PROPERTIES *) mem_zalloc(sz);
	ZeroMemory(properties, sz);
	properties->Wnode.BufferSize = sz;
	properties->Wnode.Guid = sguid;
	status = StopTrace(0, sname, properties);
	if (status != ERROR_SUCCESS) {
		dprintf("etw_end_trace, failed (%x)\n", status);
	}
}

static int
etw_enable_user(TRACEHANDLE hsession, GUID *guid, int kw, int level, int enablestack)
{
	ENABLE_TRACE_PARAMETERS EnableParameters;

	ZeroMemory(&EnableParameters, sizeof(EnableParameters));
	EnableParameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

	if (enablestack) {
		EnableParameters.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;
	}
	DWORD status = EnableTraceEx2(hsession, (LPCGUID)guid,
	        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
	        level,
	        kw, 0, 0, &EnableParameters);

	if (ERROR_SUCCESS != status) {
		dprintf("etw_enable_user, EnableTraceEx() failed with (%lu)\n", status);
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
		return 0;
	}

	map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (map == NULL) {
		CloseHandle(file);
		return 0;
	}
	base = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
	if (base == NULL) {
		CloseHandle(map);
		CloseHandle(file);
		return 0;
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

	return sum;
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
		return NULL;
	}

	map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (map == NULL) {
		CloseHandle(file);
		return NULL;
	}

	base = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
	if (base == NULL) {
		CloseHandle(map);
		CloseHandle(file);
		return NULL;
	}

	dbase = (PIMAGE_DEBUG_DIRECTORY)
	    ImageDirectoryEntryToDataEx(base, FALSE,
	        IMAGE_DIRECTORY_ENTRY_DEBUG, &size, NULL);
	if (dbase) {
		size_t count = size / sizeof(IMAGE_DEBUG_DIRECTORY);

		for (size_t i = 0; i < count; ++i) {
			if (dbase[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
				cvpdbinfo_t *cv0 = (cvpdbinfo_t *) ((char *) base +
				        dbase[i].PointerToRawData);
				if (cv0->cvsig == 0x53445352) {	//RSDS
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

	return cv;
}

static int
etw_create_ni_pdb(char *image, char *dir)
{
	char cmd[1024];
	char path[MAX_PATH];
	int  n = 0;
	int arch = 0, isnet = 0, code;

	if (filetype(image, &arch, &isnet) < 0) {
		dprintf("etw_create_ni_pdb, unknown file type (%s)\n", image);
		return (0);
	}

	if ((n=ngenpath(path, MAX_PATH, 1, isnet > 0 ? isnet-1: 0)) <= 0) {
		dprintf("etw_create_ni_pdb(), failed to get NGEN path (%x)\n", GetLastError());
		return (0);
	}

	sprintf(cmd, "%s %s %s %s", path, "createPDB", image, dir);

	if ((code = runcmd(cmd)) < 0) {
		dprintf("etw_create_ni_pdb, failed to run cmd (%s) (%x)\n", cmd, GetLastError());
		return (0);
	}

	return code;
}

/*
 * check if pdb file for the ngened module exists
 * in dbghelp search path. If not create one.
 * ex. _NT_SYMBOL_PATH=srv*c:\symbols*http://msdl.microsoft.com/download/symbols;e:\sym
 */

#define SYMBOLS_PATH "SRV*c:\\symbols*https://msdl.microsoft.com/download/symbols"

static cvpdbinfo_t *
etw_find_ni_syms(cvpdbinfo_t *cv, etw_module_t *mod)
{
	char SYMPATH[256];		 //; = getenv("_NT_SYMBOL_PATH");
	char pdbdir[MAX_PATH];
	char fn[MAX_PATH];
	char nifn[MAX_PATH];
	char *tmp1 = SYMPATH, *tmp0, *symdir = NULL;
	int fnd = 0;
	size_t r = 0;

	getenv_s(&r, SYMPATH, 256, "_NT_SYMBOL_PATH");
	ASSERT(r != 0);

	tmp1 = SYMPATH;
	sprintf(pdbdir, "\\%s\\%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%x\\%s",
	    cv->pdbname,
	    cv->sig.Data1, cv->sig.Data2,
	    cv->sig.Data3, cv->sig.Data4[0], cv->sig.Data4[1],cv->sig.Data4[2],
	    cv->sig.Data4[3],cv->sig.Data4[4],cv->sig.Data4[5],cv->sig.Data4[6],
	    cv->sig.Data4[7], cv->age, cv->pdbname);

	wcstombs_d(nifn, mod->name, MAX_PATH);

	do {
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
			strcpy(fn+strlen(s0), pdbdir);
			if (PathFileExistsA(fn)) {
				fnd = 1;
				break;
			}
		}
	} while (tmp1!= NULL);

	if (fnd == 0) {
		etw_create_ni_pdb(nifn, symdir);
	}
	return cv;
}

/*
 * if pdb info is missing for the module, try to extract
 * it from the source file. First try matching with the file
 * from the host os.
 * If no match found in the host machine and datetime is present
 * try to download the source file from MS server, and then extract
 * the pdb info from the downloaded file.
 *
 */
static cvpdbinfo_t *
etw_match_datatime(HANDLE h, etw_module_t *mod, uetwptr_t base)
{
	char filen[MAX_PATH] = {0};
	char dest[MAX_PATH+1] = {0};
	DWORD date, size, three = 0, flags = SSRVOPT_DWORDPTR;
	SYMSRV_INDEX_INFO info = {0};
	BOOL r;
	int flag = 0;

	wcstombs_d(filen, mod->name, MAX_PATH);
	info.sizeofstruct = sizeof(SYMSRV_INDEX_INFO);

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
				cvpdbinfo_t *cv0 = (cvpdbinfo_t *) mem_zalloc(sizeof(cvpdbinfo_t)+len);
				cv0->age = info.age;
				cv0->cvsig = 0x53445352; //XXXXX??
				cv0->sig = info.guid;
				strcpy((char *) &cv0->pdbname, info.pdbfile);
				return cv0;
			} else {
				cvpdbinfo_t *cv = etw_pdb_info(mod->name);
				return etw_find_ni_syms(cv, mod);
			}
		}
	} else {
		dprintf("SymSrvGetFileIndexInfo failed (%d)\n", GetLastError());
	}

	if (mod->tmstamp == 0) {
		dprintf("etw_match_datatime, timestamp == 0 (%s)\n", filen);
		return NULL;
	}


	// DATETIME  value is represented in the number of seconds elapsed
	//	since midnight (00:00:00), January 1, 1970, Universal Coordinated Time
	date = mod->tmstamp;
	size = mod->size;

	wcstombs_d(filen, mod->name, MAX_PATH);

	fprintf(stderr, "[#] Locating module (%s)\r", filen);
	// Set a search path and cache directory. If this isn't set
	// then _NT_SYMBOL_PATH will be used instead.
	// Force setting it here to make sure that the test succeeds.
	//SymSetSearchPath(h,
	//    "SRV*c:\\symbolstest*https://msdl.microsoft.com/download/symbols");
	if (SymFindFileInPath(h, NULL, filen, &date, size, three,
	        flags, dest, NULL, NULL) == 0) {
		//SymSetSearchPath(h, NULL);
		dprintf("SymFindFileInPath failed for (%s) - (%d)\n", filen, GetLastError());
		return NULL;
	}
	fprintf(stderr, "%90s\r\t      ", "");
	//SymSetSearchPath(h, NULL);
	wchar_t wdest[MAX_PATH+1] = {0};
	mbstowcs(wdest, dest, MAX_PATH);
	cvpdbinfo_t *cv = etw_pdb_info(wdest);

	return cv;
}

/*
 * Match the etw process pdb info events, with the module
 * DbgID_RSDS base == struct Image ImageBase ??? XXX
 */
static cvpdbinfo_t *
etw_match_cvinfo(etw_proc_cvinfo *lcvinfo, etw_module_t *mod, uetwptr_t base)
{
	char nmod[MAX_PATH] = {0}, mname[MAX_PATH];

	wcstombs_d(mname, mod->name, MAX_PATH);

	//extact lowercase module name without extention
	_splitpath(mname, NULL, NULL, nmod, NULL);

	if (nmod[0] == '\0')
		return NULL;
	_strlwr(nmod);

	while(lcvinfo) {
		char npdb[MAX_PATH] = {0};
		//extact lowercase pdb name without extention
		_splitpath((char *) lcvinfo->cv->pdbname, NULL, NULL, npdb, NULL);
		if (npdb[0] == '\0')
			return NULL;
		_strlwr(npdb);

		if (strcmp(nmod, npdb) == 0)	//XXXX
			return lcvinfo->cv;
		else if (lcvinfo->base == base)
			return lcvinfo->cv;
		lcvinfo = lcvinfo->next;
	}
	return NULL;
}


static etw_jit_symbol_t *
etw_lookup_jit_sym(pid_t pid, uetwptr_t addr)
{
	etw_jitsym_map_t& symmap = pid_jit_symtable[pid];
	etw_jit_symbol_t *tsym = NULL;

	if (symmap.sorted == 0) {
		std::sort(symmap.jit_syms.begin(), symmap.jit_syms.end(), jit_sym_cmp);
		symmap.sorted = 1;
	}
	int low, high, mid, size = symmap.jit_syms.size();
	low  =  0;
	high  =  size  -  1;
	while (low  <=  high) {
		mid  =  (low  +  high)  /  2;
		tsym = symmap.jit_syms[mid];
		if (addr < tsym->MethodStartAddress)
			high = mid - 1;
		else if (addr >= tsym->MethodStartAddress+tsym->MethodSize)
			low = mid + 1;
		else {
			return tsym;
		}
	}
	return NULL;
}


/*
 * get keyword information of a provider
 */
static etw_provkw_t *
etw_prov_kw(GUID *pguid, int *nkw)
{
	DWORD status = ERROR_SUCCESS;
	PROVIDER_FIELD_INFOARRAY* penum = NULL, *ptemp = NULL;
	DWORD BufferSize = 0;                       // Size of the penum buffer
	etw_provkw_t *etwp = NULL;
	int num = 0;

	*nkw = 0;

	status = TdhEnumerateProviderFieldInformation(pguid,
	        EventKeywordInformation, penum, &BufferSize);
	if (ERROR_INSUFFICIENT_BUFFER == status) {
		ptemp = (PROVIDER_FIELD_INFOARRAY*) realloc(penum, BufferSize);
		if (ptemp == NULL) {
			dprintf("Allocation failed (size=%lu).\n", BufferSize);
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
	etwp = (etw_provkw_t *) mem_zalloc(sizeof(etw_provkw_t)*(num+1));
	// Loop through the list of field information and print the field's name,
	// description (if it exists), and value.

	for (DWORD j = 0; j < num; j++) {

		wchar_t *wtmp =  (PWCHAR)((PBYTE)(penum) + penum->FieldInfoArray[j].NameOffset);
		char *s = (char *) mem_zalloc(256);
		wcstombs_d(s, wtmp, 256);
		int len = strlen(s);
		for (int i = 0; i < len; i++) {
			if (s[i] == ' ' || s[i] == ';' || s[i] == ':')
				s[i] = '_';
		}
		etwp[j].kwn = s;
		etwp[j].kwv =  penum->FieldInfoArray[j].Value;

	}

	etwp[num].kwn = NULL;
	*nkw = num;

	cleanup0:

	if (penum) {
		free(penum);
		penum = NULL;
	}

	return etwp;
}

/*
 * enumerate etw providers
 */
static etw_provinfo_t *
etw_provlist(int *nprov)
{
	DWORD status = ERROR_SUCCESS;
	PROVIDER_ENUMERATION_INFO* penum = NULL, *ptemp = NULL;
	DWORD BufferSize = 0, i;                       // Size of the penum buffer
	etw_provinfo_t *lprov = NULL;
	BufferSize = 1024*256;
	penum = (PROVIDER_ENUMERATION_INFO*) malloc(BufferSize);

	*nprov = 0;
	// Retrieve the required buffer size.
	status = TdhEnumerateProviders(penum, &BufferSize);

	while (ERROR_INSUFFICIENT_BUFFER == status) {
		ptemp = (PROVIDER_ENUMERATION_INFO*) realloc(penum, BufferSize);
		if (NULL == ptemp) {
			dprintf("Allocation failed (size=%lu).\n", BufferSize);
			break;
		}
		penum = ptemp;
		status = TdhEnumerateProviders(penum, &BufferSize);
	}

	lprov = (etw_provinfo_t *) mem_zalloc((penum->NumberOfProviders+1) *
	        sizeof(etw_provinfo_t));

	for (i = 0; i < penum->NumberOfProviders; i++) {
		wchar_t *wtmp =  (LPWSTR)((PBYTE)(penum) +
		        penum->TraceProviderInfoArray[i].ProviderNameOffset);
		char *s = (char *) mem_zalloc(256);
		GUID *g = (GUID *) mem_zalloc(sizeof(GUID));
		int nkw = 0;

		wcstombs_d(s, wtmp, 256);

		int len = strlen(s);
		for (int j = 0; j < len; j++) {
			if (s[j] == ' ' || s[j] == ';' || s[j] == ':' || s[j] == '(' || s[j] == ')')
				s[j] = '_';
		}
		lprov[i].provn = s;
		lprov[i].provg = penum->TraceProviderInfoArray[i].ProviderGuid;;
		lprov[i].provkw = etw_prov_kw(&lprov[i].provg, &nkw);
		lprov[i].provnkw = nkw;
	}
	lprov[i].provn = NULL;
	*nprov = i;

	return lprov;
}

/*
 * cache the list of providers and its keyword in a
 * file "dt_provlist.dat", in dtrace binary directory.
 * sudsequent calls to dtrace will read this file to get the
 * provider list. If you need dtrace to refresh the provider list, then
 * delete this file.
 */

/* FILE FORMAT
 * I 4bytes, II 8bytes, S null terminated string, G sizeof(GUID)
 * I<number of providers>
 * S<provider0 name>G<provider0 GUID>
 * 	I<number of keywords >
 * 		S<keyword00 name>II<keyword00 value>
 * 		S<keyword01 name>II<keyword01 value>
 * 		.....
 * 		S<keyword0m name>II<keyword0m value>
 * S<provider1 name>G<provider1 GUID>
 * 	....
 * 	....
 * S<providern name>G<providern GUID>
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
	int i,j;

	FILE *fp = fopen(fn, "wb");
	fwrite(&nprov, sizeof(int), 1, fp);

	for (i = 0; i < nprov; i++) {
		lkw = lprov[i].provkw;
		fwrite(lprov[i].provn, sizeof(char), strlen(lprov[i].provn)+1, fp);
		fwrite(&lprov[i].provg, sizeof(GUID), 1, fp);
		fwrite(&lprov[i].provnkw, sizeof(int), 1, fp);
		for (j = 0; j < lprov[i].provnkw; j++) {
			fwrite(lkw[j].kwn, sizeof(char), strlen(lkw[j].kwn)+1, fp);
			fwrite(&lkw[j].kwv, sizeof(uint64_t), 1, fp);
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
	DWORD i, j, k, l, nkw,  num = 0;
	ULONG64 val = 0;
	char provn[MAX_PATH], kwn[MAX_PATH],*s, *skw;
	GUID g;
	int c, sum = 0;
	FILE *fp = fopen(fprov, "rb");

	if (fp == NULL)
		return NULL;

	*nprov = 0;

	fread(&num, sizeof(int), 1, fp);
	ASSERT(num != 0);
	lprov = (etw_provinfo_t *) mem_zalloc((num+1)*sizeof(etw_provinfo_t));
	sum = (num+1)*sizeof(etw_provinfo_t);
	for (i = 0, j = 0; i < num; i++, j = 0) {
		do {
			c = fgetc(fp);
			provn[j++] = c;
		} while(c != '\0');

		s = (char *) mem_zalloc(j);
		memcpy(s, provn, j);
		fread(&g, sizeof(GUID), 1, fp);
		fread(&nkw, sizeof(int), 1, fp);
		lkw = (etw_provkw_t *) mem_zalloc((nkw+1)*sizeof(etw_provkw_t));
		sum += (nkw+1)*sizeof(etw_provkw_t);
		for (k = 0, l = 0; k < nkw; k++, l = 0) {
			do {
				c = fgetc(fp);
				kwn[l++] = c;
			} while(c != '\0');
			skw = (char *) mem_zalloc(l);
			sum += l;
			memcpy(skw, kwn, l);
			fread(&val, sizeof(uint64_t), 1, fp);
			lkw[k].kwn = skw;
			lkw[k].kwv = val;
		}
		lkw[k].kwn = NULL;

		lprov[i].provn = s;
		lprov[i].provg = g;
		lprov[i].provnkw = nkw;
		lprov[i].provkw = lkw;
	}
	lprov[i].provn = NULL;
	*nprov = num;

	fclose(fp);
	return lprov;
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

	return lprov;
}

/*
 * ETW Event processing function
 * Common to all providers
 */

// FileIO CB Name
// create a map of all open files during startup
static int
fileio_func(PEVENT_RECORD ev, void *data)
{
	struct FileIo_Name *fio;
	size_t len;
	wchar_t *fname;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, FileIoGuid));

	switch(ev->EventHeader.EventDescriptor.Opcode) {
	case 0:
	case 32:
	case 35:
	case 36:
		fio = (struct FileIo_Name *) ev->UserData;
		len = wcslen((wchar_t *) &fio->FileName);
		fname = (wchar_t *) mem_zalloc((len+2) * sizeof(wchar_t));
		wcsncpy(fname,(const wchar_t *) &fio->FileName, len);
		fname[len] = L'\0';
		etw_add_fname(fio->FileObject, fname);
		break;
	default:
		return (0);
	}
	return 0;
}

// process event processing function
#define SeLengthSid( Sid ) \
  (8 + (4 * ((SID *)Sid)->SubAuthorityCount))

template<class T> static proc_t *
	process_event(T *data, int dlen, int ver)
{
	proc_t *p = (proc_t *) mem_zalloc(sizeof(proc_t));
	wchar_t *wstr;
	char *str;
	size_t len;

	if (p == NULL)
		return NULL;
	ZeroMemory(p, sizeof(proc_t));
	p->ppid = data->ParentId;
	p->pid = data->ProcessId;

	ULONG* sid = (ULONG *) &data->UserSID;
	if (*sid == 0) {
		str = (char *) ((char *) &data->UserSID + 16);
	} else {
		SID *sid = (SID *) ((char *) &data->UserSID + 16);
		len = SeLengthSid(sid);
		str = (char *) ((char *) sid + len);
	}

	if ((str - (char *)data) >= dlen)
		return p;
	str = _strlwr(str);
	len = strlen(str) + 1;
	p->name = (char *) mem_zalloc(len);
	strcpy(p->name, str);
	if (ver < 2)
		return p;
	wstr = (wchar_t *) (str + len);
	len = wcslen(wstr)*2 + 2;
	p->cmdline = (wchar_t *) mem_zalloc(len);
	wcscpy(p->cmdline,  wstr);

	return p;
}

// last cb function to run for process event
// doesnt do anything yet. remove defunct/exit process
static int
process_func_last(PEVENT_RECORD ev, void *data)
{
	pid_t pid = ev->EventHeader.ProcessId;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, ProcessGuid));

	switch(ev->EventHeader.EventDescriptor.Opcode) {
	case 2:
	case 4:
		//remove from proclist
		;
		return (0);
	}
	return (1);
}

// first cb function to run for process event
static int
process_func_first(PEVENT_RECORD ev, void *data)
{
	proc_t *p = NULL, *p0 = NULL;
	uint32_t st, pid;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, ProcessGuid));

	switch(ev->EventHeader.EventDescriptor.Opcode) {
	case 1:
	case 3:
	case 4:
		switch(ev->EventHeader.EventDescriptor.Version) {
		case 0:
			p = process_event<Process_V0_TypeGroup1>
			    ((Process_V0_TypeGroup1 *) ev->UserData, ev->UserDataLength, 0);
			break;
		case 1: {
			Process_V1_TypeGroup1 *tmp = (Process_V1_TypeGroup1 *) ev->UserData;
			p = process_event<Process_V1_TypeGroup1>
			    (tmp, ev->UserDataLength, 1);
			p->sessid = tmp->SessionId;
			p->exitval = tmp->ExitStatus;
			p->pageaddr = tmp->PageDirectoryBase;
			break;
		}
		case 2: {
			Process_V2_TypeGroup1 *tmp = (Process_V2_TypeGroup1 *) ev->UserData;
			p = process_event<Process_V2_TypeGroup1>
			    (tmp, ev->UserDataLength, 2);
			p->sessid = tmp->SessionId;
			p->exitval = tmp->ExitStatus;
			p->addr = tmp->UniqueProcessKey;
			break;
		}
		case 3: {
			Process_V3_TypeGroup1 *tmp = (Process_V3_TypeGroup1 *) ev->UserData;
			p = process_event<Process_V3_TypeGroup1>
			    (tmp, ev->UserDataLength, 3);
			p->sessid = tmp->SessionId;
			p->exitval = tmp->ExitStatus;
			p->pageaddr = tmp->DirectoryTableBase;
			p->addr = tmp->UniqueProcessKey;
			break;
		}
		case 4: {
			Process_V4_TypeGroup1 *tmp = (Process_V4_TypeGroup1 *) ev->UserData;
			p = process_event<Process_V4_TypeGroup1>
			    (tmp, ev->UserDataLength, 4);
			p->sessid = tmp->SessionId;
			p->exitval = tmp->ExitStatus;
			p->pageaddr = tmp->DirectoryTableBase;
			p->addr = tmp->UniqueProcessKey;
			p->model = tmp->Flags == 2 ? 0: 1; //flags == 2 WOW64 ??
			break;
		}
		default:
			return (-1);
		}
		break;
	case 2:
	case 39: {
		switch(ev->EventHeader.EventDescriptor.Version) {
		case 1: {
			Process_V1_TypeGroup1 *tmp = (Process_V1_TypeGroup1 *) ev->UserData;
			pid = tmp->ProcessId;
			st = tmp->ExitStatus;
			break;
		}
		case 2: {
			Process_V2_TypeGroup1 *tmp = (Process_V2_TypeGroup1 *) ev->UserData;
			pid = tmp->ProcessId;
			st = tmp->ExitStatus;
			break;
		}
		case 3: {
			Process_V3_TypeGroup1 *tmp = (Process_V3_TypeGroup1 *) ev->UserData;
			pid = tmp->ProcessId;
			st = tmp->ExitStatus;
			break;
		}
		case 4: {
			Process_V4_TypeGroup1 *tmp = (Process_V4_TypeGroup1 *) ev->UserData;
			pid = tmp->ProcessId;
			st = tmp->ExitStatus;
			break;
		}
		default:
			return -1;
		}
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
		//p0->p_model = p->p_model;
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
	int i=0;

	while (iter != proclist.end()) {
		printf("%d - %s %S\n", i++, iter->second->name, iter->second->cmdline);
		iter++;
	}
}

// thread event processing function
template<class T> static thread_t *
	thread_event(T *data, int dlen, int version)
{
	thread_t *td = (thread_t *) mem_zalloc(sizeof(thread_t));

	if (td == NULL)
		return (NULL);

	ASSERT((int) data->ProcessId != -1);

	proc_t *p = etw_get_proc(data->ProcessId, ETW_PROC_CREATE);

	switch (version) {
	case 3:
	case 2:
	case 1:
		td->kbase = *((uetwptr_t *) ((char *) data + 8));
		td->klimit = *((uetwptr_t *) ((char *) data + 8 + sizeof(uetwptr_t)));
		td->ubase = *((uetwptr_t *) ((char *) data + 8 + sizeof(uetwptr_t)*2));
		td->ulimit = *((uetwptr_t *) ((char *) data + 8 + sizeof(uetwptr_t)*3));
	case 0:
		td->tid = data->TThreadId;
		td->pid = data->ProcessId;
		if (p != NULL) {
			td->ppid = p->ppid;
			td->proc = p;
		}
		break;
	default:
		return (NULL);
	}
	return (td);
}

// first cb function to run for thread event
static int
thread_func_first(PEVENT_RECORD ev, void *data)
{
	thread_t *td, *t0;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, ThreadGuid));

	switch(ev->EventHeader.EventDescriptor.Opcode) {
	case 1:
	case 3:
	case 4:
		switch(ev->EventHeader.EventDescriptor.Version) {
		case 0:
			td = thread_event<Thread_V0_TypeGroup1>
			    ((Thread_V0_TypeGroup1 *) ev->UserData, ev->UserDataLength, 0);
			break;
		case 1:
			td = thread_event<Thread_V1_TypeGroup1>
			    ((Thread_V1_TypeGroup1 *) ev->UserData, ev->UserDataLength, 1);
			break;
		case 2:
			td = thread_event<Thread_V2_TypeGroup1>
			    ((Thread_V2_TypeGroup1 *) ev->UserData, ev->UserDataLength, 2);
			break;
		case 3: {
			Thread_V3_TypeGroup1 *data = (Thread_V3_TypeGroup1 *) ev->UserData;
			td = thread_event<Thread_V3_TypeGroup1>
			    ((Thread_V3_TypeGroup1 *) ev->UserData, ev->UserDataLength, 3);
			td->affinity = data->Affinity;
			td->pri = data->BasePriority;
			td->iopri = data->IoPriority;
			td->pagepri = data->PagePriority;
			td->flags = data->ThreadFlags;
			break;
		}
		default:
			return (-1);
		}

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
			if (t0->tid != td->tid) {		// XXXXXX
				int off = offsetof(thread_t, kbase);
				memcpy((char*)td+off, (char*)t0+off, sizeof(thread_t)-off);
				free(t0);
				etw_add_thread(td->tid, td);
			}
		}
	}

	return (0);
}

// last cb function to run for thread event
// doesnt do anything yet. remove defunct/exit threads
static int
thread_func_last(PEVENT_RECORD ev, void *data)
{
	pid_t tid;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, ThreadGuid));

	switch(ev->EventHeader.EventDescriptor.Opcode) {
	case 2:
		switch(ev->EventHeader.EventDescriptor.Version) {
		case 0:
			tid = *((uint32_t *) ev->UserData);
			break;
		case 1:
		case 2:
		case 3:
			tid = *((uint32_t *) ((char *)ev->UserData+4));
			break;
		default:
			return (-1);
		}
	default:
		return (-1);
	}
	// remove from threadlist
	;

	return (0);
}

static void
print_threadlist()
{
	unordered_map<pid_t, thread_t *>::iterator iter = threadlist.begin();
	int i=0;

	while (iter != threadlist.end()) {
		printf("%d - %s %lld\n", i++, iter->second->proc ? iter->second->proc->name:"",
		    iter->second->tid);
		iter++;
	}
}

// first cb function to run for profile (perfinfo) event
static int
profile_func_first(PEVENT_RECORD ev, void *data)
{
	if (ev->EventHeader.EventDescriptor.Opcode != 46)
		return 0;

	if (ev->UserDataLength != 0) {
		SampledProfile *sample = (SampledProfile *) ev->UserData;
		sessinfo->tid = sample->ThreadId;

		sessinfo->td = etw_get_td(sample->ThreadId, -1, ETW_THREAD_CREATE);

		sessinfo->proc = sessinfo->td->proc;

		return (0);
	}

	return (-1);
}


// xperf synthetic image events
// creates a list of pdb info for each process
// having this events
static int
xperf_image_events(PEVENT_RECORD ev, void *data)
{
	struct DbgID_RSDS *dbg;
	int fnd = 0;
	size_t size = 0;
	cvpdbinfo_t *cv = NULL;
	proc_t *p;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, KernelTraceControlGuid));

	if (ev->EventHeader.EventDescriptor.Opcode == 36 ||
	    ev->EventHeader.EventDescriptor.Opcode == 37) {
		dbg = (struct DbgID_RSDS *)  ev->UserData;

		ASSERT(ev->EventHeader.ProcessId == dbg->pid);
		//ASSERT(proclist[dbg->pid] != NULL);

		p = etw_get_proc(dbg->pid, ETW_PROC_CREATE);
		char *s = (char *)&dbg->pdbfilename;
		if ((cv = cvinfolist[dbg->sig]) == NULL) {
			size_t len = strlen((char *)&dbg->pdbfilename);
			size = (int) offsetof(cvpdbinfo_t, pdbname)
			    + len +1;
			cv = (cvpdbinfo_t *) mem_zalloc(size);
			cv->cvsig = 0x53445352;
			cv->sig = dbg->sig;
			cv->age = dbg->age;
			strcpy((char *) &cv->pdbname[0], dbg->pdbfilename);
			cv->pdbname[len] = 0;
			cvinfolist[dbg->sig] = cv;
		} else {
			/*
			 * if we have already received this event,
			 * ex for a different process, dont create a new cvpdbinfo_t.
			 * Check whether it is linked with existing process.
			 */
			etw_proc_cvinfo_t *tmp = (etw_proc_cvinfo_t *) p->cvinfo;
			while(tmp) {
				if (tmp->cv == cv)
					return (0);
				tmp = tmp->next;
			}
			size_t len = strlen((char *)cv->pdbname);
			size = (int) offsetof(cvpdbinfo_t, pdbname) + len + 1;
			//return (0);
		}

		etw_proc_cvinfo_t * cvinfo = (etw_proc_cvinfo_t *) mem_zalloc(sizeof(etw_proc_cvinfo_t));
		cvinfo->cv = cv;
		cvinfo->base = dbg->base;
		cvinfo->size = size;
		cvinfo->next = (etw_proc_cvinfo_t *) p->cvinfo;
		p->cvinfo = cvinfo;
	} else if (ev->EventHeader.EventDescriptor.Opcode == 0) {
		;
	}

	return (0);
}

// image load
static void
print_modulelist()
{
	unordered_map<wstring, etw_module_t *>::iterator iter = modlist.begin();
	int i=0;
	fprintf(stderr, "Module list\n");
	while (iter != modlist.end()) {
		printf("%ls\n", iter->second->name);
		iter++;
	}
}

// processing for module load event
static int
image_load_func(PEVENT_RECORD ev, void *data)
{
	proc_t *p;
	pid_t pid = 0;
	etw_module_t *fmod, *mod = (etw_module_t *) mem_zalloc(sizeof(etw_module_t));
	etw_proc_module_t *pmod;
	uetwptr_t pbase;
	Image *img;
	wchar_t *pstr;
	wstring wstr;
	int fnd = 0;

	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, ImageLoadGuid));

	ASSERT(ev->EventHeader.EventDescriptor.Opcode != 1);
	memset(mod, 0, sizeof(etw_module_t));
	switch(ev->EventHeader.EventDescriptor.Opcode) {
	case 10: 	// Load
	case 3:		// DCStartLoad
	case 4:		//DCEndUnLoad
		switch(ev->EventHeader.EventDescriptor.Version) {
		case 0:
			mod->base = ((Image_V0 *) ev->UserData)->BaseAddress;
			mod->size = ((Image_V0 *) ev->UserData)->ModuleSize;
			wcscpy(mod->name, ((Image_V0 *) ev->UserData)->ImageFileName);
			pbase = mod->base;
			break;
		case 1:
			mod->base = ((Image_V1 *) ev->UserData)->ImageBase;
			mod->size = ((Image_V1 *) ev->UserData)->ImageSize;
			wcscpy(mod->name, ((Image_V1 *) ev->UserData)->FileName);
			pid = ((Image_V1 *) ev->UserData)->ProcessId;
			break;
		case 2:
			//dprintf("(%s), version (2) Not Implemeted\n", __func__);
			//ASSERT(0);
		case 3:
			img = ((Image *) ev->UserData);
			mod->base = img->DefaultBase;
			pbase = img->ImageBase;
			mod->size = img->ImageSize;
			mod->chksum = img->ImageCheckSum;
			mod->tmstamp = img->TimeDateStamp;
			pstr = (wchar_t *) &img->FileName;
			wcscpy(mod->name, pstr);
			pid = img->ProcessId;

			break;
		default:
			dprintf("image_load_func, unknown version number (%d)\n",
			    ev->EventHeader.EventDescriptor.Version);
			ASSERT(0);
			break;
		}
		break;
	case 2:		//UnLoad
		return (0);
		break;
	default:
		dprintf("(%s), unknown event (%d) version (%d)\n", __func__,
		    ev->EventHeader.EventDescriptor.Opcode,
		    ev->EventHeader.EventDescriptor.Version);
		return (0);
		break;
	}

	etw_rep_dev_to_path(mod->name);	//Normalize pathname
	_wcslwr(mod->name);
	wstr = wstring((wchar_t *) mod->name);

	if ((fmod = modlist[wstr]) == NULL) {
		mod->cvinfo = NULL;//etw_pdb_info(mod->name);
		etw_add_module(mod, wstr);
	} else {
		//timestamp is zero for rundowns, only has value for load & unload events
		if (fmod->tmstamp == 0 && mod->tmstamp > 0)
			fmod->tmstamp = mod->tmstamp;
		free(mod);
		mod = fmod;
	}

	if (pid != -1) {
		pmod = (etw_proc_module_t *) mem_zalloc(sizeof(etw_proc_module_t));
		pmod->mod =  mod;
		pmod->base = pbase;
		p = etw_get_proc(pid, ETW_PROC_FIND);
		if (p != NULL) {
			pmod->next = (etw_proc_module_t *) p->mod;
			p->mod = pmod;
		}
	}

	return (0);
}

// etw user stack event processing
// this are additional stacks whick were not included in the
// user event extended data stack. (ex. kernel stack trace of the user event)
static int
ustack_func(PEVENT_RECORD ev, void *data)
{
	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, KernelEventTracing));
	if (ev->EventHeader.EventDescriptor.Id != 18) {
		return (0);
	}

	int i = 0;
	etw_sessioninfo_t *sess = sessinfo->etw;
	int size = 0, psize = 0, matchid = 0;

	if (ev->ExtendedDataCount) {
		do {
			if (ev->ExtendedData[i].ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
				psize = sizeof(ULONG64);
				size = (ev->ExtendedData[i].DataSize - sizeof(ULONG64)) / psize;
			}
			if (ev->ExtendedData[i].ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32) {
				psize = sizeof(ULONG);
				size = (ev->ExtendedData[i].DataSize - sizeof(ULONG64)) / psize;
			} else {
				continue;
			}
			matchid = *((ULONG64 *)ev->ExtendedData[i].DataPtr);
			etw_stack_t *stackp = sess->Q.map[ev->BufferContext.ProcessorNumber][matchid];

			/*
			 * processor number in the event and its stackwalk
			 * may not match. so check for the event in all the cpu.
			 */
			if (stackp == NULL) {
				for (uint32_t i = 0 ; i < sess->ncpus && stackp == NULL; i++) {
					stackp = sess->Q.map[i][matchid];
				}
			}
			if (stackp == NULL) {
				if (etw_diag_cb) {
					etw_diag_cb(ev,  (void *) etw_diag_id);
				}
				return (-1);
			}

			memcpy((char *) stackp->stack + (stackp->stacklen*psize),
			    (char *) ev->ExtendedData[i].DataPtr+sizeof(ULONG64), size*psize);

			stackp->stacklen += size;
			stackp->stackready = 1;
		} while(++i < ev->ExtendedDataCount);
	}
	return (0);
}

//Stack
static int
stack_func(PEVENT_RECORD ev, void *data)
{
	struct ETWStackWalk *sw = (struct ETWStackWalk *) ev->UserData;
	int offset = (sizeof(struct ETWStackWalk) - sizeof(uetwptr_t));
	int depth =  (ev->UserDataLength - offset)/sizeof(uetwptr_t);
	etw_sessioninfo_t *sess = sessinfo->etw;

	etw_stack_t *stackp = sess->Q.map[ev->BufferContext.ProcessorNumber][sw->EventTimeStamp];

	/*
	 * processor number in the event and its stackwalk
	 * may not match. so check for the event in all the cpu.
	 */
	if ((stackp == NULL) || (stackp->dprobe.tid != -1 &&
	        (stackp->dprobe.tid != sw->StackThread))) {
		stackp = NULL;
		for (uint32_t i = 0 ; i < sess->ncpus && stackp == NULL; i++) {
			stackp = sess->Q.map[i][sw->EventTimeStamp];
			if (stackp && (stackp->dprobe.tid != sw->StackThread))
				stackp = NULL;
		}
	}

	if (stackp == NULL) {
		if (etw_diag_cb) {
			etw_diag_cb(ev,  (void *) etw_diag_id);
		}
		return (-1);
	}

	ASSERT(stackp->dprobe.ts == sw->EventTimeStamp);
	ASSERT(stackp->dprobe.tid == sw->StackThread || stackp->dprobe.tid == -1);

	/* 
	 * if the initial events process id or thread id is equal to -1
	 * update it here
	 */
	stackp->dprobe.pid = sw->StackProcess;
	if (stackp->dprobe.tid == -1) {
		stackp->dprobe.tid = sw->StackThread;
	}

	if (depth+stackp->stacklen > ETW_MAX_STACK) {
		depth = ETW_MAX_STACK - stackp->stacklen;
	}

	if (depth) {
		memcpy((char *)stackp->stack + (stackp->stacklen*sizeof(uetwptr_t)),
		    (char *)ev->UserData+offset,
		    (ev->UserDataLength - offset));
		stackp->stacklen += depth;
		stackp->stackready = 1;
	}

	return (0);
}

// lost event //opcode = 32
static int
lost_event_func(PEVENT_RECORD ev, void *data)
{
	ASSERT(IsEqualGUID(ev->EventHeader.ProviderId, RTLostEvent));
	dprintf("Lost Events\n");
	return (0);
}

/*
 * Return the linked list of modules loaded for the process
 */
etw_proc_module_t *
dtrace_etw_pid_modules(pid_t pid)
{
	proc_t *p = NULL;

	p = etw_get_proc(pid, ETW_PROC_FIND);

	return (etw_proc_module_t *) (p ? p->mod: NULL);
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
		return buf;
	}
	tmod = symmap.jit_modules[tsym->ModuleID];
	if (tmod == NULL) {
		buf[0] = 0;
		return buf;
	}
	wchar_t name[MAX_PATH];
	_wsplitpath(tmod, NULL, NULL, name, NULL);
	wcstombs_d(buf, name, size);
	return buf;
}

int
dtrace_etw_lookup_jit_addr(pid_t pid, uetwptr_t addr, char *buf,
    size_t size, GElf_Sym *symp)
{
	etw_jit_symbol_t *jsym = etw_lookup_jit_sym(pid, addr);
	if (jsym) {
		symp->st_name = 0;
		symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
		symp->st_other = 0;
		symp->st_shndx = 1;
		symp->st_value = jsym->MethodStartAddress;
		symp->st_size = jsym->MethodSize;
		int ls = wcstombs_d(buf, jsym->MethodFullName, size);
		int lw = wcslen(jsym->MethodFullName);
		buf[ls++] = '.';
		ls = wcstombs_d(buf+ls, jsym->MethodFullName + lw+1,  size-ls);
		return (0);
	}
	return -1;
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
dtrace_etw_lookup_addr(etw_proc_module_t *pmod, pid_t pid, uetwptr_t addr,
    char *buf, size_t size, GElf_Sym *symp)
{
	int fnd = 0;
	proc_t *p;
	etw_module_t *mod;
	cvpdbinfo_t *cv;
	uint64_t base;
	uetwptr_t tmpa;

	if (pmod == NULL) {
		p = etw_get_proc(pid, ETW_PROC_FIND);
		if (p) {
			pmod = (etw_proc_module_t *) p->mod;
		}
	}

	NTKERNEL:

	while(pmod) {
		mod = pmod->mod;

		ASSERT(mod != NULL);

		if (addr >= pmod->base && addr < pmod->base+mod->size) {
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
				/* if module previously loaded in dbghelp without
					pdb info. try again with this process pdb info
					collection */
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
					cv = mod->cvinfo = etw_match_cvinfo((etw_proc_cvinfo *) p->cvinfo,
					            mod, pmod->base);
				} else {
					cv = mod->cvinfo = etw_match_datatime(pdbsyms.h, mod, pmod->base);
				}
			}

			if (cv == NULL) {
				/* No symbol file found. load anyway into dbghelp
				 * at the next free address
				 */
				wchar_t *ws0 = PathFindFileNameW(mod->name);
				uint64_t base0 = SymLoadModuleExW(nopdbsyms.h, 0, ws0, NULL,
				        nopdbsyms.endaddr, (DWORD) mod->size, NULL, 0);
				mod->dbgbase = nopdbsyms.endaddr;
				nopdbsyms.endaddr += mod->size;
				mod->sym = &nopdbsyms;
				pmod->symloaded = 1;
				fnd = 1;
				break;
			}

			size_t len = strlen((char *)cv->pdbname);
			size_t size = offsetof(cvpdbinfo_t, pdbname)
			    + len + 1;
			size_t sz = sizeof(MODLOAD_CVMISC) + size;

			MODLOAD_CVMISC * cvmisc = (MODLOAD_CVMISC *) mem_zalloc(sz);
			cvmisc->oCV = sizeof(MODLOAD_CVMISC);
			cvmisc->cCV = size;
			cvmisc->oMisc = 0;
			cvmisc->cMisc = 0;
			cvmisc->dtImage = 0;
			cvmisc->cImage = 0;
			memcpy((char *) cvmisc + sizeof(MODLOAD_CVMISC), cv, size);

			MODLOAD_DATA md = {0};
			md.ssize = sizeof(md);
			md.ssig = DBHHEADER_CVMISC;
			md.data = cvmisc;
			md.size = (DWORD) sz;
			wchar_t *ws = PathFindFileNameW(mod->name);
			/* load into dbghelp at the next free address */
			base = SymLoadModuleExW(pdbsyms.h, 0, ws, NULL,
			        pdbsyms.endaddr, (DWORD) mod->size, &md, 0);
			mod->dbgbase = pdbsyms.endaddr;
			pdbsyms.endaddr += mod->size;
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
		return dtrace_etw_lookup_jit_addr(pid, addr, buf, size, symp);
	}

	SYMBOL_INFO *s;
	s = (SYMBOL_INFO *) malloc(sizeof(SYMBOL_INFO) + size-1);
	if (s == NULL)
		return -1;

	s->SizeOfStruct = sizeof(SYMBOL_INFO);
	s->MaxNameLen = size;
	int64_t fac =  (int64_t) mod->dbgbase - pmod->base;
	tmpa = addr + fac;
	if (SymFromAddr(mod->sym->h, tmpa, 0, s) == TRUE) {
		symp->st_name = 0;
		symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
		symp->st_other = 0;
		symp->st_shndx = 1;
		symp->st_value = s->Address - fac;
		symp->st_size = s->Size;
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

	while(pmod) {
		mod = pmod->mod;

		ASSERT(mod != NULL);

		if (addr >= pmod->base && addr < pmod->base+mod->size) {
			wchar_t *ws = PathFindFileNameW(mod->name);
			WideCharToMultiByte(CP_UTF8, 0, ws, -1, buffer, bufsize, NULL, NULL );
			buffer[bufsize-1] = 0;
			return buffer;
		}
		pmod = pmod->next;
	}
	return dtrace_etw_lookup_jit_module(pid, addr, buffer, bufsize);;
}

etw_proc_module_t *
dtrace_etw_pid_symhandle(pid_t pid)
{
	proc_t *p;
	p = etw_get_proc(pid, ETW_PROC_FIND);
	if (p) {
		return (etw_proc_module_t *) (p->mod);
	}
	return 0;
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
			sessioninfo_t *tmp = (sessioninfo_t *) mem_zalloc(sizeof(sessioninfo_t));
			sessinfo = tmp;
		}
		sessinfo->td = td;
		sessinfo->tid = tid;
		sessinfo->pid = td->pid;
		sessinfo->proc = td->proc;
	}

	return td;
}

/*
 * Return NULL if kernel session doesnt exist
 */
int
dtrace_etw_session_on(etw_sessions_t *sinfo)
{
	return (int) dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]->psession; //XXX
}

int
dtrace_set_ft_stack(uetwptr_t *stack, uint32_t size)
{
	sessinfo->etw->ftstack = stack;
	sessinfo->etw->ftsize = size;

	return 0;
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
	while((sess = dtrace_etw_sessions[DT_ETW_FT_SESSION]) && loop) {
		Sleep(2000);
		if (sess->hb == hb) {
			etw_stop_ft();
			return (0);
		}
		hb = sess->hb;
		loop--;
	}
	etw_stop_ft();
	return 0; //XXX
}

/*
 * Returns the thread which generated the ETW event
 */
thread_t *
dtrace_etw_curthread()
{
	if (sessinfo) {
		return sessinfo->td;
	} else {
		thread_t *td = etw_get_td(GetCurrentThreadId(),
		        GetCurrentProcessId(), ETW_THREAD_CREATE);
		return td;
	}
}

/*
 * Returns the process which generated the ETW event
 */
proc_t *
dtrace_etw_curproc()
{
	if (sessinfo) {
		return sessinfo->proc;
	} else {
		proc_t *p = etw_get_proc(GetCurrentProcessId(), ETW_PROC_CREATE);
		return p;
	}
}

int
dtrace_etw_current_cpu()
{
	if (sessinfo) {
		return sessinfo->cpuno;
	} else {
		return -1;
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


/*
 * stacktrace of a kernel event may come any time after the event, in
 * a seperate stack event, in more than one event packet.
 * Here we wait for ETW_QUEUE_SIZE events before sending the event.
 * If stacktrace for the event comes after ETW_QUEUE_SIZE events, then
 * the trace is lost.
 */
void
dtrace_etw_probe(dtrace_id_t id, uetwptr_t arg0, uetwptr_t arg1,
    uetwptr_t arg2, uetwptr_t arg3, uetwptr_t arg4, int isstack)
{
	HANDLE *lock = 0;
	etw_stack_t *del, *stackp = (etw_stack_t *) mem_zalloc(sizeof(etw_stack_t));
	etw_dprobe_t *dprobe = &stackp->dprobe;

	stackp->stacklen = 0;
	stackp->stackready = 0;
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

	while(InterlockedExchange(&sessinfo->etw->Q.lock, TRUE) == TRUE)
		Sleep(1);

	sessinfo->etw->Q.queue.push(stackp);

	/* user mode ETW stacktrace */
	if (sessinfo->etw->ev && sessinfo->etw->ev->ExtendedDataCount) {
		PEVENT_RECORD ev= sessinfo->etw->ev;
		int size = 0, psize = 0, matchid = 0, i = 0;

		if (ev->ExtendedDataCount) {
			do {
				if (ev->ExtendedData[i].ExtType ==
				    EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
					psize = sizeof(ULONG64);
					size = (ev->ExtendedData[i].DataSize - sizeof(ULONG64)) / psize;
				} else if (ev->ExtendedData[i].ExtType ==
				    EVENT_HEADER_EXT_TYPE_STACK_TRACE32) {
					psize = sizeof(ULONG);
					size = (ev->ExtendedData[i].DataSize - sizeof(ULONG64)) / psize;
				} else {
					continue;
				}

				memcpy((char *) stackp->stack + (stackp->stacklen*psize),
				    (char *) ev->ExtendedData[i].DataPtr+sizeof(ULONG64), size*psize);
				stackp->stacklen += size;
				stackp->stackready = 1;
				matchid = *((ULONG64 *)ev->ExtendedData[i].DataPtr);
				//if matchid == 0 both kernel and user stack complete;
				if (matchid != 0) {
					sessinfo->etw->Q.map[dprobe->cpuno][matchid] = stackp;
				}
			} while(++i < ev->ExtendedDataCount);
		}
	}

	if (sessinfo->etw->ftsize) {
		memcpy(stackp->stack, sessinfo->etw->ftstack,
		    sessinfo->etw->ftsize*sizeof(uetwptr_t));
		stackp->stacklen = sessinfo->etw->ftsize;
		sessinfo->etw->ftsize = 0;
		stackp->stackready = 1;
	} else {
		sessinfo->etw->Q.map[dprobe->cpuno][dprobe->ts] = stackp;
	}
	del = stackp;
	if (sessinfo->etw->Q.queue.size() > ETW_QUEUE_SIZE) {
		stackp = sessinfo->etw->Q.queue.front();
		sessinfo->etw->stackinfo = stackp;
		sessinfo->etw->Q.queue.pop();
		sessinfo->etw->Q.map[stackp->dprobe.cpuno].erase(stackp->dprobe.ts);

		etw_send_dprobe(stackp);
		free(stackp); 
	}
	InterlockedExchange(&sessinfo->etw->Q.lock, FALSE);
}

void
dtrace_etw_reset_cur(HANDLE *lock)
{
	return etw_reset_cur(lock);
}

HANDLE *
dtrace_etw_set_cur(pid_t pid, pid_t tid, hrtime_t tm, int cpuno)
{
	return etw_set_cur(pid, tid, tm, cpuno);
}

/*
 * Dtrace etw helper functions
 */
int
dtrace_etw_samplerate(int interval)
{
	return etw_set_freqNT(interval);
}

int
dtrace_etw_set_stackid(CLASSIC_EVENT_ID id[], int len)
{
	int fnd = 0;
	etw_sessioninfo_t *sess = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	ASSERT(sess->stackidlen+len < ETW_MAX_STACKID);

	for(int i = 0; i < len; i++) {
		for (int j=0 ; j < sess->stackidlen; j++) {
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

	return etw_set_kernel_stacktrace(sess->hsession,
	        sess->stackid, sess->stackidlen);
}

/*
 * Get the stacktrace for current event,
 * returns stack depth
 */
int
dtrace_etw_get_stack(uint64_t *pcstack, int pcstack_limit, int usermode)
{
	int n = pcstack_limit;
	etw_stack_t *stackp;

	if (!sessinfo || sessinfo->etw == NULL)
		return 0;

	stackp = sessinfo->etw->stackinfo;

	if (!stackp || stackp->stackready == 0) {
		return (0);
	}

	if (usermode) {
		for (int i = 0; i < stackp->stacklen && pcstack_limit; i++) {
			if (!INKERNEL(stackp->stack[i])) {
				*pcstack++ = (uint64_t)stackp->stack[i];
				pcstack_limit--;
			}
		}
	} else {
		for (int i = 0; i < stackp->stacklen && pcstack_limit; i++) {
			if (INKERNEL(stackp->stack[i])) {
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

	if (sessinfo) {
		tmp = sessinfo->etw->timescale*100UL;
		ts = sessinfo->timestamp * tmp;
	}
	return ts == 0 ? sys_gethrtime(): ts;
}

hrtime_t
dtrace_etw_gethrestime(void)
{
	hrtime_t ts = sessinfo && sessinfo->timestamp ?
	    etw_event_timestamp(sessinfo->timestamp) : sys_gethrestime();

	return (ts);
}

int
dtrace_etw_hook_event(const GUID *guid, Function efunc, void *data, int place)
{
	return etw_hook_event(guid, efunc, data, place, TRUE);
}

int
dtrace_etw_unhook_event(const GUID *guid, Function efunc, void *data)
{
	return etw_unhook_event(guid, efunc, data, FALSE);
}

int
dtrace_etw_nprocessors()
{
	if (!sessinfo) {
		if (dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]) {
			return dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]->ncpus;
		}
		return -1;
	}
	return sessinfo->etw->ncpus;
}

wchar_t *
dtrace_etw_get_fname(uetwptr_t fobj)
{
	return etw_get_fname(fobj);
}
int
dtrace_etw_kernel_stack_enable(CLASSIC_EVENT_ID id[], int len)
{
	return dtrace_etw_set_stackid(id, len);
}

int
dtrace_etw_profile_enable(hrtime_t interval, int type)
{
	etw_sessioninfo_t *sess = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	etw_hook_event(&PerfInfoGuid, profile_func_first, NULL, ETW_EVENTCB_ORDER_FRIST, TRUE);

	if (sess->isfile)
		return 0;

	CLASSIC_EVENT_ID  id[1];

	id[0].EventGuid = PerfInfoGuid;
	id[0].Type = 46;

	dtrace_etw_set_stackid(id, 1);

	dtrace_etw_samplerate((int)(interval/100.0));

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

	if (!sess || sess->isfile)
		return 0;

	if (etw_enable_kernel_prov(NULL, sess->sessname,
	        EVENT_TRACE_FLAG_PROFILE, FALSE) != 0) {
		dprintf("dtrace_etw_profile_disable, failed\n ");
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
	etw_sessioninfo_t *sess = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	if (sess->isfile)
		return 0;

	if (etw_enable_kernel_prov(NULL, sess->sessname,
	        flags, TRUE) != 0) {
		dprintf("dtrace_etw_prov_enable, failed for flags (%d)\n ", flags);
		return (-1);
	}
	return 0;
}

/*
 * Disable (flags) kernel provider
 */
int
dtrace_etw_prov_disable(int flags)
{
	etw_sessioninfo_t *sess = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	if (sess == NULL || sess->isfile)
		return 0;

	if (etw_enable_kernel_prov(NULL, sess->sessname,
	        flags, FALSE) != 0) {
		dprintf("dtrace_etw_prov_disable, failed for flags (%d)\n ", flags);
		return (-1);
	}
	return (0);
}

int
dtrace_etw_uprov_enable(GUID *pguid, uint64_t keyword,
    uint32_t eventno, int level, int estack)
{
	if (dtrace_etw_sessions[DT_ETW_USER_SESSION]) {
		return etw_enable_user(dtrace_etw_sessions[DT_ETW_USER_SESSION]->hsession,
	        	pguid, keyword, level, estack);
	} else if (dtrace_etw_sessions[DT_ETW_KERNEL_SESSION]->isfile) {
		return (0);
	}
	
	return (-1);
}

/*
 * Initialize ETW to read from a etl file
 */
etw_sessions_t *
dtrace_etwfile_init(etw_dtrace_probe_t probef, etw_dtrace_ioctl_t ioctlf,
    wchar_t *etlfile)
{
	int iskevent = 0;

	etw_initialize();
	etw_sessioninfo_t *sinfo = new etw_sessioninfo_t();

	sinfo->dtrace_probef = probef;
	sinfo->dtrace_ioctlf = ioctlf;
	sinfo->isfile = 1;
	sinfo->etlfile = etlfile;

	wmutex_init(&etw_eventcb_lock);
	wmutex_init(&etw_cur_lock);
	wmutex_init(&etw_proc_lock);
	wmutex_init(&etw_thread_lock);

	etw_devname_to_path(devmap);

	etw_hook_event(&ProcessGuid, process_func_first, NULL, 1, iskevent);
	etw_hook_event(&ProcessGuid, process_func_last, NULL, 2, iskevent);
	etw_hook_event(&ThreadGuid, thread_func_first, NULL, 1, iskevent);
	etw_hook_event(&ThreadGuid, thread_func_last, NULL, 2, iskevent);
	///etw_hook_event(&PerfInfoGuid, profile_func_first, NULL, 1, iskevent);
	etw_hook_event(&StackWalkGuid, stack_func, NULL, 0, iskevent);
	etw_hook_event(&ImageLoadGuid, image_load_func, NULL, 0, iskevent);
	etw_hook_event(&FileIoGuid, fileio_func, NULL, 0, iskevent);
	//etw_hook_event(&RTLostEvent, lost_event_func, NULL, 0, iskevent);
	etw_hook_event(&KernelTraceControlGuid, xperf_image_events, NULL, 0, iskevent);
	etw_hook_event(&MSDotNETRuntimeRundownGuid, clr_jitted_rd_func, NULL, 1, iskevent);
	etw_hook_event(&MSDotNETRuntimeGuid, clr_jitted_func, NULL, 1, iskevent);
	etw_hook_event(&KernelEventTracing, ustack_func, NULL, 0, iskevent);


	dtrace_etw_sessions[DT_ETW_KERNEL_SESSION] = sinfo;

	if (etw_start_trace(sinfo, TRUE, etw_event_cb, NULL, 1) == 0) {
		etw_end_session(sinfo, NULL);
		delete sinfo;
		return (NULL);
	}
	sinfo->data = etw_get_providers();
	return dtrace_etw_sessions;
}

etw_sessioninfo_t*
etw_session_add_fileext(etw_sessioninfo_t *sess, wchar_t *ext, int id)
{
	int len;
	len = (wcslen(sess->etlfile) + wcslen(ext)+1)*2;

	wchar_t *etlrdfile = (wchar_t *) mem_zalloc(len);
	wcscpy(etlrdfile, sess->etlfile);
	wchar_t *dot = wcsrchr(etlrdfile, L'.');
	wcscpy(++dot, ext);

	if (!PathFileExistsW(etlrdfile))
		return NULL;
	etw_sessioninfo_t *sinfo = new etw_sessioninfo_t();


	sinfo->isfile = 1;
	sinfo->etlfile = etlrdfile;
	if ((etw_start_trace(sinfo, FALSE,
	            etw_event_cb, etw_event_thread, 0)) == 0) {

		etw_end_session(sinfo, NULL);
		delete sinfo;
		return NULL;
	}
	sinfo->dtrace_ioctlf = sess->dtrace_ioctlf;
	sinfo->dtrace_probef = sess->dtrace_probef;
	dtrace_etw_sessions[id] = sinfo;

	return sinfo;
}

/*
 * Start etw trace from a etl file
 */
HANDLE
dtrace_etwfile_start(etw_sessions_t *dummy)
{
	HANDLE thr;
	etw_sessioninfo_t *session = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	if (session->isfile == 0)
		return (NULL);
	/* perfview trace file */
	etw_session_add_fileext(session, L"kernel.etl", DT_ETW_USER_SESSION);
	etw_session_add_fileext(session, L"clrRundown.etl", DT_ETW_KERNEL_SESSION);

	if ((thr = etw_start_trace(session, FALSE,
	                etw_event_cb, etw_event_thread, 0)) == 0) {

		etw_end_session(session, NULL);
		return (0);
	}

	return (thr);
}

/*
 * missed events and missed stack
 */
int
dtrace_etw_set_diagnostic(int (*cb) (PEVENT_RECORD, void *), uint32_t id)
{
	etw_diag_cb = cb;
	etw_diag_id = id;

	return 0;
}

/*
 * Enable user mode etl providers
 */
int
dtrace_etw_enable_ft(GUID *guid, int kw, int enablestack)
{
	etw_sessioninfo_t * sinfo, *ksinfo = dtrace_etw_sessions[DT_ETW_KERNEL_SESSION];

	if (!dtrace_etw_sessions[DT_ETW_FT_SESSION]) {
		sinfo = etw_new_session(DTRACE_SESSION_NAME_FT, &DtraceSessionGuidFT,
		        ETW_TS_QPC, EVENT_TRACE_REAL_TIME_MODE,
		        ksinfo->dtrace_probef, ksinfo->dtrace_ioctlf);
		if (sinfo == NULL) {
			return (0);
		}
		dtrace_etw_sessions[DT_ETW_FT_SESSION] = sinfo;
	}

	return etw_enable_user(dtrace_etw_sessions[DT_ETW_FT_SESSION]->hsession, guid, kw,
	        TRACE_LEVEL_VERBOSE, enablestack);
}

/*
 * Initialize ETW for real time events
 */
etw_sessions_t *
dtrace_etw_init(etw_dtrace_probe_t probef, etw_dtrace_ioctl_t ioctlf)
{
	ULONG flags = EVENT_TRACE_FLAG_PROCESS |
	    EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_THREAD |
	    EVENT_TRACE_FLAG_DISK_FILE_IO;
	ULONG iflags = 0;
	TRACEHANDLE handle = 0, hsession = 0;
	HANDLE thread = 0;
	int iskevent;
	const GUID *sguid;
	void (WINAPI *cb)(PEVENT_RECORD ev);
	wchar_t *sname;
	etw_sessioninfo_t *sinfo;

	etw_initialize();

	wmutex_init(&etw_eventcb_lock);
	wmutex_init(&etw_cur_lock);
	wmutex_init(&etw_proc_lock);
	wmutex_init(&etw_thread_lock);

	etw_devname_to_path(devmap);

	if (etw_win8_or_gt()) {
		iskevent = FALSE;
		sname = DTRACE_SESSION_NAME;
		sguid = &DtraceSessionGuid;
		cb = etw_event_cb;
		iflags = EVENT_TRACE_REAL_TIME_MODE|EVENT_TRACE_SYSTEM_LOGGER_MODE;
	} else {
		iskevent = FALSE;
		sname = KERNEL_LOGGER_NAME;
		sguid = &SystemTraceControlGuid;
		cb = etw_event_cb;
		iflags = EVENT_TRACE_REAL_TIME_MODE;
	}

	etw_hook_event(&ProcessGuid, process_func_first, NULL, 1, iskevent);
	etw_hook_event(&ProcessGuid, process_func_last, NULL, 2, iskevent);
	etw_hook_event(&ThreadGuid, thread_func_first, NULL, 1, iskevent);
	etw_hook_event(&ThreadGuid, thread_func_last, NULL, 2, iskevent);
	//etw_hook_event(&PerfInfoGuid, profile_func_first, NULL, 1, iskevent);
	etw_hook_event(&StackWalkGuid, stack_func, NULL, 0, iskevent);
	etw_hook_event(&ImageLoadGuid, image_load_func, NULL, 0, iskevent);
	etw_hook_event(&FileIoGuid, fileio_func, NULL, 0, iskevent);
	//etw_hook_event(&RTLostEvent, lost_event_func, NULL, 0, iskevent);
	etw_hook_event(&MSDotNETRuntimeRundownGuid, clr_jitted_rd_func, NULL, 1, 0);
	etw_hook_event(&MSDotNETRuntimeGuid, clr_jitted_func, NULL, 1, 0);
	etw_hook_event(&KernelEventTracing, ustack_func, NULL, 0, iskevent);
	if ((hsession =
	            etw_init_session(sname, *sguid, ETW_TS_QPC, iflags)) == 0) {
		etw_end_session(NULL, sname);
		return (NULL);
	}

	/*
	 * Get rundown of all the open files
	 * Slows down the startup
	 */
	LONG result = EnableTraceEx(&KernelRundownGuid_I, NULL, hsession, 1, 0, 0x10, 0, 0, NULL);

	if (result != ERROR_SUCCESS) {
		dprintf("dtrace_etw_init, failed to get rundown of open files (%x)\n", result);
	}

	if (etw_enable_kernel_prov(hsession, sname, flags, TRUE) != 0) {
		etw_end_session(NULL, sname);
		return (NULL);
	}

	sinfo = new etw_sessioninfo_t();

	sinfo->dtrace_probef = probef;
	sinfo->dtrace_ioctlf = ioctlf;
	sinfo->isfile = 0;
	sinfo->sessname = sname;
	sinfo->sessguid = (GUID *) sguid;
	sinfo->hsession = hsession;

	if ((thread = etw_start_trace(sinfo, TRUE, cb, etw_event_thread, 0)) == 0) {
		free(sinfo);
		etw_end_session(sinfo, NULL);
		return (NULL);
	}

	dtrace_etw_sessions[DT_ETW_KERNEL_SESSION] = sinfo;
	sinfo->data = etw_get_providers();

	sinfo = etw_new_session(DTRACE_SESSION_NAME_USER, &DtraceSessionGuidUser,
	        ETW_TS_QPC, EVENT_TRACE_REAL_TIME_MODE, probef, ioctlf);
	dtrace_etw_sessions[DT_ETW_USER_SESSION] = sinfo;
	sinfo = etw_new_session(DTRACE_SESSION_NAME_CLR, &DtraceSessionGuidCLR,
	        ETW_TS_QPC, EVENT_TRACE_REAL_TIME_MODE, probef, ioctlf);
	dtrace_etw_sessions[DT_ETW_CLR_SESSION] = sinfo;

	result = EnableTraceEx(&MSDotNETRuntimeRundownGuid, NULL,
	        sinfo->hsession, 1, 0, 0x50, 0, 0, NULL);
	if (result != ERROR_SUCCESS) {
		dprintf("dtrace_etw_init, failed to get rundown of \
			.net jitted methods (%x)\n", result);
	}
	result = EnableTraceEx(&MSDotNETRuntimeGuid, NULL,
	        sinfo->hsession, 1, 0, 0x10, 0, 0, NULL);
	if (result != ERROR_SUCCESS) {
		dprintf("dtrace_etw_init, failed to get event fot jit methods (%x)\n", result);
	}

	return dtrace_etw_sessions;
}

void
dtrace_etw_stop(etw_sessions_t *sinfo)
{
	ULONG status[DT_ETW_MAX_SESSION] = {0};

	for (int i=0; i<DT_ETW_MAX_SESSION; i++) {
		if (dtrace_etw_sessions[i]) {
			status[i] = CloseTrace(dtrace_etw_sessions[i]->psession);
			dtrace_etw_sessions[i]->psession = 0;
		}
	}

	for (int i=0; i<DT_ETW_MAX_SESSION; i++) {
		if (status[i] == ERROR_CTX_CLOSE_PENDING) {
			Sleep(100);
			break;
		}
	}
}

void
dtrace_etw_close(etw_sessions_t *sinfo)
{
	for (int i=0; i<DT_ETW_MAX_SESSION; i++) {
		if (dtrace_etw_sessions[i] && dtrace_etw_sessions[i]->sessname != NULL) {
			etw_end_session(dtrace_etw_sessions[i], NULL);
		}
	}
}
