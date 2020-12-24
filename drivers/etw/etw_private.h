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
 */

#ifndef _ETW_PRIVATE_H
#define	_ETW_PRIVATE_H
#include <iostream>
#include <vector>
#include <map>
#include <unordered_map>
#include <queue>
#include <string>
#include <iterator>
#include <utility>

using std::vector;
using std::unordered_map;
using std::map;
using std::queue;
using std::pair;
using std::wstring;

typedef pair<Function, void *> Pair;	/* cb function and 2nd argument (void *) to cb*/
typedef vector<Pair> Functions;			/* a event can have more than in cb */

#define DTRACE_SESSION_PATH "e:/temp/dtrace.etl"
#define DTRACE_SESSION_NAME L"Dtrace Event Trace Session"
#define DTRACE_SESSION_NAME_USER L"UserDtrace"
#define DTRACE_SESSION_NAME_CLR L"CLRDtrace"
#define DTRACE_SESSION_NAME_FT L"FTDtrace"
#define DTRACE_SESSION_NAME_HFREQ L"DtraceHREQ"

static const GUID DtraceSessionGuid =
{0xc298dd9e, 0x42f9, 0x4b55, {0x8a, 0x94, 0xb7, 0x9a, 0x3b, 0x21, 0xcc, 0x10}};
static const GUID DtraceSessionGuidUser =
{0x587f5d29, 0xeff3, 0x4659, {0x9b,0x1a,0xc1,0xb1,0x57,0x18,0x3d,0x42}};
static const GUID DtraceSessionGuidCLR =
{0xa68e0e30,0x4486,0x4a39, {0xaf,0x78,0x54,0x50,0x54,0x63,0xcc,0x69}};
static const GUID DtraceSessionGuidFT =
{0xada80ef6, 0x714f, 0x4c01, {0xb3, 0xf0, 0x0d, 0xed, 0x56, 0x87, 0x9d, 0x75}};
static const GUID DtraceSessionGuidHFREQ =
{0x754125ca, 0x1c11, 0x4089, {0x85, 0x18, 0xaf, 0x7a, 0x80, 0x86, 0x38, 0xab}};

#define NANOSEC		1000000000

/* Pthread
 * time between jan 1, 1601 and jan 1, 1970 in units of 100 nanoseconds
 */
#define PTW32_TIMESPEC_TO_FILETIME_OFFSET \
	  ( ((int64_t) 27111902 << 32) + (int64_t) 3577643008 )

#define ETW_TS_QPC 1
#define ETW_TS_SYSTEM 2
#define ETW_TS_CYCLE 3

#define ETW_MAX_STACKID 256
#define ETW_MAX_STACK 256
#define ETW_QUEUE_SIZE 100

#define wcstombs_d(dest, src, size) \
	WideCharToMultiByte(CP_UTF8, 0, (src), -1, (dest), (size), NULL, NULL )
	
#ifdef __cplusplus
extern "C" {
#endif

typedef struct etw_dprobe {
	dtrace_id_t id;
	uetwptr_t args[5];
	hrtime_t ts;
	proc_t *proc;
	thread_t *td;
	uint32_t pid;
	uint32_t tid;
	uint32_t cpuno;

} etw_dprobe_t;

typedef struct etw_stack {
	etw_dprobe_t dprobe;
	int stacklen;
	int stackready;
	uetwptr_t stack[ETW_MAX_STACK];
} etw_stack_t;

#pragma pack(1)
typedef struct CV_INFO_PDB70 {
	DWORD cvsig;
	GUID  sig;
	DWORD age;
	BYTE pdbname[1];
} cvpdbinfo_t;
#pragma pack()

typedef struct etw_dbg {
	HANDLE h;
	uint64_t endaddr;
	struct etw_dbgmod{
		etw_module_t *mod;
		struct etw_dbgmod *next;
	} mods;
} etw_dbg_t;

struct etw_module {
 	size_t size;
 	uetwptr_t base;
	uetwptr_t dbgbase;
	etw_dbg_t *sym;
	uint32_t chksum;
	uint32_t tmstamp;
	uint32_t tmbuild;
	cvpdbinfo_t *cvinfo;
	wchar_t  name[MAX_PATH_NAME];
};

typedef struct etw_proc_cvinfo {
	cvpdbinfo_t *cv;
	uetwptr_t base;
	size_t size;
	struct etw_proc_cvinfo *next;
} etw_proc_cvinfo_t;

typedef struct etw_sym_info {
	const char *object;			/* object name */
	const char *name;			/* symbol name */
	uetwptr_t addr;
} etw_sym_info_t;


struct etw_proc_module {
	uetwptr_t base;
	int symloaded;
	etw_module_t *mod;
	etw_proc_module_t *next;
};


#define DT_ETW_KERNEL_SESSION	0
#define DT_ETW_FT_SESSION 1
#define DT_ETW_USER_SESSION 2
#define DT_ETW_CLR_SESSION 3
#define DT_ETW_HFREQ_SESSION 4
#define DT_ETW_MAX_SESSION 5



typedef struct etw_sessioninfo {
	DWORD id; //thread id of the helper thread
	uint32_t ncpus;
	hrtime_t boottime;
	hrtime_t perffreq;
	hrtime_t starttime;
	ulong_t cpumhz;
	uint32_t ptrsz;
	uint32_t clctype;
	TRACEHANDLE hsession;
	TRACEHANDLE psession;
	ulong_t timerres;
	
	void (*evcb)(Functions&, PEVENT_RECORD);
	uint64_t timebase;		// converting etw trace raw timestamp to system time
	double timescale;
	etw_dtrace_probe_t dtrace_probef;
	etw_dtrace_ioctl_t dtrace_ioctlf;
	wchar_t *sessname;
	GUID *sessguid;
	wchar_t *etlfile;

	// Used to determine if the session is a private session or kernel session.
	// You need to know this when accessing some members of the EVENT_TRACE.Header
	// member (for example, KernelTime or UserTime).
	int isusermode;
	//https://docs.microsoft.com/en-us/windows/desktop/etw/wnode-header
	int israwtime;		
	int isfile;			// Trace data from a file 
	void *data;			// etw provider data
	struct {			// stalkwalk data. stack info for ncpus
		queue<etw_stack_t *> queue;
		map<hrtime_t, etw_stack_t *> *map;
		uint32_t lock;
	} Q;
	etw_stack_t *stackinfo;
	int stackidlen;
	CLASSIC_EVENT_ID stackid[ETW_MAX_STACKID];
	int hb;		//FT heartheat
	PEVENT_RECORD ev;
	uetwptr_t *ftstack;
	uint32_t ftsize;
	int islive;
} etw_sessioninfo_t;

typedef struct sessioninfo {
	hrtime_t timestamp;
	hrtime_t walltimestamp;
	int cpuno;
	pid_t pid;
	pid_t tid;
	proc_t *proc;
	thread_t *td;
	struct etw_sessioninfo *etw;
} sessioninfo_t;

typedef struct etw_jitsym_map {
	int sorted;
	map<uint64_t, wchar_t *> jit_modules;
	vector<etw_jit_symbol_t *> jit_syms;
} etw_jitsym_map_t;


#ifdef __cplusplus
}
#endif

#endif