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

#ifndef _ETW_H
#define	_ETW_H

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <evntrace.h>
#include <evntcons.h>
#include <sys/dtrace_misc.h>
#include <libelf.h>

#define ASSERT assert

#ifdef __cplusplus
extern "C" {
#endif

#define ARCH_WIN32	0
#define ARCH_AMD64	1

extern uint64_t kernellmts[2][2];

#define INKERNEL_ETW(va, arch) (((va)) >= (uint64_t) kernellmts[(arch)][0] && ((va)) < (uint64_t) kernellmts[(arch)][1])
//#define INKERNEL(va, low, high) (((va)) >= (uint64_t) low && ((va)) < (uint64_t) high)

#if defined(__amd64_etw__)
typedef uint64_t uetwptr_t;
#define INKERNEL(va) (((va)) >= (uetwptr_t) 0x7ffffffeffff && ((va)) < (uetwptr_t) ~(0))
#elif defined(__i386_etw__)
typedef uint32_t uetwptr_t;
#define INKERNEL(va) (((va)) >= (uetwptr_t) 0x7FFFFFFF && ((va)) < (uetwptr_t) 0xFFFFFFFF)
#endif

typedef LONG64 hrtime_t;

#define PERF_PMC_PROFILR_GM1	0x20000400

#define SDT_ETW_USER_EVENTS	-1
#define SDT_DIAG_ALL_EVENTS	-3
#define SDT_DIAG_IGNORED_EVENTS	-5
#define SDT_DIAG_ZUSTACK_EVENTS	-9
#define SDT_DIAG_ZSTACK_EVENTS	-17
#define SDT_DIAG_NSTACK_EVENTS	-33

// SystemTraceControlGuid = 9e814aad-3204-11d2-9a82-006008a86939
// EventTraceGuid = 68fdd900-4a3e-11d1-84f4-0000f80464e3
static const GUID TcpIpGuid =
{0x9a280ac0,0xc8e0,0x11d1,{0x84,0xe2,0x00,0xc0,0x4f,0xb9,0x98,0xa2}};
static const GUID PerfInfoGuid =
{0xce1dbfb4,0x137e,0x4da6,{0x87,0xb0,0x3f,0x59,0xaa,0x10,0x2c,0xbc}};
static const GUID StackWalkGuid =
{0xdef2fe46,0x7bd6,0x4b80,{0xbd,0x94,0xf5,0x7f,0xe2,0x0d,0x0c,0xe3}};
static const GUID ProcessGuid =
{0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
static const GUID ThreadGuid =
{0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
static const GUID RegistryGuid =
{0xae53722e, 0xc863, 0x11d2, {0x86, 0x59, 0x00, 0xc0, 0x4f, 0xa3, 0x21, 0xa1}};
static const GUID ImageLoadGuid =
{0x2cb15d1d, 0x5fc1, 0x11d2, {0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18}};
static const GUID FileIoGuid =
{0x90cbdc39, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3}};
static const GUID DiskIoGuid =
{0x3d6fa8d4, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
static const GUID UdpIpGuid =
{0xbf3a50c5, 0xa9c9, 0x4988, {0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80}};
static const GUID PageFaultGuid =
{0x3d6fa8d3, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
static GUID KernelRundownGuid_I =
{0x3b9c9951, 0x3480, 0x4220, { 0x93, 0x77, 0x9c, 0x8e, 0x51, 0x84, 0xf5, 0xcd}};
//always enabled for NT kernel loggers
static const GUID HWSystemConfigGuid =
{0x01853a65,0x418f,0x4f36,{0xae,0xfc,0xdc,0x0f,0x1d,0x2f,0xd2,0x35}};
static GUID UMDEtwProviderId = 
{0xa688ee40, 0xd8d9, 0x4736, { 0xb6, 0xf9, 0x6b, 0x74, 0x93, 0x5b, 0xa3, 0xb1}};

//This struct is always the first event trace struct sent to a consumer
// (this event is not sent to real-time consumers)
//contains information about the event tracing session
static const GUID EventTraceEventGuid =
{0x68fdd900,0x4a3e,0x11d1,{0x84,0xf4,0x00,0x00,0xf8,0x04,0x64,0xe3}};

static GUID KernelTraceControlGuid =
{0xb3e675d7, 0x2554, 0x4f18, {0x83, 0x0b, 0x27, 0x62, 0x73, 0x25, 0x60, 0xde}};

//Microsoft-Windows-Kernel-EventTracing
// event 18 = Stack correlation event. This event contains a call stack which is
//	associated with a prior event which is correlated
//  by the MatchId
static const GUID KernelEventTracing =
{0xb675ec37,0xbdb6,0x4648,{0xbc,0x92,0xf3,0xfd,0xc7,0x4d,0x3c,0xa2}};

// RT lost events
static const GUID RTLostEvent =
{0x6a399ae0, 0x4bc6,0x4de9, {0x87,0x0b,0x36,0x57,0xf8,0x94,0x7e,0x7e}};

static const GUID FastTrapGuid =
{0xd8909c24, 0x5be9, 0x4502, {0x98, 0xca, 0xab, 0x7b, 0xdc, 0x24, 0x89, 0x9d}};
static const GUID MSDotNETRuntimeRundownGuid =
{0xA669021C,0xC450,0x4609, {0xA0,0x35,0x5A,0xF5,0x9A,0xF4,0xDF,0x18}}; //Microsoft-Windows-DotNETRuntimeRundown

static const GUID MSDotNETRuntimeGuid =
{0xE13C0D23, 0xCCBC, 0x4E12, {0x93, 0x1B, 0xD9, 0xCC, 0x2E, 0xEE, 0x27, 0xE4}};

static const GUID WGDiagEventsGuid = 
	{0xe10ad5ec, 0xef54, 0x4c79, {0x8b, 0x02, 0xb8, 0x5b, 0x8d, 0xbb, 0x9f, 0x3f}};

/* provider keyword info */
typedef struct etw_provkw {
	char *kwn;			/* keyword name */
	uint64_t kwv;		/* value */
} etw_provkw_t;

/* etw provider info */
typedef struct etw_provinfo {
	char *provn;		/* provider name */
	GUID provg;			/* GUID */
	int src;			/* provider type */
	int provnkw;		/* number of keywords */
	struct etw_provkw *provkw; 	/* keyword info */
} etw_provinfo_t;

typedef struct etw_pmc {
	char name[DTRACE_FUNCNAMELEN];
	ulong_t srcid;
	ulong_t interval, minint, maxint;
} etw_pmc_t;

typedef struct etw_module etw_module_t;	/* module info */
typedef struct etw_proc_module etw_proc_module_t;	/* process module info */

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
	struct etw_dbgmod {
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

struct etw_proc_module {
	uetwptr_t base;
	int symloaded;
	etw_module_t *mod;
	etw_proc_module_t *next;
};
struct ImageLoad {
	int base, size, pid, chksum, tmstamp, dbase, wname;
};

extern struct ImageLoad etw_imgload[][4];

typedef int (*Function)(PEVENT_RECORD ev, void *data);
typedef void
(*etw_dtrace_probe_t)(dtrace_id_t id, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4);
typedef int (*etw_dtrace_ioctl_t)(HANDLE, int, void*);
typedef struct etw_sessioninfo* etw_sessions_t;

proc_t *dtrace_etw_proc_find(pid_t pid, int create);
thread_t *dtrace_etw_td_find(pid_t pid, pid_t tid, int current);
etw_sessions_t * dtrace_etw_init(etw_dtrace_probe_t,
    etw_dtrace_ioctl_t ioctlf, wchar_t *oetwfile, uint32_t flags);
etw_sessions_t *dtrace_etwfile_init(etw_dtrace_probe_t probef,
    etw_dtrace_ioctl_t ioctlf, wchar_t *etlfile, uint32_t flags);
HANDLE dtrace_etwfile_start(etw_sessions_t *session);
int dtrace_etw_profile_disable();
int dtrace_etw_profile_enable(hrtime_t interval, int type);
int dtrace_etw_samplerate(int interval);
int dtrace_etw_hook_event(const GUID *guid, Function efunc, void *data, int place);
int dtrace_etw_unhook_event(const GUID *guid, Function efunc, void *data);
int dtrace_etw_set_stackid(CLASSIC_EVENT_ID id[], int len);
int dtrace_etw_prov_disable(int flags);
int dtrace_etw_prov_enable(int flags);
int dtrace_etw_enable_ft(GUID *guid, int kw, int enablestack);
etw_proc_module_t *dtrace_etw_pid_modules(pid_t pid);
int dtrace_etw_nprocessors();
int dtrace_etw_session_on(etw_sessions_t *sinfo);
etw_proc_module_t *dtrace_etw_pid_symhandle(pid_t pid);
void dtrace_etw_stop(etw_sessions_t *sinfo);
void dtrace_etw_close(etw_sessions_t *sinfo); //XXXX
int dtrace_etw_kernel_stack_enable(CLASSIC_EVENT_ID id[], int len);
char *dtrace_etw_objname(etw_proc_module_t *pmod, pid_t pid, uint64_t addr, 
	char *buffer, size_t bufsize);
int dtrace_etw_lookup_addr(etw_proc_module_t *pmod, pid_t pid, uetwptr_t addr, 
	char *buf, size_t size, GElf_Sym *symp);
char *dtrace_etw_lookup_jit_module(pid_t pid, uetwptr_t addr, char *buf,
     size_t size);
thread_t * dtrace_etw_curthread();
proc_t * dtrace_etw_curproc();
int dtrace_etw_current_cpu();
int dtrace_etw_get_stack(uint64_t *pcstack, int pcstack_limit, int usermode);
hrtime_t dtrace_etw_gethrtime();
hrtime_t dtrace_etw_gethrestime(void);
HANDLE *dtrace_etw_set_cur(pid_t pid, pid_t tid, hrtime_t tm, int cpuno);
void dtrace_etw_reset_cur(HANDLE *lock);
void dtrace_etw_probe(dtrace_id_t id, uetwptr_t arg0, uetwptr_t arg1,
    uetwptr_t arg2, uetwptr_t arg3, uetwptr_t arg4);
void dtrace_etw_probe_sdt(dtrace_id_t id, uetwptr_t arg0, uetwptr_t arg1,
    uetwptr_t arg2, uetwptr_t arg3, uetwptr_t arg4, uetwptr_t stackid, uetwptr_t pl, uetwptr_t epl);
void *dtrace_etw_user_providers();
int dtrace_etw_uprov_enable(GUID *pguid, uint64_t keyword,
    uint32_t eventno, int level, int estack, int capture);
int dtrace_etw_session_ft_on(etw_sessions_t *sinfo);
int dtrace_etw_set_diagnostic(int (*cb) (PEVENT_RECORD, void *), uint32_t flags);
int dtrace_set_ft_stack(uetwptr_t *stack, uint32_t size);
wchar_t *dtrace_etw_get_fname(uetwptr_t fobj);
void *dtrace_sdtmem_alloc(int sz);
int dtrace_sdtmem_free(intptr_t sz);
etw_pmc_t *dtrace_etw_pmc_info(ulong_t *count, ulong_t *maxpmc);
void dtrace_etw_pmc_samples(ulong_t *ids, TRACE_PROFILE_INTERVAL *tpintrval, int length);
void dtrace_etw_pmc_counters(int h, ulong_t *ids, CLASSIC_EVENT_ID *events, int length);
void dtrace_etw_prov_enable_gm(int sid, ulong_t mask, int level);
int dtrace_stack_func(PEVENT_RECORD ev, void *data);
int dtrace_etwloadinfo(int arch, int ver, char *p, int len, etw_module_t *mod, int32_t *pid, uint64_t *pbase);
int dtrace_dnet_stack_func(PEVENT_RECORD ev, void *data);

#define ETW_SET_CURRENT 1
#define ETW_PROC_FIND 0
#define ETW_PROC_CREATE 1
#define ETW_PROC_CREATE_LIVE 2
#define ETW_PROC_TEMP 3
#define ETW_THREAD_FIND 0
#define ETW_THREAD_CREATE 1
#define ETW_THREAD_TEMP 3

#define PSYS_FUNC 0
#define PSYS_SYM_HANDLE 1
#define PSYS_FPID_QUEUE_CLEAR 2
#define PSYS_FPID_TID 3
#define PSYS_RELEASE_PROC 4
#define PSYS_PROC_DEAD 5

enum {
	ETW_EVENTCB_ORDER_FRIST,
	ETW_EVENTCB_ORDER_ANY,
	ETW_EVENTCB_ORDER_LAST,
	SDT_ARG0 = 0,
	SDT_ARG1,
	SDT_ARG2,
	SDT_ARG3,
	SDT_ARG4,
	SDT_ARG5,
	SDT_ARG6,
	SDT_ARG7,
	SDT_ARG8,
	SDT_ARGPL,
	SDT_ARGEXTPL,
	SDT_ARGSTACK,
	SDT_CUR_LOCK,
	SDT_ARGMAX,

};

enum {
	NETExceptionKeyword = 0x00008000,
	NETContentionKeyword = 0x00004000,
	NETThreadingKeyword = 0x00010000,
	NETJITKeyword = 0x00000010,
	NETNGenKeyword = 0x00000020,
	NETJITTracingKeyword = 0x00001000,
	NETInteropKeyword = 0x00002000,
	NETAppDomainResourceManagementKeyword = 0x00000800,
	NETSecurityKeyword = 0x00000400,
	NETLoaderKeyword = 0x00000008,
	NETGCKeyword = 0x00000001,
	NETPerfTrackKeyWord = 0x2000000,
	NETStackKeyword = 0x40000000,
	NETOverrideAndSuppressNGenEventsKeyword = 0x00040000,
};

#define	ARCHETW(ev)	EVENT_HEADER_FLAG_32_BIT_HEADER == \
	((ev)->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 0 : 1
#define PTR(arch, p, off)	(arch) ? *(uint64_t *) ((p)+(off)) : *(uint32_t *) ((p)+(off))
#define V32(p, off)	*(uint32_t *) ((p) + (off))
#define V64(p, off)	*(uint64_t *) ((p) + (off))
#define WSTR(p, off)	(wchar_t *) ((p)+(off))
#define V16(p, off)	*(uint16_t *) ((p) + (off))
#define V8(p, off)	*(uint8_t *) ((p) + (off))

#ifdef __cplusplus
}
#endif

#endif

/*
ClientContext  = 1	w/o PROCESS_TRACE_MODE_RAW_TIMESTAMP
	Timestamp = 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)

ClientContext  = 1 with PROCESS_TRACE_MODE_RAW_TIMESTAMP
	Timestap = high resolution number
	StartTime + ((TimeStamp (of StartTime) - TimeStamp (Present) ) *10000000.0 / PerfFreq) ==
		64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)
	ReservedFlags = 1;
ClientContext  = 2 with PROCESS_TRACE_MODE_RAW_TIMESTAMP
	Timestamp = 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)
	StartTime == Timestamp

ClientContext  = 2 w/o PROCESS_TRACE_MODE_RAW_TIMESTAMP
	Timestamp = 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)
	StartTime == Timestamp

ClientContext  = 3 with PROCESS_TRACE_MODE_RAW_TIMESTAMP
	Timestap = high resolution number
	StartTime + ((TimeStamp (of StartTime) - TimeStamp (Present) ) /CPUSpeed) == ???
		64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)
	ReservedFlags = 1;

*/