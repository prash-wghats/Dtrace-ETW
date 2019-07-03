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

#ifndef	_DTRACE_MISC_H
#define	_DTRACE_MISC_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winnt.h>
#include <in6addr.h>


#ifdef	__cplusplus
extern "C" {
#endif

#define _BIG_INDIAN 	2
#define _LITTLE_ENDIAN 	1
#define BYTE_ORDER	_LITTLE_ENDIAN

#define MAX_SYMBOL_NAME 255
/*
 * POSIX Extensions
 */
typedef UINT32 	uint32_t;
typedef INT32	int32_t;
typedef ULONG64 uint64_t;
typedef uint32_t __uint32_t;
typedef LONG64	int64_t;
typedef int64_t	__int64_t;
typedef UINT16 	uint16_t;
typedef uint16_t __uint16_t;
typedef INT16	int16_t;
typedef UINT8	uint8_t;
typedef UINT8 	u_int8_t;
typedef INT8	int8_t;
typedef	unsigned char	uchar_t;
typedef	unsigned char	u_char;
typedef	unsigned short	ushort_t;
typedef	unsigned int	uint_t;
typedef	unsigned long	ulong_t;
typedef	char		*caddr_t;
typedef	unsigned int	processorid_t;
typedef int cred_t;

#ifndef _AMD64_
typedef int	pid_t;
typedef int ssize_t;
#else
/* pid_t should be uint32_t. process id in windows is DWORD type.
 * But pid_t in mingw 64 is int64_t type.While testing for equality of
 * pid type, cast it to DWORD type.
 */
typedef long pid_t;
typedef int64_t ssize_t;
#endif
typedef pid_t	uid_t;
typedef pid_t	zoneid_t;
typedef pid_t 	id_t;
typedef ulong_t	Lmid_t;
typedef ULONG64 u_longlong_t;
typedef LONG64	hrtime_t;
typedef long long off64_t;
typedef unsigned long ipaddr_t;
typedef unsigned short port_t;


#define B_TRUE 1
#define B_FALSE 0

#define NBBY 8
#define _SC_CPUID_MAX -1
#define _SC_NPROCESSORS_MAX -2
typedef	unsigned short	u_short;
typedef	unsigned int	u_int;
//typedef	unsigned int	u_long;
typedef LONG64	longlong_t;

#define SEC			1
#define MILLISEC	1000
#define MICROSEC	1000000
#define NANOSEC		1000000000
//#define EOVERFLOW	84
//#define EALREADY	37
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#define bcopy(s, d, len) (memcpy((d), (s), (len)))
typedef int 	boolean_t;

#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))  /* to any y */
#ifndef MAX
#define	MAX(a, b) 		((a) < (b) ? (b) : (a))
#endif

#ifndef MIN
#define	MIN(a, b) 		((a) > (b) ? (b) : (a))
#endif

#define P2ROUNDUP(x, align)             (-(-(x) & -(align)))

#include <sys/dtrace.h>

/* fasttrap_win32.h */

#define kthread_t thread_t
#define MAXCPU NCPU
#define CPU_FOREACH(i)	for (i = 0; i < NCPU; i++)
#define membar_producer		MemoryBarrier
#define atomic_add_32		InterlockedExchangeAdd
#define atomic_add_64		InterlockedExchangeAdd

/* end fasttrap_win32.h */

/* misc.h */

#define MAX_PATH_NAME 256
#define MAX_THREAD_NAME 64

typedef struct modctl {
	int nenabled;		/* number of enabled probes. */
	int fbt_nentries;	/* number of fbt entries created. */
	int loadcnt;
	char *mod_modname;
	uintptr_t imgbase;
	size_t size;
	struct modctl *mod_next;
} modctl_t;

// context switch, scheduler
typedef struct contextsw {
	char ot_pri;
	char ot_state;
	char ot_waitreason;
	char ot_waitmode;
	char ot_waitidealcpu;
	char nt_pri;
	char cpuno;
	uint32_t nt_waittime;
} contextsw_t;

typedef struct sched {
	char t_reason;
	char t_incpri;
	char t_flags;
} sched_t;

//file i/o operations
typedef struct buf {
	uint32_t b_flags;	/* read 1, write 2, flush 4 */
	uint32_t b_diskno;
	uint32_t b_irpflags;
	caddr_t b_irpaddr;			/* buffer address */
	size_t b_bcount;		/* number of bytes */
	uint64_t b_offset;
	uint64_t b_lblkno;		/* block # on device */
	uint64_t b_blkno;		/* expanded block # on device */
	int b_error;			/* expanded error field */
	uint64_t b_resptm;  	/* The time between I/O initiation and completion as measured
							   by the partition manager (in the KeQueryPerformanceCounter tick units).*/
	wchar_t *b_fname;

} buf_t;

typedef struct wfileinfo {
	uint64_t f_offset;	 	/* Starting file offset for the requested operation. */
	uintptr_t f_irpptr;	 	/* request packet. This property identifies the IO activity. */
	uint32_t f_tid;
	uintptr_t f_fileobj;	 	/* Identifier that can be used for correlating operations to the same opened file object instance between file create and close events */
	/* uintptr_t FileKey; hash to filename */
	uint32_t f_iosize;	 	/* Number of bytes requested. */
	uint32_t f_ioflags;	 	/* IO request packet flags specified for this operation */
	uint32_t f_createopt;	 	/* CreateOptions flags */
	uint32_t f_fileattrib;	 	/* File Attributes flags */
	uint32_t f_shareflags;	 	/* File Share Access Flags */
	uint64_t f_extinfo;	 	/* Extra information returned by the file system for the operation. */
	uint32_t f_ntstatus;	 	/* Return value from the operation */
	uint64_t f_infoclass;	 	/* Requested file information class */
	wchar_t *f_name;	 	/* File index from which to continue directory enumeration. */
	uint32_t f_dlen;	 	/* Size of the query buffer, in bytes. */
	uint32_t f_dfileindex;
	wchar_t *f_dpattspec;	 	/* Pattern specified for directory enumeration. */
} wfileinfo_t;

typedef struct dirinfo {
	uintptr_t d_irpptr;
	uint32_t d_tid;	// Thread identifier of the thread that is performing the operation.
	uintptr_t d_fileobj;	// File index from which to continue directory enumeration.
	//uintptr_t FileKey; //To determine the directory name, match the value of this property to the FileObject property of a FileIo_Name event.
	uint32_t d_len;	//Size of the query buffer, in bytes.
	uintptr_t d_infoclass;	//Requested directory enumeration information class.
	uint32_t d_fileindex;	// File index from which to continue directory enumeration.
	wchar_t *d_pattspec;	//Pattern specified for directory enumeration.
	wchar_t *d_name;
} dirinfo_t;
//tcpip packet
#define AF_INET 2
#define AF_INET6 23
typedef struct tcpip_msg
{
	int ti_ver;
	uint32_t ti_pid;
	uint32_t ti_size;					/* Size of the packet. */
	uint16_t ti_dport;					/* Destination port number. */
	uint16_t ti_sport;					/* Source port number. */
	uint32_t ti_seqnum;				/* Sequence number. */
	uint32_t ti_connid;				/* A unique connection identifier to correlate events belonging to the same connection.*/

	uint32_t ti_starttime;				/* Start send request time. */
	uint32_t ti_endtime;				/* End send request time. */
	union {
		struct {
			struct in6_addr daddr;	/* Destination IP address. */
			struct in6_addr saddr;	/* Source IP address. */
		} ip6;
		struct {
			ipaddr_t daddr;
			ipaddr_t saddr;
		} ip4;
	} ti_addr;
	uint16_t ti_mss;			/* Maximum segment size. */
	uint16_t ti_sackopt;		/* Selective Acknowledgment (SACK) option in TCP header. */
	uint16_t ti_tsopt;			/* Time Stamp option in TCP header. */
	uint16_t ti_wsopt;			/* Window Scale option in TCP header. */
	uint32_t ti_rcvwin;		/* TCP Receive Window size. */
	int16_t ti_rcvwinscale;	/* TCP Receive Window Scaling factor. */
	int16_t ti_sndwinscale;	/* TCP Send Window Scaling factor. */

} tcpip_msg_t;

typedef struct tcpip_fail {
	uint16_t ti_proto;			/* Identifies the protocol v4 or v6 */
	uint16_t ti_code;			/* Reason for the failure */
} tcpip_fail_t, udpip_fail_t;

typedef struct udpip_msg
{
	int ui_ver;
	uint32_t ui_size;
	uint32_t ui_dport;
	uint32_t ui_sport;
	uint32_t ui_seqnum;
	uint32_t ui_connid;
	uint32_t ui_pid;
	union {
		struct {
			struct in6_addr daddr;
			struct in6_addr saddr;
		} ip6;
		struct {
			ipaddr_t daddr;
			ipaddr_t saddr;
		} ip4;
	} ui_addr;
} udpip_msg_t;

typedef struct reginfo {
	int64_t r_time;		/* Initial time of the registry operation. */
	uint32_t r_status;	/* NTSTATUS value of the registry operation. */
	uint32_t r_index;		/* The subkey index for the registry operation (such as EnumerateKey). */
	uintptr_t r_handle;	/* Handle to the registry key. */
	wchar_t *r_name;		/* Name of the registry key. */
} reginfo_t;

typedef struct vminfo {
	uint32_t time;			/*	Inital time */
	uint64_t rdoffset;		/* File offset from which data was read to satisfy fault. */
	uint32_t nbyte;			/* Amount of data read from ReadOffset to satisfy the fault. */
	uintptr_t va;		/* Virtual address of the page that caused the page fault. */
	uintptr_t pc;			/* Pointer to the current instruction being executed. */
	uintptr_t fname;		/* name of the file causing */
	uint32_t tid;
	uint32_t devchar;
	uint16_t filechar;
	uintptr_t baseaddr;		/* The starting address at which memory was allocated or freed. */
	SIZE_T regsz;			/* The size, in bytes, of the memory that was allocated or freed. */
	uint32_t pid;
	uint32_t flags;			/* The type of memory allocation that was performed flAllocationType) */
} vminfo_t;

struct reg;
struct scr_page;

typedef struct proc {
	pid_t pid;
	pid_t ppid;				/* pid of parent */
	char *name;
	int		model;
	wchar_t *cmdline;

	int flags;			/* ETW flags */
	int sessid;			/* session id */
	int exitval;			/* exit status */
	uintptr_t addr;		/* address of the process object in the kernel */
	uintptr_t pageaddr;	/* physical address of the page table of the process */

	HANDLE handle;
	HANDLE symhandle;
	int		p_dtrace_probes;	/* Are there probes for this proc? */
	uint64_t	p_dtrace_count;		/* Number of DTrace tracepoints */
	void		*p_dtrace_helpers;	/* DTrace helpers, if any */
	void *mod;						/* loaded modules */
	void *cvinfo;						/* loaded modules debug info*/
	void *pipe;
	PVOID scr_var;
	struct scr_page *scr_mem;
	LONG scr_queued;
	//int exiting;
	KSPIN_LOCK scr_lock;
	int dead;
	int agent_loaded;
	int mini, mque, mdque, withstacks;
} proc_t;

typedef struct thread {
	pid_t pid;
	pid_t tid;
	pid_t ppid;
	proc_t *proc;

	uintptr_t kbase;	/* Kernel stack base */
	uintptr_t klimit; /* Kernel stack limit */
	uintptr_t ubase;  /* Thread user stack base */
	uintptr_t ulimit;		/* Thread user stack limit */

	char pri; 			/* thread priority */
	char waitr; 		/* thread wait reason */
	char waitm;			/* wait mode */
	char state; 		/* thread state */
	char wipr; 			/* wait ideal processor */
	uint32_t waittm; 	/* wait time */
	char cpu; 			/* current cpu */
	uint32_t rdflags;
	int flags;
	uint32_t affinity;	/* The set of processors on which the thread is allowed to run */
	char iopri;			/* io priority */
	char pagepri;		/* page priority */

	uint64_t t_hrtime;	/* Last time on cpu. */
	int t_errno;	/* Syscall return value. */
	char t_name[MAX_THREAD_NAME];	/* Thread Name */
	HANDLE handle;

	struct {
		uintptr_t upc;
		uintptr_t pc;
	} profile;
	uintptr_t ebp; 	/* Kernel BP when probe activated */
	struct reg *tf;	/* trap frame when probe activated */
	void *td_dtrace_sscr; /* Saved scratch space location. */
	uint8_t t_dtrace_stop;	/* Indicates a DTrace-desired stop */
	uint8_t t_dtrace_sig;	/* Signal sent via DTrace's raise() */
	uint32_t t_predcache;	/* DTrace predicate cache */
	uint64_t t_dtrace_vtime; /* DTrace virtual time */
	uint64_t t_dtrace_start; /* DTrace slice start time */
	union __tdu {
		struct __tds {
			uint8_t	_td_dtrace_on;
			/* Hit a fasttrap tracepoint. */
			uint8_t	_td_dtrace_step;
			/* About to return to kernel. */
			uint8_t	_td_dtrace_ret;
			/* Handling a return probe. */
			uint8_t	_td_dtrace_ast;
			/* Saved ast flag. */
#ifdef _AMD64_
			uint8_t	_td_dtrace_reg;
#endif
		} _tds;
		ulong_t	_td_dtrace_ft;	/* Bitwise or of these flags. */
	} _tdu;
#define	t_dtrace_ft	_tdu._td_dtrace_ft
#define	t_dtrace_on	_tdu._tds._td_dtrace_on
#define	t_dtrace_step	_tdu._tds._td_dtrace_step
#define	t_dtrace_ret	_tdu._tds._td_dtrace_ret
#define	t_dtrace_ast	_tdu._tds._td_dtrace_ast
#define	t_dtrace_reg	_tdu._tds._td_dtrace_reg

	uintptr_t	t_dtrace_pc;	/* DTrace saved pc from fasttrap. */
	uintptr_t	t_dtrace_npc;	/* DTrace next pc from fasttrap. */
	uintptr_t	t_dtrace_scrpc;
	/* DTrace per-thread scratch location. */
	uintptr_t	t_dtrace_astpc;
	/* DTrace return sequence location. */
#ifdef _AMD64_
	uintptr_t	t_dtrace_regv;
#endif
	void *context;

} thread_t;


void free_thread_list();
void free_proc_list();
void free_proc_exiting();

extern proc_t *pfind(pid_t id);
extern int del_proc_node(pid_t pid);
extern int del_thread_node(int tid);
extern proc_t *_curproc();
extern thread_t *_curthread();
extern proc_t *fasttrap_pfind(pid_t id);
extern void *int_malloc(unsigned nbytes);
extern void int_morecore();
extern void int_freecore();
extern void int_free(void *ap);

#define curthread	(_curthread())
#define curproc		(_curproc())

struct frame {
	struct frame *f_frame;
	uintptr_t f_retaddr;
};

#if 0
#ifdef _AMD64_
#define INKERNEL(va) (((va)) >= (uintptr_t) 0x7ffffffeffff && ((va)) < (uintptr_t) ~(0))
#else
#define INKERNEL(va) (((va)) >= (uintptr_t) 0x7FFFFFFF && ((va)) < (uintptr_t) 0xFFFFFFFF)
#endif

#endif

#ifndef _AMD64_
struct trap_frame {
	int	edi;
	int	esi;
	int	ebp;
	int	esp;
	int	ebx;
	int	edx;
	int	ecx;
	int	eax;
	int 	eip; /* rip where the interrupt occured */
	int	cs;
	int	eflags;
	int 	usp;		/* esp if trap from user mode,
					   return address if trap in kernel at entry,
  					   ebp if trap in kernel mode at return (of the callee?) */
	int	arg0;			/* arguments to the function at entry */
};
#else
struct trap_frame {
	uintptr_t rcx;
	uintptr_t rdx;
	uintptr_t r8;
	uintptr_t r9;
	uintptr_t r10;
	uintptr_t r11;
	uintptr_t r12;
	uintptr_t r13;
	uintptr_t r14;
	uintptr_t r15;
	uint16_t es;
	uint16_t ds;
	uint16_t gs;
	uint16_t fs;
	uintptr_t rbx;
	uintptr_t rax;
	uintptr_t rsi;
	uintptr_t rdi;
	uintptr_t rbp;
	uintptr_t trap_no;
	/*below defined in hw */
	uintptr_t rip;
	uintptr_t cs;
	uintptr_t rflags;
	uintptr_t rsp;
	uintptr_t arg0;
};
#endif

#ifdef _AMD64_
#define DATAMODEL_NATIVE 1
#else
#define DATAMODEL_NATIVE 0
#endif

#define DATAMODEL_LP64 1
#define DATAMODEL_LP32 0

#ifdef _AMD64_
struct reg {
	__int64_t	r_r15;
	__int64_t	r_r14;
	__int64_t	r_r13;
	__int64_t	r_r12;
	__int64_t	r_r11;
	__int64_t	r_r10;
	__int64_t	r_r9;
	__int64_t	r_r8;
	__int64_t	r_rdi;
	__int64_t	r_rsi;
	__int64_t	r_rax;
	__int64_t	r_rbx;
	__int64_t	r_rdx;
	__int64_t	r_rcx;
	__uint32_t	r_trapno;
	__uint16_t	r_fs;
	__uint16_t	r_gs;
	__uint32_t	r_err;
	__uint16_t	r_es;
	__uint16_t	r_ds;

	__int64_t	r_rbp;
	__int64_t	r_rip;
	__int64_t	r_cs;
	__int64_t	r_rflags;
	__int64_t	r_rsp;
	__int64_t	r_ss;
};

#else
struct reg {
	__uint32_t	r_gs;
	__uint32_t	r_fs;
	__uint32_t	r_es;
	__uint32_t	r_ds;
	__uint32_t	r_edi;
	__uint32_t	r_esi;
	__uint32_t	r_ebp;
	__uint32_t	r_isp;
	__uint32_t	r_ebx;
	__uint32_t	r_edx;
	__uint32_t	r_ecx;
	__uint32_t	r_eax;
	__uint32_t	r_trapno;
	__uint32_t	r_err;
	__uint32_t	r_eip;
	__uint32_t	r_cs;
	__uint32_t	r_eflags;
	__uint32_t	r_esp;
	__uint32_t	r_ss;
};
#endif

#ifdef _AMD64_

typedef UCHAR UBYTE;

typedef struct rtf {
	ULONG baddr;
	ULONG eaddr;
	ULONG unwnd_addr;
} rtf_t;

typedef struct unwind_code {
	UBYTE pro_off;
	UBYTE op_code:4;
	UBYTE op_info:4;
} unwind_code_t;

typedef struct unwind_info {
	UBYTE ver:3;
	UBYTE flags:5;
	UBYTE pro_size;
	UBYTE cnt;
	UBYTE fp:4;
	UBYTE fpoff:4;
	unwind_code_t code[1];
	//unwind_code_t code[1];
	/*	 Exception Handler
			or
		Chained Unwind Info */
} unwind_info_t;



enum unwind_opcodes{
	UWOP_PUSH_NONVOL = 0,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR,
	/* gdb source */
	UWOP_SAVE_XMM = 6, 	// v1
	UWOP_EPILOG = 6,	// v2
	UWOP_SAVE_XMM_FAR = 7,	// v1
	UWOP_SPARE = 7,		// v2
	/* .... */
	UWOP_SAVE_XMM128 = 8,
	UWOP_SAVE_XMM128_FAR,
	UWOP_PUSH_MACHFRAME
};
//#define UNW_FLAG_NHANDLER 0
//#define UNW_FLAG_EHANDLER 1
//#define UNW_FLAG_UHANDLER 2
//#define UNW_FLAG_CHAININFO 4

#define PtrFromRva( base, rva ) ( ( ( PUCHAR ) base ) + rva )

#endif



#define THREAD_TYPE	1
#define PROC_TYPE	2
#define ALL_TYPE	4

#define FTT_PAGE_SIZE 1024
#define FTT_SCRATCH_SIZE 64

struct scr_page {
	uintptr_t addr;
	int free_list[FTT_PAGE_SIZE / FTT_SCRATCH_SIZE];
	int free_co;
	SIZE_T size;
	struct scr_page *next;
};
PVOID scr_alloc_mem(proc_t *p);

int
uread(proc_t *p, void *kaddr, size_t len, uintptr_t uaddr);
int
uwrite(proc_t *p, void *kaddr, size_t len, uintptr_t uaddr);


#ifdef _AMD64_

rtf_t *winos_kernel_func_rtf(modctl_t *ctl, uintptr_t pc);
void winos_free_user_modules();
int winos_user_module_mdl(pid_t pid, dtrace_user_module_t *mod);
int winos_unwind_user_stack(thread_t *td, CONTEXT *ct, int frame, uintptr_t out);
void winos_reg_to_context(CONTEXT *ct, struct reg *rp);
int IsProc32Bit(HANDLE pid);
int IsDebuggerAttached(void);
#else
void DtraceWinOSFbtStack(thread_t *td, uintptr_t *stack);
#endif


#define DDI_PROP_SUCCESS 1
#define DDI_PROP_FAILURE 0

/*#define wcstombs_d(dest, src, size) \
	__try {	\
		WideCharToMultiByte(CP_UTF8, 0, (src), -1, (dest), (size), NULL, NULL ) \
	} __except(EXCEPTION_EXECUTE_HANDLER) { \
		*flags |= CPU_DTRACE_FAULT; \
	} */
int dtrace_wcstombs(char * dest, wchar_t *src, int size);
size_t dtrace_wstrlen(const wchar_t *s, size_t lim);

#define	DIGIT(x)	\
	(isdigit(x) ? (x) - '0' : islower(x) ? (x) + 10 - 'a' : (x) + 10 - 'A')


/*
 * The following macro is a version of isalnum() that limits alphabetic
 * characters to the ranges a-z and A-Z; locale dependent characters will not
 * return 1.  The members of a-z and A-Z are assumed to be in ascending order
 * and contiguous.
 */
#define	lisalnum(x)	\
	(isdigit(x) || ((x) >= 'a' && (x) <= 'z') || ((x) >= 'A' && (x) <= 'Z'))
	
/* end misc.h */

#ifdef	__cplusplus
}
#endif

#endif /* _DTRACE_MISC_H */