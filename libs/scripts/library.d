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
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"@(#)unistd.d	1.4	07/02/20 SMI"

inline int DTRACEFLT_UNKNOWN = 0;	/* Unknown fault */
#pragma D binding "1.0" DTRACEFLT_UNKNOWN

inline int DTRACEFLT_BADADDR = 1;	/* Bad address */
#pragma D binding "1.0" DTRACEFLT_BADADDR

inline int DTRACEFLT_BADALIGN = 2;	/* Bad alignment */
#pragma D binding "1.0" DTRACEFLT_BADALIGN

inline int DTRACEFLT_ILLOP = 3;		/* Illegal operation */
#pragma D binding "1.0" DTRACEFLT_ILLOP

inline int DTRACEFLT_DIVZERO = 4;	/* Divide-by-zero */
#pragma D binding "1.0" DTRACEFLT_DIVZERO

inline int DTRACEFLT_NOSCRATCH = 5;	/* Out of scratch space */
#pragma D binding "1.0" DTRACEFLT_NOSCRATCH

inline int DTRACEFLT_KPRIV = 6;		/* Illegal kernel access */
#pragma D binding "1.0" DTRACEFLT_KPRIV

inline int DTRACEFLT_UPRIV = 7;		/* Illegal user access */
#pragma D binding "1.0" DTRACEFLT_UPRIV

inline int DTRACEFLT_TUPOFLOW = 8;	/* Tuple stack overflow */
#pragma D binding "1.0" DTRACEFLT_TUPOFLOW

inline int DTRACEFLT_BADSTACK = 9;	/* Bad stack */
#pragma D binding "1.4.1" DTRACEFLT_BADSTACK

typedef unsigned int u_int;
typedef unsigned short wchar_t;
typedef uintptr_t caddr_t;

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
 * Portions Copyright 2006 John Birrell jb@freebsd.org
 *
 * $FreeBSD$
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



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
}	proc_t;

typedef struct thread {
	pid_t		pid;
	pid_t		tid;
	pid_t		ppid;
	proc_t		*proc;
	
	uintptr_t		kbase;	/* Kernel stack base */
	uintptr_t		klimit; /* Kernel stack limit */
	uintptr_t		ubase;  /* Thread user stack base */
	uintptr_t		ulimit; /* Thread user stack limit */
	char 			pri; /* thread priority */
	char waitr; 		/* thread wait reason */
	char waitm;			/* wait mode */
	char state; 		/* thread state */
	char wipr; 			/* wait ideal processor */
	uint32_t waittm; 	/* wait time */
	char cpu; 			/* current cpu */
	int rdlags;			/* readythread flags,reason, mode */
	int flags;
	uint32_t affinity;	/* The set of processors on which the thread is allowed to run */ 
	char iopri;			/* io priority */
	char pagepri;		/* page priority */
} thread_t;

/* context switch, scheduler */
typedef struct contextsw {
	char ot_pri;
	char ot_state;
	char ot_waitreason;
	char ot_waitmode;
	char ot_waitidealcpu;
	char nt_pri;
	uint32_t nt_waittime;
} contextsw_t;

typedef struct sched {
	char t_reason;
	char t_incpri;
	char t_flags;
} sched_t;

/* disk io */

/* disk i/o operations */
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

/* file i/o operations */
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
	uint64_t f_extinfo;	 	/* Extra information returned by the file system for the operation. For example for a read request, the actual number of bytes that were read */
	uint32_t f_ntstatus;	 	/* Return value from the operation */
	uint64_t f_infoclass;	 	/* Requested file information class */
	wchar_t *f_name;	 	/* File index from which to continue directory enumeration. */
	uint32_t f_dlen;	 	/* Size of the query buffer, in bytes. */
	uint32_t f_dfileindex;
	wchar_t *f_dpattspec;	 	/* Pattern specified for directory enumeration. */
} wfileinfo_t;

typedef struct reginfo {
	int64_t r_time;		/* Initial time of the registry operation. */
	uint32_t r_status;	/* NTSTATUS value of the registry operation. */
	uint32_t r_index;		/* The subkey index for the registry operation (such as EnumerateKey). */
	uintptr_t r_handle;	/* Handle to the registry key. */
	wchar_t *r_name;		/* Name of the registry key. */
} reginfo_t;

typedef struct in6_addr {
  union {
    uint8_t  Byte[16];
    uint16_t Word[8];
  } u;
} in6_addr_t;

/*
 * long is 64 bit in dtrace LP64 dynamic "C" CTF type container ???
 */
typedef uint32_t ipaddr_t, *pipaddr_t;

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

/*#pragma D depends_on module kernel*/
#pragma D depends_on provider proc

typedef struct psinfo {
	pid_t	pr_ppid;	/* process id of parent */
	pid_t	pr_pid;		/* unique process id */
	pid_t	pr_pgid;	/* pid of process group leader */
	pid_t	pr_sid;		/* session id */
	int pr_arch;		/* process architecture */
	uintptr_t pr_addr;	/* address of process */
	string  pr_fname;	/* process name */
	string	pr_psargs;	/* process arguments */
	u_int	pr_arglen;	/* process argument length */
} psinfo_t;

#pragma D binding "1.0" translator
translator psinfo_t < struct proc *T > {
	pr_ppid = T->ppid;
	pr_pid = T->pid;
	pr_arch = T->model;
	pr_fname = stringof(T->name);
	pr_psargs = wstringof(T->cmdline);
	pr_addr = T->addr;
	pr_sid = T->sessid;
};

#pragma D binding "1.0" translator
translator psinfo_t < struct thread *T > {
	pr_ppid = xlate <psinfo_t> (T->proc).pr_ppid;
	pr_pid = xlate <psinfo_t> (T->proc).pr_pid;
	pr_arch = xlate <psinfo_t> (T->proc).pr_arch;
	pr_fname = xlate <psinfo_t> (T->proc).pr_fname;
	pr_psargs = xlate <psinfo_t> (T->proc).pr_psargs;
	pr_addr = xlate <psinfo_t> (T->proc).pr_addr;
	pr_sid = xlate <psinfo_t> (T->proc).pr_sid;
/*	pr_start = (timestruc_t)xlate <psinfo_t> (T->t_procp).pr_start; */
};

typedef struct lwpsinfo {
	id_t	pr_lwpid;	/* thread ID. */
	int	pr_flag;	/* thread flags. */
	int	pr_pri;		/* thread priority. */
	char	pr_state;	/* numeric lwp state */
	char	pr_sname;	/* printable character for pr_state */
	short	pr_syscall;	/* system call number (if in syscall) */
	uintptr_t
		pr_addr;	/* internal address of lwp */
	uintptr_t
		pr_wchan;	/* sleep address */
	char pr_waitr; 		/* thread wait reason */
	char pr_waitm;			/* wait mode */
	char pr_wipr; 			/* wait ideal processor */
	uint32_t pr_waittm; 	/* wait time */
	char pr_cpu; 			/* current cpu */
	uint32_t pr_affinity;	/* The set of processors on which the thread is allowed to run */ 
	char pr_iopri;			/* io priority */
	char pr_pagepri;		/* page priority */
} lwpsinfo_t;


#pragma D binding "1.0" translator
translator lwpsinfo_t < struct thread *T > {
	pr_lwpid = T->tid;
	pr_flag = T->flags;
	pr_pri = T->pri;
	pr_state = T->state;
	pr_waitr = T->waitr;
	pr_waitm = T->waitm;
	pr_wipr = T->wipr;
	pr_waittm = T->waittm;
	pr_cpu = T->cpu;
	pr_affinity = T->affinity;
	pr_iopri = T->iopri;
	pr_pagepri = T->pagepri;
};



inline psinfo_t *curpsinfo = xlate <psinfo_t *> (((struct thread *)curthread)->proc);
#pragma D attributes Stable/Stable/Common curpsinfo
#pragma D binding "1.0" curpsinfo

inline lwpsinfo_t *curlwpsinfo = xlate <lwpsinfo_t *> ((struct thread *) curthread);
#pragma D attributes Stable/Stable/Common curlwpsinfo
#pragma D binding "1.0" curlwpsinfo



/*#pragma D depends_on provider reg*/

typedef struct registry {
	int r_index;			/* The subkey index for the registry operation (such as EnumerateKey) */
	int r_status;			/* NTSTATUS value of the registry operation. */
	int64_t r_intime;		/* Initial time of the registry operation. */
	string r_rname;		/* Name of the registry key. */
} registry_t;

#pragma D binding "1.0" translator
translator registry_t < struct reginfo *R > {
	r_index = R->r_index;
	r_status = R->r_status;
	r_intime = R->r_time;
	r_rname = wstringof(R->r_name);
};



/*
 * Copyright (c) 2006-2008 Apple Computer, Inc.  All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*#pragma D depends_on provider sched*/

struct _processor_info {
    int pi_state;           /* processor state, see above */
    char    pi_processor_type[32];  /* ASCII CPU type */
    char    pi_fputypes[32];    /* ASCII FPU types */
    int pi_clock;           /* CPU clock freq in MHz */
};

typedef struct _processor_info _processor_info_t;

typedef int chipid_t;
typedef int lgrp_id_t;
typedef int processorid_t;
typedef int psetid_t;

struct cpuinfo {
	processorid_t cpu_id;		/* CPU identifier */
	psetid_t cpu_pset;		/* processor set identifier */
	chipid_t cpu_chip;		/* chip identifier */
	lgrp_id_t cpu_lgrp;		/* locality group identifer */
	/*_processor_info_t cpu_info;	 CPU information */
};

typedef struct cpuinfo cpuinfo_t;

translator cpuinfo_t < struct thread *T > {
	cpu_id = T->cpu;
	cpu_pset = 0; 
	cpu_chip = T->cpu; 
	cpu_lgrp = 0;
	/*cpu_info = *((_processor_info_t *)dtrace`dtrace_zero);  */
}; 

inline cpuinfo_t *curcpu = xlate <cpuinfo_t *> (curthread);
#pragma D attributes Stable/Stable/Common curcpu
#pragma D binding "1.0" curcpu

inline processorid_t cpu = curcpu->cpu_id;
#pragma D attributes Stable/Stable/Common cpu
#pragma D binding "1.0" cpu

inline psetid_t pset = curcpu->cpu_pset;
#pragma D attributes Stable/Stable/Common pset
#pragma D binding "1.0" pset

inline chipid_t chip = curcpu->cpu_chip;
#pragma D attributes Stable/Stable/Common chip
#pragma D binding "1.0" chip

inline lgrp_id_t lgrp = curcpu->cpu_lgrp;
#pragma D attributes Stable/Stable/Common lgrp
#pragma D binding "1.0" lgrp

#pragma D depends_on provider tcpip

inline int AF_INET = 2;
#pragma D binding "1.0" AF_INET
inline int AF_INET6 = 23;
#pragma D binding "1.0" AF_INET6

/* failure flags */
inline int ERROR_INSUFFICIENT_RESOURCES = 1;
#pragma D binding "1.0" ERROR_INSUFFICIENT_RESOURCES
inline int ERROR_TOO_MANY_ADDRESSES = 2;
#pragma D binding "1.0" ERROR_TOO_MANY_ADDRESSES
inline int ERROR_ADDRESS_EXISTS = 3;
#pragma D binding "1.0" ERROR_ADDRESS_EXISTS
inline int ERROR_INVALID_ADDRESS = 4;
#pragma D binding "1.0" ERROR_INVALID_ADDRESS
inline int ERROR_OTHER = 5;
#pragma D binding "1.0" ERROR_OTHER
inline int ERROR_TIMEWAIT_ADDRESS_EXIST = 6;
#pragma D binding "1.0" ERROR_TIMEWAIT_ADDRESS_EXIST


typedef struct ipinfo {
	uint8_t  ip_ver;		/* IP version (4, 6) */
	uint16_t ip_plength;		/* payload length */
	string   ip_saddr;		/* source address */
	string   ip_daddr;		/* destination address */
	uint32_t ip_connid;		/* A unique connection identifier to correlate events belonging to the same connection.*/
	uint64_t ip_stime;		/* Start send request time. */
	uint32_t ip_etime;		/* End send request time. */
} ipinfo_t;

#pragma D binding "1.0" translator
translator ipinfo_t < struct tcpip_msg *T > {
	ip_ver = T->ti_ver;
	ip_plength = T->ti_size;
	ip_saddr = (T->ti_ver == AF_INET) ? inet_ntoa(&T->ti_addr.ip4.saddr):
		inet_ntoa6(&T->ti_addr.ip6.saddr);
	ip_daddr = (T->ti_ver == AF_INET) ? inet_ntoa(&T->ti_addr.ip4.daddr):
		inet_ntoa6(&T->ti_addr.ip6.saddr);
	ip_connid = T->ti_connid;
	ip_stime = T->ti_starttime;
	ip_etime = T->ti_endtime;
};

typedef struct tcpinfo {
	uint16_t tcp_sport;	/* source port */
	uint16_t tcp_dport;	/* destination port */
	uint32_t tcp_seq;	/* sequence number */
	uint32_t tcp_ack;	/* acknowledgement number */
	uint8_t tcp_offset;	/* data offset, in bytes */
	uint8_t tcp_flags;	/* flags */
	uint16_t tcp_window;	/* window size */
	uint16_t tcp_checksum;	/* checksum */
	uint16_t tcp_urgent;	/* urgent data pointer */
	struct tcphdr *tcp_hdr;	/* raw TCP header */
	uint16_t tcp_mss;			/* Maximum segment size. */
	uint16_t tcp_sackopt;		/* Selective Acknowledgment (SACK) option in TCP header. */
	uint16_t tcp_tsopt;			/* Time Stamp option in TCP header. */
	uint16_t tcp_wsopt;			/* Window Scale option in TCP header. */
	uint16_t tcp_rcvws;			/* TCP Receive Window Scaling factor. */
	uint16_t tcp_sndws;			/* TCP Send Window Scaling factor. */
	
} tcpinfo_t;

#pragma D binding "1.0" translator
translator tcpinfo_t < struct tcpip_msg *T > {
	tcp_sport = T->ti_sport;
	tcp_dport = T->ti_dport;
	tcp_seq = T->ti_seqnum;
	tcp_ack =
	tcp_offset =
	tcp_window = T->ti_rcvwin;
	tcp_checksum = 0;
	tcp_urgent = 0;
	tcp_hdr = 0;
	tcp_mss = T->ti_mss;
	tcp_sackopt = T->ti_sackopt;
	tcp_tsopt = T->ti_tsopt;
	tcp_wsopt = T->ti_wsopt;
	tcp_rcvws = T->ti_rcvwinscale;
	tcp_sndws = T->ti_sndwinscale;
};
/*
 * udpinfo contains stable UDP details.
 */
typedef struct udpinfo {
	uint32_t udp_connid;
	uint32_t udp_seq;
	uint16_t udp_plength;
	uint16_t udp_sport;		/* local port */
	uint16_t udp_dport;		/* remote port */
	string udp_saddr;		/* local address, as a string */
	string udp_daddr;		/* remote address, as a string */
} udpinfo_t;

#pragma D binding "1.0" translator
translator udpinfo_t < struct udpip_msg *U > {
	udp_connid = U->ui_connid;
	udp_seq = U->ui_seqnum;
	udp_plength = U->ui_size;
	udp_sport = U->ui_sport;
	udp_dport = U->ui_dport;
	udp_saddr = (U->ui_ver == AF_INET) ? inet_ntoa(&U->ui_addr.ip4.saddr):
		inet_ntoa6(&U->ui_addr.ip6.saddr);
	udp_daddr = (U->ui_ver == AF_INET) ? inet_ntoa(&U->ui_addr.ip4.daddr):
		inet_ntoa6(&U->ui_addr.ip6.saddr);
};


/*#pragma D depends_on module ntkernel
#pragma D depends_on provider io
*/

/*inline int B_BUSY = @B_BUSY@;
#pragma D binding "1.0" B_BUSY
inline int B_DONE = @B_DONE@;
#pragma D binding "1.0" B_DONE
inline int B_ERROR = @B_ERROR@;
#pragma D binding "1.0" B_ERROR
inline int B_PAGEIO = @B_PAGEIO@;
#pragma D binding "1.0" B_PAGEIO
inline int B_PHYS = @B_PHYS@;
#pragma D binding "1.0" B_PHYS*/
inline int B_READ = 0x01;
#pragma D binding "1.0" B_READ
inline int B_WRITE = 0x02;
#pragma D binding "1.0" B_WRITE
inline int B_FLUSH = 0x04;
#pragma D binding "1.0" B_FLUSH
/*inline int B_ASYNC = @B_ASYNC@;
#pragma D binding "1.0" B_ASYNC*/

typedef struct bufinfo {
	int b_flags;			/* buffer status */
	int b_irpflags;			/* I/O request packet flags */
	size_t b_bcount;		/* number of bytes */
	caddr_t b_addr;			/* buffer address */
	uint64_t b_lblkno;		/* block # on device */
	uint64_t b_blkno;		/* expanded block # on device */
	size_t b_resid;			/* # of bytes not transferred */
	size_t b_bufsize;		/* size of allocated buffer */
	caddr_t b_iodone;		/* I/O completion routine */
	int b_error;			/* expanded error field */
	int b_edev;			/* extended device */
	uint64_t resp;			/* The time between I/O initiation and completion */
} bufinfo_t;

#pragma D binding "1.0" translator
translator bufinfo_t < struct buf *B > {
	b_flags = B->b_flags;
	b_irpflags = B->b_irpflags;
	b_addr = B->b_irpaddr;
	b_bcount = B->b_bcount;
	b_lblkno = 0;
	b_blkno = 0;
	b_resid = 0;
	b_bufsize = 0;
	b_iodone = 0;
	b_error = 0;
	b_edev = B->b_diskno;
}; 

typedef struct devinfo {
	int dev_major;			/* major number */
	int dev_minor;			/* minor number */
	int dev_instance;		/* instance number */
	string dev_name;		/* name of device */
	string dev_statname;		/* name of device + instance/minor */
	string dev_pathname;		/* pathname of device */
} devinfo_t;

#pragma D binding "1.0" translator
translator devinfo_t < struct buf *B > {
	dev_major = 0;
	dev_minor = 0;
	dev_instance = 0;
	dev_name = "?";
	dev_statname = B->b_fname == NULL ? "":substr(wstringof(B->b_fname), 0, 2);
	dev_pathname = "?";
};

typedef struct fileinfo {
	string fi_name;			/* name (basename of fi_pathname) */
	string fi_dirname;		/* directory (dirname of fi_pathname) */
	string fi_pathname;		/* full pathname */
	uint64_t fi_offset;		/* offset within file */
	string fi_fs;			/* filesystem */
	string fi_mount;		/* mount point of file system */
	int fi_oflags;			/* open(2) flags for file descriptor (create options)*/
	int fi_cflags;
	int fi_aflags;			/* File attributes */
	int fi_sflags;			/* File share access flags */
	int fi_bcount;			/* number of bytes requested*/ 
	int fi_extinfo;			/* extra info */
	int fi_rstatus;			/* return (NTSTATUS) status */
	int fi_dbuflen;			/* directory enum buffer size */
	caddr_t fi_irp;         /* unique irp address */
	string fi_dpattern;		/* directory search pattern */
} fileinfo_t;

#pragma D binding "1.0" translator
translator fileinfo_t < struct buf *B > {
	fi_name = B->b_fname == NULL ? "<none>" :
	    basename(wstringof(B->b_fname));
	fi_dirname = B->b_fname == NULL ? "<none>" :
	    dirname(wstringof(B->b_fname));
	fi_pathname = B->b_fname == NULL ? "<none>" :
	    wstringof(B->b_fname);
	fi_offset = B->b_offset;
	fi_fs = "?";
	fi_mount = "?";
	fi_oflags = 0;
};

#pragma D binding "1.0" translator
translator fileinfo_t < struct wfileinfo *F > {
	fi_name = F->f_name == NULL ? "<none>" :
	    basename(wstringof(F->f_name));
	fi_dirname = F->f_name == NULL ? "<none>" :
	    dirname(wstringof(F->f_name));
	fi_pathname = F->f_name == NULL ? "<none>" :
	    wstringof(F->f_name);
	fi_offset = F->f_offset;
	fi_fs = "?";
	fi_mount = "?";
	fi_oflags = F->f_ioflags;
	fi_cflags = F->f_createopt;
	fi_aflags = F->f_fileattrib;
	fi_sflags = F->f_shareflags;
	fi_bcount = F->f_iosize;
	fi_extinfo = F->f_extinfo;
	fi_rstatus = F->f_ntstatus;
	fi_dbuflen = F->f_dlen;
	fi_irp = F->f_irpptr;
	fi_dpattern = wstringof(F->f_dpattspec);
};

/* irp flags */
inline int IRP_NOCACHE = 0x1;
#pragma D binding "1.0" IRP_NOCACHE
inline int IRP_PAGING_IO = 0x2;
#pragma D binding "1.0" IRP_PAGING_IO
inline int IRP_MOUNT_COMPLETION = 0x2;
#pragma D binding "1.0" IRP_MOUNT_COMPLETION
inline int IRP_SYNCHRONOUS_API = 0x4;
#pragma D binding "1.0" IRP_SYNCHRONOUS_API
inline int IRP_ASSOCIATED_IRP = 0x8;
#pragma D binding "1.0" IRP_ASSOCIATED_IRP
inline int IRP_BUFFERED_IO = 0x10;
#pragma D binding "1.0" IRP_BUFFERED_IO
inline int IRP_DEALLOCATE_BUFFER = 0x20;
#pragma D binding "1.0" IRP_DEALLOCATE_BUFFER
inline int IRP_INPUT_OPERATION = 0x40;
#pragma D binding "1.0" IRP_INPUT_OPERATION
inline int IRP_SYNCHRONOUS_PAGING_IO = 0x40;
#pragma D binding "1.0" IRP_SYNCHRONOUS_PAGING_IO
inline int IRP_CREATE_OPERATION = 0x80;
#pragma D binding "1.0" IRP_CREATE_OPERATION
inline int IRP_READ_OPERATION = 0x100;
#pragma D binding "1.0" IRP_READ_OPERATION
inline int IRP_WRITE_OPERATION = 0x200;
#pragma D binding "1.0" IRP_WRITE_OPERATION
inline int IRP_CLOSE_OPERATION = 0x400;
#pragma D binding "1.0" IRP_CLOSE_OPERATION
inline int IRP_DEFER_IO_COMPLETION = 0x800;
#pragma D binding "1.0" IRP_DEFER_IO_COMPLETION
inline int IRP_OB_QUERY_NAME = 0x1000;
#pragma D binding "1.0" IRP_OB_QUERY_NAME
inline int IRP_HOLD_DEVICE_QUEUE = 0x2000;
#pragma D binding "1.0" IRP_HOLD_DEVICE_QUEUE
inline int IRP_RETRY_IO_COMPLETION = 0x4000;
#pragma D binding "1.0" IRP_RETRY_IO_COMPLETION

/* File ShareAccess flags */
inline int FILE_SHARE_READ = 0x00000001;
#pragma D binding "1.0" FILE_SHARE_READ
inline int FILE_SHARE_WRITE = 0x00000002;
#pragma D binding "1.0" FILE_SHARE_WRITE
inline int FILE_SHARE_DELETE = 0x00000004;
#pragma D binding "1.0" FILE_SHARE_DELETE
inline int FILE_SHARE_VALID_FLAGS = 0x00000007;
#pragma D binding "1.0" FILE_SHARE_VALID_FLAGS

/* File CreateDisposition flags */

inline int FILE_SUPERSEDE = 0x00000000;
#pragma D binding "1.0" FILE_SUPERSEDE
inline int FILE_OPEN = 0x00000001;
#pragma D binding "1.0" FILE_OPEN
inline int FILE_CREATE = 0x00000002;
#pragma D binding "1.0" FILE_CREATE
inline int FILE_OPEN_IF = 0x00000003;
#pragma D binding "1.0" FILE_OPEN_IF
inline int FILE_OVERWRITE = 0x00000004;
#pragma D binding "1.0" FILE_OVERWRITE
inline int FILE_OVERWRITE_IF = 0x00000005;
#pragma D binding "1.0" FILE_OVERWRITE_IF
inline int FILE_MAXIMUM_DISPOSITION = 0x00000005;
#pragma D binding "1.0" FILE_MAXIMUM_DISPOSITION

/* File CreateOptions  flags */

inline int FILE_DIRECTORY_FILE = 0x00000001;
#pragma D binding "1.0" FILE_DIRECTORY_FILE
inline int FILE_WRITE_THROUGH = 0x00000002;
#pragma D binding "1.0" FILE_WRITE_THROUGH
inline int FILE_SEQUENTIAL_ONLY = 0x00000004;
#pragma D binding "1.0" FILE_SEQUENTIAL_ONLY
inline int FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008;
#pragma D binding "1.0" FILE_NO_INTERMEDIATE_BUFFERING
inline int FILE_SYNCHRONOUS_IO_ALERT = 0x00000010;
#pragma D binding "1.0" FILE_SYNCHRONOUS_IO_ALERT
inline int FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
#pragma D binding "1.0" FILE_SYNCHRONOUS_IO_NONALERT
inline int FILE_NON_DIRECTORY_FILE = 0x00000040;
#pragma D binding "1.0" FILE_NON_DIRECTORY_FILE
inline int FILE_CREATE_TREE_CONNECTION = 0x00000080;
#pragma D binding "1.0" FILE_CREATE_TREE_CONNECTION
inline int FILE_COMPLETE_IF_OPLOCKED = 0x00000100;
#pragma D binding "1.0" FILE_COMPLETE_IF_OPLOCKED
inline int FILE_NO_EA_KNOWLEDGE = 0x00000200;
#pragma D binding "1.0" FILE_NO_EA_KNOWLEDGE
inline int FILE_OPEN_FOR_RECOVERY = 0x00000400;
#pragma D binding "1.0" FILE_OPEN_FOR_RECOVERY
inline int FILE_RANDOM_ACCESS = 0x00000800;
#pragma D binding "1.0" FILE_RANDOM_ACCESS
inline int FILE_DELETE_ON_CLOSE = 0x00001000;
#pragma D binding "1.0" FILE_DELETE_ON_CLOSE
inline int FILE_OPEN_BY_FILE_ID = 0x00002000;
#pragma D binding "1.0" FILE_OPEN_BY_FILE_ID
inline int FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000;
#pragma D binding "1.0" FILE_OPEN_FOR_BACKUP_INTENT
inline int FILE_NO_COMPRESSION = 0x00008000;
#pragma D binding "1.0" FILE_NO_COMPRESSION
inline int FILE_RESERVE_OPFILTER = 0x00100000;
#pragma D binding "1.0" FILE_RESERVE_OPFILTER
inline int FILE_OPEN_REPARSE_POINT = 0x00200000;
#pragma D binding "1.0" FILE_OPEN_REPARSE_POINT
inline int FILE_OPEN_NO_RECALL = 0x00400000;
#pragma D binding "1.0" FILE_OPEN_NO_RECALL
inline int FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000;
#pragma D binding "1.0" FILE_OPEN_FOR_FREE_SPACE_QUERY

/* File Attributes */

inline int FILE_ATTRIBUTE_READONLY = 0x00000001;
#pragma D binding "1.0" FILE_ATTRIBUTE_READONLY
inline int FILE_ATTRIBUTE_HIDDEN = 0x00000002;
#pragma D binding "1.0" FILE_ATTRIBUTE_HIDDEN
inline int FILE_ATTRIBUTE_SYSTEM = 0x00000004;
#pragma D binding "1.0" FILE_ATTRIBUTE_SYSTEM
inline int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
#pragma D binding "1.0" FILE_ATTRIBUTE_DIRECTORY
inline int FILE_ATTRIBUTE_ARCHIVE = 0x00000020;
#pragma D binding "1.0" FILE_ATTRIBUTE_ARCHIVE
inline int FILE_ATTRIBUTE_DEVICE = 0x00000040;
#pragma D binding "1.0" FILE_ATTRIBUTE_DEVICE
inline int FILE_ATTRIBUTE_NORMAL = 0x00000080;
#pragma D binding "1.0" FILE_ATTRIBUTE_NORMAL
inline int FILE_ATTRIBUTE_TEMPORARY = 0x00000100;
#pragma D binding "1.0" FILE_ATTRIBUTE_TEMPORARY
inline int FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200;
#pragma D binding "1.0" FILE_ATTRIBUTE_SPARSE_FILE
inline int FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
#pragma D binding "1.0" FILE_ATTRIBUTE_REPARSE_POINT
inline int FILE_ATTRIBUTE_COMPRESSED = 0x00000800;
#pragma D binding "1.0" FILE_ATTRIBUTE_COMPRESSED
inline int FILE_ATTRIBUTE_OFFLINE = 0x00001000;
#pragma D binding "1.0" FILE_ATTRIBUTE_OFFLINE
inline int FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000;
#pragma D binding "1.0" FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
inline int FILE_ATTRIBUTE_ENCRYPTED = 0x00004000;
#pragma D binding "1.0" FILE_ATTRIBUTE_ENCRYPTED