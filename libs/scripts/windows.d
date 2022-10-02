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


inline int SDT_MSGHDR_SIZE = 4;
inline int SDT_MSGHDRLOC_CHAR_ARCH = 1;
inline int SDT_MSGHDRLOC_CHAR_VERSION = 2;
inline int SDT_MSGHDRLOC_SHORT_ID = 4;
inline int PL_ARCH_HEADER = 1;
inline int PL_VER_HEADER = 2;
inline int PL_ID_HEADER = 3;

typedef struct guid {
	uint8_t guid[16];
} guid_t;

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

	uint64_t t_hrtime;	/* Last time on cpu. */
	int t_errno;	/* Syscall return value. */
	char t_name[64];	/* Thread Name */
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

