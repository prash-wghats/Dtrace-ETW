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
	pr_psargs = T->cmdline ? wstringof(T->cmdline):"";
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
	id_t	pr_lwpid;		/* thread ID. */
	int	pr_flag;			/* thread flags. */
	int	pr_pri;				/* thread priority. */
	char	pr_state;		/* numeric lwp state */
	char	pr_sname;		/* printable character for pr_state */
	short	pr_syscall;		/* system call number (if in syscall) */
	uintptr_t	pr_addr;	/* internal address of lwp */
	uintptr_t pr_wchan;		/* sleep address */
	char pr_waitr; 			/* thread wait reason */
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
