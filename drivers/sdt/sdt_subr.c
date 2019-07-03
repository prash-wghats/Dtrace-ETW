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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 * Copyright (C) 2019, PK.
 */

#include <sys/dtrace_misc.h>
#include <sys/dtrace_win32.h>
#include <etw.h>
#include "sdt.h"

#if !defined(STATIC)
BOOL APIENTRY
DllMain(HMODULE hmodule, DWORD  reason, LPVOID notused)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		(void) sdt_attach();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		if (sdt_detach() != 0) {
			dprintf("provider sdt failed to unload\n");
		}
		break;
	}
	return (TRUE);
}
#endif

static dtrace_pattr_t stab_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ETW },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t sdt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

int sdt_etw_procp_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_proct_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_diskio_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_tcpip_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_udpip_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_fileio_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_reg_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_pf_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_sched_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_dpc_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_isr_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_syscall_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_guid_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_diag_cb(PEVENT_RECORD ev, void *data);
int sdt_etw_lost_cb(PEVENT_RECORD ev, void *data);

sdt_etw_provider_t sdt_proc_events[] = {
	{ "proc", "start", &ProcessGuid, 1, sdt_etw_procp_cb},
	{ "proc", "exit", &ProcessGuid, 2, sdt_etw_procp_cb},
	{ "proc", "lwp-start", &ThreadGuid, 1, sdt_etw_proct_cb },
	{ "proc", "lwp-exit", &ThreadGuid, 2, sdt_etw_proct_cb },
	{ NULL }
};

sdt_etw_provider_t sdt_io_events[] = {
	{ "io", "start", &DiskIoGuid, 12, sdt_etw_diskio_cb, &FileIoGuid, NULL },
	{ "io", "done", &DiskIoGuid, 10, sdt_etw_diskio_cb, &FileIoGuid, NULL },
	{ NULL }
};

sdt_etw_provider_t sdt_tcpip_events[] = {
	{ "tcpip", "send", &TcpIpGuid, 10, sdt_etw_tcpip_cb }, 		/* 26 */
	{ "tcpip", "receive", &TcpIpGuid, 11, sdt_etw_tcpip_cb }, 	/* 27 */
	{ "tcpip", "connect", &TcpIpGuid, 12, sdt_etw_tcpip_cb }, 	/* 28 */
	{ "tcpip", "disconnect", &TcpIpGuid, 13, sdt_etw_tcpip_cb },	/* 29 */
	{ "tcpip", "retransmit", &TcpIpGuid, 14, sdt_etw_tcpip_cb },	/* 30 */
	{ "tcpip", "accept", &TcpIpGuid, 15, sdt_etw_tcpip_cb }, 	/* 31 */
	{ "tcpip", "reconnect", &TcpIpGuid, 16, sdt_etw_tcpip_cb }, /* 32 */
	{ "tcpip", "fail", &TcpIpGuid, 17, sdt_etw_tcpip_cb },
	{ "tcpip", "copy", &TcpIpGuid, 18, sdt_etw_tcpip_cb },		/* 34 */
	{ NULL }
};

sdt_etw_provider_t sdt_udpip_events[] = {
	{ "udpip", "send", &UdpIpGuid, 10, sdt_etw_udpip_cb }, /* 26 */
	{ "udpip", "receive", &UdpIpGuid, 11, sdt_etw_udpip_cb }, /* 27 */
	{ "udpip", "fail", &TcpIpGuid, 17, sdt_etw_tcpip_cb },
	{ NULL }
};

sdt_etw_provider_t sdt_fsinfo_events[] = {
	{ "fsinfo", "create", &FileIoGuid, 64, sdt_etw_fileio_cb }, /* 32 */
	{ "fsinfo", "cleanup", &FileIoGuid, 65, sdt_etw_fileio_cb },
	{ "fsinfo", "close", &FileIoGuid, 66, sdt_etw_fileio_cb },
	{ "fsinfo", "read", &FileIoGuid, 67, sdt_etw_fileio_cb },
	{ "fsinfo", "write", &FileIoGuid, 68, sdt_etw_fileio_cb },
	{ "fsinfo", "setinfo", &FileIoGuid, 69, sdt_etw_fileio_cb },
	{ "fsinfo", "delete", &FileIoGuid, 70, sdt_etw_fileio_cb }, /* 35 */
	{ "fsinfo", "rename", &FileIoGuid, 71, sdt_etw_fileio_cb },
	{ "fsinfo", "direnum", &FileIoGuid, 72, sdt_etw_fileio_cb },
	{ "fsinfo", "flush", &FileIoGuid, 73, sdt_etw_fileio_cb },
	{ "fsinfo", "queryinfo", &FileIoGuid, 74, sdt_etw_fileio_cb },
	{ "fsinfo", "fscontrol", &FileIoGuid, 75, sdt_etw_fileio_cb },
	{ "fsinfo", "done", &FileIoGuid, 76, sdt_etw_fileio_cb },
	{ "fsinfo", "dirnotify", &FileIoGuid, 77, sdt_etw_fileio_cb },
	{ NULL }
};

/*
 * [EventType{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27},
 * EventTypeName{"Create", "Open", "Delete", "Query", "SetValue", "DeleteValue", "QueryValue",
 * "EnumerateKey", "EnumerateValueKey", "QueryMultipleValue", "SetInformation", "Flush", "KCBCreate",
 * "KCBDelete", "KCBRundownBegin", "KCBRundownEnd", "Virtualize", "Close"}]
 */

sdt_etw_provider_t sdt_reg_events[] = {
	{ "reg", "create", &RegistryGuid, 10, sdt_etw_reg_cb },
	{ "reg", "open", &RegistryGuid, 11, sdt_etw_reg_cb },
	{ "reg", "delete", &RegistryGuid, 12, sdt_etw_reg_cb },
	{ "reg", "query", &RegistryGuid, 13, sdt_etw_reg_cb },
	{ "reg", "setvalue", &RegistryGuid, 14, sdt_etw_reg_cb },
	{ "reg", "delvalue", &RegistryGuid, 15, sdt_etw_reg_cb },
	{ "reg", "queryvalue", &RegistryGuid, 16, sdt_etw_reg_cb },
	{ "reg", "enumkey", &RegistryGuid, 17, sdt_etw_reg_cb },
	{ "reg", "enumvaluekey", &RegistryGuid, 18, sdt_etw_reg_cb },
	{ "reg", "querymulvalue", &RegistryGuid, 19, sdt_etw_reg_cb },
	{ "reg", "setinfo", &RegistryGuid, 20, sdt_etw_reg_cb },
	{ "reg", "flush", &RegistryGuid, 21, sdt_etw_reg_cb },
	{ "reg", "kcbcreate", &RegistryGuid, 22, sdt_etw_reg_cb },
	{ "reg", "kcbdelete", &RegistryGuid, 23, sdt_etw_reg_cb },
	{ "reg", "virtualize", &RegistryGuid, 26, sdt_etw_reg_cb },
	{ "reg", "close", &RegistryGuid, 27, sdt_etw_reg_cb },
	{ NULL }
};

sdt_etw_provider_t sdt_pf_events[] = {
	{ "pf", "hardflt", &PageFaultGuid, 32, sdt_etw_pf_cb },
	{ "pf", "imgload", &PageFaultGuid, 105, sdt_etw_pf_cb },
	{ "pf", "valloc", &PageFaultGuid, 98, sdt_etw_pf_cb },
	{ "pf", "vfree", &PageFaultGuid, 99, sdt_etw_pf_cb },
	{ "pf", "trans_flt", &PageFaultGuid, 10, sdt_etw_pf_cb },
	{ "pf", "dzero_flt", &PageFaultGuid, 11, sdt_etw_pf_cb },
	{ "pf", "cow_flt", &PageFaultGuid, 12, sdt_etw_pf_cb },
	{ "pf", "gp_flt", &PageFaultGuid, 13, sdt_etw_pf_cb },
	{ "pf", "hp_flt", &PageFaultGuid, 14, sdt_etw_pf_cb },
	{ "pf", "av_flt", &PageFaultGuid, 15, sdt_etw_pf_cb },
	{ NULL }
};

sdt_etw_provider_t sdt_sched_events[] = {
	{ "sched", "on-cpu", &ThreadGuid, 36, sdt_etw_sched_cb },	/* switch */
	{ "sched", "off-cpu", &ThreadGuid, 35, sdt_etw_sched_cb },	/* switch */
	{ "sched", "wakeup", &ThreadGuid, 50, sdt_etw_sched_cb },	/* ready */
	{ NULL }
};

sdt_etw_provider_t sdt_dpc_events[] = {
	{ "dpc", "thread", &PerfInfoGuid, 66, sdt_etw_dpc_cb },
	{ "dpc", "dpc", &PerfInfoGuid, 68, sdt_etw_dpc_cb },
	{ "dpc", "timer", &PerfInfoGuid, 69, sdt_etw_dpc_cb },
	{ NULL }
};

sdt_etw_provider_t sdt_isr_events[] = {
	{ "isr", "isr", &PerfInfoGuid, 67, sdt_etw_isr_cb },
	{ NULL }
};

sdt_etw_provider_t sdt_lost_events[] = {
	{ "lostevent", "lostevent", &RTLostEvent, 32, sdt_etw_lost_cb },
	{ NULL }
};

sdt_etw_provider_t sdt_syscall_events[] = {
	{ "syscall", "entry", &PerfInfoGuid, 51, sdt_etw_syscall_cb },
	{ "syscall", "return", &PerfInfoGuid, 52, sdt_etw_syscall_cb },
	{ NULL }
};

sdt_etw_provider_t sdt_guid_events[] = {
	{ "diag", "events", &AllEventsGuid, -2, sdt_etw_diag_cb },
	{ "diag", "lostevent", &RTLostEvent, 32, sdt_etw_lost_cb },
	{ NULL }
};

sdt_provider_t sdt_providers[] = {
	{ "proc", "proc", &stab_attr, sdt_proc_events},
	{ "io", "io", &stab_attr, sdt_io_events,
	    EVENT_TRACE_FLAG_DISK_IO |
	    EVENT_TRACE_FLAG_DISK_IO_INIT},
	{ "fsinfo", "fsinfo", &stab_attr, sdt_fsinfo_events,
	    EVENT_TRACE_FLAG_DISK_FILE_IO |
	    EVENT_TRACE_FLAG_FILE_IO |
	    EVENT_TRACE_FLAG_FILE_IO_INIT},
	{ "tcpip", "tcpip", &stab_attr, sdt_tcpip_events,
	    EVENT_TRACE_FLAG_NETWORK_TCPIP },
	{ "udpip", "udpip", &stab_attr, sdt_udpip_events,
	    EVENT_TRACE_FLAG_NETWORK_TCPIP },
	{ "reg", "reg", &stab_attr, sdt_reg_events,
	    EVENT_TRACE_FLAG_REGISTRY },
	{ "pf", "pf", &stab_attr, sdt_pf_events,
	    EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS |
	    EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS |
	    EVENT_TRACE_FLAG_VIRTUAL_ALLOC },
	{ "sched", "sched", &stab_attr, sdt_sched_events,
	    EVENT_TRACE_FLAG_CSWITCH |
	    EVENT_TRACE_FLAG_DISPATCHER /* ReadyThread */ },
	{ "dpc", "dpc", &stab_attr, sdt_dpc_events,
	    EVENT_TRACE_FLAG_DPC },
	{ "isr", "isr", &stab_attr, sdt_isr_events,
	    EVENT_TRACE_FLAG_INTERRUPT },
	{ "syscall", "syscall", &stab_attr, sdt_syscall_events,
	    EVENT_TRACE_FLAG_SYSTEMCALL },
	{ "diag", "diag", &stab_attr, sdt_guid_events},
	{ "sdt", NULL, &sdt_attr },
	{ NULL }
};

sdt_argdesc_t sdt_args[] = {
	{ "proc", "start", 0, 0, "proc_t *", "psinfo_t *" },
	{ "proc", "exit", 0, 0, "int", NULL },
	{ "proc", "lwp-start", 0, 0, "thread_t *", "lwpsinfo_t *" },
	{ "proc", "lwp-start", 1, 0, "thread_t *", "psinfo_t *" },
	{ "io", "start", 0, 0, "buf_t *", "bufinfo_t *" },
	{ "io", "start", 1, 0, "buf_t *", "devinfo_t *" },
	{ "io", "start", 2, 0, "buf_t *", "fileinfo_t *" },
	{ "io", "done", 0, 0, "buf_t *", "bufinfo_t *" },
	{ "io", "done", 1, 0, "buf_t *", "devinfo_t *" },
	{ "io", "done", 2, 0, "buf_t *", "fileinfo_t *" },
	{ "fsinfo", NULL, 0, 0, "wfileinfo_t *", "fileinfo_t *" },
	{ "tcpip", "send", 0, 0, "tcpip_msg_t *", "ipinfo_t *"},
	{ "tcpip", "send", 1, 0, "tcpip_msg_t *", "tcpinfo_t *"},
	{ "tcpip", "receive", 0, 0, "tcpip_msg_t *", "ipinfo_t *"},
	{ "tcpip", "receive", 1, 0, "tcpip_msg_t *", "tcpinfo_t *"},
	{ "tcpip", "connect", 0, 0, "tcpip_msg_t *", "ipinfo_t *"},
	{ "tcpip", "connect", 1, 0, "tcpip_msg_t *", "tcpinfo_t *"},
	{ "tcpip", "disconnect", 0, 0, "tcpip_msg_t *", "ipinfo_t *"},
	{ "tcpip", "disconnect", 1, 0, "tcpip_msg_t *", "tcpinfo_t *"},
	{ "tcpip", "retransmit", 0, 0, "tcpip_msg_t *", "ipinfo_t *"},
	{ "tcpip", "retransmit", 1, 0, "tcpip_msg_t *", "tcpinfo_t *"},
	{ "tcpip", "accept", 0, 0, "tcpip_msg_t *", "ipinfo_t *"},
	{ "tcpip", "accept", 1, 0, "tcpip_msg_t *", "tcpinfo_t *"},
	{ "tcpip", "reconnect", 0, 0, "tcpip_msg_t *", "ipinfo_t *"},
	{ "tcpip", "reconnect", 1, 0, "tcpip_msg_t *", "tcpinfo_t *"},
	{ "tcpip", "copy", 0, 0, "tcpip_msg_t *", "ipinfo_t *"},
	{ "tcpip", "copy", 1, 0, "tcpip_msg_t *", "tcpinfo_t *"},
	{ "tcpip", "fail", 0, 0, "uint16_t", NULL},
	{ "tcpip", "fail", 1, 1, "uint16_t", NULL},
	{ "udpip", "send", 0, 0, "udpip_msg_t *", "udpinfo_t *"},
	{ "udpip", "receive", 0, 0, "udpip_msg_t *", "udpinfo_t *"},
	{ "udpip", "fail", 0, 0, "uint16_t", NULL},
	{ "udpip", "fail", 1, 1, "uint16_t", NULL},
	{ "reg", NULL, 0, 0, "reginfo_t *", "registry_t *"},
	{ "sched", "off-cpu", 0, 0, "thread_t *", "lwpsinfo_t *" },
	{ "sched", "off-cpu", 1, 1, "proc_t *", "psinfo_t *" },
	{ "sched", "wakeup", 0, 0, "thread_t *", "lwpsinfo_t *"},
	{ "sched", "wakeup", 1, 1, "proc_t *", "psinfo_t *"},
	{ NULL }
};


/*ARGSUSED*/
void
sdt_getargdesc(void *arg, dtrace_id_t id, void *parg, dtrace_argdesc_t *desc)
{
	sdt_probe_t *sdp = parg;
	int i;

	desc->dtargd_native[0] = '\0';
	desc->dtargd_xlate[0] = '\0';

	for (i = 0; sdt_args[i].sda_provider != NULL; i++) {
		sdt_argdesc_t *a = &sdt_args[i];

		if (strcmp(sdp->sdp_provider->sdtp_name, a->sda_provider) != 0)
			continue;

		if (a->sda_name != NULL &&
		    strcmp(sdp->sdp_name, a->sda_name) != 0)
			continue;

		if (desc->dtargd_ndx != a->sda_ndx)
			continue;

		if (a->sda_native != NULL)
			(void) strcpy(desc->dtargd_native, a->sda_native);

		if (a->sda_xlate != NULL)
			(void) strcpy(desc->dtargd_xlate, a->sda_xlate);

		desc->dtargd_mapping = a->sda_mapping;
		return;
	}

	desc->dtargd_ndx = DTRACE_ARGNONE;
}
