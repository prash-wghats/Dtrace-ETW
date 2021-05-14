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

int sdt_etw_procp_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_proct_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_diskio_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_tcpip_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_udpip_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_fileio_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_reg_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_pf_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_sched_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_dpc_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_isr_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_syscall_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_guid_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);

int sdt_etw_lost_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_pmc_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_module_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_hwconfig_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_dnet_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);
int sdt_etw_fpid_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack);

sdt_etw_event_t sdt_proc_events[] = {
	{ "systemtrace", "event", "start", &ProcessGuid, 1, sdt_etw_procp_cb},
	{ "systemtrace", "event", "exit", &ProcessGuid, 2, sdt_etw_procp_cb},
	{ "systemtrace", "event", "lwp-start", &ThreadGuid, 1, sdt_etw_proct_cb },
	{ "systemtrace", "event", "lwp-exit", &ThreadGuid, 2, sdt_etw_proct_cb },
	{ "systemtrace", "event", "module-load", &ImageLoadGuid, 10, sdt_etw_module_cb},
	{ "systemtrace", "event", "module-unload", &ImageLoadGuid, 2, sdt_etw_module_cb},
	{ NULL }
};

sdt_etw_event_t sdt_io_events[] = {
	{ "systemtrace", "event", "start", &DiskIoGuid, 12, sdt_etw_diskio_cb, &FileIoGuid, NULL, EVENT_TRACE_FLAG_DISK_IO_INIT },
	{ "systemtrace", "event", "done", &DiskIoGuid, 10, sdt_etw_diskio_cb, &FileIoGuid, NULL, EVENT_TRACE_FLAG_DISK_IO },
	{ NULL }
};

sdt_etw_event_t sdt_tcpip_events[] = {
	{ "systemtrace", "event", "send", &TcpIpGuid, 10, sdt_etw_tcpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP }, 		/* 26 */
	{ "systemtrace", "event", "receive", &TcpIpGuid, 11, sdt_etw_tcpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP }, 	/* 27 */
	{ "systemtrace", "event", "connect", &TcpIpGuid, 12, sdt_etw_tcpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP }, 	/* 28 */
	{ "systemtrace", "event", "disconnect", &TcpIpGuid, 13, sdt_etw_tcpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP },	/* 29 */
	{ "systemtrace", "event", "retransmit", &TcpIpGuid, 14, sdt_etw_tcpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP },	/* 30 */
	{ "systemtrace", "event", "accept", &TcpIpGuid, 15, sdt_etw_tcpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP }, 	/* 31 */
	{ "systemtrace", "event", "reconnect", &TcpIpGuid, 16, sdt_etw_tcpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP }, /* 32 */
	{ "systemtrace", "event", "fail", &TcpIpGuid, 17, sdt_etw_tcpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP },
	{ "systemtrace", "event", "copy", &TcpIpGuid, 18, sdt_etw_tcpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP },		/* 34 */
	{ NULL }
};

sdt_etw_event_t sdt_udpip_events[] = {
	{ "systemtrace", "event", "send", &UdpIpGuid, 10, sdt_etw_udpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP  }, /* 26 */
	{ "systemtrace", "event", "receive", &UdpIpGuid, 11, sdt_etw_udpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP }, /* 27 */
	{ "systemtrace", "event", "fail", &UdpIpGuid, 17, sdt_etw_udpip_cb, NULL, NULL, EVENT_TRACE_FLAG_NETWORK_TCPIP }, //XXX
	{ NULL }
};

// EVENT_TRACE_FLAG_DISK_FILE_IO |

sdt_etw_event_t sdt_fsinfo_events[] = {
	{ "systemtrace", "event", "create", &FileIoGuid, 64, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT }, /* 32 */
	{ "systemtrace", "event", "cleanup", &FileIoGuid, 65, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "close", &FileIoGuid, 66, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "read", &FileIoGuid, 67, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "write", &FileIoGuid, 68, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "setinfo", &FileIoGuid, 69, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "delete", &FileIoGuid, 70, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT }, /* 35 */
	{ "systemtrace", "event", "rename", &FileIoGuid, 71, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "direnum", &FileIoGuid, 72, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "flush", &FileIoGuid, 73, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "queryinfo", &FileIoGuid, 74, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "fscontrol", &FileIoGuid, 75, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "done", &FileIoGuid, 76, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ "systemtrace", "event", "dirnotify", &FileIoGuid, 77, sdt_etw_fileio_cb, NULL, NULL, EVENT_TRACE_FLAG_FILE_IO | 	    EVENT_TRACE_FLAG_FILE_IO_INIT },
	{ NULL }
};

/*
 * [EventType{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27},
 * EventTypeName{"Create", "Open", "Delete", "Query", "SetValue", "DeleteValue", "QueryValue",
 * "EnumerateKey", "EnumerateValueKey", "QueryMultipleValue", "SetInformation", "Flush", "KCBCreate",
 * "KCBDelete", "KCBRundownBegin", "KCBRundownEnd", "Virtualize", "Close"}]
 */

sdt_etw_event_t sdt_reg_events[] = {
	{ "systemtrace", "event", "create", &RegistryGuid, 10, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "open", &RegistryGuid, 11, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "delete", &RegistryGuid, 12, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "query", &RegistryGuid, 13, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "setvalue", &RegistryGuid, 14, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "delvalue", &RegistryGuid, 15, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "queryvalue", &RegistryGuid, 16, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "enumkey", &RegistryGuid, 17, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "enumvaluekey", &RegistryGuid, 18, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "querymulvalue", &RegistryGuid, 19, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "setinfo", &RegistryGuid, 20, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "flush", &RegistryGuid, 21, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "kcbcreate", &RegistryGuid, 22, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "kcbdelete", &RegistryGuid, 23, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "virtualize", &RegistryGuid, 26, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ "systemtrace", "event", "close", &RegistryGuid, 27, sdt_etw_reg_cb, NULL, NULL, EVENT_TRACE_FLAG_REGISTRY },
	{ NULL }
};

sdt_etw_event_t sdt_pf_events[] = {
	{ "systemtrace", "event", "hardflt", &PageFaultGuid, 32, sdt_etw_pf_cb, NULL, NULL, EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS },
	{ "systemtrace", "event", "imgload", &PageFaultGuid, 105, sdt_etw_pf_cb, NULL, NULL, EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS },
	{ "systemtrace", "event", "valloc", &PageFaultGuid, 98, sdt_etw_pf_cb, NULL, NULL, EVENT_TRACE_FLAG_VIRTUAL_ALLOC },
	{ "systemtrace", "event", "vfree", &PageFaultGuid, 99, sdt_etw_pf_cb, NULL, NULL, EVENT_TRACE_FLAG_VIRTUAL_ALLOC },
	{ "systemtrace", "event", "trans_flt", &PageFaultGuid, 10, sdt_etw_pf_cb, NULL, NULL, EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS },
	{ "systemtrace", "event", "dzero_flt", &PageFaultGuid, 11, sdt_etw_pf_cb, NULL, NULL, EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS },
	{ "systemtrace", "event", "cow_flt", &PageFaultGuid, 12, sdt_etw_pf_cb, NULL, NULL, EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS },
	{ "systemtrace", "event", "gp_flt", &PageFaultGuid, 13, sdt_etw_pf_cb, NULL, NULL, EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS },
	{ "systemtrace", "event", "hp_flt", &PageFaultGuid, 14, sdt_etw_pf_cb, NULL, NULL, EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS },
	{ "systemtrace", "event", "av_flt", &PageFaultGuid, 15, sdt_etw_pf_cb, NULL, NULL, EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS },
	{ NULL }
};

sdt_etw_event_t sdt_sched_events[] = {
	{ "systemtrace", "event", "on-cpu", &ThreadGuid, 36, sdt_etw_sched_cb, NULL, NULL, EVENT_TRACE_FLAG_CSWITCH, 36 },	/* switch */
	{ "systemtrace", "event", "off-cpu", &ThreadGuid, 35, sdt_etw_sched_cb, NULL, NULL, EVENT_TRACE_FLAG_CSWITCH, 36 },	/* switch */
	{ "systemtrace", "event", "wakeup", &ThreadGuid, 50, sdt_etw_sched_cb, NULL, NULL, EVENT_TRACE_FLAG_DISPATCHER, 50 },	/* ReadyThread */
	{ NULL }
};

sdt_etw_event_t sdt_dpc_events[] = {
	{ "systemtrace", "event", "thread", &PerfInfoGuid, 66, sdt_etw_dpc_cb, NULL, NULL, EVENT_TRACE_FLAG_DPC },
	{ "systemtrace", "event", "dpc", &PerfInfoGuid, 68, sdt_etw_dpc_cb, NULL, NULL, EVENT_TRACE_FLAG_DPC },
	{ "systemtrace", "event", "timer", &PerfInfoGuid, 69, sdt_etw_dpc_cb, NULL, NULL, EVENT_TRACE_FLAG_DPC },
	{ NULL }
};

sdt_etw_event_t sdt_isr_events[] = {
	{ "systemtrace", "event", "isr", &PerfInfoGuid, 67, sdt_etw_isr_cb, NULL, NULL, EVENT_TRACE_FLAG_INTERRUPT },
	{ NULL }
};

sdt_etw_event_t sdt_lost_events[] = {
	{ "systemtrace", "event", "lostevent", &RTLostEvent, 32, sdt_etw_lost_cb },
	{ NULL }
};

sdt_etw_event_t sdt_syscall_events[] = {
	{ "systemtrace", "event", "entry", &PerfInfoGuid, 51, sdt_etw_syscall_cb, NULL, NULL, EVENT_TRACE_FLAG_SYSTEMCALL },
	{ "systemtrace", "event", "return", &PerfInfoGuid, 52, sdt_etw_syscall_cb, NULL, NULL, EVENT_TRACE_FLAG_SYSTEMCALL },
	{ NULL }
};

sdt_etw_event_t sdt_guid_events[] = {
	{ "diag", "", "events", &WGDiagEventsGuid, SDT_DIAG_ALL_EVENTS, NULL },
	{ "diag", "", "ignored", &WGDiagEventsGuid, SDT_DIAG_IGNORED_EVENTS, NULL },
	{ "diag", "", "missed-ustack", &WGDiagEventsGuid, SDT_DIAG_ZUSTACK_EVENTS, NULL },
	{ "diag", "", "missed-stack", &WGDiagEventsGuid, SDT_DIAG_ZSTACK_EVENTS, NULL },
	{ "diag", "", "missed-dnet-stack", &WGDiagEventsGuid, SDT_DIAG_NSTACK_EVENTS, NULL },
	{ "diag", "", "lostevent", &RTLostEvent, 32, sdt_etw_lost_cb },
	{ "diag", "", "fpid", &FastTrapGuid, 0, sdt_etw_fpid_cb},
	{ NULL }
};

sdt_etw_event_t sdt_pmc_events[] = {
	{ "systemtrace", "event", "sample-src", &PerfInfoGuid, 73, sdt_etw_pmc_cb },
	{ "systemtrace", "event", "counter-src", &PerfInfoGuid, 48, sdt_etw_pmc_cb },
	{ NULL, "pmc", NULL, &PerfInfoGuid, 0, sdt_etw_pmc_cb, NULL, NULL, PERF_PMC_PROFILR_GM1, 47 }
};

sdt_etw_event_t sdt_hwconfig_events[] = {
	{ "systemtrace", "event", "cpu", &HWSystemConfigGuid, 10, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "disk-phy", &HWSystemConfigGuid, 11, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "disk-log", &HWSystemConfigGuid, 12, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "nic", &HWSystemConfigGuid, 13, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "video", &HWSystemConfigGuid, 14, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "service", &HWSystemConfigGuid, 15, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "power", &HWSystemConfigGuid, 16, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "network", &HWSystemConfigGuid, 17, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "disk-optical", &HWSystemConfigGuid, 18, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "irq", &HWSystemConfigGuid, 21, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "pnp", &HWSystemConfigGuid, 22, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "ide", &HWSystemConfigGuid, 23, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "platform", &HWSystemConfigGuid, 25, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "dpi", &HWSystemConfigGuid, 28, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "code-integrity", &HWSystemConfigGuid, 29, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "telemetry", &HWSystemConfigGuid, 30, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "defrag", &HWSystemConfigGuid, 31, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "dev-family", &HWSystemConfigGuid, 33, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "boot", &HWSystemConfigGuid, 37, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "flight-ids", &HWSystemConfigGuid, 34, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "processor", &HWSystemConfigGuid, 35, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ "systemtrace", "event", "virtualization", &HWSystemConfigGuid, 36, sdt_etw_hwconfig_cb, NULL, NULL, 0 },
	{ NULL }
};


sdt_etw_event_t sdt_dnet_events[] = {
	{ ".net", "event", "runtime", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, 0, 187 },
	{ ".net", "event", "excp", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETExceptionKeyword, 80 },
	{ ".net", "lock", "lck-wait", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETContentionKeyword, 81 },
	{ ".net", "lock", "lck-done", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETContentionKeyword, 91 },
	{ ".net", "thread", "thr-start", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 50 },
	{ ".net", "thread", "thr-stop", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 51 },
	{ ".net", "thread", "thr-retire", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 52 },
	{ ".net", "thread", "thr-unretire", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 53 },
	{ ".net", "thread", "io-start", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 44 },
	{ ".net", "thread", "io-exit", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 45 },
	{ ".net", "thread", "io-retire", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 46 },
	{ ".net", "thread", "io-unretire", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 47 },
	{ ".net", "thread", "adj", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 54 },
	{ ".net", "thread", "adj-adj", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 55 },
	{ ".net", "thread", "adj-stats", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETThreadingKeyword, 56 },

	{ ".net", "jit", "method-jit-begin", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETJITKeyword | NETNGenKeyword, 145 },
	{ ".net", "jit", "method-load", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETJITKeyword | NETNGenKeyword, 143 },
	{ ".net", "jit", "method-unload", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETJITKeyword | NETNGenKeyword, 144 },
	{ ".net", "jit", "static-method-load", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETJITKeyword | NETNGenKeyword, 136 },
	{ ".net", "jit", "static-method-unload", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETJITKeyword | NETNGenKeyword, 137 },
	{ ".net", "jit", "inline-fail", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETJITTracingKeyword, 186 },
	{ ".net", "jit", "inline-success", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETJITTracingKeyword, 185 },
	{ ".net", "jit", "tailcall-fail", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETJITTracingKeyword, 189 },
	{ ".net", "jit", "tailcall-success", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETJITTracingKeyword, 188 },
	{ ".net", "interop", "stub-gen", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETInteropKeyword, 88 },
	{ ".net", "interop", "stub-hit", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETInteropKeyword, 89 },
	{ ".net", "arm", "thr-create", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETAppDomainResourceManagementKeyword | NETThreadingKeyword, 85 },
	{ ".net", "arm", "mem-allocate", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETAppDomainResourceManagementKeyword, 83 },
	{ ".net", "arm", "mem-survive", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETAppDomainResourceManagementKeyword, 84 },
	{ ".net", "arm", "thr-enter", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETAppDomainResourceManagementKeyword | NETThreadingKeyword, 87 },
	{ ".net", "arm", "thr-exit", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETAppDomainResourceManagementKeyword | NETThreadingKeyword, 86 },
	{ ".net", "security", "strongname-start", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETSecurityKeyword, 181 },
	{ ".net", "security", "strongname-end", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETSecurityKeyword, 182 },
	{ ".net", "security", "authcode-start", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETSecurityKeyword, 183 },
	{ ".net", "security", "authocode-end", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETSecurityKeyword, 184 },
	{ ".net", "loader", "appdomain-load", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETLoaderKeyword, 156 },
	{ ".net", "loader", "appdomain-unload", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETLoaderKeyword, 157 },
	{ ".net", "loader", "assembly-load", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETLoaderKeyword, 154 },
	{ ".net", "loader", "assembly-unload", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETLoaderKeyword, 155 },
	{ ".net", "loader", "module-load", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETLoaderKeyword, 152 },
	{ ".net", "loader", "module-unload", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETLoaderKeyword, 153 },
	{ ".net", "loader", "module-range", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETPerfTrackKeyWord, 158 },
	{ ".net", "gc", "gc-start", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 1 },
	{ ".net", "gc", "gc-end", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 2 },
	{ ".net", "gc", "heapstat", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 4 },
	{ ".net", "gc", "seg-create", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 5 },
	{ ".net", "gc", "seg-free", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 6 },
	{ ".net", "gc", "resume-begin", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 7 },
	{ ".net", "gc", "resume-end", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 3 },
	{ ".net", "gc", "suspend-start", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 9 },
	{ ".net", "gc", "suspend-end", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 8 },
	{ ".net", "gc", "allocate-tick", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 10 },
	{ ".net", "gc", "finalizer-begin", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 14 },
	{ ".net", "gc", "finalizer-end", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 13 },
	{ ".net", "gc", "conc-thr-create", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 11 },
	{ ".net", "gc", "conc-thr-exit", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETGCKeyword, 12 },
	//{ ".net", "stack", "stack", &MSDotNETRuntimeGuid, SDT_ETW_USER_EVENTS, sdt_etw_dnet_cb, NULL, NULL, NETStackKeyword , 82 },
	{ NULL }
};

sdt_provider_t sdt_providers[] = {
	{ "proc", "proc", &stab_attr, sdt_proc_events},
	{ "io", "io", &stab_attr, sdt_io_events},
	{ "fsinfo", "fsinfo", &stab_attr, sdt_fsinfo_events},
	{ "tcpip", "tcpip", &stab_attr, sdt_tcpip_events },
	{ "udpip", "udpip", &stab_attr, sdt_udpip_events },
	{ "reg", "reg", &stab_attr, sdt_reg_events },
	{ "pf", "pf", &stab_attr, sdt_pf_events },
	{ "sched", "sched", &stab_attr, sdt_sched_events },
	{ "dpc", "dpc", &stab_attr, sdt_dpc_events },
	{ "isr", "isr", &stab_attr, sdt_isr_events },
	{ "syscall", "syscall", &stab_attr, sdt_syscall_events },
	{ "pmc", "pmc", &stab_attr, sdt_pmc_events},
	{ "diag", "diag", &stab_attr, sdt_guid_events},
	{ "dnet", "dnet", &stab_attr, sdt_dnet_events},
	{ "hwconfig", "hwconfig", &stab_attr, sdt_hwconfig_events},
	{ "sdt", NULL, &sdt_attr },
	{ NULL }
};

sdt_argdesc_t sdt_args[] = {
	{ "proc", "start", 0, 0, "proc_t *", "psinfo_t *" },
	{ "proc", "exit", 0, 0, "int", NULL },
	{ "proc", "lwp-start", 0, 0, "thread_t *", "lwpsinfo_t *" },
	{ "proc", "lwp-start", 1, 0, "thread_t *", "psinfo_t *" },
	{ "proc", "module-load", 0, 0, "wchar_t *", NULL },
	{ "proc", "module-load", 1, 1, "intptr_t", NULL },
	{ "proc", "module-unload", 0, 0, "wchar_t *", NULL },
	{ "proc", "module-unload", 1, 1, "intptr_t", NULL },
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
	{ "dnet", "runtime", 0, 0, "char *", "netrt_t *" },
	{ "dnet", "excp", 0, 0, "char *", "netexcp_t *" },
	{ "dnet", "stub-gen", 0, 0, "char *", "netirop_t *" },
	{ "dnet", "appdomain-load", 0, 0, "char *", "netappdom_t *" },
	{ "dnet", "assembly-load", 0, 0, "char *", "netassm_t *" },
	{ "dnet", "module-load", 0, 0, "char *", "netmodule_t *" },
	{ "dnet", "heapstat", 0, 0, "char *", "netgcheapstat_t *" },
	{ "dnet", "allocate-tick", 0, 0, "char *", "netgcalloctick_t *" },
	{ "dnet", "gc-start", 0, 0, "char *", "netgc_t *" },
	{ "dnet", "seg-create", 0, 0, "char *", "netgcseg_t *" },
	{ "dnet", "seg-free", 0, 0, "char *", "netgcseg_t *" },
	{ "dnet", "finalizer-end", 0, 0, "char *", "netgc_t *" },
	{ "dnet", "suspend-start", 0, 0, "char *", "netgc_t *" },
	{ "dnet", "lck-wait", 0, 0, "char *", "netlck_t *" },
	{ "dnet", "lck-done", 0, 0, "char *", "netlck_t *" },
	{ "dnet", "thr-create", 0, 0, "char *", "netthr_t *" },
	{ "dnet", "thr-start", 0, 0, "intptr_t", "netthrinfo_t *" },
	{ "dnet", "io-start", 0, 0, "char *", "netthrinfo_t *" },
	{ "hwconfig", "cpu", 0, 0, "char *", "hwcpu_t *" },
	{ "hwconfig", "service", 0, 0, "char *", "hwservice_t *" },
	{ "hwconfig", "nic", 0, 0, "char *", "hwnic_t *" },
	{ "hwconfig", "pnp", 0, 0, "char *", "hwpnp_t *" },
	{ "hwconfig", "virtualization", 0, 0, "char *", "hwvirt_t *" },
	{ "hwconfig", "disk-phy", 0, 0, "char *", "hwdphy_t *" },
	{ "hwconfig", "disk-log", 0, 0, "char *", "hwdlog_t *" },
	{ "hwconfig", "disk-optical", 0, 0, "char *", "hwopt_t *" },
	{ "hwconfig", "video", 0, 0, "char *", "hwvideo_t *" },
	{ "hwconfig", "dpi", 0, 0, "char *", "hwdpi_t *" },
	{ "hwconfig", "network", 0, 0, "char *", "hwnw_t *" },
	{ "hwconfig", "processor", 0, 0, "char *", "hwprocs_t *" },
	{ "hwconfig", "irq", 0, 0, "char *", "hwirq_t *" },
	{ "hwconfig", "platform", 0, 0, "char *", "hwplat_t *" },
	{ "pmc", "counter-src", 0, 0, "uint64_t", "int" },
	{ "pmc", "counter-src", 1, 1, "void *", "wchar_t **" },
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
