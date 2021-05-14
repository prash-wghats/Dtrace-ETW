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
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 * Copyright (C) 2019, PK.
 */

#ifndef _SYS_SDT_IMPL_H
#define	_SYS_SDT_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/dtrace.h>

#if defined(__i386) || defined(__amd64)
typedef uint8_t sdt_instr_t;
#else
typedef uint32_t sdt_instr_t;
#endif

int sdt_attach();
int sdt_detach();

typedef struct sdt_etw_event sdt_etw_event_t;

typedef struct sdt_provider {
	char *sdtp_name;			/* name of provider */
	char *sdtp_prefix;			/* prefix for probe names */
	dtrace_pattr_t *sdtp_attr;		/* stability attributes */
	sdt_etw_event_t *sdtp_etw;	/* etw events */
	uint32_t sdtp_priv;				/* privilege, if any */
	dtrace_provider_id_t sdtp_id;	/* provider ID */
	uint32_t sdtp_nprobes;
} sdt_provider_t;

extern sdt_provider_t sdt_providers[];		/* array of providers */

typedef struct sdt_probe {
	sdt_provider_t	*sdp_provider;		/* provider */
	char		*sdp_name;		/* name of probe */
	int		sdp_namelen;		/* length of allocated name */
	dtrace_id_t	sdp_id;			/* probe ID */
	sdt_etw_event_t	*sdp_ctl;		/* etw for probe */
	int		sdp_loadcnt;		/* load count for module */
	int		sdp_primary;		/* non-zero if primary mod */
	sdt_instr_t	*sdp_patchpoint;	/* patch point */
	sdt_instr_t	sdp_patchval;		/* instruction to patch */
	sdt_instr_t	sdp_savedval;		/* saved instruction value */
	struct sdt_probe *sdp_next;		/* next probe */
	struct sdt_probe *sdp_hashnext;		/* next on hash */
} sdt_probe_t;

typedef struct sdt_argdesc {
	const char *sda_provider;		/* provider for arg */
	const char *sda_name;			/* name of probe */
	const int sda_ndx;			/* argument index */
	const int sda_mapping;			/* mapping of argument */
	const char *sda_native;			/* native type of argument */
	const char *sda_xlate;			/* translated type of arg */
} sdt_argdesc_t;

extern void sdt_getargdesc(void *, dtrace_id_t, void *, dtrace_argdesc_t *);

#define	SDT_TRACE_ENABLE_STACK	1
#define SDT_TRACE_ENABLE_CAPTURESTATE 2
#define SDT_TRACE_ENABLE_PMC_SAMPLE 4
#define SDT_TRACE_ENABLE_PMC_COUNTER 8
#define SDT_TRACE_PROBE_ENABLED 0x8000
#define SDT_TRACE_EXTENDED 0x10000

#define ISENABLED(sdt)	((sdt)->sdp_ctl->etw_flags & SDT_TRACE_PROBE_ENABLED)

typedef struct {
	long pmc_i;
	long pmc_int;
	int pmc_seqno;
} pmc_data_t;

struct sdt_etw_event {
	char *etw_nprov;
	char *etw_type;
	char *etw_name;
	const GUID *etw_guid;
	int etw_eventno;
	int (*etw_cb) (PEVENT_RECORD, void *, sdt_probe_t *, uint64_t *);
	const GUID *etw_bguid;
	int (*etw_bcb) (PEVENT_RECORD, void *);
	uint64_t etw_kw;
	int etw_opcode;
	uint64_t etw_flags;
	void *etw_data;
};

typedef void (*sdt_create_probe_t) (sdt_provider_t *prov, sdt_etw_event_t *etw, char *mod,
    char *func);
void etw_dynamic_probes(dtrace_probedesc_t *desc, sdt_provider_t *prov,
	sdt_create_probe_t sdt_create_probe);
void etw_provider_dynamic_probes(dtrace_probedesc_t *desc, sdt_provider_t *prov,
	sdt_create_probe_t sdt_create_probe);
int addextendeddata(sdt_probe_t *sdt, PEVENT_RECORD ev, uint64_t *arg4);
void etw_kernel_probe_extra(int sessionid, sdt_etw_event_t *etw);
int etw_userprov_enable(sdt_etw_event_t *etw, int stackon);
void sdt_add_providers(etw_provinfo_t *lprov, void *attr, void *funcs);
char *sdt_guid_str(GUID * g);
int sdt_etw_diag_cb(PEVENT_RECORD ev, void *data);
char *
payloadhdr(PEVENT_RECORD ev, int hdrsize, USHORT id, UCHAR arch, UCHAR version);
enum {

	SDT_MSGHDR_SIZE = 4,
	SDT_MSGHDRLOC_ARCH = 3,
	SDT_MSGHDRLOC_VERSION = 2,
	SDT_MSGHDRLOC_ID = 0
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SDT_IMPL_H */
