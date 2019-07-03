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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 * Copyright (c) 2013, 2014 by Delphix. All rights reserved.
 * Copyright (C) 2019, PK.
 */

#include <sys/dtrace_misc.h>

#include <sys/dtrace_win32.h>
#include <sys/dtrace.h>
#include <evntrace.h>
#include <tdh.h>
#include "etw.h"
#include "etw_struct.h"
#include "sdt.h"

#define	SDT_PATCHVAL	0xf0
#define	SDT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & sdt_probetab_mask)
#define	SDT_PROBETAB_SIZE	0x1000		/* 4k entries -- 16K total */

#define	cmn_err fprintf
#undef CE_WARN
#define	CE_WARN stderr

static int			sdt_verbose = 0;
static sdt_probe_t		**sdt_probetab;
static int			sdt_probetab_size;
static int			sdt_probetab_mask;
static char			*sdt_temp_vars;
static char 		*sdt_temp_off;
static int			sdt_temp_size = 1024 * 256;


/*ARGSUSED*/
static void
sdt_provide(void *arg, dtrace_probedesc_t *desc)
{
	sdt_probe_t *sdp;
	sdt_provider_t *prov0, *prov = arg ? arg : sdt_providers;
	sdt_etw_provider_t *etwp, *etw;
	int len;
	dtrace_id_t id;
	char *sname;

	/*
	 * One for all, and all for one:  if we haven't yet registered all of
	 * our providers, we'll refuse to provide anything.
	 */
	for (prov0 = sdt_providers; prov0->sdtp_name != NULL; prov0++) {
		if (prov0->sdtp_id == DTRACE_PROVNONE)
			return;
	}

	do {
		etwp = prov->sdtp_etw;

		for (etw = etwp; etw != NULL && etw->etw_nprov != NULL; etw++) {
			sname = kmem_alloc((len = strlen(etw->etw_name)) + 1,
			    KM_SLEEP);
			strncpy(sname, etw->etw_name, len);
			sname[len] = '\0';

			/*
			 * We have our provider.  Now create the probe.
			 */
			if ((id = dtrace_probe_lookup(prov->sdtp_id, NULL,
			    NULL, sname)) != DTRACE_IDNONE) {
				continue;
			} else {
				sdp = kmem_zalloc(sizeof (sdt_probe_t),
				    KM_SLEEP);
				sdp->sdp_name = sname;
				sdp->sdp_namelen = len;
				sdp->sdp_provider = prov;
				sdp->sdp_ctl = etw;
				sdp->sdp_id = dtrace_probe_create(prov->sdtp_id,
				    NULL, NULL, sname, 3, sdp);
			}
			sdp->sdp_hashnext =
			    sdt_probetab[SDT_ADDR2NDX(etw->etw_guid->Data1)];
			sdt_probetab[SDT_ADDR2NDX(etw->etw_guid->Data1)] = sdp;
			sdp->sdp_patchval = etw->etw_eventno;
			sdp->sdp_patchpoint =
			    (sdt_instr_t *) etw->etw_guid->Data1;
		}
	} while (!arg && (++prov)->sdtp_name != NULL);
}

/*ARGSUSED*/
static void
sdt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t *sdp = parg, *old, *last, *hash;
	int ndx;

	while (sdp != NULL) {
		old = sdp;

		/*
		 * Now we need to remove this probe from the sdt_probetab.
		 */
		ndx = SDT_ADDR2NDX(sdp->sdp_patchpoint);
		last = NULL;
		hash = sdt_probetab[ndx];

		while (hash != sdp) {
			ASSERT(hash != NULL);
			last = hash;
			hash = hash->sdp_hashnext;
		}

		if (last != NULL) {
			last->sdp_hashnext = sdp->sdp_hashnext;
		} else {
			sdt_probetab[ndx] = sdp->sdp_hashnext;
		}
		kmem_free(sdp->sdp_name, sdp->sdp_namelen);
		sdp = sdp->sdp_next;
		kmem_free(old, sizeof (sdt_probe_t));
	}
}

/*ARGSUSED*/
static int
sdt_enable(void *arg, dtrace_id_t id, void *parg, int stackon)
{
	sdt_probe_t *sdp = parg;
	sdt_etw_provider_t *etw = sdp->sdp_ctl;
	int  r = 0;

	if (etw->etw_bcb)
		dtrace_etw_hook_event(etw->etw_bguid, etw->etw_bcb,
		    NULL, ETW_EVENTCB_ORDER_FRIST);
	if (etw->etw_cb)
		dtrace_etw_hook_event(etw->etw_guid, etw->etw_cb,
		    NULL, ETW_EVENTCB_ORDER_ANY);
	if (etw->etw_eventno > 0) {
		CLASSIC_EVENT_ID id[1];

		if (sdp->sdp_provider->sdtp_etw_flags) {
			dtrace_etw_prov_enable(
			    sdp->sdp_provider->sdtp_etw_flags);
		}

		id[0].EventGuid = *etw->etw_guid;
		id[0].Type = etw->etw_eventno;

		dtrace_etw_kernel_stack_enable(id, 1);
	} else if (etw->etw_eventno == -1) {
		uint64_t kw =  etw->etw_kw;
		r = dtrace_etw_uprov_enable(etw->etw_guid, kw,
		    etw->etw_eventno, TRACE_LEVEL_VERBOSE, stackon);
		sdp->sdp_provider->sdtp_etw_flags = kw;

	} else  if (etw->etw_eventno == -2) {
		dtrace_etw_set_diagnostic(etw->etw_cb, id);
	}
	return (r);
}

/*ARGSUSED*/
static void
sdt_disable(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t *sdp = parg;
	sdt_etw_provider_t *etw = sdp->sdp_ctl;

	if (sdp->sdp_provider->sdtp_etw_flags)
		dtrace_etw_prov_disable(sdp->sdp_provider->sdtp_etw_flags);
	if (etw->etw_bcb)
		dtrace_etw_unhook_event(etw->etw_bguid, etw->etw_bcb, NULL);
	if (etw->etw_cb)
		dtrace_etw_unhook_event(etw->etw_guid, etw->etw_cb, NULL);
}

static /*ARGSUSED*/
uint64_t
sdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
	uintptr_t val = 0;

	return (val);
}

static dtrace_pops_t sdt_pops = {
	sdt_provide,
	NULL,
	sdt_enable,
	sdt_disable,
	NULL,
	NULL,
	sdt_getargdesc,
	sdt_getarg,
	NULL,
	sdt_destroy
};

static dtrace_pattr_t stab_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ETW },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

/*
 * provide temporary memory to hold data,
 * being sent to user of dtrace
 */
#define	ALIGNMENT 4
void *
sdt_temp_mem(int size)
{
	size = ((size + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT;
	if ((sdt_temp_off - sdt_temp_vars)+size > sdt_temp_size)
		sdt_temp_off = sdt_temp_vars;
	void *tmp = sdt_temp_off;
	sdt_temp_off += size;

	return (tmp);
}

static sdt_etw_provider_t *
sdt_guid_kw0(etw_provinfo_t *pprov, int (*cb) (PEVENT_RECORD, void *))
{
	etw_provkw_t *pkw;
	sdt_etw_provider_t *etwp = NULL, *tmp;
	int num = 0;

	/*
	 * The first call can fail with ERROR_NOT_FOUND if none
	 * of the provider's event descriptions contain the
	 * requested field type information.
	 */
	num = pprov->provnkw;
	etwp = kmem_zalloc(sizeof (sdt_etw_provider_t)*(num+2), 0);

	/*
	 * Loop through the list of field information and print
	 * the field's name, description (if it exists), and value.
	 */
	etwp[0].etw_nprov = pprov->provn;
	etwp[0].etw_name = "events";
	etwp[0].etw_guid = &pprov->provg;
	etwp[0].etw_cb = cb;
	etwp[0].etw_eventno = -1;
	/*
	 * 0 for a manifest-based provider or TraceLogging provider and
	 * 0xFFFFFFFF for a classic provider.
	 */
	etwp[0].etw_kw = 0;		/* ~ (uint64_t) 0; */
	pkw = pprov->provkw;

	for (int j = 0; j < num; j++) {
		etwp[j+1].etw_nprov = pprov->provn;
		etwp[j+1].etw_guid = &pprov->provg;
		etwp[j+1].etw_cb = cb;
		etwp[j+1].etw_name = pkw[j].kwn;
		etwp[j+1].etw_kw =  pkw[j].kwv;
		etwp[j+1].etw_eventno = -1;
	}

	tmp = &etwp[num+1];
	tmp = NULL;

	return (etwp);
}

static int
sdt_etw_guid_cb(PEVENT_RECORD ev, void *data)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	USHORT event = ev->EventHeader.EventDescriptor.Id;
	sdt_probe_t *sdt;
	void *payload = sdt_temp_mem(ev->UserDataLength);

	memcpy(payload, ev->UserData, ev->UserDataLength);
	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_ctl->etw_kw == 0 ||
			    (sdt->sdp_ctl->etw_kw &
			    ev->EventHeader.EventDescriptor.Keyword)) {
				/*
				 * each event might trigger multiple probes.
				 * so set current pid & tid for each probe,
				 * since the current process might change
				 * if the session Queue has filled up, which
				 * will trigger sending of a probe.
				 */
				HANDLE *lock = dtrace_etw_set_cur(
				    ev->EventHeader.ProcessId,
				    ev->EventHeader.ThreadId,
				    ev->EventHeader.TimeStamp.QuadPart,
				    ev->BufferContext.ProcessorNumber);
				dtrace_etw_probe(sdt->sdp_id, event, opcode,
				    payload, ev->UserDataLength, 0, FALSE);
				dtrace_etw_reset_cur(lock);
			}
		}
	}

	return (0);
}

static void
sdt_add_providers(etw_provinfo_t *lprov)
{
	sdt_provider_t *prov = NULL;
	GUID *pguid = NULL;

	if (lprov == NULL)
		return;

	do {
		prov = kmem_zalloc(sizeof (sdt_provider_t), 0);
		if (prov == NULL) {
			dprintf("Allocation failed (size=%lld).\n",
			    sizeof (sdt_provider_t));
			break;
		}

		prov->sdtp_name = lprov->provn;
		prov->sdtp_attr = &stab_attr;
		prov->sdtp_etw = sdt_guid_kw0(lprov, sdt_etw_guid_cb);

		if (dtrace_register(prov->sdtp_name, prov->sdtp_attr,
		    DTRACE_PRIV_KERNEL, NULL, &sdt_pops,
		    prov, &prov->sdtp_id) != 0) {
			cmn_err(CE_WARN, "failed to register sdt provider %s",
			    prov->sdtp_name);
		}
	} while ((++lprov)->provn != NULL);
}

/*ARGSUSED*/
int
sdt_attach()
{
	sdt_provider_t *prov;

	if (sdt_probetab_size == 0)
		sdt_probetab_size = SDT_PROBETAB_SIZE;

	sdt_probetab_mask = sdt_probetab_size - 1;
	sdt_probetab =
	    kmem_zalloc(sdt_probetab_size * sizeof (sdt_probe_t *), KM_SLEEP);
	sdt_temp_vars =
	    kmem_zalloc(sdt_temp_size, KM_SLEEP);
	sdt_temp_off = sdt_temp_vars;

	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (dtrace_register(prov->sdtp_name, prov->sdtp_attr,
		    DTRACE_PRIV_KERNEL, NULL, &sdt_pops,
		    prov, &prov->sdtp_id) != 0) {
			cmn_err(CE_WARN, "failed to register sdt provider %s",
			    prov->sdtp_name);
		}
	}

	sdt_add_providers(dtrace_etw_user_providers());

	return (0);
}

/*ARGSUSED*/
int
sdt_detach()
{
	sdt_provider_t *prov;

	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (prov->sdtp_id != DTRACE_PROVNONE) {
			if (dtrace_unregister(prov->sdtp_id) != 0)
				return (-1);
			prov->sdtp_id = DTRACE_PROVNONE;
		}
	}

	kmem_free(sdt_probetab, sdt_probetab_size * sizeof (sdt_probe_t *));

	return (0);
}


/* Process CB */
int
sdt_etw_procp_cb(PEVENT_RECORD ev, void *data)
{
	proc_t *p = curproc;
	sdt_probe_t *sdt;

	if (p == NULL)
		return (-1);

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (ev->EventHeader.EventDescriptor.Opcode ==
			    sdt->sdp_patchval) {
				if (sdt->sdp_patchval == 1) {
					dtrace_etw_probe(sdt->sdp_id, p, 0,
					    0, 0, 0, FALSE);
				} else if (sdt->sdp_patchval == 2) {
					dtrace_etw_probe(sdt->sdp_id,
					    p->exitval, 0,
					    0, 0, 0, FALSE);
				}
			}
		}
	}

	return (0);
}

/* Thread CB */
int
sdt_etw_proct_cb(PEVENT_RECORD ev, void *data)
{
	thread_t *td = curthread;
	sdt_probe_t *sdt;

	if (td == NULL)
		return (-1);

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (ev->EventHeader.EventDescriptor.Opcode ==
			    sdt->sdp_patchval) {
				if (sdt->sdp_patchval == 1) {
					dtrace_etw_probe(sdt->sdp_id, td, 0,
					    0, 0, 0, FALSE);
				} else if (sdt->sdp_patchval == 2) {
					dtrace_etw_probe(sdt->sdp_id, 0, 0,
					    0, 0, 0, FALSE);
				}
			}
		}
	}

	return (0);
}

/* DiskIO CB */
int
sdt_etw_diskio_cb(PEVENT_RECORD ev, void *data)
{
	buf_t *buf = sdt_temp_mem(sizeof (buf_t));
	struct DiskIo_TypeGroup1 *d1;
	struct DiskIo_TypeGroup2 *d2;
	struct DiskIo_TypeGroup3 *d3;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	sdt_probe_t *sdt;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &DiskIoGuid));

	switch (opcode) {
	case 12:	/* Read Initiate */
	case 13:	/* Write Initiate */
	case 15:	/* Flush Initiate */
		d2 = (struct DiskIo_TypeGroup2 *) ev->UserData;
		dtrace_etw_td_find(ev->EventHeader.ProcessId,
		    d2->IssuingThreadId, ETW_SET_CURRENT);
		buf->b_irpaddr = d2->Irp;
		buf->b_flags = opcode == 12 ? 1 : (opcode == 13 ? 2 : 4);
		break;
	case 14:		/* flush done */
		d3 = (struct DiskIo_TypeGroup3 *) ev->UserData;
		dtrace_etw_td_find(ev->EventHeader.ProcessId,
		    d3->IssuingThreadId, ETW_SET_CURRENT);
		buf->b_irpaddr = d3->Irp;
		buf->b_diskno = d3->DiskNumber;
		buf->b_irpflags = d3->IrpFlags;
		buf->b_resptm = d3->HighResResponseTime;
		buf->b_flags = 4;
		break;
	case 10:		/* Read Complete */
	case 11:		/* Write Complete */
		d1 = (struct DiskIo_TypeGroup1 *) ev->UserData;
		dtrace_etw_td_find(ev->EventHeader.ProcessId,
		    d1->IssuingThreadId, ETW_SET_CURRENT);
		buf->b_irpaddr = d1->Irp;
		buf->b_diskno = d1->DiskNumber;
		buf->b_irpflags = d1->IrpFlags;
		buf->b_resptm = d1->HighResResponseTime;
		buf->b_bcount = d1->TransferSize;
		buf->b_offset = d1->ByteOffset;
		buf->b_fname = dtrace_etw_get_fname(d1->FileObject);
		buf->b_flags = opcode == 10 ? 1 : 2;
		break;
	default:
		break;
	}

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_patchval == 10 && (opcode == 10 ||
			    opcode == 11 || opcode == 14)) {
				dtrace_etw_probe(sdt->sdp_id, buf, 0,
				    0, 0, 0, FALSE);
			} else if (sdt->sdp_patchval == 12 && (opcode == 12 ||
			    opcode == 13 || opcode == 15)) {
				dtrace_etw_probe(sdt->sdp_id, buf, 0,
				    0, 0, 0, FALSE);
			}
		}
	}

	return (0);
}

int
sdt_etw_tcpip_cb(PEVENT_RECORD ev, void *data)
{
	tcpip_msg_t *ip = sdt_temp_mem(sizeof (tcpip_msg_t));
	tcpip_fail_t fail = {0};
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	sdt_probe_t *sdt;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &TcpIpGuid));

	if (ev->EventHeader.EventDescriptor.Version == 0) {
		switch (opcode) {
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15: {
			struct TcpIp_V0_TypeGroup1 *msg =
			    (struct TcpIp_V0_TypeGroup1 *) ev->UserData;
			ip->ti_ver = AF_INET;
			ip->ti_dport = msg->dport;
			ip->ti_sport = msg->sport;
			ip->ti_addr.ip4.daddr = msg->daddr;
			ip->ti_addr.ip4.saddr = msg->saddr;
			ip->ti_pid = msg->PID;
			ip->ti_size = msg->size;
			break;
		}
		default:
			break;
		}
	} else {
		switch (opcode) {
		case 10: {
			struct TcpIp_SendIPV4 *msg =
			    (struct TcpIp_SendIPV4 *) ev->UserData;
			ip->ti_ver = AF_INET;
			ip->ti_addr.ip4.daddr = msg->daddr;
			ip->ti_addr.ip4.saddr = msg->saddr;
			ip->ti_dport = msg->dport;
			ip->ti_sport = msg->sport;
			ip->ti_pid = msg->PID;
			ip->ti_size = msg->size;
			ip->ti_starttime = msg->starttime;
			ip->ti_endtime = msg->endtime;
			ip->ti_connid = msg->connid;
			ip->ti_seqnum = msg->seqnum;
			break;
		}
		case 26: {
			struct TcpIp_SendIPV6 *msg =
			    (struct TcpIp_SendIPV6 *) ev->UserData;
			ip->ti_ver = AF_INET6;
			ip->ti_addr.ip6.daddr = msg->daddr;
			ip->ti_addr.ip6.saddr = msg->saddr;
			ip->ti_dport = msg->dport;
			ip->ti_sport = msg->sport;
			ip->ti_pid = msg->PID;
			ip->ti_size = msg->size;
			ip->ti_starttime = msg->starttime;
			ip->ti_endtime = msg->endtime;
			ip->ti_connid = msg->connid;
			ip->ti_seqnum = msg->seqnum;
			opcode = 10;
			break;
		}
		case 11:
		case 13:
		case 14:
		case 16:
		case 18: {
			struct TcpIp_TypeGroup1 *msg =
			    (struct TcpIp_TypeGroup1 *) ev->UserData;
			ip->ti_ver = AF_INET;
			ip->ti_addr.ip4.daddr = msg->daddr;
			ip->ti_addr.ip4.saddr = msg->saddr;
			ip->ti_dport = msg->dport;
			ip->ti_sport = msg->sport;
			ip->ti_addr.ip4.daddr = msg->daddr;
			ip->ti_addr.ip4.saddr = msg->saddr;
			ip->ti_pid = msg->PID;
			ip->ti_size = msg->size;
			ip->ti_connid = msg->connid;
			ip->ti_seqnum = msg->seqnum;
			break;
		}
		case 12:
		case 15: {
			struct TcpIp_TypeGroup2 *msg =
			    (struct TcpIp_TypeGroup2 *) ev->UserData;
			ip->ti_ver = AF_INET;
			ip->ti_addr.ip4.daddr = msg->daddr;
			ip->ti_addr.ip4.saddr = msg->saddr;
			ip->ti_dport = msg->dport;
			ip->ti_sport = msg->sport;
			ip->ti_pid = msg->PID;
			ip->ti_size = msg->size;
			ip->ti_connid = msg->connid;
			ip->ti_seqnum = msg->seqnum;
			ip->ti_mss = msg->mss;
			ip->ti_sackopt = msg->sackopt;
			ip->ti_tsopt = msg->tsopt;
			ip->ti_wsopt = msg->wsopt;
			ip->ti_rcvwin = msg->rcvwin;
			ip->ti_rcvwinscale = msg->rcvwinscale;
			ip->ti_sndwinscale = msg->sndwinscale;
			break;
		}
		case 27:
		case 29:
		case 30:
		case 32:
		case 34: {
			struct TcpIp_TypeGroup3 *msg =
			    (struct TcpIp_TypeGroup3 *) ev->UserData;
			ip->ti_ver = AF_INET6;
			ip->ti_dport = msg->dport;
			ip->ti_sport = msg->sport;
			ip->ti_addr.ip6.daddr = msg->daddr;
			ip->ti_addr.ip6.saddr = msg->saddr;
			ip->ti_pid = msg->PID;
			ip->ti_size = msg->size;
			ip->ti_connid = msg->connid;
			ip->ti_seqnum = msg->seqnum;
			opcode -= 16;
			break;
		}
		case 28:
		case 31: {
			struct TcpIp_TypeGroup4 *msg =
			    (struct TcpIp_TypeGroup4 *) ev->UserData;
			ip->ti_ver = AF_INET6;
			ip->ti_dport = msg->dport;
			ip->ti_sport = msg->sport;
			ip->ti_addr.ip6.daddr = msg->daddr;
			ip->ti_addr.ip6.saddr = msg->saddr;
			ip->ti_pid = msg->PID;
			ip->ti_size = msg->size;
			ip->ti_connid = msg->connid;
			ip->ti_seqnum = msg->seqnum;
			ip->ti_mss = msg->mss;
			ip->ti_sackopt = msg->sackopt;
			ip->ti_tsopt = msg->tsopt;
			ip->ti_wsopt = msg->wsopt;
			ip->ti_rcvwin = msg->rcvwin;
			ip->ti_rcvwinscale = msg->rcvwinscale;
			ip->ti_sndwinscale = msg->sndwinscale;
			opcode -= 16;
			break;
		}
		case 17: {
			struct TcpIp_Fail *msg =
			    (struct TcpIp_Fail *) ev->UserData;
			fail.ti_code = msg->FailureCode;
			fail.ti_proto = msg->Proto;
			break;
		}
		default:
			return (-1);
		}
	}

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_patchval == opcode) {
				if (sdt->sdp_patchval == 17) {
					dtrace_etw_probe(sdt->sdp_id,
					    fail.ti_proto, fail.ti_code,
					    0, 0, 0, FALSE);
				} else {
					dtrace_etw_probe(sdt->sdp_id, ip, 0,
					    0, 0, 0, FALSE);
				}
			} else if ((opcode == 26 && sdt->sdp_patchval == 10) ||
			    (opcode == 27 && sdt->sdp_patchval == 11) ||
			    (opcode == 28 && sdt->sdp_patchval == 12) ||
			    (opcode == 29 && sdt->sdp_patchval == 13) ||
			    (opcode == 30 && sdt->sdp_patchval == 14) ||
			    (opcode == 31 && sdt->sdp_patchval == 15) ||
			    (opcode == 32 && sdt->sdp_patchval == 16) ||
			    (opcode == 34 && sdt->sdp_patchval == 18)) {

				dtrace_etw_probe(sdt->sdp_id, ip, 0,
				    0, 0, 0, FALSE);
			}
		}
	}

	return (0);
}

int
sdt_etw_udpip_cb(PEVENT_RECORD ev, void *data)
{
	udpip_msg_t *ip = sdt_temp_mem(sizeof (udpip_msg_t));
	udpip_fail_t fail = {0};
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	sdt_probe_t *sdt;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &UdpIpGuid));

	if (ev->EventHeader.EventDescriptor.Version == 0) {
		switch (opcode) {
		case 10:
		case 11: {
			struct UdpIp_V0_TypeGroup1 *msg =
			    (struct UdpIp_V0_TypeGroup1 *) ev->UserData;
			ip->ui_ver = AF_INET;
			ip->ui_dport = msg->dport;
			ip->ui_sport = msg->sport;
			ip->ui_addr.ip4.daddr = msg->daddr;
			ip->ui_addr.ip4.saddr = msg->saddr;
			ip->ui_pid = msg->context;
			if (ev->EventHeader.EventDescriptor.Opcode == 10)
				ip->ui_size = msg->size;
			else
				ip->ui_size = msg->dsize;
			break;
		}
		default:
			break;
		}
	} else {
		switch (opcode) {
		case 10:
		case 11: {
			struct UdpIp_TypeGroup1 *msg =
			    (struct UdpIp_TypeGroup1 *) ev->UserData;
			ip->ui_ver = AF_INET;
			ip->ui_dport = msg->dport;
			ip->ui_sport = msg->sport;
			ip->ui_addr.ip4.daddr = msg->daddr;
			ip->ui_addr.ip4.saddr = msg->saddr;
			ip->ui_pid = msg->PID;
			ip->ui_size = msg->size;
			ip->ui_connid = msg->connid;
			ip->ui_seqnum = msg->seqnum;
			break;
		}
		case 26:
		case 27: {
			struct UdpIp_TypeGroup2 *msg =
			    (struct UdpIp_TypeGroup2 *) ev->UserData;
			ip->ui_ver = AF_INET6;
			ip->ui_dport = msg->dport;
			ip->ui_sport = msg->sport;
			ip->ui_addr.ip6.daddr = msg->daddr;
			ip->ui_addr.ip6.saddr = msg->saddr;
			ip->ui_pid = msg->PID;

			ip->ui_size = msg->size;
			ip->ui_connid = msg->connid;
			ip->ui_seqnum = msg->seqnum;
			break;
		}
		case 17: {
			struct UdpIp_Fail *msg =
			    (struct UdpIp_Fail *) ev->UserData;
			fail.ti_code = msg->FailureCode;
			fail.ti_proto = msg->Proto;
			break;
		}
		default:
			return (-1);
		}
	}

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_patchval == opcode) {
				if (sdt->sdp_patchval == 17) {
					dtrace_etw_probe(sdt->sdp_id,
					    fail.ti_proto, fail.ti_code,
					    0, 0, 0, FALSE);
				} else {
					dtrace_etw_probe(sdt->sdp_id, ip, 0,
					    0, 0, 0, FALSE);
				}
			} else if ((opcode == 26 &&
			    sdt->sdp_patchval == 10) ||
			    (opcode == 27 && sdt->sdp_patchval == 11)) {
				dtrace_etw_probe(sdt->sdp_id, ip, 0,
				    0, 0, 0, FALSE);
			}
		}
	}

	return (0);
}

int
sdt_etw_fileio_cb(PEVENT_RECORD ev, void *data)
{
	struct wfileinfo *info = sdt_temp_mem(sizeof (wfileinfo_t));
	struct dirinfo dinfo = {0};
	size_t len;
	wchar_t *fname;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	sdt_probe_t *sdt;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &FileIoGuid));

	ZeroMemory(info, sizeof (wfileinfo_t));
	switch (ev->EventHeader.EventDescriptor.Opcode) {
	case 0:
	case 32:
	case 35: {
		struct FileIo_Name *fio =
		    (struct FileIo_Name *) ev->UserData;
		info->f_name = dtrace_etw_get_fname(fio->FileObject);
		break;
	}
	case 64: {
		struct FileIo_Create *fio =
		    (struct FileIo_Create *) ev->UserData;
		len = wcslen((wchar_t *) &fio->OpenPath);
		fname = (wchar_t *) malloc((len + 2) * sizeof (wchar_t));
		wcsncpy(fname, (const wchar_t *) &fio->OpenPath, len);
		fname[len] = L'\0';
		info->f_name = fname;
		info->f_createopt = fio->CreateOptions;
		info->f_fileattrib = fio->FileAttributes;
		info->f_fileobj =  fio->FileObject;
		info->f_irpptr = fio->IrpPtr;
		info->f_shareflags = fio->ShareAccess;
		info->f_tid = fio->TTID;
		break;
	}
	case 69:
	case 70:
	case 71:
	case 74:
	case 75: {
		struct FileIo_Info *fio =
		    (struct FileIo_Info *) ev->UserData;
		info->f_fileobj =  fio->FileObject;
		info->f_irpptr = fio->IrpPtr;
		info->f_tid = fio->TTID;
		info->f_name = dtrace_etw_get_fname(fio->FileKey);
		info->f_extinfo = fio->ExtraInfo;
		info->f_infoclass = fio->InfoClass;
		break;
	}
	case 65:
	case 66:
	case 73: {
		struct FileIo_SimpleOp *fio =
		    (struct FileIo_SimpleOp *) ev->UserData;
		info->f_fileobj =  fio->FileObject;
		info->f_irpptr = fio->IrpPtr;
		info->f_tid = fio->TTID;
		info->f_name = dtrace_etw_get_fname(fio->FileKey);
		break;
	}
	case 67:		/* read */
	case 68: {		/* write */
		struct FileIo_ReadWrite *fio =
		    (struct FileIo_ReadWrite *) ev->UserData;
		info->f_fileobj =  fio->FileObject;
		info->f_irpptr = fio->IrpPtr;
		info->f_tid = fio->TTID;
		info->f_name = dtrace_etw_get_fname(fio->FileKey);
		info->f_iosize = fio->IoSize;
		info->f_ioflags = fio->IoFlags;
		info->f_offset = fio->Offset;
		break;
	}
	case 72:
	case 77: {
		struct FileIo_DirEnum *fio =
		    (struct FileIo_DirEnum *) ev->UserData;
		info->f_fileobj =  fio->FileObject;
		info->f_irpptr = fio->IrpPtr;
		info->f_tid = fio->TTID;
		info->f_name = dtrace_etw_get_fname(fio->FileKey);
		info->f_dlen = fio->Length;
		info->f_infoclass = fio->InfoClass;
		len = wcslen((wchar_t *) &fio->PatternSpec);
		fname = (wchar_t *) malloc((len + 2) * sizeof (wchar_t));
		wcsncpy(fname, (const wchar_t *) &fio->PatternSpec, len);
		fname[len] = L'\0';
		info->f_dpattspec = fname;
		info->f_dfileindex = fio->FileIndex;
		break;
	}
	case 76: {
		struct FileIo_OpEnd *fio =
		    (struct FileIo_OpEnd *) ev->UserData;
		info->f_irpptr = fio->IrpPtr;
		info->f_extinfo = fio->ExtraInfo;
		info->f_ntstatus = fio->NtStatus;
		break;
	}
	default:
		return (0);
	}

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_patchval == opcode) {
				if (sdt->sdp_patchval == 72 ||
				    sdt->sdp_patchval == 77) {
					dtrace_etw_probe(sdt->sdp_id, info, 0,
					    0, 0, 0, FALSE);
				} else {
					dtrace_etw_probe(sdt->sdp_id, info, 0,
					    0, 0, 0, FALSE);
				}
			} else if ((opcode == 32 && sdt->sdp_patchval == 64) ||
			    (opcode == 35 && sdt->sdp_patchval == 70)) {
				dtrace_etw_probe(sdt->sdp_id, info, 0,
				    0, 0, 0, FALSE);
			}
		}
	}

	return (0);
}

int
sdt_etw_reg_cb(PEVENT_RECORD ev, void *data)
{
	struct reginfo *rinfo = sdt_temp_mem(sizeof (reginfo_t));
	size_t len;
	wchar_t *rname, *name;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	sdt_probe_t *sdt;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &RegistryGuid));

	switch (ev->EventHeader.EventDescriptor.Version) {
	case 0: {
		struct Registry_V0_TypeGroup1 *reg =
		    (struct Registry_V0_TypeGroup1 *) ev->UserData;
		rinfo->r_status = reg->Status;
		rinfo->r_handle = reg->KeyHandle;
		rinfo->r_time = reg->ElapsedTime;
		rname = (wchar_t *) &reg->KeyName;
		break;
	}
	case 1: {
		struct Registry_V1_TypeGroup1 *reg =
		    (struct Registry_V1_TypeGroup1 *) ev->UserData;
		rinfo->r_status = reg->Status;
		rinfo->r_handle = reg->KeyHandle;
		rinfo->r_time = reg->ElapsedTime;
		rinfo->r_index = reg->Index;
		rname = (wchar_t *) &reg->KeyName;
		break;
	}
	case 2: {
		struct Registry_TypeGroup1 *reg =
		    (struct Registry_TypeGroup1 *) ev->UserData;
		rinfo->r_status = reg->Status;
		rinfo->r_handle = reg->KeyHandle;
		rinfo->r_time = reg->InitialTime;
		rinfo->r_index = reg->Index;
		rname = (wchar_t *) &reg->KeyName;
		break;
	}

	default:
		ASSERT(0);
	}

	len = wcslen(rname);
	name = (wchar_t *) malloc((len+2) * sizeof (wchar_t));
	wcsncpy(name, rname, len);
	name[len] = L'\0';
	rinfo->r_name = name;

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_patchval == opcode) {
				dtrace_etw_probe(sdt->sdp_id, rinfo, 0,
				    0, 0, 0, FALSE);
			}
		}
	}
	return (0);
}

int
sdt_etw_pf_cb(PEVENT_RECORD ev, void *data)
{
	struct vminfo vinfo = {0};
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	sdt_probe_t *sdt;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &PageFaultGuid));

	switch (opcode) {
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
	case 15: {
		struct PageFault_TypeGroup1 *vm =
		    (struct PageFault_TypeGroup1 *) ev->UserData;
		vinfo.va = vm->VirtualAddress;
		vinfo.pc = vm->ProgramCounter;
		break;
	}
	case 32: {
		struct PageFault_HardFault *vm =
		    (struct PageFault_HardFault *) ev->UserData;
		vinfo.time = vm->InitialTime;
		vinfo.tid = vm->TThreadId;
		vinfo.va = vm->VirtualAddress;
		vinfo.fname = dtrace_etw_get_fname(vm->FileObject);
		vinfo.nbyte = vm->ByteCount;
		vinfo.rdoffset = vm->ReadOffset;
		break;
	}
	case 98:
	case 99: {
		struct PageFault_VirtualAlloc *vm =
		    (struct PageFault_VirtualAlloc *) ev->UserData;
		vinfo.baseaddr = vm->BaseAddress;
		vinfo.flags = vm->Flags;
		vinfo.pid = vm->ProcessId;
		vinfo.regsz = vm->RegionSize;
		break;
	}
	case 105: {
		struct PageFault_ImageLoadBacked *vm =
		    (struct PageFault_ImageLoadBacked *) ev->UserData;
		vinfo.devchar = vm->DeviceChar;
		vinfo.filechar = vm->FileChar;
		vinfo.fname = dtrace_etw_get_fname(vm->FileObject);
		vinfo.flags = vm->LoadFlags;
		break;
	}
	default:
		return (-1);
	}

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_patchval == opcode) {
				switch (opcode) {	/* transition faults */
				case 10:
				case 11:
				case 12:
				case 13:
				case 14:
				case 15: {
					dtrace_etw_probe(sdt->sdp_id,
					    vinfo.va, vinfo.pc,
					    0, 0, 0, FALSE);
					break;
				}
				case 32: {		/* hard fault */
					dtrace_etw_probe(sdt->sdp_id,
					    vinfo.fname, vinfo.va,
					    vinfo.time, vinfo.rdoffset,
					    vinfo.tid, FALSE);
					break;
				}
				case 98:		/* virtalalloc */
				case 99: {		/* virtalfree */
					dtrace_etw_probe(sdt->sdp_id,
					    vinfo.baseaddr, vinfo.pid,
					    vinfo.regsz, vinfo.flags, 0, FALSE);
					break;
				}
				case 105: {		/* img load */
					dtrace_etw_probe(sdt->sdp_id,
					    vinfo.fname, vinfo.flags,
					    vinfo.devchar, vinfo.filechar,
					    0, FALSE);
					break;
				}
				default:
					ASSERT(0);
				}
			}
		}
	}

	return (0);
}

int
sdt_etw_sched_cb(PEVENT_RECORD ev, void *data)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	thread_t *oldtd, *newtd, *td;
	int on = 0;
	struct CSwitch *cs;
	sdt_probe_t *tsdt, *sdt;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &ThreadGuid));
	ASSERT(version >= 2);

	if (opcode != 36 && opcode != 50)
		return (1);

	/*
	 * Wait --> Ready (Queue) --> Run (Context switch)
	 */
	if (opcode == 36) {
		/*
		 * etw buffer cpu no represents the cpu of the
		 * context switch any thread stack represents the
		 * new thread stack, or the stack when it previously
		 * went into wait mode.So the off cpu stack will
		 * show up when it goes on-cpu.
		 */
		cs = (struct CSwitch *) ev->UserData;
		oldtd = dtrace_etw_td_find(-1, cs->OldThreadId, 0);
		newtd = dtrace_etw_td_find(-1, cs->NewThreadId, 0);
		oldtd->pri = cs->OldThreadPriority;
		oldtd->state = cs->OldThreadState;
		oldtd->waitr = cs->OldThreadWaitReason;
		oldtd->waitm = cs->OldThreadWaitMode;
		oldtd->wipr = cs->OldThreadWaitIdealProcessor;
		newtd->pri = cs->NewThreadPriority;
		newtd->waittm = cs->NewThreadWaitTime;
		newtd->cpu = ev->BufferContext.ProcessorNumber;
	} else {
		/*
		 * thread goes from wait to ready queue
		 * any thread stack could represents the readying thread,
		 * that satisfied whatever the waiting thread was waiting on.
		 */
		struct ReadyThread *rd = (struct ReadyThread *) ev->UserData;
		td = dtrace_etw_td_find(-1, rd->TThreadId, 0);
		td->rdflags = rd->AdjustIncrement;
		td->rdflags |= rd->Flags << 8;
		td->rdflags |= rd->AdjustReason << 16;
	}

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (opcode == 36 && sdt->sdp_patchval == 35) {
				/* off-cpu */
				HANDLE *lock = dtrace_etw_set_cur(oldtd->pid,
				    oldtd->tid,
				    ev->EventHeader.TimeStamp.QuadPart-1,
				    ev->BufferContext.ProcessorNumber);
				dtrace_etw_probe(sdt->sdp_id,
				    newtd, newtd->proc,
				    0, 0, 0, TRUE);
				dtrace_etw_reset_cur(lock);
			} else if (opcode == 36 && sdt->sdp_patchval == 36) {
				tsdt = sdt;
				on = 1;
			} else if (opcode == 50 && sdt->sdp_patchval == 50) {
				/* wakeup */
				HANDLE *lock = dtrace_etw_set_cur(
				    ev->EventHeader.ProcessId,
				    ev->EventHeader.ThreadId,
				    ev->EventHeader.TimeStamp.QuadPart,
				    ev->BufferContext.ProcessorNumber);
				dtrace_etw_probe(sdt->sdp_id, td, td->proc,
				    0, 0, 0, TRUE);
				dtrace_etw_reset_cur(lock);
			}
		}
	}

	if (on) {
		/* on-cpu */
		HANDLE *lock = dtrace_etw_set_cur(newtd->pid, newtd->tid,
		    ev->EventHeader.TimeStamp.QuadPart,
		    ev->BufferContext.ProcessorNumber);
		dtrace_etw_probe(tsdt->sdp_id, 0, 0,
		    0, 0, 0, TRUE);
		dtrace_etw_reset_cur(lock);
	}

	return (0);
}

int
sdt_etw_dpc_cb(PEVENT_RECORD ev, void *data)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	sdt_probe_t *sdt;
	struct DPC *dpc;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &PerfInfoGuid));

	if (opcode != 66 && opcode != 68 && opcode != 69)
		return (1);

	dpc = (struct DPC *) ev->UserData;
	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_patchval == opcode) {
				dtrace_etw_probe(sdt->sdp_id,
				    dpc->InitialTime, dpc->Routine,
				    0, 0, 0, FALSE);
			}
		}
	}

	return (0);
}

int
sdt_etw_isr_cb(PEVENT_RECORD ev, void *data)
{
	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &PerfInfoGuid));

	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	struct ISR *isr = (struct ISR *) ev->UserData;
	sdt_probe_t *sdt;

	if (opcode != 67)
		return (1);

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_patchval == opcode) {
				dtrace_etw_probe(sdt->sdp_id,
				    isr->InitialTime, isr->Routine,
				    isr->ReturnValue, isr->Vector, 0, FALSE);
			}
		}
	}

	return (0);
}

int
sdt_etw_syscall_cb(PEVENT_RECORD ev, void *data)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	sdt_probe_t *sdt;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &PerfInfoGuid));

	if (opcode != 51 && opcode != 52)
		return (1);

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_patchval == opcode) {
				if (opcode == 51)
					dtrace_etw_probe(sdt->sdp_id,
					    *((uint64_t *) ev->UserData), 0,
					    0, 0, 0, FALSE);
				else
					dtrace_etw_probe(sdt->sdp_id,
					    *((uint32_t *) ev->UserData), 0,
					    0, 0, 0, FALSE);
			}
		}
	}

	return (0);
}

#define	GUID_STR_SIZE	40

char *
sdt_guid_str(GUID *g)
{
	char *str = (char *) sdt_temp_mem(GUID_STR_SIZE);

	sprintf(str, "{%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x}",
	    g->Data1, g->Data2, g->Data3, g->Data4[0],
	    g->Data4[1], g->Data4[2], g->Data4[3], g->Data4[4],
	    g->Data4[5], g->Data4[6], g->Data4[7]);

	return (str);
}

int
sdt_etw_diag_cb(PEVENT_RECORD ev, void *data)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	USHORT event = ev->EventHeader.EventDescriptor.Id;
	uint32_t id = (uint32_t) data;
	void *pname = NULL;
	sdt_probe_t *sdt;

	ASSERT(id > 0);

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_ctl->etw_kw ==
			    ev->EventHeader.EventDescriptor.Keyword) {
				pname = sdt->sdp_ctl->etw_nprov;
			}
		}
	}

	if (pname == NULL) {
		pname = sdt_guid_str(&ev->EventHeader.ProviderId);
	}

	dtrace_etw_probe(id, pname, event, opcode,
	    0, 0, FALSE);

	return (0);
}

int
sdt_etw_lost_cb(PEVENT_RECORD ev, void *data)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	sdt_probe_t *sdt;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &RTLostEvent));

	sdt = sdt_probetab[SDT_ADDR2NDX(ev->EventHeader.ProviderId.Data1)];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint ==
		    ev->EventHeader.ProviderId.Data1) {
			if (sdt->sdp_patchval == opcode) {
				dtrace_etw_probe(sdt->sdp_id,
				    0, 0, 0, 0, 0, FALSE);
			}
		}
	}
	return (0);
}