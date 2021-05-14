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

static int
sdt_invop(PEVENT_RECORD ev, void *func)
{
	sdt_probe_t *sdt;
	void *pl = NULL;
	int loop = 0;
	uint32_t pp = SDT_ADDR2NDX(*(uint64_t *) &ev->EventHeader.ProviderId.Data2);
	sdt = sdt_probetab[pp];
	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		uint64_t stack[SDT_ARGMAX] = {0};
		if ((sdt->sdp_ctl->etw_flags & SDT_TRACE_PROBE_ENABLED) == 0 ||
			((sdt->sdp_ctl->etw_flags & SDT_TRACE_EXTENDED) && ev->ExtendedDataCount == 0))
			continue;
		if (IsEqualGUID(&ev->EventHeader.ProviderId, sdt->sdp_ctl->etw_guid)) {
			if (sdt->sdp_ctl->etw_cb(ev, 0, sdt, stack) != 0) {
				if (ev->ExtendedDataCount) {
					if (!addextendeddata(sdt, ev, stack)) {
						//dtrace_sdtmem_free(stack[SDT_ARGPL]);
						continue;
					}
				}
				dtrace_etw_probe_sdt(sdt->sdp_id, stack[SDT_ARG0], stack[SDT_ARG1],
				    stack[SDT_ARG2], stack[SDT_ARG3], stack[SDT_ARG4],
					stack[SDT_ARGSTACK], stack[SDT_ARGPL], stack[SDT_ARGEXTPL]);
				dtrace_etw_reset_cur(stack[SDT_CUR_LOCK]);
				loop++;
			}
		}
	}

	return (0);
}

static void
sdt_create_probe(sdt_provider_t *prov, sdt_etw_event_t *etw, char *mod,
    char *func)
{
	sdt_probe_t *sdp;
	dtrace_id_t id;
	char *sname;
	int len;

	sname = kmem_alloc((len = strlen(etw->etw_name)) + 1, KM_SLEEP);
	strncpy(sname, etw->etw_name, len);
	sname[len] = '\0';

	/*
	 * We have our provider.  Now create the probe.
	 */
	if ((id = dtrace_probe_lookup(prov->sdtp_id, mod,
	    func, sname)) != DTRACE_IDNONE) {
		return;
	}
	sdp = kmem_zalloc(sizeof (sdt_probe_t), KM_SLEEP);
	sdp->sdp_name = sname;
	sdp->sdp_namelen = len;
	sdp->sdp_provider = prov;
	sdp->sdp_ctl = etw;
	sdp->sdp_id = dtrace_probe_create(prov->sdtp_id,
	    mod, func, sname, 3, sdp);
	uint32_t pp = SDT_ADDR2NDX(*(uint64_t *) &etw->etw_guid->Data2);
	sdp->sdp_hashnext = sdt_probetab[pp];
	sdt_probetab[pp] = sdp;
	sdp->sdp_patchval = etw->etw_eventno == -1 ? etw->etw_opcode : etw->etw_eventno;
	sdp->sdp_patchpoint =
	    (sdt_instr_t *) *(uint64_t *) &etw->etw_guid->Data2;
}


/*ARGSUSED*/
static void
sdt_provide(void *arg, dtrace_probedesc_t *desc)
{
	sdt_probe_t *sdp;
	sdt_provider_t *prov0, *prov = arg ? arg : sdt_providers;
	sdt_etw_event_t *etwp, *etw;
	int len;
	dtrace_id_t id;
	char *sname, *mod = NULL, *func = NULL;

	/*
	 * One for all, and all for one:  if we haven't yet registered all of
	 * our providers, we'll refuse to provide anything.
	 */
	for (prov0 = sdt_providers; prov0->sdtp_name != NULL; prov0++) {
		if (prov0->sdtp_id == DTRACE_PROVNONE)
			return;
	}

	if (prov->sdtp_nprobes != 0) {
		/* dynamic probes for existing providers; currently PMC
		 * isr::pmc:isr-BranchInstructionRetired
		 */
		etw_dynamic_probes(desc, prov, sdt_create_probe);
		return;
	}

	for (etw = prov->sdtp_etw; etw != NULL && etw->etw_nprov != NULL; etw++) {
		sdt_create_probe(prov, etw, NULL/*etw->etw_nprov == NULL ? mod : etw->etw_nprov*/,
		    etw->etw_type == NULL ? func : etw->etw_type);
		prov->sdtp_nprobes++;
	}

	/* create dynamic provider probes; currently PMC provider
	 * pmc:::BranchMispredictions
	 */

	etw_provider_dynamic_probes(desc, prov, sdt_create_probe);
	
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
	sdt_etw_event_t *etw = sdp->sdp_ctl;
	int  r = 0, capturestate = 0;

	if (etw->etw_bcb)
		dtrace_etw_hook_event(etw->etw_bguid, etw->etw_bcb,
		    NULL, ETW_EVENTCB_ORDER_FRIST);
	if (etw->etw_cb)
		dtrace_etw_hook_event(etw->etw_guid, sdt_invop, NULL,
		    ETW_EVENTCB_ORDER_ANY);

	etw->etw_flags |= SDT_TRACE_PROBE_ENABLED;

	if (etw->etw_eventno > 0) {
		CLASSIC_EVENT_ID ceid[1];
		
		etw_kernel_provider_extra(etw);
		if (etw->etw_kw) {
			int id = dtrace_etw_prov_enable(etw->etw_kw);
			etw_kernel_probe_extra(id, etw);
		}
		if (stackon) {
			ceid[0].EventGuid = *etw->etw_guid;
			ceid[0].Type = etw->etw_opcode ? etw->etw_opcode : etw->etw_eventno;
			dtrace_etw_kernel_stack_enable(ceid, 1);
		}
	} else if (etw->etw_eventno == -1) {
		r = etw_userprov_enable(etw, stackon);
	} else  if (etw->etw_eventno <= SDT_DIAG_ALL_EVENTS) {
		dtrace_etw_set_diagnostic(sdt_etw_diag_cb, etw->etw_eventno);
	}

	return (r);
}

/*ARGSUSED*/
static void
sdt_disable(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t *sdp = parg;
	sdt_etw_event_t *etw = sdp->sdp_ctl;

	etw->etw_flags &= ~SDT_TRACE_PROBE_ENABLED;

	if (etw->etw_kw)
		dtrace_etw_prov_disable(etw->etw_kw);
	if (etw->etw_bcb)
		dtrace_etw_unhook_event(etw->etw_bguid, etw->etw_bcb, NULL);
	if (etw->etw_cb)
		dtrace_etw_unhook_event(etw->etw_guid, sdt_invop, NULL);
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

	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (dtrace_register(prov->sdtp_name, prov->sdtp_attr,
		    DTRACE_PRIV_KERNEL, NULL, &sdt_pops,
		    prov, &prov->sdtp_id) != 0) {
			cmn_err(CE_WARN, "failed to register sdt provider %s",
			    prov->sdtp_name);
		}
	}

	sdt_add_providers(dtrace_etw_user_providers(), &stab_attr, &sdt_pops);

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

int
sdt_etw_diag_cb(PEVENT_RECORD ev, void *data)
{
    UCHAR version = ev->EventHeader.EventDescriptor.Version;
    UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
    USHORT event = ev->EventHeader.EventDescriptor.Id;
    int32_t id = (int32_t) data;
    int arch = ARCHETW(ev);
    void *pname = NULL;
    sdt_probe_t *sdt;
    char *payload;

    ASSERT(id < 0);

    sdt = sdt_probetab[SDT_ADDR2NDX(*(uint64_t *) &WGDiagEventsGuid.Data2)];
    for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
        if ((uintptr_t)sdt->sdp_patchpoint ==
            *(uint64_t *) &WGDiagEventsGuid.Data2) {
            if (sdt->sdp_ctl->etw_eventno == id) {
                if (sdt->sdp_ctl->etw_eventno == SDT_DIAG_IGNORED_EVENTS ||
                    sdt->sdp_ctl->etw_eventno == SDT_DIAG_ALL_EVENTS) {
                    payload = payloadhdr(ev, SDT_MSGHDR_SIZE, event, arch, version);
                    pname = sdt_guid_str(&ev->EventHeader.ProviderId);

                    dtrace_etw_probe_sdt(sdt->sdp_id, pname, event, opcode,
                        ev->UserDataLength, payload + SDT_MSGHDR_SIZE, 0, payload, 0);
                } else if (sdt->sdp_ctl->etw_eventno == SDT_DIAG_ZSTACK_EVENTS) {
                    struct ETWStackWalk *sw = (struct ETWStackWalk *) ev->UserData;
                    dtrace_etw_probe_sdt(sdt->sdp_id, sw->EventTimeStamp, 0, 0,
                        0, 0, 0, 0, 0);
                    dtrace_stack_func(ev, id);
                } else if (sdt->sdp_ctl->etw_eventno == SDT_DIAG_ZUSTACK_EVENTS) {
                    ULONG64 matchid = *((ULONG64 *)ev->ExtendedData[0].DataPtr);
                    dtrace_etw_probe_sdt(sdt->sdp_id, matchid, 0, 0,
                        0, 0, 0, 0, 0);
                } else if (sdt->sdp_ctl->etw_eventno == SDT_DIAG_NSTACK_EVENTS) {
                    uint16_t instid = *((uint16_t *)ev->UserData);
                    dtrace_etw_probe_sdt(sdt->sdp_id, instid, 0, 0,
                        0, 0, instid, 0, 0);
                    dtrace_dnet_stack_func(ev, data);
                }
            }
        }
    }

    return (0);
}