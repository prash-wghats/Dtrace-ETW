
#include <sys/dtrace_misc.h>
#include <sys/dtrace_win32.h>
#include <sys/dtrace.h>
#include <evntrace.h>
#include <tdh.h>
#include "etw.h"
#include "etw_struct.h"
#include "sdt.h"
#include "../inject/inject.h"

#define NHASH	1024
typedef struct Guidstr Guidstr;
Guidstr *guidtostr[NHASH];
int sdt_etw_guid_cb(PEVENT_RECORD ev, void *data);

struct {
#define PMC_MAX	8
	const char *pmc_mod;
	const char *pmc_func;
	const char *pmc_prov;
	etw_pmc_t *pmc_srcs;			/* profile sources */
	int pmc_nsrcs;					/* number of sources */
	int pmc_maxconfig;				/* max configuragle per etw session */
	int *pmc_counters;		/* counters pmc configured */
	int pmc_nsample;
	int pmc_ncounter;
} pmcinfo = {"systemtrace", "", "pmc"};

struct Guidstr {
	char *name;
	GUID guid;
	uint64_t kw;
	int level; //XXXXXX
	int flags;
	struct Guidstr *next;
};

unsigned int
hashguid(GUID *guid)
{
	uint64_t *p;
	p = (uint64_t *) guid;

	return (p[0] ^ p[1]) % NHASH;
}

static Guidstr *
lookupguid(Guidstr **hashmap, GUID *guid)
{
	int h;
	Guidstr *pguid;

	h = hashguid(guid);
	for (pguid = hashmap[h]; pguid != NULL; pguid = pguid->next) {
		if (memcmp(&pguid->guid, guid, sizeof(GUID)) == 0)
			return pguid;
	}

	return pguid;
}

static Guidstr *
addguid(Guidstr **hashmap, GUID *guid, char *name)
{
	int h;
	Guidstr *pguid;

	h = hashguid(guid);
	pguid = (Guidstr *) malloc(sizeof(Guidstr));
	pguid->guid = *guid;
	pguid->name = name;
	pguid->kw = 0;
	pguid->level = 0;
	pguid->flags = 0;
	pguid->next = hashmap[h];
	hashmap[h] = pguid;

	return (pguid);
}

/* provider PMC probes */
void
sdt_create_prov_pmc_probes(sdt_provider_t *prov, dtrace_probedesc_t *desc,
    sdt_create_probe_t sdt_create_probe)
{
	sdt_etw_event_t *etwp, *etw;
	pmc_data_t * pd;

	for (etw = prov->sdtp_etw; etw != NULL && etw->etw_nprov != NULL; etw++) {
		if (strstr(desc->dtpd_name, etw->etw_name) == desc->dtpd_name) {
			char *spmc = &desc->dtpd_name[strlen(etw->etw_name)];
			if  (*spmc != '-') {
				if (*spmc == 0) {
					etwp = kmem_zalloc(sizeof (sdt_etw_event_t), 0);
					pd = (pmc_data_t *) kmem_zalloc(sizeof(pmc_data_t), 0);
					memcpy(etwp, etw, sizeof (sdt_etw_event_t));
					etwp->etw_data = pd;
					pd->pmc_i = -1;
					etwp->etw_type = strdup(desc->dtpd_func);

					etwp->etw_flags |= SDT_TRACE_ENABLE_PMC_COUNTER | SDT_TRACE_EXTENDED;
					sdt_create_probe(prov, etwp, desc->dtpd_mod, desc->dtpd_func);
				}
				return;
			}
			spmc++;
			for (int i = 0; i < pmcinfo.pmc_nsrcs; i++) {
				if (strcmp(spmc, pmcinfo.pmc_srcs[i].name) == 0) {
					etwp = kmem_zalloc(sizeof (sdt_etw_event_t), 0);
					pd = (pmc_data_t *) kmem_zalloc(sizeof(pmc_data_t), 0);
					memcpy(etwp, etw, sizeof (sdt_etw_event_t));
					etwp->etw_data = pd;
					pd->pmc_i = i;
					pd->pmc_int = pmcinfo.pmc_srcs[i].interval;
					etwp->etw_name = strdup(desc->dtpd_name);
					etwp->etw_flags |= SDT_TRACE_ENABLE_PMC_COUNTER | SDT_TRACE_EXTENDED;
					sdt_create_probe(prov, etwp, desc->dtpd_mod, desc->dtpd_func);
				}
			}
		}
	}
}

/* PMC provider probes */
void
sdt_create_pmc_probes(sdt_provider_t *prov, dtrace_probedesc_t *desc,
    sdt_create_probe_t sdt_create_probe)
{
	sdt_etw_event_t *etwp, *etw = prov->sdtp_etw;
	char *mod = pmcinfo.pmc_mod, *func = pmcinfo.pmc_func;
	dtrace_id_t id;
	pmc_data_t * pd;
	int nsrcs = pmcinfo.pmc_nsrcs;
	etw_pmc_t *srcs = pmcinfo.pmc_srcs, *src;

	if (desc == NULL) {
		for( ; etw->etw_nprov != NULL; etw++);
		int ssize = (sizeof (sdt_etw_event_t));
		etwp = kmem_zalloc(ssize * (nsrcs + 1), 0);
		for (int i = 0; i < nsrcs; i++) {
			memcpy(&etwp[i], etw, sizeof (sdt_etw_event_t));
			pd = etwp[i].etw_data = kmem_zalloc(sizeof (pmc_data_t), 0);
			etwp[i].etw_name = srcs[i].name;
			pd->pmc_i = i;
			pd->pmc_int = srcs[i].interval;
			etwp[i].etw_flags |= SDT_TRACE_ENABLE_PMC_SAMPLE;
			etwp[i].etw_eventno = srcs[i].srcid;
			sdt_create_probe(prov, &etwp[i], mod, func);
		}
		memcpy(&etwp[nsrcs], etw, sizeof (sdt_etw_event_t));
		prov->sdtp_etw = etwp;
	} else {
		/* PMC sampling probes with interval */
		if ((*desc->dtpd_name != '\0') && (*desc->dtpd_mod == '\0' ||
		    !strcmp(desc->dtpd_mod, mod)) &&
		    (*desc->dtpd_func == '\0' || !strcmp(desc->dtpd_func, func))) {
			if ((id = dtrace_probe_lookup(prov->sdtp_id, mod, func,
			    desc->dtpd_name)) != DTRACE_IDNONE) {
				return;
			}
			for (etw = prov->sdtp_etw; etw != NULL && etw->etw_name != NULL; etw++) {
				char *intr;
				ulong_t val = 0, mult = 1;
				int i = 1;
				pmc_data_t *tpd = etw->etw_data;
				int id = tpd->pmc_i;
				if ((strstr(desc->dtpd_name, etw->etw_name)) == desc->dtpd_name &&
				    (intr = strchr(desc->dtpd_name, '-')) != NULL) {
					while(intr[i] != '\0') {
						if (intr[i] < '0' || intr[i] > '9')
							return;

						val = (intr[i++] - '0') +  10 * val;
						mult *= (ulong_t)10;
					}
					etwp = kmem_zalloc(sizeof (sdt_etw_event_t), 0);
					memcpy(etwp, etw, sizeof (sdt_etw_event_t));
					etwp->etw_data = kmem_zalloc(sizeof (pmc_data_t), 0);
					pd = etwp->etw_data;
					etwp->etw_name = strdup(desc->dtpd_name);
					pd->pmc_i = tpd->pmc_i;

					if (val < srcs[id].minint)
						val = srcs[id].minint;
					else if (val > srcs[id].maxint)
						val = srcs[id].maxint;
					etwp->etw_eventno = srcs[id].srcid;
					pd->pmc_int = val;
					etwp->etw_flags |= SDT_TRACE_ENABLE_PMC_SAMPLE;
					sdt_create_probe(prov, etwp, mod, desc->dtpd_func);
				}
			}
		}
	}
	return;
}

void
etw_dynamic_probes(dtrace_probedesc_t *desc, sdt_provider_t *prov,
    sdt_create_probe_t sdt_create_probe)
{
	if (strcmp(desc->dtpd_func, "pmc") == 0 &&
	    strcmp(desc->dtpd_provider, prov->sdtp_name) == 0)
		sdt_create_prov_pmc_probes(prov, desc, sdt_create_probe);
	else if (strcmp("pmc", prov->sdtp_name) == 0) {
		sdt_create_pmc_probes(prov, desc, sdt_create_probe);
	}
}

void
etw_provider_dynamic_probes(dtrace_probedesc_t *desc, sdt_provider_t *prov,
    sdt_create_probe_t sdt_create_probe)
{
	if (strcmp("pmc", prov->sdtp_name) == 0) {
		sdt_create_pmc_probes(prov, desc, sdt_create_probe);
	}
}

void
etw_kernel_provider_extra(sdt_etw_event_t *etw)
{
	pmc_data_t *pd;

	if (etw->etw_flags & SDT_TRACE_ENABLE_PMC_SAMPLE) {
		pd = etw->etw_data;
		TRACE_PROFILE_INTERVAL interval[1] = { etw->etw_eventno, pd->pmc_int };
		ulong_t ids[1] = { pmcinfo.pmc_srcs[pd->pmc_i].srcid };
		dtrace_etw_pmc_samples(ids, interval, 1);
		pmcinfo.pmc_nsample++;
	}
}

void
etw_kernel_probe_extra(int sessionid, sdt_etw_event_t *etw)
{
	pmc_data_t *pd;
	if (etw->etw_flags & SDT_TRACE_ENABLE_PMC_COUNTER) {
		pd = etw->etw_data;
		pd->pmc_seqno = -1;
		if (sessionid >= 0 && pd->pmc_i >= 0) {
			if (!pmcinfo.pmc_counters[pd->pmc_i]) {
				ulong_t ids[1] = { pmcinfo.pmc_srcs[pd->pmc_i].srcid };
				CLASSIC_EVENT_ID cid[1] = { *etw->etw_guid, etw->etw_opcode ? etw->etw_opcode : etw->etw_eventno};
				dtrace_etw_pmc_counters(sessionid, ids, cid, 1);
				pmcinfo.pmc_counters[pd->pmc_i] = ++pmcinfo.pmc_ncounter;
			}
			pd->pmc_seqno = pmcinfo.pmc_counters[pd->pmc_i] - 1;
		}
	}
}

int
etw_userprov_enable(sdt_etw_event_t *etw, int stackon)
{
	int capturestate = 0;
	Guidstr *gu = lookupguid(guidtostr, etw->etw_guid);

	gu->kw |= etw->etw_kw;
	gu->level = gu->level < TRACE_LEVEL_VERBOSE ? TRACE_LEVEL_VERBOSE : gu->level;
	gu->flags |= stackon ? SDT_TRACE_ENABLE_STACK : 0;
	if (strcmp(etw->etw_name, "capturestate") == 0) {
		if ((gu->flags && SDT_TRACE_ENABLE_CAPTURESTATE) == 0) {
			capturestate = 1;
			gu->flags |= SDT_TRACE_ENABLE_CAPTURESTATE;
		}
		etw->etw_flags &= ~SDT_TRACE_PROBE_ENABLED;
	}

	int r =  dtrace_etw_uprov_enable(etw->etw_guid, gu->kw,
	    etw->etw_eventno, gu->level, gu->flags & SDT_TRACE_ENABLE_STACK, capturestate);
	if (r != ERROR_SUCCESS) {
		eprintf("Enable error (%d) Provider (%s) probe (%s) kw (%x)",
			r, etw->etw_nprov, etw->etw_name, gu->kw);
	}

	return (r);
}

static sdt_etw_event_t *
sdt_guid_kw0(etw_provinfo_t *pprov, int (*cb) (PEVENT_RECORD, void *))
{
	etw_provkw_t *pkw;
	sdt_etw_event_t *etwp = NULL, *tmp;
	int num = 0;

	/*
	 * The first call can fail with ERROR_NOT_FOUND if none
	 * of the provider's event descriptions contain the
	 * requested field type information.
	 */
	num = pprov->provnkw;
	etwp = kmem_zalloc(sizeof (sdt_etw_event_t) * (num + 3), 0);

	/*
	 * Loop through the list of field information and print
	 * the field's name, description (if it exists), and value.
	 */
	etwp[0].etw_nprov = pprov->provn;
	etwp[0].etw_name = "events";
	etwp[0].etw_type = "event";
	etwp[0].etw_guid = &pprov->provg;
	etwp[0].etw_cb = cb;
	etwp[0].etw_eventno = -1;
	/*
	 * 0 for a manifest-based provider or TraceLogging provider and
	 * 0xFFFFFFFF for a (MOF) classic provider.
	 */
	if (pprov->src == 1)	//MOF
		etwp[0].etw_kw = ~ (uint64_t) 0;		/* ~ (uint64_t) 0; */
	else
		etwp[0].etw_kw = 0; //manifest, tracelog

	etwp[1].etw_nprov = pprov->provn;
	etwp[1].etw_name = "capturestate";
	etwp[1].etw_type = "";
	etwp[1].etw_guid = &pprov->provg;
	etwp[1].etw_cb = cb;
	etwp[1].etw_eventno = -1;
	etwp[1].etw_kw = 0;
	etwp[1].etw_flags = SDT_TRACE_ENABLE_CAPTURESTATE;

	pkw = pprov->provkw;

	for (int j = 0; j < num; j++) {
		etwp[j + 2].etw_nprov = pprov->provn;
		etwp[j + 2].etw_guid = &pprov->provg;
		//etwp[j + 2].etw_type = "event";
		etwp[j + 2].etw_cb = cb;
		etwp[j + 2].etw_name = pkw[j].kwn;
		etwp[j + 2].etw_kw =  pkw[j].kwv;
		etwp[j + 2].etw_eventno = -1;
	}

	tmp = &etwp[num + 2];
	tmp = NULL;

	return (etwp);
}

void
sdt_add_providers(etw_provinfo_t *lprov, void *attr, void *pops)
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
		prov->sdtp_attr = attr;
		prov->sdtp_etw = sdt_guid_kw0(lprov, sdt_etw_guid_cb);

		if (dtrace_register(prov->sdtp_name, prov->sdtp_attr,
		    DTRACE_PRIV_KERNEL, NULL, pops,
		    prov, &prov->sdtp_id) != 0) {
			fprintf(stderr, "failed to register sdt provider %s",
			    prov->sdtp_name);
		}
		addguid(guidtostr, &lprov->provg, lprov->provn);
	} while ((++lprov)->provn != NULL);

	pmcinfo.pmc_srcs = dtrace_etw_pmc_info(&pmcinfo.pmc_nsrcs,
	    &pmcinfo.pmc_maxconfig);
	pmcinfo.pmc_counters = malloc(sizeof(int) * pmcinfo.pmc_nsrcs);
	memset(pmcinfo.pmc_counters, 0, sizeof(int) * pmcinfo.pmc_nsrcs);
}

int
sdt_etw_procp_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack)
{
	proc_t *p;

	int arch = ARCHETW(ev), ver = ev->EventHeader.EventDescriptor.Version;
	int pid;
	char *ud = ev->UserData;

	if (sdt->sdp_patchval != ev->EventHeader.EventDescriptor.Opcode)
		return (0);
	if (ev->EventHeader.EventDescriptor.Opcode == 1) {
		pid = arch ? (ver == 0 ? * (uint32_t *) ud : * (uint32_t *) (ud + 8) ) :
		    (ver == 0 ? * (uint32_t *) ud : * (uint32_t *) (ud + 4));
		p = dtrace_etw_proc_find(pid, 0);
		stack[SDT_ARG0] = p;
	} else if (ev->EventHeader.EventDescriptor.Opcode == 2) {
		p = curproc;
		stack[SDT_ARG0] = p->exitval;
	}

	return (1);
}
int
sdt_etw_proct_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack)
{
	thread_t *td = NULL;

	int pid, tid;
	char *ud = ev->UserData;

	if (sdt->sdp_patchval != ev->EventHeader.EventDescriptor.Opcode)
		return (0);

	if (ev->EventHeader.EventDescriptor.Opcode == 1) {
		pid = *(uint32_t *) ud;
		tid = *(uint32_t *) (ud + 4);
		td = dtrace_etw_td_find(pid, tid, 0);
	}
	if (sdt->sdp_patchval == 1) {
		stack[SDT_ARG0] = td;
	} else if (sdt->sdp_patchval == 2) {
		;
	} else {
		ASSERT (0);
	}

	return (1);
}

int
sdt_etw_sched_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	thread_t *oldtd, *newtd, *td;
	int on = 0;
	struct CSwitch *cs;
	void *payload = 0;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &ThreadGuid));
	ASSERT(version >= 2);

	if (!(sdt->sdp_ctl->etw_flags & SDT_TRACE_PROBE_ENABLED) ||
	    (opcode != 36  && opcode != 50) || (opcode != sdt->sdp_ctl->etw_opcode))
		return (0);

	/*
	 * Wait --> Ready (Queue) --> Run (Context switch)
	 */
	if (opcode == 36) {
		/*
		 * etw buffer cpu no represents the cpu of the
		 * context switch. any thread stack represents the
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

		if (sdt->sdp_patchval == 35) {
			stack[SDT_CUR_LOCK] = dtrace_etw_set_cur(oldtd->pid, oldtd->tid,
			    ev->EventHeader.TimeStamp.QuadPart - 1, ev->BufferContext.ProcessorNumber);
			stack[SDT_ARG0] = newtd;
			stack[SDT_ARG1] = newtd->proc;
		} else {
			stack[SDT_CUR_LOCK] = dtrace_etw_set_cur(newtd->pid, newtd->tid,
			    ev->EventHeader.TimeStamp.QuadPart, ev->BufferContext.ProcessorNumber);
		}

	} else if (opcode == 50) {
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
		stack[SDT_CUR_LOCK] =  dtrace_etw_set_cur(ev->EventHeader.ProcessId,
		    ev->EventHeader.ThreadId, ev->EventHeader.TimeStamp.QuadPart,
		    ev->BufferContext.ProcessorNumber);
		stack[SDT_ARG0] = td;
		stack[SDT_ARG1] = td->proc;
	}

	return (1);
}

/* DiskIO CB */
int
sdt_etw_diskio_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack)
{
	struct DiskIo_TypeGroup1 *d1;
	struct DiskIo_TypeGroup2 *d2;
	struct DiskIo_TypeGroup3 *d3;
	struct Diskiotg1 {
		int no, flags, trfsz, res, off, obj, irp, restm, tid;
	} diskiotg1[2][1] = {
		{
			{ 0, 4, 8, 12, 16, 24, 28, 32, 40 }
		},
		{
			{ 0, 4, 8, 12, 16, 24, 32, 40, 48 }
		}
	};
	struct Diskiotg2 {
		int irp, tid;
	} diskiotg2[2][1] = {
		{
			{0, 4}
		},
		{
			{0, 8}
		}
	};
	struct Diskiotg3 {
		int no, flags, restm, irp, tid;
	} diskiotg3[2][1] = {
		{
			{0, 4, 8, 16, 20}
		},
		{
			{0, 4, 8, 16, 24}
		}
	};
	int arch = ARCHETW(ev), ver = 0;//ev->EventHeader.EventDescriptor.Version;
	char *ud = (char *) ev->UserData;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &DiskIoGuid));

	if (!((sdt->sdp_patchval == 10 && (opcode == 10 || opcode == 11 ||
	    opcode == 14)) ||
	    (sdt->sdp_patchval == 12 && (opcode == 12 || opcode == 13 || opcode == 15)))) {
		return(0);
	}

	buf_t *buf = dtrace_sdtmem_alloc(sizeof (buf_t));

	switch (opcode) {
	case 12:	/* Read Initiate */
	case 13:	/* Write Initiate */
	case 15:	/* Flush Initiate */
		struct Diskiotg2 *tg2 = &diskiotg2[arch][ver];

		buf->b_irpaddr = PTR(arch, ud, tg2->irp);
		buf->b_flags = opcode == 12 ? 1 : (opcode == 13 ? 2 : 4);
		break;
	case 14:		/* flush done */
		struct Diskiotg3 *tg3 = &diskiotg3[arch][ver];

		buf->b_flags = 4;
		buf->b_irpaddr = PTR(arch, ud, tg3->irp);
		buf->b_diskno = V32(ud, tg3->no);
		buf->b_irpflags = V32(ud, tg3->flags);
		buf->b_resptm = V64(ud, tg3->restm);
		break;
	case 10:		/* Read Complete */
	case 11:		/* Write Complete */
		struct Diskiotg1 *tg1 = &diskiotg1[arch][ver];
		buf->b_fname = dtrace_etw_get_fname(PTR(arch, ud, tg1->obj));
		buf->b_flags = opcode == 10 ? 1 : 2;
		buf->b_irpaddr = PTR(arch, ud, tg1->irp);
		buf->b_diskno = V32(ud, tg1->no);
		buf->b_irpflags = V32(ud, tg1->flags);
		buf->b_resptm = V64(ud, tg1->restm);
		buf->b_bcount = V32(ud, tg1->trfsz);
		buf->b_offset = V64(ud, tg1->off);
		break;
	default:
		dtrace_sdtmem_free(buf);
		ASSERT(0);
		break;
	}

	stack[SDT_ARG0] = buf;
	stack[SDT_ARGPL] = buf;

	return (1);
}

int
sdt_etw_tcpip_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack)
{
	tcpip_msg_t *ip = dtrace_sdtmem_alloc(sizeof (tcpip_msg_t));
	tcpip_fail_t fail = {0};
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &TcpIpGuid));

	if (sdt->sdp_patchval != opcode && sdt->sdp_patchval == (opcode - 16))
		return (0);

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
			dtrace_sdtmem_free(ip);
			ASSERT(0);
		}
	}

	if (sdt->sdp_patchval == 17) {
		stack[SDT_ARG0] = fail.ti_proto;
		stack[SDT_ARG1] = fail.ti_code;
		dtrace_sdtmem_free(ip);
	} else {
		stack[SDT_CUR_LOCK] = dtrace_etw_set_cur(ip->ti_pid, ev->EventHeader.ThreadId,
			    ev->EventHeader.TimeStamp.QuadPart, ev->BufferContext.ProcessorNumber);
		stack[SDT_ARG0] = ip;
		stack[SDT_ARGPL] = ip;
	}

	return (1);
}

int
sdt_etw_udpip_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack)
{
	udpip_msg_t *ip = dtrace_sdtmem_alloc(sizeof (udpip_msg_t));
	udpip_fail_t fail = {0};
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &UdpIpGuid));

	if (sdt->sdp_patchval != opcode && sdt->sdp_patchval == (opcode - 16))
		return (0);

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
			ASSERT(0);
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
			dtrace_sdtmem_free(ip);
			ASSERT(0);
		}
	}

	if (sdt->sdp_patchval == 17) {
		stack[SDT_ARG0] = fail.ti_proto;
		stack[SDT_ARG1] = fail.ti_code;
		dtrace_sdtmem_free(ip);
	} else {
		stack[SDT_CUR_LOCK] = dtrace_etw_set_cur(ip->ui_pid, ev->EventHeader.ThreadId,
			    ev->EventHeader.TimeStamp.QuadPart, ev->BufferContext.ProcessorNumber);
		stack[SDT_ARG0] = ip;
		stack[SDT_ARGPL] = ip;
	}

	return (1);
}

int
sdt_etw_fileio_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack)
{
	struct dirinfo dinfo = {0};
	size_t len;
	wchar_t *fname;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;

	int fnd = 0;
	struct FileIoName {
		int obj, name;
	} fion[2][1] = {{{0, 4}}, {{0, 8}}};
	struct FileIoCreate {
		int irp, tid, obj, flags, attr, share, path;
	} fioc[2][4] = {
		{	{0, 4, 8, 12, 16, 20, 24},
			{0, 4, 8, 12, 16, 20, 24},
			{0, 4, 8, 12, 16, 20, 24},
			{0, 8, 4, 12, 16, 20, 24}
		},
		{	{0, 8, 16, 24, 28, 32, 36},
			{0, 8, 16, 24, 28, 32, 36},
			{0, 8, 16, 24, 28, 32, 36},
			{0, 16, 8, 24, 28, 32, 36}
		}
	};
	struct FileIoInfo {
		int irp_p, tid_p, obj_p, key_p, ext_p, info_i;
	} fioi[2][4] = {
		{
			{0, 4, 8, 12, 16, 20},
			{0, 4, 8, 12, 16, 20},
			{0, 4, 8, 12, 16, 20},
			{0, 16, 4, 8, 12, 20}
		}, {
			{0, 8, 16, 24, 32, 40},
			{0, 8, 16, 24, 32, 40},
			{0, 8, 16, 24, 32, 40},
			{0, 32, 8, 16, 24, 40},
		}
	};
	struct FileIoSimpleOp {
		int irp_p, tid_p, obj_p, key_p;
	} fios[2][4] = {
		{
			{0, 4, 8, 12},
			{0, 4, 8, 12},
			{0, 4, 8, 12},
			{0, 12, 4, 8},
		}, {
			{0, 8, 16, 24},
			{0, 8, 16, 24},
			{0, 8, 16, 24},
			{0, 24, 8, 16},
		}
	};
	struct FileIoReadWrite {
		int off_l, irp_p, tid_p, obj_p, key_p, sz_i, flags_i;
	} fiorw[2][4] = {
		{
			{0, 8, 12, 16, 20, 24, 28},
			{0, 8, 12, 16, 20, 24, 28},
			{0, 8, 12, 16, 20, 24, 28},
			{0, 8, 20, 12, 16, 24, 28},
		}, {
			{0, 8, 16, 24, 32, 40, 44},
			{0, 8, 16, 24, 32, 40, 44},
			{0, 8, 16, 24, 32, 40, 44},
			{0, 8, 32, 16, 24, 40, 44},
		}
	};
	struct FileIoDirEnum {
		int irp_p, tid_p, obj_p, key_p, len_i, info_p, ind_i, patt_w;
	} fiod[2][4] = {
		{	{0, 4, 8, 12, 16, 20, 24, 28},
			{0, 4, 8, 12, 16, 20, 24, 28},
			{0, 4, 8, 12, 16, 20, 24, 28},
			{0, 12, 4, 8, 16, 20, 24, 28}
		}, {
			{0, 8, 16, 24, 32, 36, 42, 46},
			{0, 8, 16, 24, 32, 36, 42, 46},
			{0, 8, 16, 24, 32, 36, 42, 46},
			{0, 24, 8, 16, 32,  36, 42, 46},
		}
	};
	struct FileIoOpEnd {
		int irp_p, ext_p, nt_i;
	} fioe[2][1] = {
		{0, 4, 8},
		{0, 8, 16}
	};
	int arch = ARCHETW(ev), ver = ev->EventHeader.EventDescriptor.Version >= 3 ?
	    3 : ev->EventHeader.EventDescriptor.Version;
	char *ud = (char *) ev->UserData;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &FileIoGuid));

	if (!(sdt->sdp_patchval == opcode || (opcode == 32 &&
	    sdt->sdp_patchval == 64) || (opcode == 35 && sdt->sdp_patchval == 70))) {
		return (0);
	}

	struct wfileinfo *info = dtrace_sdtmem_alloc(sizeof (wfileinfo_t));

	ZeroMemory(info, sizeof (wfileinfo_t));
	switch (ev->EventHeader.EventDescriptor.Opcode) {
	case 0:
	case 32:
	case 35: {
		struct FileIoName *fi = &fion[arch][0];
		info->f_name = dtrace_etw_get_fname(PTR(arch, ud, fi->obj));
		break;
	}
	case 64: {
		struct FileIoCreate *fi = &fioc[arch][ver];

		len = wcslen(WSTR(ud, fi->path));
		fname = (wchar_t *) malloc((len + 2) * sizeof (wchar_t));
		wcsncpy(fname, WSTR(ud, fi->path), len);
		info->f_createopt = V32(ud, fi->flags);
		info->f_fileattrib = V32(ud, fi->attr);
		info->f_fileobj =  PTR(arch, ud, fi->obj);
		info->f_irpptr = PTR(arch, ud, fi->irp);
		info->f_shareflags = *(uint32_t *) (ud + fi->share);
		info->f_tid = PTR(arch, ud, fi->tid);
		break;
	}
	case 69:
	case 70:
	case 71:
	case 74:
	case 75: {
		struct FileIoInfo *fi = &fioi[arch][ver];

		info->f_fileobj =  PTR(arch, ud, fi->obj_p);
		info->f_irpptr =  PTR(arch, ud, fi->irp_p);
		info->f_tid = PTR(arch, ud, fi->tid_p);
		info->f_name = dtrace_etw_get_fname(PTR(arch, ud, fi->key_p));
		info->f_extinfo = PTR(arch, ud, fi->ext_p);
		info->f_infoclass = V32(ud, fi->info_i);
		break;
	}
	case 65:
	case 66:
	case 73: {
		struct FileIoSimpleOp *fi = &fios[arch][ver];

		info->f_fileobj =   PTR(arch, ud, fi->obj_p);
		info->f_irpptr = PTR(arch, ud, fi->irp_p);
		info->f_tid = V32(ud, fi->tid_p);
		info->f_name = dtrace_etw_get_fname(PTR(arch, ud, fi->key_p));
		break;
	}
	case 67:		/* read */
	case 68: {		/* write */
		struct FileIoReadWrite *fi = &fiorw[arch][ver];

		info->f_fileobj =   PTR(arch, ud, fi->obj_p);
		info->f_irpptr = PTR(arch, ud, fi->irp_p);
		info->f_tid = V32(ud, fi->tid_p);
		info->f_name = dtrace_etw_get_fname(PTR(arch, ud, fi->key_p));
		info->f_iosize = V32(ud, fi->sz_i);
		info->f_ioflags = V32(ud, fi->flags_i);
		info->f_offset = V32(ud, fi->off_l);
		break;
	}
	case 72:
	case 77: {
		struct FileIoDirEnum *fi = &fiod[arch][ver];

		info->f_fileobj = PTR(arch, ud, fi->obj_p);
		info->f_irpptr = PTR(arch, ud, fi->irp_p);
		info->f_tid = PTR(arch, ud, fi->tid_p);
		info->f_name = dtrace_etw_get_fname(PTR(arch, ud, fi->key_p));
		info->f_dlen = V32(ud, fi->len_i);
		info->f_infoclass = PTR(arch, ud, fi->info_p);
		len = wcslen(WSTR(ud, fi->patt_w));
		fname = (wchar_t *) malloc((len + 2) * sizeof (wchar_t));
		wcsncpy(fname, WSTR(ud, fi->patt_w), len);
		fname[len] = L'\0';
		info->f_dpattspec = fname;
		info->f_dfileindex = V32(ud, fi->ind_i);
		break;
	}
	case 76: {
		struct FileIoOpEnd *fi = &fioe[arch][0];

		info->f_irpptr = PTR(arch, ud, fi->irp_p);
		info->f_extinfo = PTR(arch, ud, fi->ext_p);
		info->f_ntstatus = V32(ud, fi->nt_i);
		break;
	}
	default:
		dtrace_sdtmem_free(info);
		ASSERT (0);
	}

	stack[SDT_ARG0] = info;
	stack[SDT_ARGPL] = info;

	return (1);
}

int
sdt_etw_reg_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt, uint64_t *stack)
{
	size_t len;
	wchar_t *rname, *name;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	int arch = ARCHETW(ev), ver = ev->EventHeader.EventDescriptor.Version > 2 ?
	    2 : ev->EventHeader.EventDescriptor.Version;
	char *ud = (char *) ev->UserData;

	struct RegistryTypeGroup1 {
		int inittm_l, st_i, ind_i, key_p, name_w;
	} regtg1[2][3] = {
		{
			{8, 0, -1, 4, 16},
			{8, 0, 16, 4, 20},
			{0, 8, 12, 16, 20}
		}, {
			{12, 0, -1, 4, 20},
			{12, 0, 20, 4, 24},
			{0, 8, 12, 16, 24}
		}
	};
	struct RegistryTypeGroup1 *rg = &regtg1[arch][ver];
	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &RegistryGuid));
	//ASSERT(ver <= 2);
	if (sdt->sdp_patchval != opcode)
		return (0);

	struct reginfo *rinfo = dtrace_sdtmem_alloc(sizeof (reginfo_t) +
	    (MAX_PATH * sizeof(wchar_t)));

	rinfo->r_status = V32(ud, rg->st_i);
	rinfo->r_handle = PTR(arch, ud, rg->key_p);
	rinfo->r_time = V64(ud, rg->inittm_l);
	rinfo->r_index = rg->ind_i == -1 ? 0 : V32(ud, rg->ind_i);

	len = wcslen(WSTR(ud, rg->name_w));
	rinfo->r_name = ((char *) rinfo + sizeof(reginfo_t));
	wcsncpy(rinfo->r_name, WSTR(ud, rg->name_w), len);

	stack[SDT_ARG0] = rinfo;
	stack[SDT_ARGPL] = rinfo;

	return (1);
}

int
sdt_etw_pf_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt, uint64_t *stack)
{
	struct vminfo vinfo = {0};
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	int arch = ARCHETW(ev), ver = ev->EventHeader.EventDescriptor.Version;
	char *ud = (char *) ev->UserData;

	struct PageFaultHardFault {
		int inittm_l, off_l, va_p, fobj_p, tid_i, bytes_i;
	} pfhf[2][1] = {{0, 8, 16, 20, 24, 28}, {0, 8, 16, 24, 32, 36}};
	struct PageFaultImageLoadBacked {
		int fobj_p, dev_i, file_s, flags_s;
	} pfil[2][1] = {{0, 4, 8, 10}, {0, 8, 12, 14}};
	struct PageFaultTransitionFault {
		int va_p, pc_p;
	} pftf[2][1] = {{0, 4}, {0, 8}};
	struct PageFault_TG1 {
		int va_p, pc_p;
	} pftg1[2][1] = {{0, 4}, {0, 8}};
	struct PageFaultVirtualAlloc {
		int va_p, len_p, pid_i, flags_i;
	} pfva[2][1] = {{0, 4, 8, 12}, {0, 8, 16, 20}};
	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &PageFaultGuid));

	if (sdt->sdp_patchval != opcode)
		return (0);

	switch (opcode) {
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
	case 15: {	/* transition faults */
		struct PageFault_TG1 *v = &pftg1[arch][0];

		vinfo.va = PTR(arch, ud, v->va_p);
		vinfo.pc = PTR(arch, ud, v->pc_p);

		stack[SDT_ARG0] = vinfo.va;
		stack[SDT_ARG1] = vinfo.pc;

		break;
	}
	case 32: {
		struct PageFaultHardFault *v = &pfhf[arch][0];

		vinfo.time = V64(ud, v->inittm_l);
		vinfo.tid = V32(ud, v->tid_i);
		vinfo.va = PTR(arch, ud, v->va_p);
		vinfo.fname = dtrace_etw_get_fname(PTR(arch, ud, v->fobj_p));
		vinfo.nbyte = V32(ud, v->bytes_i);
		vinfo.rdoffset = V64(ud, v->off_l);

		/* hard fault */
		stack[SDT_ARG0] = vinfo.fname;
		stack[SDT_ARG1] = vinfo.va;
		stack[SDT_ARG2] = vinfo.time;
		stack[SDT_ARG3] = vinfo.rdoffset;
		stack[SDT_ARG4] = vinfo.tid;
		break;
	}
	case 98:	/* virtalalloc */
	case 99: {	/* virtalfree */
		struct PageFaultVirtualAlloc *v = &pfva[arch][0];

		vinfo.baseaddr = PTR(arch, ud, v->va_p);
		vinfo.flags = V32(ud, v->flags_i);
		vinfo.pid = V32(ud, v->pid_i);
		vinfo.regsz = PTR(arch, ud, v->len_p);

		stack[SDT_ARG0] = vinfo.baseaddr;
		stack[SDT_ARG1] = vinfo.pid;
		stack[SDT_ARG2] = vinfo.regsz;
		stack[SDT_ARG3] = vinfo.flags;

		break;
	}
	case 105: {
		struct PageFaultImageLoadBacked *v = &pfil[arch][0];

		vinfo.devchar =  V32(ud, v->dev_i);
		vinfo.filechar = V16(ud, v->file_s);
		vinfo.fname = dtrace_etw_get_fname(PTR(arch, ud, v->fobj_p));
		vinfo.flags = V16(ud, v->flags_s);

		/* img load */
		stack[SDT_ARG0] = vinfo.fname;
		stack[SDT_ARG1] = vinfo.flags;
		stack[SDT_ARG2] = vinfo.devchar;
		stack[SDT_ARG3] = vinfo.filechar;

		break;
	}
	default:
		ASSERT (0);
	}

	return (1);
}

#define ETW_EXT_HDRSZ	8
#define EG_ETW_EXT_PMC_COUNTER 1

typedef struct etwext {
	uint32_t ext_type;
	uint32_t ext_size;
	char data[1];
} etwext_t;

int
addextendeddata(sdt_probe_t *sdt, PEVENT_RECORD ev, uint64_t *stack)
{
	char *data = NULL;
	etwext_t *tmp;
	int i = 0;

	if ((sdt->sdp_ctl->etw_flags & SDT_TRACE_ENABLE_PMC_COUNTER) &&
	    (ev->ExtendedData[0].ExtType == EVENT_HEADER_EXT_TYPE_PMC_COUNTERS)) {
		pmc_data_t *pd = sdt->sdp_ctl->etw_data;

		if (pd->pmc_i >= 0) {
			if (pd->pmc_seqno >= 0) {
				stack[SDT_ARG4] = ((uint64_t *)ev->ExtendedData[0].DataPtr)[pd->pmc_seqno];
				return (1);
			}
		} else {
			data = dtrace_sdtmem_alloc(ETW_EXT_HDRSZ + ev->ExtendedData[0].DataSize);
			tmp = data;
			tmp->ext_type = EG_ETW_EXT_PMC_COUNTER;
			tmp->ext_size = ev->ExtendedData[0].DataSize;
			memcpy(data + ETW_EXT_HDRSZ, ev->ExtendedData[0].DataPtr, tmp->ext_size);
			stack[SDT_ARG4] = data;
			stack[SDT_ARGEXTPL] = data;
			return (1);
		}
		return (0);
	}
	ASSERT((sdt->sdp_ctl->etw_flags & SDT_TRACE_EXTENDED) == 0);
	return (1);
}

int
sdt_etw_dpc_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt, uint64_t *stack)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;

	struct DPC *dpc;
	int arch = ARCHETW(ev), ver = ev->EventHeader.EventDescriptor.Version;
	char *ud = (char *) ev->UserData;

	struct DPC_ {
		int inittm_l, func_p;
	} dpc_[2][1] = { {0, 8}, {0, 8}};
	struct DPC_ *d = &dpc_[arch][0];

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &PerfInfoGuid));

	if (sdt->sdp_patchval != opcode || (opcode != 66 && opcode != 68 &&
	    opcode != 69))
		return (0);

	dpc = (struct DPC *) ev->UserData;

	stack[SDT_ARG0] = V64(ud, d->inittm_l);
	stack[SDT_ARG1] = PTR(arch, ud, d->func_p);

	return (1);
}

int
sdt_etw_isr_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt, uint64_t *stack)
{
	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &PerfInfoGuid));

	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	struct ISR *isr = (struct ISR *) ev->UserData;

	void *payload = 0;
	int arch = ARCHETW(ev), ver = ev->EventHeader.EventDescriptor.Version;
	char *ud = (char *) ev->UserData;

	struct ISR_ {
		int inittm_l, func_p, ret_b, vec_b, res_s;
	} isr_[2][1] = {{0, 8, 12, 13, 14}, {0, 8, 16, 17, 18}};
	struct ISR_ *is = &isr_[arch][0];

	if (opcode != 67 && sdt->sdp_patchval != opcode)
		return (0);

	stack[SDT_ARG0] = V64(ud, is->inittm_l);
	stack[SDT_ARG1] = PTR(arch, ud, is->func_p);
	stack[SDT_ARG2] = V8(ud, is->ret_b);
	stack[SDT_ARG3] = V8(ud, is->vec_b);

	return (1);
}

int
sdt_etw_syscall_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;

	int arch = ARCHETW(ev), ver = ev->EventHeader.EventDescriptor.Version;
	char *ud = (char *) ev->UserData;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &PerfInfoGuid));

	if (sdt->sdp_patchval != opcode || (opcode != 51 && opcode != 52))
		return (0);

	if (opcode == 51) {
		stack[SDT_ARG0] = PTR(arch, ud, 0);
	} else {
		stack[SDT_ARG0] = V32(ud, 0);
	}

	return (1);
}

#define	GUID_STR_SIZE	40

char *
sdt_guid_str(GUID *g)
{
	Guidstr *val = lookupguid(guidtostr, g);
	if (val == NULL) {
		char *str = kmem_zalloc(GUID_STR_SIZE,
		    KM_SLEEP);
		sprintf(str, "{%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x}",
		    g->Data1, g->Data2, g->Data3, g->Data4[0],
		    g->Data4[1], g->Data4[2], g->Data4[3], g->Data4[4],
		    g->Data4[5], g->Data4[6], g->Data4[7]);
		val = addguid(guidtostr, g, str);
	}

	return (val->name);
}

int
sdt_etw_module_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	USHORT event = ev->EventHeader.EventDescriptor.Id;
	int arch = ARCHETW(ev);

	proc_t *p = curproc;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &ImageLoadGuid));

	if (sdt->sdp_patchval != opcode || (opcode != 10 && opcode != 2))
		return (0);

	etw_module_t *mod = dtrace_sdtmem_alloc(sizeof(etw_module_t));
	int32_t pid;
	uint64_t base;
	dtrace_etwloadinfo(arch, version, ev->UserData, ev->UserDataLength, mod, &pid,
	    &base); ///XXX unload
	stack[SDT_ARG0] = mod->name;
	stack[SDT_ARG1] = base;
	stack[SDT_ARG2] = pid;
	stack[SDT_ARGPL] = mod;

	return (1);
}

int
sdt_etw_lost_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt, uint64_t *stack)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;


	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &RTLostEvent));

	if (sdt->sdp_patchval == opcode) {
		;
	} else ASSERT (0);

	return (1);
}

int
sdt_etw_pmc_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt, uint64_t *stack)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;

	thread_t *td;
	char str[DTRACE_FUNCNAMELEN];
	int fnd = 0, fndi, co;
	void *payload = NULL;
	struct SampledProfileInterval_V3 *sm;
	int arch = ARCHETW(ev), ver = ev->EventHeader.EventDescriptor.Version;
	char *ud = (char *) ev->UserData;
	int patch = sdt->sdp_patchval;

	struct PMC {
		int ip_p, tid_i, srcid_s, na_s;
	} pmc_[2][1] = {{0, 4, 8, 10}, {0, 8, 12, 14}};

	//struct PMC_v2 *pmc = (struct PMC_v2 *) ev->UserData;

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &PerfInfoGuid));

	if (sdt->sdp_patchval == opcode && opcode == 48) {
		/* PMC counter registers */
		int len = 4, slen = 0, j = 0;
		co = *(uint32_t *) ud;
		payload = dtrace_sdtmem_alloc(sizeof(wchar_t *) * co + ev->UserDataLength);
		wchar_t **names = payload;
		char *base = (char *) payload + sizeof(wchar_t *) * co;
		memcpy(((char *) payload + sizeof(wchar_t *) * co), ev->UserData,
		    ev->UserDataLength);
		for (int i = 0; i < co; i++) {
			names[j++] = (wchar_t *) (base + len);
			wcslwr((wchar_t *) (base + len));
			len += wcslen((wchar_t *) (ud + len)) * 2 + 2;
		}

		stack[SDT_ARG0] = co;
		stack[SDT_ARG1] = payload;
		stack[SDT_ARGPL] = payload;

	} else if (sdt->sdp_patchval == 73 && (opcode == 73 || opcode == 74)) {
		/* 73 , Sampled PMC registers, pmc:::br */
		sm = (struct SampledProfileInterval_V3 *) ev->UserData;

		WideCharToMultiByte(CP_UTF8, 0, &sm->SourceName, -1, str,
		    DTRACE_FUNCNAMELEN, NULL, NULL);
		strlwr(str);
		//if (opcode == 73) {
		for (int i = 0; i < pmcinfo.pmc_nsrcs; i++) {
			if (pmcinfo.pmc_srcs[i].srcid == sm->Source) {
				pmcinfo.pmc_srcs[i].interval = sm->NewInterval;
				ASSERT(strcmp(pmcinfo.pmc_srcs[i].name, str) == 0);
				fndi = i;
				fnd = 1;
				pmcinfo.pmc_counters[pmcinfo.pmc_ncounter++] = i;
				break;
			}
		}
		if (fnd == 0) {
			/* create probe if doesnt exist ? */
			ASSERT(0);
		}

		stack[SDT_ARG0] = pmcinfo.pmc_srcs[fndi].srcid;
		stack[SDT_ARG1] = pmcinfo.pmc_srcs[fndi].name;
		stack[SDT_ARG2] = pmcinfo.pmc_srcs[fndi].interval;
		stack[SDT_ARG3] = sm->OldInterval;

	} else if (opcode == 47) {
		int tid = V32(ud, pmc_[arch][0].tid_i);
		uint16_t srcid = V16(ud, pmc_[arch][0].srcid_s);
		if (sdt->sdp_patchval != srcid)
			return (0);
		td = dtrace_etw_td_find(-1, tid, 0);
		stack[SDT_CUR_LOCK] =  dtrace_etw_set_cur(td->pid, td->tid,
		    ev->EventHeader.TimeStamp.QuadPart, ev->BufferContext.ProcessorNumber);
		stack[SDT_ARG0] = PTR(arch, ud, pmc_[arch][0].ip_p);
	} else {
		ASSERT(payload == NULL);
		return (0);
	}

	return (1);
}

char *
payloadhdr(PEVENT_RECORD ev, int hdrsize, USHORT id, UCHAR arch, UCHAR version)
{
	char *payload = dtrace_sdtmem_alloc(ev->UserDataLength + SDT_MSGHDR_SIZE);

	memcpy(payload + hdrsize, ev->UserData, ev->UserDataLength);
	*(UCHAR *) (payload + SDT_MSGHDRLOC_ARCH) = arch;
	*(UCHAR *) (payload + SDT_MSGHDRLOC_VERSION) = version;
	*(USHORT *) (payload + SDT_MSGHDRLOC_ID) = id;

	return payload;
}

static int
sdt_etw_guid_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt, uint64_t *stack)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	USHORT event = ev->EventHeader.EventDescriptor.Id;
	int arch = ARCHETW(ev);

	char *payload = NULL;
	int fnd = 0;

	if (sdt->sdp_ctl->etw_kw == 0 ||
	    (sdt->sdp_ctl->etw_kw & ev->EventHeader.EventDescriptor.Keyword)) {
		/*
		 * each event might trigger multiple probes.
		 * so set current pid & tid for each probe,
		 * since the current process might change
		 * if the session Queue has filled up, which
		 * will trigger sending of a probe.
		 */
		payload = payloadhdr(ev, SDT_MSGHDR_SIZE, event, arch, version);
		stack[SDT_CUR_LOCK] =  dtrace_etw_set_cur(
		    ev->EventHeader.ProcessId,
		    ev->EventHeader.ThreadId,
		    ev->EventHeader.TimeStamp.QuadPart,
		    ev->BufferContext.ProcessorNumber);
		stack[SDT_ARG0] = event;
		stack[SDT_ARG1] = opcode;
		stack[SDT_ARG2] = payload + SDT_MSGHDR_SIZE;
		stack[SDT_ARG3] = ev->UserDataLength;
		stack[SDT_ARG4] = version;
		stack[SDT_ARGPL] = payload;
	} else {
		return (0);
	}

	return (1);
}

int
sdt_etw_dnet_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt, uint64_t *stack)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	UCHAR id = ev->EventHeader.EventDescriptor.Id;
	int arch = ARCHETW(ev);

	int len;
	uint16_t instid = 0;
	char *p = (char *) ev->UserData;
	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &MSDotNETRuntimeGuid));


	if (p != NULL && sdt->sdp_patchval == id) {
		if (id == 187) {
			instid = *(uint16_t *) p;
		} else if ((id == 152 || id == 153) && version >= 2) {
			instid = *(uint16_t *) (p + (len = wcslen(p + 24) + 26, wcslen(p + len) + 2));
		} else if (id == 4 && version >= 2) {
			instid = *(uint16_t *) (p + ev->UserDataLength - 18);
		} else if (id == 10) {
			instid = *(uint16_t *) (p + 8);
		} else {
			instid = *(uint16_t *) (p + ev->UserDataLength - sizeof(uint16_t));
		}
		char *payload = payloadhdr(ev, SDT_MSGHDR_SIZE, id, arch, version);
		stack[SDT_ARG0] = payload + SDT_MSGHDR_SIZE;
		stack[SDT_ARG1] = ev->UserDataLength;
		stack[SDT_ARG2] = arch;
		stack[SDT_ARG3] = version;
		stack[SDT_ARGSTACK] = instid;
	} else {
		return (0);
	}
	return (1);
}

int
sdt_etw_hwconfig_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt,
    uint64_t *stack)
{
	UCHAR version = ev->EventHeader.EventDescriptor.Version;
	UCHAR opcode = ev->EventHeader.EventDescriptor.Opcode;
	USHORT id = ev->EventHeader.EventDescriptor.Id;
	int arch = ARCHETW(ev);

	ASSERT(IsEqualGUID(&ev->EventHeader.ProviderId, &HWSystemConfigGuid));

	if (sdt->sdp_patchval == opcode) {
		char *payload = payloadhdr(ev, SDT_MSGHDR_SIZE, id, arch, version);
		stack[SDT_ARG0] = payload + SDT_MSGHDR_SIZE;
		stack[SDT_ARG1] = ev->UserDataLength;
		stack[SDT_ARG2] = arch;
		stack[SDT_ARG3] = version;
	} else
		return (0);

	return (1);
}

int
sdt_etw_fpid_cb(PEVENT_RECORD ev, void *data, sdt_probe_t *sdt, uint64_t *stack)
{
	uintptr_t pc;
	uint32_t pid = ev->EventHeader.ProcessId;
	uint32_t tid = ev->EventHeader.ThreadId;

	if (ev->EventHeader.EventDescriptor.Id == 1) {
		struct ftetw_event_entry *ft = (struct ftetw_event_entry *) ev->UserData;

		ASSERT(ft->addr > 0);

		pc = ft->addr;
		stack[SDT_ARG0] = 0;
		stack[SDT_ARG1] = pc;
		stack[SDT_ARG2] = ft->arg0;
		stack[SDT_ARG3] = ft->arg1;
		stack[SDT_ARG4] = ft->arg2;
		stack[SDT_ARG5] = ft->arg3;
		stack[SDT_ARG6] = ft->arg4;
		dtrace_set_ft_stack(ft->stack, (ft->stacksz / sizeof (uint64_t)));
	} else if (ev->EventHeader.EventDescriptor.Id == 2) {
		struct ftetw_event_return *ft = (struct ftetw_event_return *) ev->UserData;

		ASSERT(ft->addr > 0);

		pc = ft->addr;

		stack[SDT_ARG0] = 1;
		stack[SDT_ARG1] = pc;
		stack[SDT_ARG2] = ft->ax;
		dtrace_set_ft_stack(ft->stack, (ft->stacksz / sizeof (uint64_t)));
	} else if (ev->EventHeader.EventDescriptor.Id == 3) {
		struct ftetw_blob *ft = (struct ftetw_blob *) ev->UserData;
		ftetw_msg_t *tmp = &ft->arr[0], *tmpr;
		int samp = ft->count, j = 0, co = 0;

		ASSERT(ev->UserDataLength >= ft->count);

		while (samp >= (int) sizeof (ftetw_msg_t)) {
			dtrace_etw_set_cur(tmp->pid, tmp->tid, tmp->time, tmp->cpuno);
			if (tmp->type == INJ_ENTRY_TYPE) {
				dtrace_set_ft_stack(&tmp->stack[INJ_ENTRY_TYPE], tmp->stacksz - INJ_ENTRY_TYPE);
				dtrace_etw_probe(sdt->sdp_id, 0, tmp->addr, tmp->stack[0], tmp->stack[1],
				    tmp->stack[2]);
			} else {
				dtrace_set_ft_stack(&tmp->stack[INJ_RETURN_TYPE],
				    tmp->stacksz - INJ_RETURN_TYPE);
				dtrace_etw_probe(sdt->sdp_id, 1, tmp->addr, tmp->stack[0], 0, 0);
			}
			tmpr = tmp;
			tmp = &(tmp->stack[tmp->stacksz + 1]);
			samp -= ((char *)tmp - (char *)tmpr);
			co++;
		}
		return (0);
	} else if (ev->EventHeader.EventDescriptor.Id == 4) {
		return (0);
	}

	return (1);
}