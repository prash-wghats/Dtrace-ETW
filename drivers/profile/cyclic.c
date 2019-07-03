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

#include <sys/dtrace_misc.h>
#include <sys/dtrace.h>
#include <errno.h>
#include <stddef.h>
#include <sys/dtrace_win32.h>
#include <subauth.h>
#include <time.h>
#include "cyclic.h"
#include "etw.h"
#include "etw_struct.h"

__declspec(dllimport) cpu_data_t *CPU;

void profile_attach(void *dummy);
int profile_detach();

static ULONG64 max_interval = ~0;
#if !defined(STATIC)
BOOL APIENTRY
DllMain(HMODULE hmodule, DWORD  reason, LPVOID notused)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		(void) profile_attach(NULL);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		if (profile_detach() != 0) {
			dprintf("profile provider unload failed\n");
		}
		break;
	}
	return (TRUE);
}
#endif

int
profilebg(PEVENT_RECORD event, void *data)
{
	HANDLE ev = (HANDLE) data;
	dtrace_etw_unhook_event(&PerfInfoGuid, profilebg, data);
	SetEvent(ev);
	return (0);
}

/*
 * TODO: multiple profle probes ???
 * wait here for perfinfo etw events to start
 * before returning to dtrace
 */

HANDLE
ProfileInitate(hrtime_t interval, int type)
{
	int isreal;
	HANDLE event = CreateEvent(NULL, FALSE, FALSE, NULL);

	if (event) {
		dtrace_etw_hook_event(&PerfInfoGuid, profilebg,
		    (void *) event, ETW_EVENTCB_ORDER_ANY);
	}
	isreal = dtrace_etw_profile_enable(interval, type);
	if (isreal) {
		WaitForSingleObject(event, INFINITE);
	} else {
		dtrace_etw_unhook_event(&PerfInfoGuid, profilebg, event);
		CloseHandle(event);
	}

	return (event);
}

int
CycFuncProc(PEVENT_RECORD event, void *data)
{
	cyclic_omni_t *c = (cyclic_omni_t *) data;
	cyclic_t *cyclic;
	void *s;
	struct reg rp = {0};
	thread_t *td = curthread;
	hrtime_t now, exp;
	int cpu;
	cpu_data_t *cpus = &CPU[curcpu];
	struct SampledProfile *samp =
	    (struct SampledProfile *) event->UserData;

	if (event->EventHeader.EventDescriptor.Opcode != 46)
		return (0);

	now = dtrace_etw_gethrtime();
	cpus->cpu_profile_upc = 0;
	cpus->cpu_profile_pc = 0;

	if (INKERNEL(samp->InstructionPointer)) {
		cpus->cpu_profile_pc = samp->InstructionPointer;
	} else {
		cpus->cpu_profile_upc = samp->InstructionPointer;
	}

	cpu = event->BufferContext.ProcessorNumber;

	if (c->type == CYCLIC) {
		cyclic = c->cyc;
	} else {
		ASSERT(c->cpus > cpu);
		cyclic = &c->cyc[cpu];
	}
	s = cyclic->cy_arg;
	td->tf = &rp;

	/*
	 * "sample" probe will just fire every time a profile event is seen.
	 * for "sample" probe cyclic->cy_expire  == -1
	 */
	if (cyclic->cy_expire == -1) {
		(void) (cyclic->cy_func)(s);
		td->tf = NULL;
		return (0);
	}

	for (;;) {
		if ((exp = cyclic->cy_expire) > now) {
			break;
		}

		(void) (cyclic->cy_func)(s);

		exp += cyclic->cy_interval;
		if (now - exp > ((hrtime_t)2*NANOSEC)) {
			hrtime_t interval = cyclic->cy_interval;
			exp += ((now - exp) / interval + 1) * interval;
		}

		cyclic->cy_expire = exp;
	}

	td->tf = NULL;

	return (0);
}

#define	ONLINE  0
#define	OFFLINE  1

int
StartProfile(PEVENT_RECORD ev, void *data)
{
	cyclic_omni_t *c = (cyclic_omni_t *) data;
	cyc_omni_handler_t *omni = &c->omni;
	cyc_handler_t hdlr;
	cyclic_t *cyc = c->cyc;
	cyc_time_t time;
	int cpus = c->cpus;

	if (ev->EventHeader.EventDescriptor.Opcode != 46)
		return (0);

	hrtime_t now = dtrace_etw_gethrtime();

	while (cpus--) {
		cyclic_t *cyclic = cyc++;
		time = cyclic->time;

		if (c->type == OMNI_CYCLIC) {
			(omni->cyo_online)(omni->cyo_arg, NULL, &hdlr, &time);
			cyclic->cy_func = hdlr.cyh_func;
			cyclic->cy_arg = hdlr.cyh_arg;
			cyclic->cy_interval = time.cyt_interval;
			cyclic->time = time;
		} else {
			cyclic->cpuno = ev->BufferContext.ProcessorNumber;
		}

		if (time.cyt_when == 0) {
			/*
			 * If a start time hasn't been explicitly specified,
			 * we'll start on the next interval boundary.
			 */
			cyclic->cy_expire = (now / cyclic->cy_interval + 1) *
			    cyclic->cy_interval;
		} else {
			cyclic->cy_expire = time.cyt_when;
		}
		dprintf("profile, StartProfile - time (%lld) interval (%lld)"
		    " expire (%lld) when (%lld)\n",
		    now, cyclic->cy_interval, cyclic->cy_expire, time.cyt_when);
	}

	dtrace_etw_unhook_event(&PerfInfoGuid, StartProfile, data);

	return (0);
}

cyclic_id_t
cyclic_add(cyc_handler_t *hdlr, cyc_time_t *time)
{
	cyclic_t *cyclic;
	LARGE_INTEGER nano;
	int cpu = curcpu;
	ULONG res;

	cyclic_omni_t *c = kmem_zalloc(sizeof (cyclic_omni_t), KM_SLEEP);

	if (c == NULL)
		return (CYCLIC_NONE);

	if ((cyclic = kmem_zalloc(sizeof (cyclic_t), KM_SLEEP)) == NULL) {
		kmem_free(c, sizeof (cyclic_omni_t));
		return (CYCLIC_NONE);
	}

	cyclic->cy_func = hdlr->cyh_func;
	cyclic->cy_arg = hdlr->cyh_arg;
	cyclic->cy_interval = time->cyt_interval;
	cyclic->cpuno = -1;
	cyclic->time = *time;

	c->cyc = cyclic;
	c->type = CYCLIC;
	c->cpus = 1;

	dtrace_etw_hook_event(&PerfInfoGuid, StartProfile,
	    (void *) c, ETW_EVENTCB_ORDER_ANY);
	dtrace_etw_hook_event(&PerfInfoGuid, CycFuncProc,
	    (void *) c, ETW_EVENTCB_ORDER_LAST);

	if (max_interval > time->cyt_interval) {
		max_interval = time->cyt_interval;
		ProfileInitate(time->cyt_interval, CYCLIC);
	}

	return ((cyclic_id_t) c);
}

cyclic_id_t
cyclic_add_omni(cyc_omni_handler_t *omni, hrtime_t interval)
{
	cyclic_t *cyclic;
	ULONG cpus = NCPU;
	cyclic_omni_t *c = kmem_zalloc(sizeof (cyclic_omni_t), KM_SLEEP);

	if (c == NULL)
		return (CYCLIC_NONE);

	if ((cyclic = kmem_zalloc(sizeof (cyclic_t)*cpus, KM_SLEEP)) == NULL) {
		kmem_free(c, sizeof (cyclic_omni_t));
		return (CYCLIC_NONE);
	}

	c->type = OMNI_CYCLIC;
	c->cyc = cyclic;
	c->cpus = cpus;
	c->omni = *omni;

	dtrace_etw_hook_event(&PerfInfoGuid, StartProfile,
	    (void *) c, ETW_EVENTCB_ORDER_ANY);
	dtrace_etw_hook_event(&PerfInfoGuid, CycFuncProc,
	    (void *) c, ETW_EVENTCB_ORDER_LAST);

	if (max_interval > interval) {
		max_interval = interval;
		ProfileInitate(interval, OMNI_CYCLIC);
	}

	return ((cyclic_id_t) c);
}

void
cyclic_remove(cyclic_id_t id)
{
	cyclic_omni_t *c = (cyclic_omni_t *) id;
	int cpus = c->cpus;

	dtrace_etw_unhook_event(&PerfInfoGuid, CycFuncProc, c);

	if (c->type == CYCLIC) {
		c->cyc->cpuno = -1;

		dtrace_etw_profile_disable(CYCLIC);

		kmem_free(c->cyc, sizeof (cyclic_t));
		kmem_free(c, sizeof (cyclic_omni_t));
	} else {
		ASSERT(c->type == OMNI_CYCLIC);

		cyclic_t *cyc = c->cyc;
		cyc_omni_handler_t *omni = &c->omni;
		int cpus = c->cpus;

		dtrace_etw_profile_disable(OMNI_CYCLIC);

		while (cpus--) {
			cyclic_t *cyclic = cyc++;
			cyclic->cpuno = -1;

			(omni->cyo_offline)(omni->cyo_arg, NULL, cyclic->cy_arg);
		}
		kmem_free(c->cyc, 1);
		kmem_free(c, sizeof (cyclic_omni_t));
	}
}
