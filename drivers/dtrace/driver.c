/*
 * Copyright (c) 2015 PK
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/dtrace_misc.h>
#include <windows.h>
#include <strsafe.h>
#include <errno.h>
#include <stddef.h>

#include <sys/dtrace_win32.h>
#include <sys/dtrace_impl.h>
#include <sys/dtrace.h>
#include "etw.h"

extern hrtime_t Hertz;
extern struct modctl *modules;

extern int (*pdtrace_ioctl)(void *addr,  int cmd, void *ext);
extern int (*pdtrace_open)(HANDLE dev, void *state);
extern int (*pdtrace_unload)(HANDLE DrvObj);
extern void (*pdtrace_close)(void *data);
extern void (*pdtrace_load)(void *dummy);

etw_sessions_t * dtrace_etw_handle = NULL;

void DtraceGetSystemHertz();

dtrace_state_t *DtraceState = NULL;
#if !defined(STATIC)
BOOL APIENTRY
DllMain(HMODULE hmodule, DWORD  reason, LPVOID notused)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return (TRUE);
}
#endif

int
DtraceIoctl(HANDLE DevObj, int val, void *data)
{
	int t;

	if (dtrace_etw_handle && val == DTRACEIOC_STOP) {
		dtrace_etw_stop(dtrace_etw_handle);
		dtrace_etw_session_ft_on(dtrace_etw_handle);
	}
	t = pdtrace_ioctl(data, val, DtraceState);

	/*
	 * Activate ETW after all the dtrace dtrace buffer are active
	 * dtrace_state_go()
	 */
	if (dtrace_etw_handle && val == DTRACEIOC_GO)
		return dtrace_etwfile_start(dtrace_etw_handle) == 0 ? -1 : 0;

	return (t);
}

NTSTATUS
DtraceClose(HANDLE DevObj)
{
	if (DtraceState != NULL)
		pdtrace_close(DtraceState);
	dtrace_etw_close(dtrace_etw_handle);

	return (0);
}

int
DtraceETWInit(char *etl, int flags)
{
	wchar_t *etlfile = NULL;

	if (etl != NULL) {
		etlfile = (wchar_t *) malloc(256);
		mbstowcs(etlfile, etl, 256);
	}

	if ((dtrace_etw_handle = etl ?
	    dtrace_etwfile_init(dtrace_probe, DtraceIoctl, etlfile, flags):
	    dtrace_etw_init(dtrace_probe, DtraceIoctl, NULL, flags)) == 0) {
		fprintf(stderr, "dtrace: failed to initialize etw\n");
		return (-1);
	}

	(void) pdtrace_load((void *) 0);

	return (0);
}

int
DtraceOpen()
{
	int st = 1;

	DtraceGetSystemHertz();
	DtraceState = malloc(sizeof (dtrace_state_t));
	if (DtraceState == NULL) {
		st =  0;
	} else {
		ZeroMemory(DtraceState, sizeof (dtrace_state_t));
		if (pdtrace_open(NULL, DtraceState))
			st = 0;
	}

	return (st);
}

void
DtraceUnload(HANDLE DrvObj)
{
}

void
DtraceGetSystemHertz()
{
	LARGE_INTEGER Frequency;

	Hertz = 0;
	QueryPerformanceFrequency(&Frequency);
	if (Frequency.QuadPart != 0)
		Hertz = Frequency.QuadPart;
}
