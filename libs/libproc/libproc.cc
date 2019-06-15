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
 *
 * Copyright (C) 2015  Prashanth K.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdio.h>
#include <conio.h>
#include <fcntl.h>
#include <sys\types.h>
#include <sys\stat.h>
#if _MSC_VER
#include <strsafe.h>
#include <io.h>
#endif
#include <pthread.h>
#include <dtrace_misc.h>
#include <dtrace.h>
#include <libpe.h>
#include <libproc.h>
#include "etw.h"
#include "libproc_win.h"
#include "common.h"

static void addmodule(struct ps_prochandle *P, HANDLE hFile, char *s,
	    PVOID base, int type, int load);
static void freemodules(struct ps_prochandle *P);
static int isfunction(struct ps_prochandle *P, PSYMBOL_INFO s);
static proc_mod_t *findmodulebyaddr(struct ps_prochandle *P, ULONG64 addr);
static proc_mod_t *findmodulebyname(struct ps_prochandle *P, const char *name);
static void delmodule(struct ps_prochandle *P, ULONG64 imgbase);
static int dw_lookup_by_name(struct ps_prochandle *P, const char *oname,
	    const char *sname, GElf_Sym *symp);
static int dw_lookup_by_addr(struct ps_prochandle *P, uint64_t addr,
	    char *buf, size_t size, GElf_Sym *symp);
static int dw_iter_by_addr(struct ps_prochandle *P, const char *object_name,
	    int which, int mask, proc_sym_f *func, void *cd);
static void *Ploopcreate(LPVOID args);
static void *Ploopgrab(LPVOID args);

static int isnetmodule(const char *s, int *arch);
static char *pathfrompid(uint32_t pid);
static int dtnetarch(int arch);

#define CREATE_FAILED -1
#define CREATE_SUCCEDED 1
#define BREAKPOINT_INSTR	0xcc	/* int 0x3 */
#define	BREAKPOINT_INSTR_SZ	1

struct ps_prochandle *Pcreate(const char * exe, char *const *args,
    int *err, char *path, size_t size)
{
	struct ps_prochandle *ps;
	struct proc_uc data;
	int arch = 0;

	if ((ps = (struct ps_prochandle *) malloc(sizeof(struct ps_prochandle))) == NULL) {
			return NULL;
		}

	ZeroMemory(ps, sizeof(struct ps_prochandle));
	ps->attached = 0;
	data.ps = ps;
	data.exe = exe;
	data.args = args;

	pthread_mutex_init(&ps->mutex, NULL);
	pthread_cond_init (&ps->cond, NULL);

	// .net or native
	if (isnetmodule(exe, &arch) > 0) {
		if (dtnetarch(arch) == 0) {
			fprintf(stderr, "dtrace: can't trace %s .net process with %s version\n",
			    arch ? "x86":"x64", arch ? "x64":"x86");
			pthread_mutex_destroy(&ps->mutex);
			pthread_cond_destroy(&ps->cond);
			free(ps);
			return NULL;
		}
		if (net_create(&data, arch)) {
			pthread_mutex_destroy(&ps->mutex);
			pthread_cond_destroy(&ps->cond);
			free(ps);
			return NULL;
		}
	} else if (pthread_create(&ps->pthr, NULL, Ploopcreate, &data)) {
		pthread_mutex_destroy(&ps->mutex);
		pthread_cond_destroy(&ps->cond);
		free(ps);
		return NULL;
	}

	pthread_mutex_lock(&ps->mutex);
	while (ps->status != PS_STOP)
		pthread_cond_wait(&ps->cond, &ps->mutex);
	pthread_mutex_unlock(&ps->mutex);

	if (ps->flags == CREATE_FAILED) {
		pthread_mutex_destroy(&ps->mutex);
		pthread_cond_destroy(&ps->cond);
		free(ps);
		return NULL;
	}

	return ps;
}

static void
common_loop(struct ps_prochandle *P)
{
	DWORD dbgstatus, excep, size = 0;
	BOOL wow = 0;
	TCHAR pszFilename[MAX_PATH+1];
	DEBUG_EVENT  dbg;
	int excep_count = 0, busy = 0;
	char *s;

	while (1) {
		if (WaitForDebugEvent(&dbg, INFINITE) == 0) {
			return;
		}
		dbgstatus = DBG_CONTINUE;

		if (P->busyloop) {
			/*
			 * for initial busyloop, thread event (CreateRemoteThread) and
			 * load library event (agentxx.dll) will be caught
			 */
			//ASSERT(dbg.dwDebugEventCode != EXCEPTION_DEBUG_EVENT);
			if (dbg.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
				P->exitcode = dbg.u.ExitProcess.dwExitCode;
				P->exited = 1;
				P->status = PS_UNDEAD;
				P->msg.type = RD_NONE;
				P->fthelper(P->pid, -1, PSYS_PROC_DEAD, NULL);
				SetEvent(P->event);
			}
			ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, dbgstatus);
			continue;
		}

		pthread_mutex_lock(&P->mutex);

		switch (dbg.dwDebugEventCode) {
		case CREATE_PROCESS_DEBUG_EVENT:
			P->phandle = dbg.u.CreateProcessInfo.hProcess;
			P->thandle = dbg.u.CreateProcessInfo.hThread;

			if (init_symbols(P->phandle, FALSE, NULL) == NULL)
				break;

			s = GetFileNameFromHandle(dbg.u.CreateProcessInfo.hFile, pszFilename);
			addmodule(P, dbg.u.CreateProcessInfo.hFile, s,
			    dbg.u.CreateProcessInfo.lpBaseOfImage,
			    PE_TYPE_EXE, P->dll_load_order);

			if ((size = GetFileSize(dbg.u.CreateProcessInfo.hFile, NULL)) == INVALID_FILE_SIZE) {
				size = 0;
			}

			if (SymLoadModuleEx(P->phandle, dbg.u.CreateProcessInfo.hFile, s, NULL,
			        (ULONG_PTR) dbg.u.CreateProcessInfo.lpBaseOfImage, size, NULL, 0) == 0) {
				dprintf("SymLoadModule64 failed for (%s):(%d)\n", s, GetLastError());
				break;
			}

#if __amd64__
			if (Is32bitProcess(P->phandle)) {
				P->model = PR_MODEL_ILP32;
				wow = 1;
			} else
				P->model = PR_MODEL_ILP64;
#else
			P->model = PR_MODEL_ILP32;
#endif
			if (P->attached) {
				P->status = PS_RUN;
			} else {
				P->status = PS_STOP;
			}
			P->msg.type = RD_NONE;
			CloseHandle(dbg.u.CreateProcessInfo.hFile);
			if (P->attached == 0) {
				pthread_cond_signal(&P->cond);
			}

			break;
		case CREATE_THREAD_DEBUG_EVENT:
			P->status = PS_RUN;
			P->msg.type = RD_NONE;
			break;
		case LOAD_DLL_DEBUG_EVENT:
			s = GetFileNameFromHandle(dbg.u.LoadDll.hFile, pszFilename);
			if (P->main) {
				P->dll_load_order++;
			}
			addmodule(P, dbg.u.LoadDll.hFile, s, dbg.u.LoadDll.lpBaseOfDll,
			    PE_TYPE_DLL, P->dll_load_order);

			if ((size = GetFileSize(dbg.u.LoadDll.hFile, NULL)) == INVALID_FILE_SIZE) {
				size = 0;
			}
#if __amd64__
			/* Not tracing 64 bit dlls for 32 bit process */
			if (P->model == PR_MODEL_ILP32 && is64bitmodule(dbg.u.LoadDll.lpBaseOfDll, s)) {
				CloseHandle(dbg.u.LoadDll.hFile );
				break;
			}
#endif
			if (SymLoadModuleEx(P->phandle, dbg.u.LoadDll.hFile, s, NULL,
			        (ULONG_PTR) dbg.u.LoadDll.lpBaseOfDll, size, NULL, 0) == FALSE) {
				dprintf("SymLoadModule64 dailed for %s:%d\n", s, GetLastError());
				break;
			}

			CloseHandle(dbg.u.LoadDll.hFile );
			if (P->attached && excep_count == 0) {
				P->status = PS_RUN;
				P->msg.type = RD_DLACTIVITY;
				break;
			}
			/*
			 * fpid provider: dynamic library loading
			 * If the agentxx.dll is already injected into the traced process,
			 * i.e some probes already been found, then we will suspend the thread
			 * inducing the library load and continue from the debug event.
			 * If no probe has been found, then we cant suspend the thread, cause if any
			 * probes are found, we will inject the tracing dll, which will
			 * cause a hang, since we are already in a suspened library load event.
			 * so will continue the event without suspending the thread. If the thread
			 * loading the dll, exits immediatly than most likely we will not able to
			 * trace any probes in the dll. There is also the possibility that the
			 * traced process may exit, while we try to inject.
			 */
			if ((P->fpid == 1) && ((P->attached == 0 && excep_count > 1) ||
			        (P->attached && excep_count > 0))) {
				P->threads[0] = dbg.dwThreadId;
				P->nthr = 1;
				/*
				 * fpid provider: (-Z) if we get here without any probes, ie agentxx.dll
				 * is not injected to thr traced process, than we cant suspend the thread
				 */
				if (P->thragent == 0) {
					P->nthr = 0;
					P->status = PS_RUN;
					P->msg.type = RD_NONE;
					//break;
				}
				suspendbusy(P, !P->model);

				P->addr = 0;

				P->status = PS_STOP;
				P->msg.type = RD_DLACTIVITY;
				P->busyloop = 1;

				HANDLE td = CreateThread(NULL, 0, busyloop_thread, P, 0, NULL);
				ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, dbgstatus);
				continue;

			}
			P->status = PS_STOP;
			P->msg.type = RD_DLACTIVITY;
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			/*
			 * If any traced dll is unloaded and loaded then no further trace will
			 * take place.
			 */
			if (SymUnloadModule64(P->phandle, (ULONG_PTR) dbg.u.UnloadDll.lpBaseOfDll) ==  FALSE) {
				dprintf("SymUnloadModule64 failed-Imagebase %p:%d\n", dbg.u.UnloadDll.lpBaseOfDll, GetLastError());
				break;
			}
			delmodule(P, (ULONG64) dbg.u.UnloadDll.lpBaseOfDll);
			P->status = PS_RUN;
			P->msg.type = RD_DLACTIVITY;
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			if (P->fthelper) {
				P->fthelper(P->pid, -1, PSYS_PROC_DEAD, NULL);
			} else {
				// Not FT provider. wait for ETW to catch up
				Sleep(2000);
			}
			P->exitcode = dbg.u.ExitProcess.dwExitCode;
			P->exited = 1;
			P->status = PS_UNDEAD;
			P->msg.type = RD_NONE;

			break;
		case EXIT_THREAD_DEBUG_EVENT:
			P->status = PS_RUN;
			P->msg.type = RD_NONE;
			break;
		case EXCEPTION_DEBUG_EVENT:
			switch(excep = dbg.u.Exception.ExceptionRecord.ExceptionCode) {
			case EXCEPTION_BREAKPOINT:
			case 0x4000001F:	/* WOW64 exception breakpoint */
				/*
				 * Initial exception from WaitForDebugEvent()
				 * NOTE: Dtrace sets a BP at main (entry point of the process), which is implemented
				 * with Psetbkpt, Pdelbkpt & Pexecbkpt. But I have implemnted it here.
				 */
				if (P->attached == 0 &&
				    ((excep == EXCEPTION_BREAKPOINT && excep_count == 0 && wow == 0) ||
				        (excep == 0x4000001F && excep_count == 0 && wow == 1)) ) {
					GElf_Sym sym;

					if (Pxlookup_by_name(P, LM_ID_BASE, "a.out", "main", &sym, NULL) != 0 &&
					    Pxlookup_by_name(P, LM_ID_BASE, "a.out", "WinMain", &sym, NULL) != 0) {
						dprintf("failed to find entry point (main):%d\n", GetLastError());
						break;
					}

					if (setbkpt(P, (uintptr_t) sym.st_value) != 0) {
						dprintf("failed to set breakpoint for %s at address %p\n", "main", sym.st_value);
						break;
					}

					excep_count = 1;
					P->status = PS_RUN;
					P->msg.type = RD_NONE;
					break;
				}

				/* exception from breakpoint set on (main) */
				if (P->attached == 0 && excep_count == 1) {
					if (dbg.u.Exception.ExceptionRecord.ExceptionAddress != (PVOID) P->addr) {
						dprintf("expecting execption at (%p):but recived from (%p)\n",
						    P->addr,
						    dbg.u.Exception.ExceptionRecord.ExceptionAddress);
						P->status = PS_RUN;
						dbgstatus = DBG_EXCEPTION_NOT_HANDLED;
						break;
					}

					if (delbkpt(P, P->addr) != 0) {
						dprintf("failed to delete brk point at (%p):(main)\n", P->addr);
						break;
					}

					if (adjbkpt(P, wow) != 0) {
						dprintf("failed to normalize brk point (main) (%x)\n",
						    GetLastError());
						break;
					}
					/*
					 * put the thread in a busy loop.
					 * This is required for fpid provider, since the process has to
					 * active to inject the agent thread. At this point, we dont known
					 * whether this is for a pid provider or fpid provider, so we set
					 * to a busy loop, which works for both providers.
					 */
					//busy = insbusyloop(P, wow);
					P->main = 1;
					excep_count = 2;
					P->status = PS_STOP;
					P->msg.type = RD_MAININIT;
				} else if (P->attached && excep_count++ == 0) {
					//P->addr = (uintptr_t) dbg.u.Exception.ExceptionRecord.ExceptionAddress;
					//busy = insbusyloop(P, wow);
					P->main = 1;
					pthread_cond_signal(&P->cond);
					P->status = PS_STOP;
					P->msg.type = RD_NONE;

				} else if (P->fthelper != NULL) {
					exception_cb(P, &dbg);
					P->status = PS_RUN;
					P->msg.type = RD_NONE;
				} else {
					P->status = PS_RUN;
					dbgstatus = DBG_EXCEPTION_NOT_HANDLED;
				}

				break;
			default:
				if (dbg.u.Exception.dwFirstChance == 0)
					P->wstat = dbg.u.Exception.ExceptionRecord.ExceptionCode;
				P->status = PS_RUN;
				dbgstatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			}
			break;
		case OUTPUT_DEBUG_STRING_EVENT: {
			WCHAR *msg;
			int sz;

			OUTPUT_DEBUG_STRING_INFO DebugString = dbg.u.DebugString;
			sz = DebugString.fUnicode ? sizeof(WCHAR) : sizeof(CHAR);
			msg = (WCHAR *) malloc(sz * dbg.u.DebugString.nDebugStringLength);
			ReadProcessMemory(P->phandle,       // HANDLE to Debuggee
			    DebugString.lpDebugStringData, // Target process' valid pointer
			    msg,                           // Copy to this address space
			    DebugString.nDebugStringLength, NULL);
#if 0
			if (DebugString.fUnicode)
				dprintf("DEBUG: (%ls)\n", msg);
			else
				dprintf("DEBUG: (%s)\n", msg);
#endif
			P->status = PS_RUN;
			break;
		}
		default:
			P->status = PS_RUN;
			dprintf("Debug Event not processed: (%d)\n", dbg.dwDebugEventCode);
			break;
		}

		if (P->status != PS_RUN)
			SetEvent(P->event);
		while (P->status == PS_STOP)
			pthread_cond_wait(&P->cond, &P->mutex);
		pthread_mutex_unlock(&P->mutex);
		if ((P->fpid == 1) &&
		    ((P->attached == 0 && excep_count == 2) ||
		        (P->attached && excep_count == 1))) {
			excep_count = 3;
			P->busyloop = 1;
			P->skip = 1;
			insbusyloop(P, wow);
			P->status = PS_STOP;
			//pthread_mutex_unlock(&P->mutex);
			pthread_cond_signal(&P->cond);
			HANDLE td = CreateThread(NULL, 0, busyloop_thread, P, 0, NULL);
			ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, dbgstatus);
			continue;
		}
		if ((P->fpid != 1)  &&
		    ((P->attached == 0 && excep_count == 2) ||
		        (P->attached && excep_count == 1))) {
			excep_count = 3;
			if (P->fthelper)
				P->fthelper(P->pid, -1, PSYS_SYM_HANDLE, P->phandle);
		}
		ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, dbgstatus);
	}

}
static void *
Ploopcreate(LPVOID args)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD symopt, size = 0;
	BOOL wow = 0;
	struct proc_uc *tmp = (struct proc_uc *) args;
	struct ps_prochandle *P = tmp->ps;
	char targs[256], *ctmp;
	char *const *argv = tmp->args;
	int excep_count = 0, len, busy = 0, agentthr = 0;

	symopt = SymGetOptions();

	/* convert array of arguments to single concated string */
	ctmp = targs;
	while (*argv != NULL) {
		len = strlen(*argv);
		sprintf(ctmp, "%s ", *argv);
		ctmp = ctmp + len + 1;
		argv++;
	}
	*ctmp = '\0';

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	if(!CreateProcess( NULL,   //  module name
	        targs,        // Command line
	        NULL,           // Process handle not inheritable
	        NULL,           // Thread handle not inheritable
	        FALSE,          // Set handle inheritance to FALSE
	        DEBUG_ONLY_THIS_PROCESS,              // No creation flags
	        NULL,           // Use parent's environment block
	        NULL,           // Use parent's starting directory
	        &si,            // Pointer to STARTUPINFO structure
	        &pi )           // Pointer to PROCESS_INFORMATION structure
	) {
		pthread_mutex_lock(&P->mutex);
		P->status = PS_STOP;
		P->flags = CREATE_FAILED;
		pthread_cond_signal(&P->cond);
		pthread_mutex_unlock(&P->mutex);
		return NULL;
	}
	P->pid = pi.dwProcessId;
	P->tid = pi.dwThreadId;
	P->wstat = 0;
	P->exitcode = 0;
	P->event = CreateEvent(NULL,FALSE,FALSE,NULL);
	P->dll_load_order = 1;

	SymSetOptions(symopt | SYMOPT_INCLUDE_32BIT_MODULES |
	    SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);

	common_loop(P);
	return NULL;
}

struct ps_prochandle *Pgrab(pid_t pid, int flags, int *perr)
{
	struct ps_prochandle *ps;
	int id, arch = 0;
	struct proc_uc data;
	char *exe;

	id = GetCurrentProcessId();

	if (pid == 0 || (pid == id && !(flags & PGRAB_RDONLY))) {
		return NULL;
	}

	if ((ps = (struct ps_prochandle *) malloc(sizeof(struct ps_prochandle))) == NULL) {
			return NULL;
		}

	ZeroMemory(ps, sizeof(*ps));
	ps->pid = pid;
	ps->flags = flags;
	ps->attached = 1;

	if (flags & PGRAB_ETW) {
		etw_proc_module_t *hprocess = dtrace_etw_pid_symhandle(pid);
		if (hprocess == NULL) {
			free(ps);
			return NULL;
		}
		ps->etwmods = hprocess;
		ps->isetw = 1;
		return ps;
	}

	if (flags & PGRAB_RDONLY) {
		DWORD Options = SymGetOptions();
		HANDLE hprocess = NULL;
		//XXXX
		//hprocess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );

		if (hprocess == NULL) {
			dprintf("failed to open process %d: %d\n", pid, GetLastError());
			etw_proc_module_t *hprocess = dtrace_etw_pid_symhandle(pid);
			if (hprocess == NULL) {
				free(ps);
				return NULL;
			}
			ps->etwmods = hprocess;
			ps->isetw = 1;
			return ps;
		}

		SymSetOptions(Options|SYMOPT_INCLUDE_32BIT_MODULES|SYMOPT_DEFERRED_LOADS|SYMOPT_DEBUG);

		if (init_symbols(hprocess, TRUE, NULL) == NULL)
			;
		ps->phandle = hprocess;
		return ps;
	}

	data.ps = ps;

	pthread_mutex_init(&ps->mutex, NULL);
	pthread_cond_init (&ps->cond, NULL);

	exe = pathfrompid(pid);

	if (exe && isnetmodule(exe, &arch) > 0) {
		if (dtnetarch(arch) == 0) {
			fprintf(stderr, "dtrace: can't trace %s .net process with %s version\n",
			    arch ? "x86":"x64", arch ? "x64":"x86");
			pthread_mutex_destroy(&ps->mutex);
			pthread_cond_destroy(&ps->cond);
			free(ps);
			return NULL;
		}
		if (net_attach(&data)) {
			pthread_mutex_destroy(&ps->mutex);
			pthread_cond_destroy(&ps->cond);
			free(ps);
			return NULL;
		}
	} else if (pthread_create(&ps->pthr, NULL, Ploopgrab, &data)) {
		pthread_mutex_destroy(&ps->mutex);
		pthread_cond_destroy(&ps->cond);
		free(ps);
		return NULL;
	}

	pthread_mutex_lock(&ps->mutex);
	while (ps->status != PS_STOP)
		pthread_cond_wait(&ps->cond, &ps->mutex);
	pthread_mutex_unlock(&ps->mutex);

	if (ps->flags == CREATE_FAILED) {
		pthread_mutex_destroy(&ps->mutex);
		pthread_cond_destroy(&ps->cond);
		free(ps);
		return NULL;
	}

	return ps;
}

void *
Ploopgrab(LPVOID args)
{
	DWORD cont = DBG_CONTINUE, size = 0;
	struct proc_uc *tmp = (struct proc_uc *) args;
	struct ps_prochandle *P = tmp->ps;
	int first_execp = 0;
	BOOL wow = 0;
	DWORD Options = SymGetOptions();
	int busy = 0;

	if (DebugActiveProcess(P->pid) == 0) {
		dprintf( "failed to debug process (%d): %d\n", P->pid, GetLastError() );
		pthread_mutex_lock(&P->mutex);
		P->status = PS_STOP;
		P->flags = CREATE_FAILED;
		if (P->status == PS_STOP)
			pthread_cond_signal(&P->cond);
		pthread_mutex_unlock(&P->mutex);
		return NULL;
	}

	DebugSetProcessKillOnExit(FALSE);

	P->wstat = 0;
	P->exitcode = 0;
	P->event = CreateEvent(NULL,FALSE,FALSE,NULL);
	P->dll_load_order = 1;
	SymSetOptions(Options|SYMOPT_INCLUDE_32BIT_MODULES|SYMOPT_DEFERRED_LOADS|SYMOPT_DEBUG);

	common_loop(P);
	return NULL;
}

int
Pstopstatus(struct ps_prochandle *P)
{
	if (P->status == PS_RUN) {
		DWORD ret, ms = 500;
		/* Not waiting indefinetly because,
		 * ctrl C is not caught by traced exe when grabbed.????
		 * So will not known when to quit */
		ret = WaitForSingleObject(P->event, ms);
		if (ret == WAIT_OBJECT_0) {
			return 0;
		} else {
			return 1;
		}
	}
	return 0;
}

int
Psetrun(struct ps_prochandle *P, int sig, int flags)
{
	pthread_mutex_lock(&P->mutex);
	if (P->status == PS_STOP) {
		P->status = PS_RUN;
		pthread_cond_signal(&P->cond);
	}
	pthread_mutex_unlock(&P->mutex);
	return 0;
}

int
Pstate(struct ps_prochandle *P)
{
	return P->status;
}

const int
Pstatus(struct ps_prochandle *P)
{
	return P->flags;
}

int
setbkpt(struct ps_prochandle *P, uintptr_t addr)
{
	SIZE_T ret;
	BYTE saved = 0, brk = BREAKPOINT_INSTR;

	ReadProcessMemory(P->phandle, (PVOID) addr, &saved, BREAKPOINT_INSTR_SZ, &ret);
	if (ret != BREAKPOINT_INSTR_SZ) {
		return -1;
	}
	P->saved = saved;
	P->addr = addr;
	WriteProcessMemory(P->phandle, (PVOID) addr, &brk, BREAKPOINT_INSTR_SZ, &ret);

	if (ret != BREAKPOINT_INSTR_SZ) {
		return -1;
	}

	FlushInstructionCache(P->phandle, (PVOID) addr, BREAKPOINT_INSTR_SZ);

	return 0;
}

int
Psetbkpt(struct ps_prochandle *P, uintptr_t addr, ulong_t *instr)
{
	return 0;
}

int
delbkpt(struct ps_prochandle *P, uintptr_t addr)
{
	SIZE_T ret;

	WriteProcessMemory(P->phandle, (PVOID) P->addr,
	    &P->saved, BREAKPOINT_INSTR_SZ, &ret);

	if (ret != BREAKPOINT_INSTR_SZ) {
		return -1;
	}

	FlushInstructionCache(P->phandle, (PVOID) P->addr, BREAKPOINT_INSTR_SZ);

	return 0;
}

int
Pdelbkpt(struct ps_prochandle *P, uintptr_t addr, ulong_t instr)
{
	return 0;
}

int
adjbkpt(struct ps_prochandle *P, int wow)
{
	CONTEXT ct;
#if __amd64__
	WOW64_CONTEXT ct32;

	if (wow) {
		ZeroMemory(&ct32, sizeof(PWOW64_CONTEXT));
		ct32.ContextFlags = CONTEXT_CONTROL;
		if (Wow64GetThreadContext(P->thandle, &ct32) == 0) {
			return -1;
		}
		ct32.Eip--;
		if (Wow64SetThreadContext(P->thandle, &ct32) == 0) {
			return -1;
		}
		return 0;
	}
#endif
	ZeroMemory(&ct, sizeof(CONTEXT));
	ct.ContextFlags = CONTEXT_CONTROL;

	if (GetThreadContext(P->thandle, &ct) == 0) {
		return -1;
	}
#if __i386__
	ct.Eip--;
#else
	ct.Rip--;
#endif
	if (SetThreadContext(P->thandle, &ct) == 0) {
		return -1;
	}
	return 0;
}

int
Pxecbkpt(struct ps_prochandle *P, ulong_t instr)
{
	return 0;
}

int
Psetflags(struct ps_prochandle *P, long flags)
{
	P->flags |= flags;
	return 0;
}

int
Punsetflags(struct ps_prochandle *P, long flags)
{
	P->flags &= ~flags;
	return 0;
}

/*
 * Release the process.  Frees the process control structure.
 * flags:
 *	PRELEASE_KILL	Terminate the process with SIGKILL.
 */
void
Prelease(struct ps_prochandle *P, int flags)
{
	if (flags & PRELEASE_KILL) {
		if (!P->exited) {
			TerminateProcess(P->phandle, 1);
		}
		if (P->isnet) {
			net_detach(P, 0);
		}
	} else {
		if (P->flags & PGRAB_RDONLY) {
			if (P->flags & PGRAB_ETW) {
				return;
			}
			SymCleanup(P->phandle);
			freemodules(P);
			//free(P);
			return;
		}
		CloseHandle(P->event);

		if (P->isnet) {
			net_detach(P, 1);
		} else {
			DebugActiveProcessStop(P->pid);
		}
	}
	SymCleanup(P->phandle);
	freemodules(P);
	//pthread_mutex_destroy(&P->mutex);
	//pthread_cond_destroy(&P->cond);
	//free(P);	// debug thread
}

void
Pupdate_syms(struct ps_prochandle *P)
{

}

rd_err_e
rd_event_getmsg(rd_agent_t *rd, rd_event_msg_t *rdm)
{
	rdm->type = rd->rda_php->msg.type;
	rdm->u.state = RD_CONSISTENT;
	return RD_OK;
}

rd_err_e
rd_event_addr(rd_agent_t *nop, rd_event_e ev, rd_notify_t *rdn)
{
	rdn->type = RD_NOTIFY_BPT;
	rdn->u.bptaddr = ev;
	return RD_OK;
}

rd_agent_t *
Prd_agent(struct ps_prochandle *P)
{
	rd_agent_t *rd;

	if ((rd = (rd_agent_t *) malloc(sizeof(rd_agent_t))) == NULL) {
		return NULL;
	}
	rd->rda_php = P;
	P->rdap = rd;
	return P->rdap;
}

rd_err_e
rd_event_enable(rd_agent_t *nop, int i)
{
	return RD_OK;
}

rd_event_e
rd_event_type(struct ps_prochandle *P)
{
	return P->msg.type;
}

/*
 * Object name matcing rules.
 * *) case insensitive (ex. system.Drawing)
 * *) match full name (ex. System.Drawing.dll)
 * *) match name without ext (ex. System.Drawing)
 * *) match a.out to exe
 */
int
cmpmodname(const char *oname, const char *mname, int isexemname)
{
	char otmp[MAX_PATH] = {0}, mtmp[MAX_PATH] = {0}, *sm = mtmp, *so = otmp;
	int olen, mlen;

	if (isexemname) {
		if (strcmp(oname, "a.out") == 0) {
			return (1);
		}
	}
	olen = strlen(oname); mlen = strlen(mname);
	if (olen > mlen) {
		return 0;
	}
	memcpy(otmp, oname, olen);
	memcpy(mtmp, mname, mlen);
	
	so = _strlwr(otmp);
	sm = _strlwr(mtmp);

	if (strncmp(mtmp, otmp, olen) == 0) {
		if (mlen == olen)
			return (1);	//exact match
		/* check next module character in '.', and the last one */
		if (mtmp[olen] == '.' && strchr(&mtmp[olen+1], '.') == NULL)
			return (1);
	}

	return (0);
}

static const char *
normobj(const char *oname, struct ps_prochandle *P)
{
	const char *s = NULL, *dot;
	static char str[256];
	int l;

	if (strcmp(oname, "a.out") == 0) {
		if (P->isnet)
			s =  P->nexe_module->nm_name;
		else
			s = P->exe_module->name;
	} else if ((dot = strrchr(oname, '.')) != NULL) {
		if (lstrcmpiA(dot, ".dll") == 0 || lstrcmpiA(dot, ".exe") == 0) {
			l = dot - oname;
			strncpy(str, oname, l);
			str[l] = 0;
			s = str;
		} else {
			s = oname;
		}
	} else {
		s = oname;
	}

	return s;
}

struct object_iter_uc {
	proc_map_f *f;
	void *cd;
	struct ps_prochandle *proc;
};

BOOL CALLBACK MyEnumerateModulesProc1(PCTSTR ModuleName,
    DWORD64 BaseOfDll, PVOID UserContext);

BOOL CALLBACK
MyEnumerateModulesProc1(PCTSTR ModuleName, DWORD64 BaseOfDll, PVOID UserContext)
{
	struct object_iter_uc *data = (struct object_iter_uc *) UserContext;
	prmap_t map;
	const char *name = ModuleName;
	proc_mod_t *mod = data->proc->modules;

	for(; mod != NULL; mod = mod->next) {
		if (mod->imgbase == BaseOfDll &&
		    mod->loaded_order == data->proc->dll_load_order) {
			map.pr_vaddr = BaseOfDll;
			map.pr_mflags = MA_READ;
			data->f(data->cd, &map, mod->name);
		}
	}
	return TRUE;
}

/*
 * Iterate over the process's mapped objects.
 */
int
Pobject_iter(struct ps_prochandle *P, proc_map_f *func, void *cd)
{
	struct object_iter_uc uc;

	if (P->isnet)
		return Netobject_iter(P, func, cd);

	uc.f = func;
	uc.cd = cd;
	uc.proc = P;

	if ((SymEnumerateModules64(P->phandle, MyEnumerateModulesProc1, &uc)) == FALSE) {
		dprintf("Pobject_iter: SymEnumerateModules64 failed %d: %d\n",
		    P->pid, GetLastError());
		return -1;
	}

	return 0;
}

int
Pnormobjname(struct ps_prochandle *P, const char *cname, char *buffer, size_t bufsize)
{
	proc_mod_t *mod;

	//cname = normobj(cname, P);

	if (P->isnet) {
		nmodinfo_t *mod = P->net_modules;

		for(; mod != NULL; mod = mod->nm_next) {
			if (cmpmodname(cname, mod->nm_name, P->nexe_module == mod)) {
				strncpy(buffer, mod->nm_name, bufsize);
				buffer[bufsize-1] = 0;
				return 1;
			}
		}
		buffer[0] = 0;
		return 0;
	}
	mod = findmodulebyname(P, cname);
	if (mod == NULL) {
		buffer[0] = 0;
		return 0;
	}
	strncpy(buffer, mod->name, bufsize);

	buffer[bufsize-1] = 0;
	return 1;
}

struct lmid_map_uc {
	const char *name;
	prmap_t *map;
	struct ps_prochandle *P;
};

BOOL CALLBACK
MyEnumerateModulesProc2(PCTSTR ModuleName, DWORD64 BaseOfDll, PVOID UserContext)
{
	struct lmid_map_uc *tmp = (struct lmid_map_uc *) UserContext;

	if (cmpmodname(ModuleName, tmp->name, 0)) {
		if ((tmp->map = (prmap_t *) malloc(sizeof(prmap_t))) == NULL) {
			return FALSE;
		}

		tmp->map->pr_vaddr = BaseOfDll;
		tmp->map->pr_mflags = MA_READ;
		return FALSE;
	}
	return TRUE;
}

/*
 * Convert a full or partial load object name to the prmap_t for its
 * corresponding primary text mapping.
 */
prmap_t *
Plmid_to_map(struct ps_prochandle *P, Lmid_t ignored, const char *cname)
{
	struct lmid_map_uc uc;
	prmap_t *map;

	if (P->isnet)
		return Netobject_to_map(P, cname);

	proc_mod_t *mod = P->modules;

	for(; mod != NULL; mod = mod->next) {
		if (cmpmodname(cname, mod->name, P->exe_module == mod)) {
			if ((map = (prmap_t *) malloc(sizeof(prmap_t))) == NULL) {
				return NULL;
			}
			map->pr_vaddr = mod->imgbase;
			map->pr_mflags = MA_READ;
			return map;
		}
	}

	return NULL;
	/*uc.name = cname;
	uc.map = NULL;
	uc.P = P;

	if ((SymEnumerateModules64(P->phandle, MyEnumerateModulesProc2, &uc) == FALSE)) {
		dprintf("SymEnumerateModules64 failed (%d): %x\n", P->pid, GetLastError());
	}

	return uc.map;*/
}

char *
Pobjname(struct ps_prochandle *P, uint64_t addr, char *buffer, size_t bufsize)
{
	IMAGEHLP_MODULE64 info;
	char *r, ext[8]= {0};

	if (P->isetw) {
		return dtrace_etw_objname(P->etwmods, P->pid, addr, buffer, bufsize);
	}

	if (P->isnet) {
		r = Netobjname(P, addr, buffer, bufsize);
		if (r) {
			return NULL;
		}
	}

	info.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

	if (SymGetModuleInfo64(P->phandle, (DWORD64) addr, &info) == FALSE) {
		buffer[0] = 0;
		return NULL;
	}

	if (((r = strrchr(info.ImageName, '\\')) || (r = strrchr(info.ImageName, '/'))) &&
	    strstr(r, "exe") == NULL) {
		strncpy(buffer, ++r, bufsize);
	} else {
		strncpy(buffer, info.ModuleName, bufsize);
	}

	buffer[bufsize-1] = 0;
	return buffer;
}


struct lookup_uc {
	proc_sym_f *f;
	void *cd;
	struct ps_prochandle *ps;
	int count;
};

BOOL CALLBACK
MyEnumSymbolsCallback(SYMBOL_INFO* SymInfo, ULONG SymbolSize, PVOID UserContext)
{
	struct lookup_uc *tmp = (struct lookup_uc *) UserContext;
	GElf_Sym *symp = (GElf_Sym *) tmp->cd;

	if (SymInfo != NULL) {
		if (isfunction(tmp->ps, SymInfo)) {
			symp->st_name = 0;
			symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
			symp->st_other = 0;
			symp->st_shndx = 1;
			symp->st_value = SymInfo->Address;
			symp->st_size = SymInfo->Size;
		} else {
			symp->st_name = 0;
			symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_NOTYPE));
			symp->st_other = 0;
			symp->st_shndx = SHN_UNDEF;
			symp->st_value = SymInfo->Address;
			symp->st_size = SymInfo->Size;
		}
	}

	return TRUE;
}

/*
 * Search the process symbol tables looking for a symbol whose name matches the
 * specified name and whose object and link map optionally match the specified
 * parameters.  On success, the function returns 0 and fills in the GElf_Sym
 * symbol table entry.  On failure, -1 is returned.
 */
int
Pxlookup_by_name(struct ps_prochandle *P, Lmid_t lmid,
	    const char *oname, const char *sname, GElf_Sym *symp, void *sip)
{
	int ol = 0, sl = 0, l;
	char *Mask;
	char obj[256] = {0};
	struct lookup_uc uc;

	if (sname == NULL)
		return -1;

	if (P->isnet)
		return Netlookup_by_name(P, oname, sname, symp);

	if (strcmp(oname, "a.out") == 0) {
		_splitpath(P->exe_module->name, NULL, NULL, obj, NULL);
	} else {
		_splitpath(oname, NULL, NULL, obj, NULL);
	}

	Mask = (char *) malloc((ol = strlen(obj)) + (sl = strlen(sname)) + 2);
	strncpy(Mask, obj, ol);
	strncpy(&Mask[ol++], "!", 1);
	strncpy(&Mask[ol], sname, sl);
	Mask[ol + sl] = 0;

	memset(symp, 0, sizeof(GElf_Sym));
	uc.ps = P;
	uc.cd = symp;
	uc.f = NULL;

	if (SymEnumSymbols(P->phandle, 0, Mask, MyEnumSymbolsCallback, &uc) == FALSE) {
		dprintf("SymEnumSymbols failed (%d): %x\n", P->pid, GetLastError());
		free(Mask);
		return -1;
	}
	free(Mask);

	if (symp->st_value != 0)
		return 0;

	return dw_lookup_by_name(P, oname, sname, symp);
}

static int
dw_lookup_by_name(struct ps_prochandle *P, const char *oname,
	    const char *sname, GElf_Sym *symp)
{
	IMAGE_SYMBOL Sym;
	int ret = -1, fd;
	Pe_object *pe;
	proc_mod_t *mod;

	mod = findmodulebyname(P, oname);
	if (mod == NULL)
		return -1;

	fd = _open(mod->fullname, _O_RDONLY|_O_BINARY, 0);

	if (fd != -1 && (pe = pe_init(fd)) != NULL) {
		char s[MAX_SYM_NAME];

		if (pe_getarch(pe) == PE_ARCH_I386) {
			s[0] = '_';
			strcpy(&s[1], sname);
		} else {
			strcpy(s, sname);
		}

		if (pe_getsymbyname(pe, s, &Sym) != NULL) {
			symp->st_name = 0;
			symp->st_other = 0;
			if (ISFCN(Sym.Type)) {
				symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
				symp->st_shndx = 1;
			} else {
				symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_NOTYPE));
				symp->st_shndx = SHN_UNDEF;
			}
			symp->st_value = Sym.Value + mod->imgbase +
			    pe_getsecva(pe, Sym.SectionNumber);
			/* If size is zero libdtrace will reject the function.
			   Allow creation of entry probe */
			symp->st_size = 1;
			ret = 0;
		}
	}

	if (pe != NULL)
		pe_end(pe);
	if (fd != -1)
		close(fd);

	return ret;
}


/*
 * Search the process symbol tables looking for a symbol whose
 * value to value+size contain the address specified by addr.
 * Return values are:
 *	sym_name_buffer containing the symbol name
 *	GElf_Sym symbol table entry
 *	prsyminfo_t ancillary symbol information
 * Returns 0 on success, -1 on failure.
 */
int
Plookup_by_addr(struct ps_prochandle *P, uint64_t addr,
	    char *buf, size_t size, GElf_Sym *symp)
{
	SYMBOL_INFO *s;

	if (P->isetw) {
		return dtrace_etw_lookup_addr(P->etwmods, P->pid, addr, buf, size, symp);
	}

	if (P->isnet) {
		if (Netlookup_by_addr(P, addr, buf, size, symp) == 0)
			return 0;
		if (P->etwmods == NULL) {
			etw_proc_module_t *etwmods = dtrace_etw_pid_symhandle(P->pid);
			P->etwmods = etwmods;
		}

		if (P->etwmods) {
			if (dtrace_etw_lookup_addr(P->etwmods, P->pid, addr, buf, size, symp) == 0)
				return 0;
		}
	}

	s = (SYMBOL_INFO *) malloc(sizeof(SYMBOL_INFO) + size-1);
	if (s == NULL)
		return -1;

	s->SizeOfStruct = sizeof(SYMBOL_INFO);
	s->MaxNameLen = size;

	if (SymFromAddr(P->phandle, addr, 0, s) == TRUE) {
		isfunction(P, s);
		symp->st_name = 0;
		symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
		symp->st_other = 0;
		symp->st_shndx = 1;
		symp->st_value = s->Address;
		symp->st_size = s->Size;
		strncpy(buf, s->Name, size);
		return 0;

	}

	return dw_lookup_by_addr(P, addr, buf, size, symp);
}

static int
dw_lookup_by_addr(struct ps_prochandle *P, uint64_t addr,
	    char *buf, size_t size, GElf_Sym *symp)
{
	proc_mod_t *mod = NULL;
	int fd, ret = -1, index, i;
	Pe_object *pe;

	mod = findmodulebyaddr(P, addr);
	if (mod == NULL)
		return -1;

	fd = _open(mod->fullname, _O_RDONLY|_O_BINARY, 0);

	if (fd == -1 )
		return -1;

	if ((pe = pe_init(fd)) != NULL) {
		IMAGE_SYMBOL *Sym = pe_getsymarr(pe, &index);
		char name[MAX_SYM_NAME];

		int secno, addr1, mark = -1, prev = 0, va;

		if (Sym == NULL)
			goto end;

		if ((secno = pe_getsecnofromaddr(pe, addr - mod->imgbase))== 0)
			goto end;

		va = pe_getsecva(pe, secno);
		addr1 = addr - (mod->imgbase + va);
		if (addr1 <= 0)
			goto end;
		for (i = 0; i < index; i++) {
			if (ISFCN(Sym[i].Type) == 0 || Sym[i].SectionNumber != secno)
				continue;
			if (addr1 == Sym[i].Value) {
				mark = i;
				break;
			} else if (addr1 > Sym[i].Value) {
				if (prev < Sym[i].Value) {
					prev = Sym[i].Value;
					mark = i;
				}
			}
		}
		if (mark >= 0) {
			symp->st_name = 0;
			symp->st_other = 0;
			symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
			symp->st_shndx = 1;
			symp->st_value = Sym[mark].Value + mod->imgbase
			    + pe_getsecva(pe, Sym[mark].SectionNumber);
			/* If size is zero libdtrace will reject the function.
			   Allow creation of entry probe */
			symp->st_size = 1;

			if (pe_getsymname(pe, &Sym[mark], name, MAX_SYM_NAME) == NULL)
				goto end;
			if (pe_getarch(pe) == PE_ARCH_I386) {
				strncpy(buf, &name[1], size);
			} else {
				strncpy(buf, name, size);
			}

			ret = 0;
		}
	}
	end:
	if (pe != NULL)
		pe_end(pe);
	if (fd != -1)
		close(fd);

	return ret;
}

BOOL CALLBACK
SymEnumSymbolsProc(PSYMBOL_INFO s, ULONG SymbolSize, PVOID UserContext)
{
	GElf_Sym symp;
	struct lookup_uc *tmp = (struct lookup_uc *) UserContext;

	if (s != NULL) {
		if (tmp->ps->fpid && (strstr(s->Name, "Mrdata") != NULL ||
		        strstr(s->Name, "SRWLock") != NULL ||
		        strstr(s->Name, "FunctionTable") != NULL ||
		        strstr(s->Name, "__security_check_cookie") != NULL ||
		        strstr(s->Name, "_chkstk") != NULL)) {
			return TRUE;
		}
		if (isfunction(tmp->ps, s)) {
			symp.st_name = 0;
			symp.st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
			symp.st_other = 0;
			symp.st_shndx = 1;
			symp.st_value = s->Address;
			symp.st_size = s->Size;
		} else {
			symp.st_name = 0;
			symp.st_info = GELF_ST_INFO((STB_GLOBAL), (STT_NOTYPE));
			symp.st_other = 0;
			symp.st_shndx = SHN_UNDEF;
			symp.st_value = s->Address;
			symp.st_size = s->Size;

		}
		tmp->count++;
		tmp->f(tmp->cd, &symp, s->Name);
	}

	return TRUE;
}

/*
 * Given an object name and optional lmid, iterate over the object's symbols.
 * If which == PR_SYMTAB, search the normal symbol table.
 * If which == PR_DYNSYM, search the dynamic symbol table.
 */
int
Psymbol_iter_by_addr(struct ps_prochandle *P, const char *object_name,
	    int which, int mask, proc_sym_f *func, void *cd)
{
	prmap_t *map ;
	struct lookup_uc uc;


	if (P->isnet)
		return Netsymbol_iter_by_addr(P, object_name, func, cd);

	proc_mod_t *mod = findmodulebyname(P, object_name);

	if (mod == NULL || mod->loaded_order < P->dll_load_order)
		return 0;

	map = Plmid_to_map(P, 0, object_name);

	if (map == NULL) {
		return -1;
	}

	uc.f = func;
	uc.cd = cd;
	uc.ps = P;
	uc.count = 0;

	if (SymEnumSymbols(P->phandle, mod->imgbase, NULL, SymEnumSymbolsProc, &uc)
	    == FALSE) {
		dprintf("Psymbol_iter_by_addr: SymEnumSymbols failed %s: %x\n",
		    object_name, GetLastError());
		return -1;
	}

	if (uc.count != 0)
		return 0;

	return dw_iter_by_addr(P, object_name, which, mask, func, cd);
}

static int
dw_iter_by_addr(struct ps_prochandle *P, const char *object_name, int which,
	    int mask, proc_sym_f *func, void *cd)
{
	int fd = 0, ret = -1, i, index = 0;
	Pe_object *pe;
	proc_mod_t *mod = findmodulebyname(P, object_name);

	fd = _open(mod->fullname, _O_RDONLY|_O_BINARY, 0);

	if (fd == -1 )
		return -1;

	if  ((pe = pe_init(fd)) != NULL) {
		IMAGE_SYMBOL *Sym = pe_getsymarr(pe, &index);
		char name[MAX_SYM_NAME];

		if (Sym == NULL)
			goto end;
		ret = 0;
		for (i = 0; i < index; i++) {
			GElf_Sym symp;
			char *n = NULL;

			if (ISFCN(Sym[i].Type) == 0)
				continue;
			symp.st_name = 0;
			symp.st_other = 0;
			symp.st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
			symp.st_shndx = 1;
			symp.st_value = Sym[i].Value+mod->imgbase +
			    pe_getsecva(pe, Sym[i].SectionNumber);
			/* If size is zero libdtrace will reject the probe.
			   Allow creation of entry probe */
			symp.st_size = 1;
			if (pe_getsymname(pe, &Sym[i], name, MAX_SYM_NAME) == NULL)
				continue;

			if (pe_getarch(pe) == PE_ARCH_I386)
				func(cd, &symp, &name[1]);
			else
				func(cd, &symp, name);
		}
	}
	end:
	if (pe != NULL)
		pe_end(pe);
	if (fd != -1)
		close(fd);
	return ret;
}

size_t
Pread(struct ps_prochandle *P, void *buf, size_t size, size_t addr)
{
	SIZE_T ret;

	if (ReadProcessMemory(P->phandle, (void *) addr, buf, size, &ret) == 0) {
		dprintf("ReadProcessMemory failed (%d) for address %p: %x\n",
		    P->pid, addr, GetLastError());
		return 0;
	}

	return ret;
}

int
Pfthelper(struct ps_prochandle *P, int (func)(pid_t, pid_t, int, void *))
{
	P->fthelper = func;
	return 0;
}

/*
 * Return the prmap_t structure containing 'addr' (no restrictions on
 * the type of mapping).
 */
prmap_t *
Paddr_to_map(struct ps_prochandle *P, uint64_t addr)
{
	DWORD64 p;
	prmap_t *t;

	if (P->isnet)
		return Netaddr_to_map(P, addr);

	if ((p = SymGetModuleBase64(P->phandle, addr)) == 0) {
		dprintf("SymGetModuleBase64 failed (%d) at address %p: %x\n",
		    P->pid, addr, GetLastError());
		return NULL;
	}
	if ((t = (prmap_t *) malloc(sizeof(prmap_t))) == NULL) {
		return NULL;
	}

	t->pr_vaddr = p;
	t->pr_mflags = MA_READ;

	return t;
}

const char *
rd_errstr(rd_err_e err)
{
	switch (err) {
	case RD_ERR:
		return "RD_ERR";
	case RD_OK:
		return "RD_OK";
	case RD_NOCAPAB:
		return "RD_NOCAPAB";
	case RD_DBERR:
		return "RD_DBERR";
	case RD_NOBASE:
		return "RD_NOBASE";
	case RD_NODYNAM:
		return "RD_NODYNAM";
	case RD_NOMAPS:
		return "RD_NOMAPS";
	default:
		return "RD_UNKNOWN";
	}
}

const char *
Pgrab_error(int err)
{
	char *s = "Pgrab error\n";
	return s;
}


const char *
Pcreate_error(int error)
{
	char *s = "Pcreate error\n";
	return s;
}

int
Ppid(struct ps_prochandle *P)
{
	return P->pid;
}

int
Psignaled(struct ps_prochandle *P)
{
	if (P->wstat)
		return 1;
	else
		return 0;
}

int
Pexitcode(struct ps_prochandle *P)
{
	return P->exitcode;
}


int
Pmodel(struct ps_prochandle *P)
{
	return P->model;
}

/*
 * Convert a full or partial load object name to the prmap_t for its
 * corresponding primary text mapping.
 */
prmap_t *
Pname_to_map(struct ps_prochandle *p, const char *name)
{
	if (strcmp("a.out", name) == 0)
		return Plmid_to_map(p, 0, p->exe_module->name);
	else
		return Plmid_to_map(p, 0, name);
}


#define BUFSIZE 512

char *
GetFileNameFromHandle(HANDLE hFile, TCHAR *pszFilename)
{
	BOOL bSuccess = FALSE;
	HANDLE hFileMap;
	void* pMem;
	// Get the file size.
	DWORD dwFileSizeHi = 0;
	DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

	if( dwFileSizeLo == 0 && dwFileSizeHi == 0 ) {
		printf(TEXT("Cannot map a file with a length of zero.\n"));
		return FALSE;
	}

	// Create a file mapping object.
	hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 1, NULL);

	if (!hFileMap)
		return FALSE;

	// Create a file mapping to get the file name.
	pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

	if (!pMem) {
		CloseHandle(hFileMap);
		return FALSE;
	}
	if (GetMappedFileName (GetCurrentProcess(), pMem, pszFilename, MAX_PATH)) {
		// Translate path with device name to drive letters.
		TCHAR szTemp[BUFSIZE];
		szTemp[0] = '\0';

		if (GetLogicalDriveStrings(BUFSIZE-1, szTemp)) {
			TCHAR szName[MAX_PATH];
			TCHAR szDrive[3] = TEXT(" :");
			BOOL bFound = FALSE;
			TCHAR* p = szTemp;

			do {
				// Copy the drive letter to the template string
				*szDrive = *p;

				// Look up each device name
				if (QueryDosDevice(szDrive, szName, MAX_PATH)) {
					size_t uNameLen = strlen(szName);

					if (uNameLen < MAX_PATH) {
						bFound = _strnicmp(pszFilename, szName, uNameLen) == 0
						    && *(pszFilename + uNameLen) == '\\';

						if (bFound) {
							// Reconstruct pszFilename using szTempFile
							// Replace device path with DOS path
							TCHAR szTempFile[MAX_PATH];
							StringCchPrintfA(szTempFile, MAX_PATH, TEXT("%s%s"),
							    szDrive, pszFilename+uNameLen);
							StringCchCopyNA(pszFilename, MAX_PATH+1,
							    szTempFile, strlen(szTempFile));
						}
					}
				}
				while (*p++);	// Go to the next NULL character.
			} while (!bFound && *p); // end of string
		}
	}
	bSuccess = TRUE;
	UnmapViewOfFile(pMem);
	CloseHandle(hFileMap);

	if (bSuccess == TRUE)
		return pszFilename;

	return NULL;
}

#if __amd64__

BOOL
Is32bitProcess(HANDLE h)
{
	BOOL f64 = 0;

	IsWow64Process(h, &f64);

	return f64;
}

int
is64bitmodule(PVOID base, char *s)
{
	int fd = _open(s, _O_RDONLY|_O_BINARY, 0);
	Pe_object *pe;

	if (fd != -1 && (pe = pe_init(fd)) != NULL) {
		int type = pe_getarch(pe);
		pe_end(pe);
		close(fd);
		if ( type == PE_ARCH_AMD64)
			return 1;
		else
			return 0;
	}
	return -1;
}
#endif
/* arch = 0 (x64), arch = 1 (x86) */
static int
isnetmodule(const char *s, int *arch)
{
	int fd = _open(s, _O_RDONLY|_O_BINARY, 0);
	Pe_object *pe;

	if (fd != -1 && (pe = pe_init(fd)) != NULL) {
		int type = pe_isnet(pe);
		*arch = type > 0 ? type-1: 0;
		pe_end(pe);
		close(fd);
		return type;
	}
	return (-1);
}

int
isfunction(struct ps_prochandle *P, PSYMBOL_INFO s)
{
	proc_mod_t *mod;
	int status = 0;
	SYMBOL_INFO *Symbol;
	char buffer[sizeof(SYMBOL_INFO )+MAX_SYM_NAME];
	DWORD64 disp;
	FPO_DATA *fpo;
#ifdef __amd64__
	_IMAGE_RUNTIME_FUNCTION_ENTRY *rtf;
#endif
	Symbol = (SYMBOL_INFO *) buffer;
	Symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	Symbol->MaxNameLen = MAX_SYM_NAME;

	if (s->Tag == 5) /* Is a Function */
		status = 1;
	else if (s->Tag != 0xa)	/* Not a public symbol */
		status = 0;
#if 0
	/* will find more function to trace, but will slow down the
	 * program
	 */
#ifdef __amd64__
	else if ((P->model == PR_MODEL_ILP64) &&
	    ((rtf = (_IMAGE_RUNTIME_FUNCTION_ENTRY *)
	                SymFunctionTableAccess64(P->phandle, s->Address)) != NULL)) {
		/* Check if FPO data is present for the Address */
		s->Size = rtf->EndAddress - rtf->BeginAddress;
		status = 1;
	}
#endif
	else if ((P->model == PR_MODEL_ILP32) &&
	    ((fpo = (FPO_DATA *)
	                SymFunctionTableAccess64(P->phandle, s->Address)) != NULL)) {
		/* Check if FPO data is present for the Address */
		/*
		 * The size from FPO data will give the total size of the function in bytes.
		 * But in some cases the function is spread in
		 * in different locations.
		 */
		if (SymFromAddr(P->phandle, s->Address+fpo->cbProcSize-1, &disp, Symbol)) {
			if (Symbol->Address == s->Address) {
				s->Size = fpo->cbProcSize;
				status = 1;
			} else if (Symbol->Address > s->Address) {
				int sz = Symbol->Address - s->Address;
				if (SymFromAddr(P->phandle, s->Address + sz-1, &disp, Symbol) &&
				    (s->Address == Symbol->Address)) {
					s->Size = sz;
					status = 1;
				} else
					status = 0;
			}
		} else
			status = 0;

	}
#endif
	else if (s->Flags != SYMFLAG_EXPORT) {
		/* Export symbol, No pdb file for the module */
		status = 0;
	} else if ((mod = findmodulebyaddr(P, s->Address)) == NULL) {
		/* find module containing the Address */
		status = 0;
	} else if (s->Address >= mod->b_faddr && s->Address < mod->e_faddr) {
		/* Is the Address a forwarding function */
		status = 0;
	} else if (s->Address < mod->b_code || s->Address >= mod->e_code) {
		/* Is the Address in code section of the module */
		status = 0;
	} else {
		/* function */
		status = 1;
	}

	return status;
}

/* Return the module containing the Address addr in the process P */
proc_mod_t *
findmodulebyaddr(struct ps_prochandle *P, ULONG64 addr)
{
	proc_mod_t *mod = P->modules;

	for(; mod != NULL; mod = mod->next) {
		if (addr >= mod->imgbase && addr < (mod->imgbase + mod->size)) {
			return mod;
		}
	}
	return NULL;
}

/* Return the module containing the Address addr in the process P */
proc_mod_t *
findmodulebyname(struct ps_prochandle *P, const char *name)
{
	proc_mod_t *mod = P->modules;

	if (name == NULL)
		return NULL;

	//if (strcmp("a.out", name) == 0)
	//	return P->exe_module;

	for(; mod != NULL; mod = mod->next) {
		//if (stricmp(mod->name, name) == 0) {
		if (cmpmodname(name, mod->name, mod == P->exe_module)) {
			return mod;
		}
	}
	return NULL;
}

void
delmodule(struct ps_prochandle *P, ULONG64 imgbase)
{
	proc_mod_t *mod = P->modules, *prev = NULL;

	for(; mod != NULL; mod = mod->next) {
		if (mod->imgbase == imgbase) {
			if (prev == NULL) {
				P->modules = mod->next;
			} else {
				prev->next = mod->next;
			}
			free(mod->name);
			free(mod->fullname);
			free(mod);
			return;
		}
		prev = mod;
	}
}

void
addmodule(struct ps_prochandle *P, HANDLE file, char *s,
	    PVOID imgbase, int type, int load)
{
	HANDLE map;
	LPVOID base;
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_DATA_DIRECTORY datadir;
	proc_mod_t *p;
	LARGE_INTEGER Size;
	char basename[256], *sp, *name = basename;
	int len;

	if ((map = CreateFileMapping(file,NULL,PAGE_READONLY,0,0,NULL)) == NULL)
		return;

	if ((base = MapViewOfFile(map,FILE_MAP_READ,0,0,0)) == NULL)
		return;

	DosHeader = (PIMAGE_DOS_HEADER) base;
	NtHeader =  (PIMAGE_NT_HEADERS) ((PUCHAR) DosHeader + DosHeader->e_lfanew);

	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		return;

	if ((p = (proc_mod_t *) malloc(sizeof(proc_mod_t))) == NULL) {
		UnmapViewOfFile(base);
		CloseHandle(map);
		return;
	}

	GetFileSizeEx(file, &Size);
	//p->imgbase = (uintptr_t) NtHeader->OptionalHeader.ImageBase;
	p->imgbase = (uintptr_t) imgbase;
	//p->size = Size.QuadPart; (Actual Size on disk)
	p->size = NtHeader->OptionalHeader.SizeOfImage; // mapped size in virtual memory
	datadir = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	/* Forwarding function address range */
	p->b_faddr = p->imgbase + datadir->VirtualAddress;
	p->e_faddr = p->b_faddr + datadir->Size;
	/* Code section address range */
	p->b_code = (uintptr_t) ( p->imgbase + NtHeader->OptionalHeader.BaseOfCode);
	p->e_code = p->b_code + NtHeader->OptionalHeader.SizeOfCode;
	p->loaded_order = load;
	p->next = NULL;

	//if (type == PE_TYPE_EXE) {
	//	_splitpath(s, NULL, NULL, name, NULL);
	//} else {
		name = PathFindFileNameA(s);
	//}
	len = strlen(name);
	sp = (char *) malloc(len+1);
	if (sp == NULL)
		p->name = NULL;
	else {
		sp = strcpy(sp, name);
		p->name = sp;
	}

	len = strlen(s);
	sp = (char *) malloc(len + 1);
	if (sp == NULL)
		p->fullname = NULL;
	else {
		strcpy(sp, s);
		p->fullname = sp;
	}

	if (P->modules == NULL) {
		P->modules = p;
	} else {
		p->next = P->modules;
		P->modules = p;
	}
	if (type == PE_TYPE_EXE)
		P->exe_module = p;

	UnmapViewOfFile(base);
	CloseHandle(map);
	return;
}


void
freemodules(struct ps_prochandle *P)
{
	proc_mod_t *next, *mod = P->modules;

	for(; mod != NULL; mod = next) {
		next = mod->next;
		free(mod->name);
		free(mod);
	}
	P->modules = NULL;
}

int
Ploadedmod(struct ps_prochandle *P, struct ps_module_info *mod)
{
	if (P->modules != NULL) {
		mod->imgbase = P->modules->imgbase;
		mod->size = P->modules->size;
		strcpy(mod->name, P->modules->name);
		return 0;
	}
	return -1;
}

int
Pmodinfo(struct ps_prochandle *P, struct ps_module_info *mod, int *count)
{
	proc_mod_t *p = P->modules;
	int i = 0, co = 0;

	for (; p != NULL; p = p->next)
		co++;

	if (mod == NULL) {
		*count = co;
		return 0;
	}
	p = P->modules;
	for (; p != NULL && i < *count; p = p->next) {
		mod[i].imgbase = p->imgbase;
		mod[i].size = p->size;
		strcpy(mod[i].name, p->name);
		i++;
	}

	return 0;
}

int
exception_cb(struct ps_prochandle *P, DEBUG_EVENT *pdbj)
{
	CONTEXT Context;
	void *data[2];
	int r;
	HANDLE hThread;

	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pdbj->dwThreadId);
	Context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &Context);
	data[0] = &Context;
	data[1] = P->phandle;

	r = (*P->fthelper)(pdbj->dwProcessId, pdbj->dwThreadId, 0, &Context);
	SetThreadContext(hThread, &Context);
	CloseHandle(hThread);

	return 1;
}

int
etw_lookupkernel_by_addr(void *d, GElf_Addr addr, GElf_Sym *symp,
    dtrace_syminfo_t *sip)
{
	etw_proc_module_t *h = dtrace_etw_pid_symhandle(0);
	static char buff[MAX_SYM_NAME], bufm[MAX_SYM_NAME];

	if (h == NULL)
		return -1;

	if (dtrace_etw_lookup_addr(h, 0, addr, buff, MAX_SYM_NAME, symp) == 0) {
		if (sip != NULL &&
		    dtrace_etw_objname(h, 0, addr, bufm, MAX_SYM_NAME) != NULL) {
			sip->dts_object = bufm;
			sip->dts_name = buff;
		}

		return (0);
	}
	/*
		static IMAGEHLP_MODULE64 mod;
		static char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
		PSYMBOL_INFO sym = (PSYMBOL_INFO)buffer;
		sym->SizeOfStruct = sizeof(SYMBOL_INFO);
		sym->MaxNameLen = MAX_SYM_NAME;
		mod.SizeOfStruct = (sizeof(IMAGEHLP_MODULE64));

		if (SymFromAddr(h,  addr, 0, sym) == TRUE) {
			if (sip != NULL && SymGetModuleInfo64(h, addr, &mod)) {
				sip->dts_object = mod.ModuleName;
				sip->dts_name = sym->Name;
			}

			if (symp != NULL)
				symp->st_value = sym->Address;
			return 0;
		}
		ULONG er = GetLastError();
	*/
	return -1;
}

int
etw_status(void *d, processorid_t cpu)
{
	return (cpu < dtrace_etw_nprocessors() ? 1 : -1);
}

long
etw_sysconf(void *d, int name)
{
	switch(name) {
	case _SC_CPUID_MAX:
	case _SC_NPROCESSORS_MAX: {
		return dtrace_etw_nprocessors();
	}
	default:
		return 1;
	}
}

const dtrace_vector_t *
Petwvector()
{
	dtrace_vector_t *vec = (dtrace_vector_t *) malloc(sizeof(dtrace_vector_t));
	vec->dtv_ioctl = NULL;
	vec->dtv_lookup_by_addr = etw_lookupkernel_by_addr;
	vec->dtv_status = etw_status;
	vec->dtv_sysconf = etw_sysconf;

	return vec;
}

int
Psetprov(struct ps_prochandle *P, int isfpid)
{
	if (P->fpid == 0) {
		if (isfpid == 0)
			P->fpid = -1;
		else
			P->fpid = 1;
	} else {
		if (((P->fpid == 1) && isfpid) || ((P->fpid == -1) && !isfpid)) {
			return (0);
		} else {
			fprintf(stderr, "Dtrace: Cannot trace pid and fpid provider "
			    "together\n");
			return (-1);
		}
	}

	if (P->attached && P->isnet && isfpid == 0) {
		fprintf(stderr, "Dtrace: Not attaching to .NET with pid provider."
		    "Detach will kill the process\n");
		net_detach(P, 1);
		return -1;
	}
	if (P->fpid == 1) {
		Psetrun(P, 0, 0);
		pthread_mutex_lock(&P->mutex);
		while (P->status != PS_STOP)
			pthread_cond_wait(&P->cond, &P->mutex);
		pthread_mutex_unlock(&P->mutex);
	}
	return 0;
}

/* busy loop */
DWORD WINAPI
busyloop_thread(LPVOID data)
{
	struct ps_prochandle *P =  (struct ps_prochandle *) data;

	if (P->skip == 0 && P->status != PS_RUN)
		SetEvent(P->event);
	P->skip = 0;
	while (P->status == PS_STOP)
		pthread_cond_wait(&P->cond, &P->mutex);
	pthread_mutex_unlock(&P->mutex);

	if (P->fthelper) {
		if (P->fpid != 1)
			P->fthelper(P->pid, -1, PSYS_SYM_HANDLE, P->phandle);
		else {
			P->fthelper(P->pid, -1, PSYS_FPID_QUEUE_CLEAR, NULL);
			if (P->thragent == 0) {
				P->thragent = P->fthelper(P->pid, -1, PSYS_FPID_TID, NULL);
			}
		}
	}

	/* reset main thread */
	if (P->addr) {
		SuspendThread(P->thandle);
		adjbusyloop(P, !P->model, P->addr);
		ResumeThread(P->thandle);
	}
	/* Resume all suspended threads */
	for (int i = 0; i < P->nblk; i++) {
		ResumeThread(P->thrblk[i]);
		CloseHandle(P->thrblk[i]);
	}
	P->nblk = 0;
	P->busyloop = 0;

	return 0;

}

/*
 *	put the main thread in a busy loop.
 */
int
insbusyloop(struct ps_prochandle *P, int wow)
{
	char *mem_base = NULL;
	static void *mem = 0;
	BOOL st;
	DWORD oldprot = 0;
	unsigned char loop[] = { 0xEB, 0xFE };
	SIZE_T num = 0, mem_size = 4;

	if (mem == 0) {
		mem = VirtualAllocEx(P->phandle, (PVOID) mem_base, mem_size,
		        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (mem == 0 ||
		    VirtualProtectEx(P->phandle, mem, mem_size,
		        PAGE_EXECUTE_READWRITE, &oldprot) == 0) {
			return -1;
		}

		WriteProcessMemory(P->phandle, mem, &loop, sizeof(loop), &num );
		FlushInstructionCache(P->phandle, mem, sizeof(loop));
	}

	adjbusyloop(P, wow, (uintptr_t) mem);

	return 1;
}

/*
 * suspend all the threads in the process, except for
 * the main thread, and the agent dll thread.
 */
int
suspendbusy(struct ps_prochandle *P, int wow)
{
	HANDLE th;

	for (int j = 0; j < P->nthr; j++) {
		if (P->threads[j] == P->thragent) {
			continue;
		}
		th = OpenThread(THREAD_ALL_ACCESS, FALSE, P->threads[j]);
		if (th) {
			SuspendThread(th);
			P->thrblk[P->nblk++] = th;
		}
	}

	return 0;
}

int
adjbusyloop(struct ps_prochandle *P, int wow, uintptr_t addr)
{
	CONTEXT ct;
#if __amd64__
	WOW64_CONTEXT ct32;

	if (wow) {
		ZeroMemory(&ct32, sizeof(PWOW64_CONTEXT));
		ct32.ContextFlags = CONTEXT_CONTROL;
		if (Wow64GetThreadContext(P->thandle, &ct32) == 0) {
			return -1;
		}
		P->addr = ct32.Eip;
		ct32.Eip = addr;
		if (Wow64SetThreadContext(P->thandle, &ct32) == 0) {
			return -1;
		}
		return 0;
	}
#endif
	ZeroMemory(&ct, sizeof(CONTEXT));
	ct.ContextFlags = CONTEXT_CONTROL;

	if (GetThreadContext(P->thandle, &ct) == 0) {
		return -1;
	}
#if __i386__
	P->addr = ct.Eip;
	ct.Eip = addr;
#else
	P->addr = ct.Rip;
	ct.Rip = addr;
#endif
	if (SetThreadContext(P->thandle, &ct) == 0) {
		return -1;
	}
	return 0;
}


static char *
pathfrompid(uint32_t pid)
{
	HANDLE p;
	static char path[MAX_PATH] = {0};

	p =  OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (p == NULL)
		return NULL;

	if (GetModuleFileNameExA(p, NULL, path, MAX_PATH) == 0)
		return NULL;
	else
		return path;

}

static int
dtnetarch(int arch)
{
	BOOL parch = 0, x86 = 0;

	x86 = !is64bitos(&parch) || parch == 1;

	if (x86 && arch == 1)
		return 1;
	if (!x86 && arch == 0)
		return 1;
	return 0;
}