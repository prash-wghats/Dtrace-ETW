/*
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
 * DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Copyright (C) 2019, PK
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <dbghelp.h>
#include <psapi.h>
#include <shlwapi.h>
#if _MSC_VER
#include <strsafe.h>
#endif
#include <fcntl.h>
#include <cor.h>
#include <cordebug.h>
#include <corpub.h>
#include <corsym.h>
#include <corerror.h>
#include <metahost.h>
#include <comdef.h>
#include <pthread.h>
#include <sys\types.h>
#include <sys\stat.h>
#include <libpe.h>
#include <dtrace_misc.h>
#include <dtrace.h>
#include <libproc.h>
#include "etw.h"
#include "libproc_win.h"
#include "common.h"


HRESULT nloadsymprocess(struct ps_prochandle *P, ICorDebugProcess *process);
uintptr_t nfuncnativeaddr(ICorDebugModule *mod, mdMethodDef md, uint32_t *size);
int nbrkonmain(struct ps_prochandle *P, ICorDebugModule *mod, int *found);
HRESULT nloadsymapp(struct ps_prochandle *P, ICorDebugAppDomain *ad);
HRESULT nloadsymassm(struct ps_prochandle *P, ICorDebugAssembly *assm);
nmodinfo_t *nloadsymmod(struct ps_prochandle *P, ICorDebugModule *mod, int oload);
ntypeinfo_t *nloadsymtype(nmodinfo_t *mod, mdTypeDef type, IMetaDataImport *mdata);
nfuncinfo_t *nloadsymfunc(ntypeinfo_t *mod, mdMethodDef ftok,
    WCHAR *cname, IMetaDataImport *mdata);
int net_ngened(const char *modname, int ver, int arch);

uintptr_t
nfuncnativeaddr(ICorDebugModule *mod, mdMethodDef md, uint32_t *size)
{
	ICorDebugFunction *func = 0;
	ICorDebugCode *dfunc = 0;
	HRESULT hr;

	hr = mod->GetFunctionFromToken(md, &func);
	if (hr < 0)
		return 0;
	hr = func->GetNativeCode(&dfunc);
	if (hr >= 0) {
		CORDB_ADDRESS addr;

		dfunc->GetSize(size);
		dfunc->GetAddress(&addr);
		if (hr < 0)
			return 0;
		else
			return (uintptr_t) addr;
		//dfunc->Release();
	}
	//func->Release();

	return 0;
}

int
nbrkonmain(struct ps_prochandle *P, nmodinfo_t *nmod, int *found)
{
	mdTypeDef types[100];
	mdToken main[10];
	HCORENUM tenum = 0, menum;
	IMetaDataImport *mdata;
	ICorDebugModule *mod = nmod->nm_mod;
	HRESULT hr;
	ULONG ret = 0, mret = 0;
	WCHAR modname[MAX_NAME_LENGTH];
	UINT slen, fnd = 0;
	uint32_t size = 0;
	ULONG32 len = 0;

	hr = mod->GetName(MAX_NAME_LENGTH, &len, modname);

	hr = mod->GetMetaDataInterface(IID_IMetaDataImport, (IUnknown**)&mdata);
	if (hr < 0)
		return 0;

	mdata->EnumTypeDefs(&tenum, types, 100, &mret);
	if (hr < 0)
		return 0;
	for (int i = 0; i < mret; i++) {

		menum = 0;
		hr = mdata->EnumMembersWithName(&menum, types[i], L"Main", main, 1, &ret);
		if (ret > 0) {
			uintptr_t addr = nfuncnativeaddr(mod, main[0], &size);
			if (addr != 0) {
				MDUTF8CSTR name = NULL;
				mdata->GetNameFromToken( main[0], &name);
				fnd = 1;
				if (setbkpt(P, (uintptr_t) addr) != 0) {
					dprintf("libdtrace: failed to set breakpoint for %s "
					    "at address %p %x\n", name, addr, GetLastError());
					fnd=0;
				}
				break;
			}
		}

	}

	return fnd;
}

HRESULT
nloadsymprocess(struct ps_prochandle *P, ICorDebugProcess *process)
{
	ICorDebugAppDomainEnum *adenum = NULL;

	ICorDebugAppDomain *ad[1];
	ULONG ret = 0;
	HRESULT hr = 0;
	if (process == NULL) {
		return hr;
	}
	hr = process->EnumerateAppDomains(&adenum);

	if (hr < 0)
		return hr;

	while (SUCCEEDED(hr) && (hr = adenum->Next(1, ad, &ret)) >= 0 && ret > 0) {
		nloadsymapp(P, ad[0]);
	}
	return hr;
}

HRESULT
nloadsymapp(struct ps_prochandle *P, ICorDebugAppDomain *ad)
{
	WCHAR adname[MAX_NAME_LENGTH];
	UINT slen;
	HRESULT hr;
	ULONG ret = 0;

	ICorDebugAssemblyEnum *aenum;
	ICorDebugAssembly *assm[1];

	ad->GetName(MAX_NAME_LENGTH, &slen, (WCHAR *) adname);
	hr = ad->EnumerateAssemblies(&aenum);
	if (hr < 0)
		return hr;

	ret = 0;
	while (SUCCEEDED(hr) && (hr = aenum->Next(1, assm, &ret)) >= 0 && ret > 0) {
		nloadsymassm(P, assm[0]);
	}

	return hr;
}

HRESULT
nloadsymassm(struct ps_prochandle *P, ICorDebugAssembly *assm)
{
	ICorDebugModuleEnum *menum;
	ICorDebugModule *mod[1];
	HRESULT hr;
	ULONG ret = 0;
	UINT slen;
	WCHAR asname[MAX_NAME_LENGTH];

	assm->GetName(MAX_NAME_LENGTH, &slen, (WCHAR *) asname);

	hr = assm->EnumerateModules(&menum);

	if (hr < 0)
		return hr;

	while ((hr = menum->Next(1, mod, &ret)) >= 0 && ret > 0) {
		nloadsymmod(P, mod[0], 0);
	}
	return hr;
}

nmodinfo_t *
nloadsymmod(struct ps_prochandle *P, ICorDebugModule *mod, int load_order)
{
	mdTypeDef types[1024];
	HCORENUM tenum = 0;
	IMetaDataImport *mdata;
	HRESULT hr;
	ULONG ret = 0, mret = 0;
	WCHAR modname[MAX_NAME_LENGTH], *stmp;
	UINT slen;
	DWORD exe = 0;
	nmodinfo_t *nmod = (nmodinfo_t *) malloc(sizeof(nmodinfo_t));
	ntypeinfo_t **ntype = NULL;
	char *s;

	mod->GetName(MAX_NAME_LENGTH, &slen, (WCHAR *) modname);
	wcstombs(nmod->nm_fname, modname, MAX_PATH);
	dprintf("Loading Symbols for (%s)\n", nmod->nm_fname);
	stmp = PathFindFileNameW(modname);

	//_splitpath(nmod->nm_fname, NULL, NULL, nmod->nm_name, NULL);
	s = PathFindFileNameA(nmod->nm_fname);
	strcpy(nmod->nm_name, s);
	nmod->nm_mod = mod;

	hr = mod->GetMetaDataInterface(IID_IMetaDataImport, (IUnknown**)&mdata);
	if (hr < 0) {
		free(nmod);
		return NULL;
	}

	hr = mdata->EnumTypeDefs(&tenum, types, 1024, &ret);

	if (hr < 0) {
		free(nmod);
		return NULL;
	}

	ntype = (ntypeinfo_t **) malloc(sizeof(ntypeinfo_t *) * ret);
	nmod->nm_ntypes = ret;
	nmod->nm_types = ntype;
	for (int i = 0; i < ret; i++) {
		ntype[i] = nloadsymtype(nmod, types[i], mdata);
	}

	nmod->nm_next = P->net_modules;
	nmod->loaded_order = load_order;
	if (GetBinaryTypeA(nmod->nm_fname, &exe)) {
		P->nexe_module = nmod;
	}
	P->net_modules = nmod;
	return nmod;
}

ntypeinfo_t *
nloadsymtype(nmodinfo_t *mod, mdTypeDef type, IMetaDataImport *mdata)
{
	WCHAR cname [256];
	ULONG len;
	DWORD flags;
	mdToken tkbase;
	HRESULT hr;
	ULONG ret = 0;
	HCORENUM fenum = 0;
	ULONG fret;
	mdMethodDef ftok[1024];
	ntypeinfo_t *ptype =  (ntypeinfo_t *) malloc(sizeof(ntypeinfo_t));
	nfuncinfo_t **ppfunc;

	hr = mdata->GetTypeDefProps(type, cname,
	        MAX_NAME_LENGTH, &len, &flags, &tkbase);

	ptype->nt_nlen = wcstombs(ptype->nt_name, cname, MAX_NAME_LENGTH);
	if (hr < 0)
		return 0;

	hr = mdata->EnumMethods(&fenum, type, ftok, 1024, &ret);
	if (hr < 0) {
		free(ptype);
		return 0;
	}
	ppfunc = (nfuncinfo_t **) malloc(sizeof(nfuncinfo_t *)*ret);
	ptype->nt_mod = mod;
	ptype->nt_tok = type;
	ptype->nt_nsyms = ret;
	ptype->nt_funcs = ppfunc;

	for (int j = 0; j < ret; j++) {
		ppfunc[j] = nloadsymfunc(ptype, ftok[j], cname, mdata);
	}

	return ptype;
}

nfuncinfo_t *
nloadsymfunc(ntypeinfo_t *type, mdMethodDef ftok,
    WCHAR *cname, IMetaDataImport *mdata)
{
	MDUTF8CSTR name = NULL;
	mdTypeDef   classToken = mdTypeDefNil;
	WCHAR       methodName[MAX_NAME_LENGTH];
	ULONG       methodNameLength = 0;
	PCCOR_SIGNATURE sigBlob = NULL;
	ULONG       sigBlobSize = 0;
	DWORD       methodAttr = 0; // CorHdr.h = CorMethodAttr
	HRESULT hr;
	uint32_t size = 0;

	//WCHAR cname [MAX_NAME_LENGTH];
	nfuncinfo_t *func = (nfuncinfo_t *) malloc(sizeof(nfuncinfo_t));

	/* hr = mdata->GetNameFromToken(ftok, &name);
	 if (hr < 0)
	    return NULL;*/

	func->nf_size = size;
	func->nf_type = type;
	hr = mdata->GetMethodProps(ftok, &classToken, methodName,
	        MAX_NAME_LENGTH, &methodNameLength, &methodAttr, &sigBlob,
	        &sigBlobSize, NULL, NULL);
	if (methodAttr & (mdAbstract|mdPinvokeImpl)) {
		free(func);
		return NULL;
	}
	/*try {
	uintptr_t addr = nfuncnativeaddr(type->nt_mod->nm_mod, ftok, &size);
	} catch (...) {
		;
	}*/
	func->nf_nlen = wcstombs(func->nf_name, methodName, MAX_NAME_LENGTH);
	uintptr_t addr = nfuncnativeaddr(type->nt_mod->nm_mod, ftok, &size);
	func->nf_tok = ftok;
	func->nf_addr = addr;
	func->nf_size = size;
	//if (hr >= 0)
	//FormatSig(sigBlob, mdata, methodName);
	if (hr < 0) {
		free(func);
		return NULL;
	} else
		return func;
}

#define COM_METHOD HRESULT STDMETHODCALLTYPE

#define BOILER_PROCESS dprintf("%s\n", __FUNCTION__); \
				process->Continue(FALSE); \
				return (S_OK);
//return (E_NOTIMPL);

#define BOILER_APP dprintf("%s\n", __FUNCTION__); \
				GetProcess(app)->Continue(FALSE); \
				return (S_OK);
//return (E_NOTIMPL);

#define BOILER_CON dprintf("%s\n", __FUNCTION__); \
				GetControllerInterface(app)->Continue(FALSE); \
				return (S_OK);

class DebuggerCB : public ICorDebugManagedCallback {
	public:
	DebuggerCB(ICorDebug *d, struct ps_prochandle *ps) : refcount(0)
	{
		dbg = d;
		P = ps;
		setmain = 0;
	}

	ULONG STDMETHODCALLTYPE
	AddRef()
	{
		return (InterlockedIncrement((long *) &refcount));
	}

	ULONG STDMETHODCALLTYPE
	Release()
	{
		long ref = InterlockedDecrement(&refcount);
		if (ref == 0)
			delete this;
		return (ref);
	}

	COM_METHOD
	QueryInterface(const IID& riid, void **out)
	{
		if (riid == IID_IUnknown)
			*out = (IUnknown *) this;
		else if (riid == IID_ICorDebugManagedCallback)
			*out = (ICorDebugManagedCallback *) this;
		else if (riid == IID_ICorDebugManagedCallback2)
			*out = (ICorDebugManagedCallback *) this;
		else
			return (E_NOINTERFACE);

		this->AddRef();
		return (S_OK);
	}

	COM_METHOD
	CreateProcess(ICorDebugProcess *process)
	{
		HPROCESS phandle = 0;

		process->GetHandle(&phandle);
		P->phandle = phandle;

		BOILER_PROCESS
	}

	COM_METHOD
	ExitProcess(ICorDebugProcess *process)
	{
		P->exitcode = 0;
		P->exited = 1;
		P->status = PS_UNDEAD;
		P->msg.type = RD_NONE;
		P->fthelper(P->pid, -1, PSYS_PROC_DEAD, NULL);
		BOILER_PROCESS
	}

	COM_METHOD
	DebuggerError(ICorDebugProcess *process,
	    HRESULT err, DWORD errcode)
	{
		BOILER_PROCESS
	}

	COM_METHOD
	CreateAppDomain(ICorDebugProcess *process,
	    ICorDebugAppDomain *app)
	{
		BOILER_PROCESS
	}

	COM_METHOD
	ExitAppDomain(ICorDebugProcess *process,
	    ICorDebugAppDomain *app)
	{
		BOILER_PROCESS
	}

	COM_METHOD
	LoadAssembly(ICorDebugAppDomain *app,
	    ICorDebugAssembly *assm)
	{

		BOILER_CON
	}

	COM_METHOD
	UnloadAssembly(ICorDebugAppDomain *app,
	    ICorDebugAssembly *assm)
	{
		BOILER_APP
	}

	COM_METHOD
	Breakpoint(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    ICorDebugBreakpoint *brkpt)
	{

		BOILER_APP
	}

	COM_METHOD
	StepComplete(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    ICorDebugStepper *stepper, CorDebugStepReason reason)
	{

		BOILER_APP
	}

	COM_METHOD
	Break(ICorDebugAppDomain *app, ICorDebugThread *thread)
	{
		//System.Diagnostics.Debugger.Break();
		BOILER_CON

	}

	COM_METHOD
	Exception(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    BOOL unhandled)
	{
		//HRESULT err = thread->ClearCurrentException();
		BOILER_APP
	}

	COM_METHOD
	EvalComplete(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    ICorDebugEval *eval)
	{

		BOILER_APP
	}

	COM_METHOD
	EvalException(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    ICorDebugEval *eval)
	{

		BOILER_APP
	}

	COM_METHOD
	CreateThread(ICorDebugAppDomain *app, ICorDebugThread *thread)
	{
		if (P->attached && P->main == 0) {
			init_symbols(P->phandle, TRUE, NULL);
#if __amd64__
			if (Is32bitProcess(P->phandle)) {
				P->model = PR_MODEL_ILP32;
			} else
				P->model = PR_MODEL_ILP64;
#else
			P->model = PR_MODEL_ILP32;
#endif
			pthread_mutex_lock(&P->mutex);

			P->status = PS_STOP;
			P->msg.type = RD_NONE;


			pthread_cond_signal(&P->cond);

			if (P->status != PS_RUN)
				SetEvent(P->event);
			while (P->status == PS_STOP)
				pthread_cond_wait(&P->cond, &P->mutex);
			pthread_mutex_unlock(&P->mutex);
			P->busyloop = 1;
			P->skip = 0;
			P->main = 1;
			insbusyloop(P, !P->model);
			P->status = PS_STOP;
			pthread_mutex_lock(&P->mutex);
			pthread_cond_signal(&P->cond);
			HANDLE td = ::CreateThread(NULL, 0, busyloop_thread, P, 0, NULL);
		}
		BOILER_CON
	}

	COM_METHOD
	ExitThread(ICorDebugAppDomain *app, ICorDebugThread *thread)
	{

		BOILER_APP
	}

	COM_METHOD
	LoadModule(ICorDebugAppDomain *app, ICorDebugModule *module)
	{
		nmodinfo_t *mod;

		if (P->main) {
			P->dll_load_order++;
		}

		mod = nloadsymmod(P, module, P->dll_load_order);
		if (P->attached == 0 && setmain == 0)
			nbrkonmain(P, mod, &setmain);
		pthread_mutex_lock(&P->mutex);
		if (P->busyloop || (P->attached && P->main == 0)) {
			P->status = PS_RUN;
			P->msg.type = RD_DLACTIVITY;
		} else {
			P->status = PS_STOP;
			P->msg.type = RD_DLACTIVITY;

			if (P->fpid) {
				P->threads[0] = GetCurrentThreadId();
				P->nthr = 0;

				if (P->thragent == 0) {
					P->nthr = 0;
					P->status = PS_RUN;
					P->msg.type = RD_NONE;
					BOILER_CON
				}
				P->busyloop = 1;
				P->skip = 0;
				insbusyloop(P, !P->model);
				P->status = PS_STOP;
				HANDLE td = ::CreateThread(NULL, 0, busyloop_thread, P, 0, NULL);
			} else {
				
				SetEvent(P->event);
				pthread_cond_wait(&P->cond, &P->mutex);
				
			}
		}
		pthread_mutex_unlock(&P->mutex);
		BOILER_CON
	}

	COM_METHOD
	UnloadModule(ICorDebugAppDomain *app, ICorDebugModule *module)
	{
		BOILER_APP
	}

	COM_METHOD
	LoadClass(ICorDebugAppDomain *app, ICorDebugClass *c)
	{
		BOILER_APP
	}

	COM_METHOD
	UnloadClass(ICorDebugAppDomain *app, ICorDebugClass *c)
	{
		BOILER_APP
	}

	COM_METHOD
	LogMessage(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    LONG lLevel, WCHAR *logname, WCHAR *msg)
	{
		BOILER_APP
	}

	COM_METHOD
	LogSwitch(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    LONG level, ULONG reason, WCHAR *logname, WCHAR *prname)
	{
		BOILER_APP
	}

	COM_METHOD
	ControlCTrap(ICorDebugProcess *process)
	{
		BOILER_PROCESS
	}

	COM_METHOD
	NameChange(ICorDebugAppDomain *app, ICorDebugThread *thread)
	{
		BOILER_APP
	}

	COM_METHOD
	UpdateModuleSymbols(ICorDebugAppDomain *app, ICorDebugModule *module,
	    IStream *symstr)
	{
		BOILER_APP
	}

	COM_METHOD
	EditAndContinueRemap(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    ICorDebugFunction *func, BOOL accurate)
	{
		BOILER_APP
	}
	COM_METHOD
	BreakpointSetError(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    ICorDebugBreakpoint *brkpt, DWORD err)
	{
		BOILER_APP
	}
//2
	COM_METHOD
	FunctionRemapOpportunity(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    ICorDebugFunction *ofunc, ICorDebugFunction *nfunc,
	    ULONG32 iloff)
	{
		BOILER_APP
	}

	COM_METHOD
	CreateConnection(ICorDebugProcess *process,
	    CONNID connid, WCHAR *coname)
	{
		BOILER_PROCESS
	}

	COM_METHOD
	ChangeConnection(ICorDebugProcess *process, CONNID connid)
	{
		BOILER_PROCESS
	}

	COM_METHOD
	DestroyConnection(ICorDebugProcess *process, CONNID connid)
	{
		BOILER_PROCESS
	}

	COM_METHOD
	Exception(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    ICorDebugFrame *frame, ULONG32 nOffset,
	    CorDebugExceptionCallbackType evtype, DWORD flags)
	{
		//HRESULT err = thread->ClearCurrentException();
		BOILER_APP
	}

	COM_METHOD
	ExceptionUnwind(
	    ICorDebugAppDomain *app, ICorDebugThread *thread,
	    CorDebugExceptionUnwindCallbackType evtype, DWORD flags)
	{

		BOILER_APP
	}

	COM_METHOD
	FunctionRemapComplete(ICorDebugAppDomain *app, ICorDebugThread *thread,
	    ICorDebugFunction *func)
	{

		BOILER_APP
	}

	COM_METHOD
	MDANotification(ICorDebugController *controller, ICorDebugThread *thread,
	    ICorDebugMDA *MDA)
	{

		controller->Continue(FALSE);
		return (S_OK);
	}

	ICorDebugController *
	GetControllerInterface(ICorDebugAppDomain *app)
	{
		ICorDebugProcess *process = NULL;
		ICorDebugController *controller = NULL;
		HRESULT hr = S_OK;

		hr = app->GetProcess(&process);
		if (FAILED(hr))
			return controller;

		hr = process->QueryInterface(IID_ICorDebugController,
		        (void**)&controller);
		//RELEASE(process);

		//_ASSERTE(controller != NULL);
		return controller;
	}

	ICorDebugProcess *
	GetProcess(ICorDebugAppDomain *app)
	{
		ICorDebugProcess *process = NULL;

		HRESULT hr = S_OK;

		hr = app->GetProcess(&process);
		if (FAILED(hr))
			return NULL;
		else
			return process;
	}

	protected:
	long        refcount;
	ICorDebug *dbg;
	int setmain;
	struct ps_prochandle *P;
};


class DebuggerUnmanagedcb : public ICorDebugUnmanagedCallback {
	public:
	DebuggerUnmanagedcb(ICorDebug *dbg, struct ps_prochandle *ps) : m_refCount(0)
	{
		debugger = dbg;
		P = ps;
		excep = 0;

	}

	ULONG STDMETHODCALLTYPE
	AddRef()
	{
		return (InterlockedIncrement((long *) &m_refCount));
	}

	ULONG STDMETHODCALLTYPE
	Release()
	{
		long refCount = InterlockedDecrement(&m_refCount);
		if (refCount == 0)
			delete this;

		return (refCount);
	}

	COM_METHOD
	QueryInterface(REFIID riid, void **ppInterface)
	{
		if (riid == IID_IUnknown)
			*ppInterface = (IUnknown*)(ICorDebugUnmanagedCallback*)this;
		else if (riid == IID_ICorDebugUnmanagedCallback)
			*ppInterface = (ICorDebugUnmanagedCallback*) this;
		else
			return (E_NOINTERFACE);

		this->AddRef();
		return (S_OK);
	}

	COM_METHOD
	DebugEvent(LPDEBUG_EVENT event, BOOL oob)
	{
		ICorDebugProcess *process;
		HRESULT hr = debugger->GetProcess(event->dwProcessId, &process);
		DWORD cont = 0;
		int busy = 0;
		char *s;
		CHAR pszFilename[MAX_PATH+1];

		pthread_mutex_lock(&P->mutex);

		switch (event->dwDebugEventCode) {
		case CREATE_PROCESS_DEBUG_EVENT:
			P->phandle = event->u.CreateProcessInfo.hProcess;
			P->thandle = event->u.CreateProcessInfo.hThread;
#if __amd64__
			if (Is32bitProcess(P->phandle)) {
				P->model = PR_MODEL_ILP32;
			} else
				P->model = PR_MODEL_ILP64;
#else
			P->model = PR_MODEL_ILP32;
#endif
			P->status = PS_STOP;
			P->msg.type = RD_NONE;

			pthread_cond_signal(&P->cond);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			P->exitcode = event->u.ExitProcess.dwExitCode;
			P->exited = 1;
			P->status = PS_UNDEAD;
			P->msg.type = RD_NONE;
			P->fthelper(P->pid, -1, PSYS_PROC_DEAD, NULL);
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			break;
		case EXCEPTION_DEBUG_EVENT:

			if (event->u.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT) {
				if (excep == 0) {
					assert(P->attached == 0);
					hr = process->ClearCurrentException(event->dwThreadId);
					P->status = PS_RUN;
					P->msg.type = RD_NONE;
					excep++;
				} else if (excep == 1) {
					if (event->u.Exception.ExceptionRecord.ExceptionAddress != 
						(PVOID) P->addr) {
						dprintf("expecting execption at %p:but recived from %p\n", 
							P->addr,
							event->u.Exception.ExceptionRecord.ExceptionAddress);
						P->status = PS_RUN;
						cont = DBG_EXCEPTION_NOT_HANDLED;
						break;
					}

					if (delbkpt(P, P->addr) != 0) {
						dprintf("failed to delete brk point at %p:(main)\n", P->addr);
						break;
					}

					if (adjbkpt(P, 0) != 0) {
						dprintf("failed to normalize brk point (main) %x\n", GetLastError());
						break;
					}

					init_symbols(P->phandle, TRUE, NULL);

					excep = 2;
					P->status = PS_STOP;
					P->msg.type = RD_MAININIT;
				} else if (P->fthelper != NULL) {
					exception_cb(P, event);
					P->status = PS_RUN;
					P->msg.type = RD_NONE;
				} else {
					P->status = PS_RUN;
					cont = DBG_EXCEPTION_NOT_HANDLED;
					break;
				}
			} else {
				P->status = PS_RUN;
				cont = DBG_EXCEPTION_NOT_HANDLED;
				break;
			}
			break;
		case LOAD_DLL_DEBUG_EVENT: {
			s = GetFileNameFromHandle(event->u.LoadDll.hFile, pszFilename);
			break;
		}
		case UNLOAD_DLL_DEBUG_EVENT:
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		case RIP_EVENT:
			break;
		default:
			break;
		}

		ICorDebugController *controller = NULL;

		hr = process->QueryInterface(IID_ICorDebugController, (void**)&controller);

		if (oob == TRUE)
			controller->Continue(oob);
		else {
			/*
				If in band then the continue should happen in any other thread other than
				this thread.
				Create a seperate thread, run continue there
			*/
			HANDLE thread = ::CreateThread(NULL, 0, inb, process, 0, NULL);
		}


		if (P->busyloop == 0) {
			if (P->status != PS_RUN)
				SetEvent(P->event);
			while (P->status == PS_STOP)
				pthread_cond_wait(&P->cond, &P->mutex);
		}
		pthread_mutex_unlock(&P->mutex);
		if (P->busyloop == 0 && P->fpid &&
		    (P->attached == 0 && excep == 2)) {
			excep = 3;
			P->busyloop = 1;
			P->skip = 1;
			P->main = 1;
			insbusyloop(P, !P->model);
			P->status = PS_STOP;
			pthread_cond_signal(&P->cond);
			HANDLE td = ::CreateThread(NULL, 0, busyloop_thread, P, 0, NULL);
		}
		return (S_OK);
	}

	static DWORD WINAPI
	inb(void* data)
	{
		((ICorDebugProcess *) data)->Continue(FALSE);
		return 0;
	}

	protected:
	ICorDebug *debugger;
	int excep;
	struct ps_prochandle *P;
	long        m_refCount;
};

/*
 * Iterate over the process's mapped objects.
 */
int
Netobject_iter(struct ps_prochandle *P, proc_map_f *func, void *cd)
{
	prmap_t map;
	nmodinfo_t *mod = P->net_modules;

	for(; mod != NULL; mod = mod->nm_next) {
		if (mod->loaded_order == P->dll_load_order) {
			map.pr_vaddr = 0;
			map.pr_mflags = MA_READ;
			func(cd, &map, mod->nm_name);
		}
	}
	return 0;
}

/*
 * Convert a full or partial load object name to the prmap_t for its
 * corresponding primary text mapping.
 */
prmap_t *
Netobject_to_map(struct ps_prochandle *P, const char *objname)
{
	prmap_t *map;
	nmodinfo_t *mod = P->net_modules;

	for(; mod != NULL; mod = mod->nm_next) {
		if (cmpmodname(objname, mod->nm_name, P->nexe_module == mod)) {
			if ((map = (prmap_t *) malloc(sizeof(prmap_t))) == NULL) {
				return NULL;
			}
			map->pr_vaddr = 0;
			map->pr_mflags = MA_READ;
			return map;
		}

	}
	return NULL;
}

char *
Netobjname(struct ps_prochandle *P, uintptr_t addr, char *buffer, size_t bufsize)
{
	nmodinfo_t *mod = P->net_modules;
	ntypeinfo_t *type;
	nfuncinfo_t *func;
	char *r;

	for(; mod != NULL; mod = mod->nm_next) {

		for (int i=0; i < mod->nm_ntypes; i++) {
			type = mod->nm_types[i];

			for (int j=0; j < type->nt_nsyms; j++) {
				func = type->nt_funcs[j];
				if (func && addr >= func->nf_addr && addr < func->nf_addr+func->nf_size)
					//break;
					goto fnd;
			}
		}

	}
	fnd:
	if (mod == NULL) {
		buffer[0] = 0;
		return NULL;
	}

	strncpy(buffer, mod->nm_name, bufsize);

	buffer[bufsize-1] = 0;
	return buffer;
}
/*
 * Search the process symbol tables looking for a symbol whose name matches the
 * specified name and whose object and link map optionally match the specified
 * parameters.  On success, the function returns 0 and fills in the GElf_Sym
 * symbol table entry.  On failure, -1 is returned.
 */
int
Netlookup_by_name(struct ps_prochandle *P, const char *oname, const char *sname, GElf_Sym *symp)
{
	nmodinfo_t *mod = P->net_modules;
	ntypeinfo_t *type;
	nfuncinfo_t *func;

	for(; mod != NULL; mod = mod->nm_next) {
		if (oname == NULL || cmpmodname(oname, mod->nm_name, mod == P->nexe_module)) {
			for (int i=0; i < mod->nm_ntypes; i++) {
				type = mod->nm_types[i];
				char *cn = type->nt_name;
				if (strncmp(cn, sname, type->nt_nlen) != 0)
					continue;
				for (int j=0; j < type->nt_nsyms; j++) {
					func = type->nt_funcs[j];
					if (func && strcmp(func->nf_name, (sname+type->nt_nlen+1)) == 0) {
						symp->st_name = 0;
						symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
						symp->st_other = 0;
						symp->st_shndx = 1;
						symp->st_value = func->nf_addr;
						symp->st_size = func->nf_size;
						return 0;
					}
				}
			}
		}
	}
	return -1;

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
Netlookup_by_addr(struct ps_prochandle *P, uintptr_t addr, char *buf, size_t size, GElf_Sym *symp)
{
	nmodinfo_t *mod = P->net_modules;
	ntypeinfo_t *type;
	nfuncinfo_t *func;

	for(; mod != NULL; mod = mod->nm_next) {
		for (int i=0; i < mod->nm_ntypes; i++) {
			type = mod->nm_types[i];
			char *cn = type->nt_name;
			for (int j=0; j < type->nt_nsyms; j++) {
				func = type->nt_funcs[j];
				if (func && addr >= func->nf_addr && addr <
				    func->nf_addr+func->nf_size) {
					if (symp != NULL) {
						symp->st_name = 0;
						symp->st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
						symp->st_other = 0;
						symp->st_shndx = 1;
						symp->st_value = func->nf_addr;
						symp->st_size = func->nf_size;
					}
					if (buf != NULL && size > 0)
						snprintf(buf, size, "%s.%s", 
						    type->nt_name, func->nf_name);

					return 0;
				}
			}
		}
	}
	return -1;
}

/*
 * Given an object name and optional lmid, iterate over the object's symbols.
 * If which == PR_SYMTAB, search the normal symbol table.
 * If which == PR_DYNSYM, search the dynamic symbol table.
 */
int
Netsymbol_iter_by_addr(struct ps_prochandle *P, const char *oname,  proc_sym_f *func, void *cd)
{
	nmodinfo_t *mod = P->net_modules;
	ntypeinfo_t *type;
	nfuncinfo_t *nfunc;
	GElf_Sym symp = {0};
	char fname[MAX_SYMBOL_NAME];

	for(; mod != NULL; mod = mod->nm_next) {
		if (mod->loaded_order == P->dll_load_order &&
		    cmpmodname(oname, mod->nm_name, mod == P->nexe_module)) {
			for (int i=0; i < mod->nm_ntypes; i++) {
				type = mod->nm_types[i];
				char *cn = type->nt_name;
				for (int j=0; j < type->nt_nsyms; j++) {
					nfunc = type->nt_funcs[j];
					if (nfunc == NULL)
						continue;
					symp.st_name = 0;
					symp.st_info = GELF_ST_INFO((STB_GLOBAL), (STT_FUNC));
					symp.st_other = 0;
					symp.st_shndx = 1;
					symp.st_value = nfunc->nf_addr;
					symp.st_size = nfunc->nf_size;
					snprintf(fname, MAX_SYMBOL_NAME, "%s.%s", type->nt_name,
					    nfunc->nf_name);
					func(cd, &symp, fname);
				}
			}
		}
	}
	if (symp.st_shndx)
		return 0;
	return -1;
}
/*
 * Return the prmap_t structure containing 'addr' (no restrictions on
 * the type of mapping).
 */
prmap_t *
Netaddr_to_map(struct ps_prochandle *P, uintptr_t addr)
{
	return NULL; //XXX
}

int
ispidnet(pid_t pid)
{
	int net = 0;

	CoInitialize(NULL);
// Get a ICLRMetaHost instance (from .NET 4.0)
	ICLRMetaHost* pCLRMetaHost = NULL;
	CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pCLRMetaHost);
// Get an enumeration of the loaded runtimes in the target process (opened prior with OpenProcess)
	IEnumUnknown* pEnumUnknown = NULL;
	HANDLE hprocess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );
	if (hprocess == NULL)
		return 0;
	HRESULT hr = pCLRMetaHost->EnumerateLoadedRuntimes(hprocess, &pEnumUnknown);
// Use the first runtime found (Note, you can only debug one runtime at once)
	IUnknown* pUnknown = NULL;
	ULONG ulFetched = 0;

	if ((hr = pEnumUnknown->Next(1, &pUnknown, &ulFetched)) == S_OK)
		net = 1;
	pEnumUnknown->Release();
	pCLRMetaHost->Release();
	CloseHandle(hprocess);
	CoUninitialize();
	return net;

	/*
	ICorPublish* pub = NULL;
	ICorPublishProcess* process = NULL;
	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	hr = CoCreateInstance(CLSID_CorpubPublish, NULL, CLSCTX_INPROC_SERVER, IID_ICorPublish,(LPVOID *)&pub);
	ICorPublishProcessEnum* pEnum;

	hr = pub->EnumProcesses(COR_PUB_MANAGEDONLY, &pEnum);

	hr = pub->GetProcess(pid, &process);
	if (process == NULL)
		return 1;
	return 0;*/
}

int
net_create(struct proc_uc *uc, int arch)
{
	HRESULT hr;
	int ng;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		dprintf("libdtrace: Failed to initialize COM: 0x%08x\n", hr);
		return -1;
	}

	// Get a ICLRMetaHost instance (from .NET 4.0)
	IUnknown* Unknown = NULL;
	ULONG Fetched = 0;
	IEnumUnknown* EnumUnknown = NULL;
	ICLRRuntimeInfo* rt = NULL;
	ICLRMetaHost* CLRMetaHost = NULL;

	CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&CLRMetaHost);

	// Get an enumeration of the loaded runtimes in
	//	the target process (opened prior with OpenProcess)
	//pCLRMetaHost->EnumerateLoadedRuntimes(NULL, &pEnumUnknown);
	CLRMetaHost->EnumerateInstalledRuntimes(&EnumUnknown);

	// Use the first runtime found (Note, you can only debug one runtime at once)
	EnumUnknown->Next(1, &Unknown, &Fetched);

	hr = CLRMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&rt);
	ng =  net_ngened(uc->exe, NET_STR_VERSION_40, arch);
	if (ng <= 0) {
		return (-1);
	}
	// QueryInterface for the ICLRRuntimeInfo interface
	//ICLRRuntimeInfo* pCLRRuntimeInfo = NULL;
	//Unknown->QueryInterface(__uuidof(ICLRRuntimeInfo), (void **)&pCLRRuntimeInfo);


	// Get the ICorDebug interface
	//	(this allows you to debug .NET 2.0 targets with the .NET 4.0 API)
	ICorDebug *dbg;
	ICorDebugProcess* process;
	ICorDebugManagedCallback *mcb;
	ICorDebugUnmanagedCallback *ucb;

	rt->GetInterface(CLSID_CLRDebuggingLegacy, IID_ICorDebug, (void **)&dbg);
	if(FAILED(hr)) {
		dprintf("libdtrace: Failed to get Interface CorDebugger %x%08\n", hr);
		return -1;
	}

	hr = dbg->Initialize();
	if(FAILED(hr)) {
		dprintf("libdtrace: Failed to initialize CorDebugger %x%08\n", hr);
		return -1;
	}
	mcb = new DebuggerCB(dbg, uc->ps);
	hr = dbg->SetManagedHandler(mcb);
	if(FAILED(hr)) {
		dprintf("libdtrace: Failed to add Managed Handler %x%08\n", hr);
		return -1;
	}
	ucb = new DebuggerUnmanagedcb(dbg, uc->ps);
	hr = dbg->SetUnmanagedHandler(ucb);
	if(FAILED(hr)) {
		dprintf("libdtrace: Failed to add UnManaged Handler %x%08\n", hr);
		return -1;
	}

	STARTUPINFOW starti;
	PROCESS_INFORMATION processi;
	ZeroMemory(&starti, sizeof(starti));
	ZeroMemory(&processi, sizeof(processi));
	starti.cb = sizeof(STARTUPINFOW);

	DWORD flag = 0;//CREATE_NEW_CONSOLE;

	flag |= DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS; //unmanaged debugging

	wchar_t exe[1024];
	wchar_t args[1024];
	char *ctmp, targs[1024];
	char *const *argv = uc->args;
	int len;


	ctmp = targs;
	while (*argv != NULL) {
		len = strlen(*argv);
		sprintf(ctmp, "%s ", *argv);
		ctmp = ctmp + len + 1;
		argv++;
	}
	mbstowcs(exe, uc->exe, 1024);
	mbstowcs(args, targs, 1024);
	hr = dbg->CreateProcess(exe, args, NULL, NULL, TRUE, flag, NULL,
	        NULL, &starti, &processi, DEBUG_NO_SPECIAL_OPTIONS, &process);
	if(FAILED(hr)) {
		dprintf("libdtrace: Failed to create .net process  %x%08\n", hr);
		return -1;
	}
	uc->ps->pid = processi.dwProcessId;
	uc->ps->tid = processi.dwThreadId;
	uc->ps->event = CreateEvent(NULL,FALSE,FALSE,NULL);
	//uc->ps->phandle = processi.hProcess;
	//uc->ps->phandle = processi.hThread;
	uc->ps->netdbg = dbg;
	uc->ps->netprocess = process;
	uc->ps->isnet = 1;

	return 0;
}

int
net_attach(struct proc_uc *uc)
{
	HRESULT hr;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		dprintf("libdtrace: Failed to initialize COM: 0x%08x\n", hr);
		return -1;
	}

	// Get a ICLRMetaHost instance (from .NET 4.0)
	IUnknown* Unknown = NULL;
	ULONG Fetched = 0;
	IEnumUnknown* EnumUnknown = NULL;
	ICLRRuntimeInfo* rt = NULL;
	ICLRMetaHost* CLRMetaHost = NULL;

	CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&CLRMetaHost);

	// Get an enumeration of the loaded runtimes in
	//	the target process (opened prior with OpenProcess)
	//pCLRMetaHost->EnumerateLoadedRuntimes(NULL, &pEnumUnknown);
	//CLRMetaHost->EnumerateInstalledRuntimes(&EnumUnknown);
	HANDLE hprocess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, uc->ps->pid );
	hr = CLRMetaHost->EnumerateLoadedRuntimes(hprocess, &EnumUnknown);
	// Use the first runtime found (Note, you can only debug one runtime at once)
	EnumUnknown->Next(1, &Unknown, &Fetched);

	hr = CLRMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&rt);

	// QueryInterface for the ICLRRuntimeInfo interface
	//ICLRRuntimeInfo* pCLRRuntimeInfo = NULL;
	//Unknown->QueryInterface(__uuidof(ICLRRuntimeInfo), (void **)&pCLRRuntimeInfo);


	// Get the ICorDebug interface
	//	(this allows you to debug .NET 2.0 targets with the .NET 4.0 API)
	ICorDebug *dbg;
	ICorDebugProcess* process;
	ICorDebugManagedCallback *mcb;
	ICorDebugUnmanagedCallback *ucb;

	rt->GetInterface(CLSID_CLRDebuggingLegacy, IID_ICorDebug, (void **)&dbg);
	if(FAILED(hr)) {
		dprintf("libdtrace: Failed to get Interface CorDebugger %x%08\n", hr);
		return -1;
	}

	hr = dbg->Initialize();
	if(FAILED(hr)) {
		dprintf("libdtrace: Failed to initialize CorDebugger %x%08\n", hr);
		return -1;
	}
	mcb = new DebuggerCB(dbg, uc->ps);
	hr = dbg->SetManagedHandler(mcb);
	if(FAILED(hr)) {
		dprintf("libdtrace: Failed to add Managed Handler %x%08\n", hr);
		return -1;
	}
	ucb = new DebuggerUnmanagedcb(dbg, uc->ps);
	hr = dbg->SetUnmanagedHandler(ucb);
	if(FAILED(hr)) {
		dprintf("libdtrace: Failed to add UnManaged Handler %x%08\n", hr);
		return -1;
	}

	hr = dbg->DebugActiveProcess(uc->ps->pid, FALSE, &process);
	if(FAILED(hr)) {
		dprintf("libdtrace: Failed to attach to .net process  %x%08\n", hr);
		return -1;
	}

	uc->ps->netdbg = dbg;
	uc->ps->netprocess = process;

	uc->ps->event = CreateEvent(NULL,FALSE,FALSE,NULL);
	uc->ps->netprocess = process;
	uc->ps->isnet = 1;

	return 0;
}

int
net_detach(struct ps_prochandle *P, int detach)
{
	ICorDebugController *pCorDebugController;
	HRESULT hr;
	if (detach) {
		ICorDebugController* pCorDebugController = NULL;
		P->netprocess->QueryInterface(__uuidof(ICorDebugController), (void**)&pCorDebugController);
		hr = pCorDebugController->Stop(INFINITE /* Note: Value is ignored – always INFINITE */);
		hr = pCorDebugController->Detach();
		hr = pCorDebugController->Release();
	}
	P->netdbg->SetUnmanagedHandler(NULL);
//pCorDebugUnmanagedCallback->Release();
	P->netdbg->SetManagedHandler(NULL);
//pCorDebugManagedCallback2->Release();
	//P->netdbg->Terminate();
	//P->netdbg->Release();
	CoUninitialize();
	return 0;
}

char *str_netver[][2] = {
	{"\\Microsoft.NET\\Framework\\v2.0.50727\\ngen.exe", "\\Microsoft.NET\\Framework64\\v2.0.50727\\ngen"},
	{"\\Microsoft.NET\\Framework\\v4.0.30319\\ngen", "\\Microsoft.NET\\Framework64\\v4.0.30319\\ngen"},
	{"", ""}
};

int
net_cmd(char *cmd)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD exit_code;


	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);

	si.dwFlags |= STARTF_USESTDHANDLES;
	si.hStdInput = NULL;
	si.hStdError = NULL;
	si.hStdOutput = NULL;
	ZeroMemory( &pi, sizeof(pi) );

	// Start the child process.
	if(!CreateProcessA( NULL,   // No module name (use command line)
	        cmd,   // Command line
	        NULL,           // Process handle not inheritable
	        NULL,           // Thread handle not inheritable
	        FALSE,          // Set handle inheritance to FALSE
	        0,              // No creation flags
	        NULL,           // Use parent's environment block
	        NULL,           // Use parent's starting directory
	        &si,            // Pointer to STARTUPINFO structure
	        &pi )           // Pointer to PROCESS_INFORMATION structure
	) {
		dprintf("net_cmd(), failed cmd (%s) (%x)\n", cmd, GetLastError());
		return (-1);
	}
	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, INFINITE);

	GetExitCodeProcess(pi.hProcess, &exit_code);

	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );

	return exit_code;
}

int
net_ngened(const char *modname, int ver, int arch)
{
	int n, nc;
	char path[MAX_PATH] = {0};
	char guiddir[256];
	char fname[_MAX_FNAME];
	char ext[_MAX_EXT];
	DWORD exit_code;

	if ((n=ngenpath(path, MAX_PATH, ver, arch)) <= 0) {
		dprintf("net_ngened(), failed to get NGEN path (%x)\n", GetLastError());
		return (-1);
	}
	nc = n;
	_splitpath(modname, NULL, NULL, fname, ext);

	strncpy(path+nc, " install ", (MAX_PATH-n));
	n = strlen(path);
	// full path or only name(w/o ext)
	strncpy(path+n, modname, (MAX_PATH-n));

	dprintf("creating ngened image (%s)\n", path);
	exit_code = net_cmd(path);
	if (exit_code == 0)
		return 1;
	dprintf("net_ngened(), failed to create ngened image (%s)\n", path);
	return 0;
}


