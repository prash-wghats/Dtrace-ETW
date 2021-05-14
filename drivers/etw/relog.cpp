#include <array>
#include <cassert>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <set>
#include <string>
#include <algorithm>
#include <memory>

#include <atlbase.h>
#include <relogger.h>
#include <windows.h>
#include <evntcons.h>
#include <etw.h>
#include "common.h"
#include "etw_struct.h"
#include "etw_private.h"

#define PATHSIZE	256
#define TMPN L"\\dtrace\\tmpetw"
#define TMPNAME L"\\dtrace\\tmpetwX.etl"
#define TMPONAME L"\\dtrace\\tmpout.etl"
#define FNSIZE		PATHSIZE+sizeof(TMPNAME)

typedef ULONG
(*CreateMergedTraceFile)(
    _In_ LPCWSTR wszMergedFileName,
    _In_ LPCWSTR wszTraceFileNames[],
    _In_ ULONG   cTraceFileNames,
    _In_ DWORD   dwExtendedDataFlags
);

TRACEHANDLE hrelog;
CComPtr<ITraceRelogger> relogger[DT_ETW_MAX_SESSION];
wchar_t tmpfiles[DT_ETW_MAX_SESSION][FNSIZE];
size_t maxfilesz[DT_ETW_MAX_SESSION] = {1024, 1024, 1024, 1024, 1024};
wchar_t ofile[FNSIZE];

HANDLE rthreads[DT_ETW_MAX_SESSION];
int rthreadmax = 0;
CComBSTR ofilenames[DT_ETW_MAX_SESSION] = {"e:\\output0.etl", "e:\\output1.etl",
    "e:\\output2.etl", "e:\\output3.etl",  "e:\\output4.etl"
    };

class TraceAnalysisCallback : public ITraceEventCallback {
	public:

	TraceAnalysisCallback ();

	STDMETHODIMP QueryInterface (const IID& iid, void **obj);
	STDMETHODIMP_ (ULONG) AddRef ();
	STDMETHODIMP_ (ULONG) Release ();

	STDMETHODIMP OnBeginProcessTrace (ITraceEvent* headerEvent,
	    ITraceRelogger* relogger);
	STDMETHODIMP OnEvent (ITraceEvent* event, ITraceRelogger* relogger);
	STDMETHODIMP OnFinalizeProcessTrace (ITraceRelogger* relogger);

	private:
	DWORD m_refCount;
};

TraceAnalysisCallback::TraceAnalysisCallback ():
	m_refCount (0)
{

}

STDMETHODIMP
TraceAnalysisCallback::QueryInterface (const IID& iid, void **obj)
{
	if (iid == IID_IUnknown) {
		*obj = static_cast<IUnknown*> (this);
	} else if (iid == __uuidof (ITraceEventCallback)) {
		*obj = static_cast<ITraceEventCallback*> (this);
	} else {
		*obj = nullptr;

		return E_NOINTERFACE;
	}

	return S_OK;
}

STDMETHODIMP_ (ULONG) TraceAnalysisCallback::AddRef (void)
{
	return InterlockedIncrement (&m_refCount);
}

STDMETHODIMP_ (ULONG) TraceAnalysisCallback::Release ()
{
	ULONG ucount = InterlockedDecrement (&m_refCount);
	if (ucount == 0) {
		delete this;
	}

	return ucount;
}

STDMETHODIMP
TraceAnalysisCallback::OnBeginProcessTrace (ITraceEvent* /*headerEvent*/,
    ITraceRelogger* /*relogger*/)
{
	return S_OK;
}


STDMETHODIMP
TraceAnalysisCallback::OnEvent (ITraceEvent* event, ITraceRelogger* relogger)
{
	relogger->Inject (event);
	return S_OK;
}

STDMETHODIMP
TraceAnalysisCallback::OnFinalizeProcessTrace (ITraceRelogger* /*relogger*/)
{
	return S_OK;
}

int relogdone = 0;
static DWORD WINAPI
relog_event_thread(void* data)
{
	ITraceRelogger* relogger = (ITraceRelogger*) data;

	HRESULT res = relogger->ProcessTrace();

	relogdone = 1;
	return 0;
}

wchar_t *sesstofile(wchar_t *sessname, size_t *fsz)
{
	wchar_t *name;
	int i;
	size_t sz;
	
	if (wcscmp(sessname, DTRACE_SESSION_NAME) == 0 ||
		wcscmp(sessname, KERNEL_LOGGER_NAME) == 0) {
		i = DT_ETW_KERNEL_SESSION;
	} else if (wcscmp(sessname, DTRACE_SESSION_NAME_USER) == 0) {
		i = DT_ETW_USER_SESSION;
	} else if (wcscmp(sessname, DTRACE_SESSION_NAME_HFREQ) == 0) {
		i = DT_ETW_HFREQ_SESSION;
	} else if (wcscmp(sessname, DTRACE_SESSION_NAME_CLR) == 0) {
		i = DT_ETW_CLR_SESSION;
	} else if (wcscmp(sessname, DTRACE_SESSION_NAME_FT) == 0) {
		i = DT_ETW_FT_SESSION;
	} else {
		printf("Unknown session name (%s).Exiting...", sessname);
		*fsz = 0;
		return NULL;
	}
	name = wcsrchr(tmpfiles[i], L'\\');
	wcscpy(name+1, sessname);
	wcscat(name+1, L".etl");
	rthreads[i] = (HANDLE) 1;
	*fsz = maxfilesz[i];
	return tmpfiles[i];
}

int
etw_merge_etlfiles()
{
	CreateMergedTraceFile fn;
	int max = 0;
	const wchar_t
	*files[DT_ETW_MAX_SESSION];// = {L"e:\\output0.etl",L"e:\\output1.etl",L"e:\\output2.etl",L"e:\\output3.etl",L"e:\\output4.etl"};
	for(int i = 0; i < DT_ETW_MAX_SESSION; i++) {
		if (rthreads[i] != NULL)
			files[max++] = tmpfiles[i];
	}
	//while(relogdone == 0)
	//	Sleep(100);
	//WaitForMultipleObjects(DT_ETW_MAX_SESSION, rthreads, TRUE, INFINITE);

	HINSTANCE dll = LoadLibrary(L"kerneltracecontrol.dll");
	if (dll == NULL) {
		printf("ERROE %d", GetLastError());
	}
	fn = (CreateMergedTraceFile)GetProcAddress(dll, "CreateMergedTraceFile");
	if (dll == NULL ||
		(fn = (CreateMergedTraceFile)
		GetProcAddress(dll, "CreateMergedTraceFile")) == NULL) {
		eprintf("KernelTraceControl Failed (%d)", GetLastError());
		return (-1);
	}

	fn(ofile, files, max,   0x000FFFFF);
	return (0);
}

int
tempfiles(wchar_t *oetwfile)
{
	wchar_t tpath[PATHSIZE], dir[PATHSIZE], *name;
	int len;

	len = GetTempPathW(PATHSIZE, tpath);
	wcscpy(dir, tpath);
	wcscat(dir, L"\\dtrace\\");
	CreateDirectory(dir, NULL);
	ASSERT(len > 0 && len < PATHSIZE);
	len += wcslen(TMPN);
	for (int i = 0; i < DT_ETW_MAX_SESSION; i++) {
		tmpfiles[i][0] = L'\0';
		wcscpy(tmpfiles[i], tpath);
		wcscat(tmpfiles[i], TMPNAME);
		tmpfiles[i][len] = L'0' + i;
	}
	if (oetwfile == NULL) {
		wcscpy(ofile, tpath);
		wcscat(ofile, TMPONAME);
	} else {
		wcscpy(ofile, oetwfile);
	}
	return 0;
}

int
relog(etw_sessioninfo **sessions, int max, wchar_t *etlfile)
{
	HANDLE thread = 0;
	int nthr = 0;

	tempfiles(etlfile);

	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	HRESULT res;
	//,IID_ITraceRelogger2, (LPVOID *)& relogger);

	for (int i = 0; i < max; i++) {
		if (sessions[i] != NULL) {

			res = relogger[i].CoCreateInstance(CLSID_TraceRelogger, 0,
			    CLSCTX_INPROC_SERVER);
			relogger[i]->SetCompressionMode(FALSE);
			hr = relogger[i]->AddRealtimeTraceStream(sessions[i]->sessname, NULL, &hrelog);
			res = relogger[i]->SetOutputFilename(tmpfiles[i]);
			TraceAnalysisCallback *ec = new TraceAnalysisCallback();
			res = relogger[i]->RegisterCallback(ec);

			DWORD id = 0;

			rthreads[i] = CreateThread(NULL, 0, relog_event_thread,
			    (void *) relogger[i], 0, &id);
		}
	}

	return 0;
}

void
relog_single(etw_sessioninfo *session, int i)
{
	HANDLE thread = 0;
	int nthr = 0;
	HRESULT hr, res;

	if (session != NULL && rthreads[i] == NULL) {
		res = relogger[i].CoCreateInstance(CLSID_TraceRelogger, 0,
		    CLSCTX_INPROC_SERVER);
		relogger[i]->SetCompressionMode(FALSE);
		hr = relogger[i]->AddRealtimeTraceStream(session->sessname, NULL, &hrelog);
		res = relogger[i]->SetOutputFilename(tmpfiles[i]);
		TraceAnalysisCallback *ec = new TraceAnalysisCallback();
		res = relogger[i]->RegisterCallback(ec);

		DWORD id = 0;

		rthreads[i] = CreateThread(NULL, 0, relog_event_thread,
		    (void *) relogger[i], 0, &id);
	}
}