/* 
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

#ifndef	_LIBPROC_WIN_H
#define	_LIBPROC_WIN_H


#include <cor.h>
#include <cordebug.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NAME_LENGTH 256

typedef ULONG ulong_t;

struct proc_mod;

typedef struct nfuncinfo nfuncinfo_t;
typedef struct nmodinfo nmodinfo_t;
typedef struct ntypeinfo ntypeinfo_t;

struct ntypeinfo {
	char nt_name[MAX_NAME_LENGTH];
	ulong_t nt_nlen;
	mdTypeDef nt_tok;
	int nt_nsyms;
	uintptr_t nt_addr;
	size_t nt_size;
	nfuncinfo_t **nt_funcs;
	nmodinfo_t *nt_mod;
};

struct nfuncinfo {
	uintptr_t nf_addr;
	char nf_name[MAX_NAME_LENGTH];
	ulong_t nf_nlen;
	size_t nf_size;
	mdMethodDef nf_tok;
	ntypeinfo_t *nf_type;
};

struct nmodinfo {
	ICorDebugModule *nm_mod;
	char nm_fname[MAX_PATH];
	char nm_name[MAX_NAME_LENGTH];
	int nm_ntypes;
	int loaded_order;
	ntypeinfo_t **nm_types;
	nmodinfo_t *nm_next;
};

struct ps_prochandle {
	pid_t pid;			/* Process ID. */
	pid_t tid;			/* main thread ID */
	HANDLE phandle;			/* process handle */
	HANDLE thandle;			/* Thread handle */
	HANDLE event;			/* signal when process stopped */
	int	flags;			/* Process flags. */
	int	status;			/* Process status (PS_*). */
	int wstat;			/* wait/error code */
	int	exitcode;			/* exit code */
	int exited;
	int model;			/* x64 or x86 */
	BYTE saved;			/* instruction at the breakpoint address */
	uintptr_t addr;			/* breakpoint address */
	rd_event_msg_t msg;
	rd_agent_t *rdap;		/* librtld_db agent */
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t pthr;			/* debugged process thread */
	struct proc_mod *modules;	/* list of modules loaded by process */
	struct proc_mod *exe_module;	/* main exe module */
	nmodinfo_t *net_modules;
	nmodinfo_t *nexe_module;
	int dll_load_order;			/* library load event count */
	int (*fthelper)(pid_t, pid_t, int, void*);	/* dtrace driver helper */
	int isnet;				/* .net module */
	int attached;
	ICorDebug *netdbg;
	ICorDebugProcess* netprocess;
	int busyloop;		/* process in busy loop */
	int fpid;			/* fpid provider */
	pid_t thragent;		/* fpid dll load thread handle */
	int isetw;
	pid_t threads[1024];
	int nthr, nblk;
	HANDLE thrblk[1024];
	int netver;
	int main;
	int skip;
	int detach;
	etw_proc_module_t *etwmods;
	ctf_file_t *p_ctf;
};

struct proc_uc {
	const char *exe;
	char *const *args;
	struct ps_prochandle *ps;
};

typedef struct proc_mod {
	char *name;
	char *fullname;
	ULONG64 imgbase;
	ULONG64 size;
	ULONG64 b_faddr; // begin forwarder address
	ULONG64 e_faddr; // end forwarder address
	ULONG64 b_code;  // begin code
	ULONG64 e_code;  // end code
	int loaded_order;
	void *c_ctf;
	struct proc_mod *next;
} proc_mod_t;

int adjbkpt(struct ps_prochandle *P, int wow);
int setbkpt(struct ps_prochandle *P, uintptr_t addr);
int delbkpt(struct ps_prochandle *P, uintptr_t addr);
int exception_cb(struct ps_prochandle *P, DEBUG_EVENT *pdbj);

int net_create(struct proc_uc *uc, int arch);
int net_detach(struct ps_prochandle *P, int detach);
int ispidnet(pid_t pid0);
int net_attach(struct proc_uc *uc);

int Netobject_iter(struct ps_prochandle *P, proc_map_f *func, void *cd);
prmap_t * Netobject_to_map(struct ps_prochandle *P, const char *objname);
char *Netobjname(struct ps_prochandle *P, uintptr_t addr, char *buffer, size_t bufsize);
int Netlookup_by_name(struct ps_prochandle *P, const char *oname, const char *sname, GElf_Sym *symp);
int Netlookup_by_addr(struct ps_prochandle *P, uintptr_t addr, char *buf, size_t size, GElf_Sym *symp);
int Netsymbol_iter_by_addr(struct ps_prochandle *P, const char *object_name,  proc_sym_f *func, void *cd);
prmap_t *Netaddr_to_map(struct ps_prochandle *P, uintptr_t addr);
prmap_t *Netname_to_map(struct ps_prochandle *P, const char *name);
int
adjbusyloop(struct ps_prochandle *P, int wow, uintptr_t addr);
int insbusyloop(struct ps_prochandle *P, int wow);
int
suspendbusy(struct ps_prochandle *P, int wow);
DWORD WINAPI busyloop_thread(LPVOID data);
char *
GetFileNameFromHandle(HANDLE hFile, TCHAR *pszFilename);
int
cmpmodname(const char *oname, const char *mname, int isexemname);

#if __amd64__
BOOL Is32bitProcess(HANDLE h);
int is64bitmodule(PVOID base, char *s);
#endif

#ifdef __cplusplus
}
#endif

#endif