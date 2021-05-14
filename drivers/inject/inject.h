#ifndef _INJECT_H_
#define	_INJECT_H_

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dt_pipe dt_pipe_t;
struct dt_pipe {
	HANDLE hfile;		/* file mapping */
	void *hmap;		/* shared memory */
	size_t size;		/* size of memory */
	HANDLE evh;			/* host event */
	HANDLE evp;			/* peer event */
	HANDLE htd;			/* control thread handle */
	dt_pipe_t * (*pfunc_data)(dt_pipe_t *);	/* message processing func */
};

typedef enum {
	PIPE_ERROR = -1,
	PIPE_DONE = 0,
	PIPE_WAIT_TID,
	PIPE_HOOK_FUNC,
	PIPE_FUNC_ENTER,
	PIPE_FUNC_RETURN,
	PIPE_FUNC_ENABLE,
	PIPE_FUNC_DISABLE,
	PIPE_QUEUE_CLEAR,
	PIPE_WITH_STACKS,
	PIPE_CLOSE,
	INJ_ENTRY_TYPE = 5,
	INJ_RETURN_TYPE = 1
} dt_id;

/* message packet header */
typedef struct dt_pmsg {
	int id;			/* type - dt_id */
	int size;		/* total size of message incl header */
	char data[1];	/* message part of packet */
} dt_pmsg_t;

/* probe function */
typedef struct dt_msg_func {
	uint64_t addr;			/* trace address */
	uint64_t faddr;		/* function address */
	int type;				/* type, entry/return */
} dt_msg_func_t;

dt_pipe_t *dt_create_pipe(DWORD pid, int size,
    dt_pipe_t * (*func)(dt_pipe_t *));
dt_pmsg_t *dt_pipe_sndrcv(dt_pipe_t *pipe, dt_pmsg_t *msg);
HANDLE dt_pipe_wait(dt_pipe_t *pipe);
int dt_injectdll(DWORD pid, wchar_t *dllpath);
void dt_pipe_destroy(dt_pipe_t *pipe);
void dt_unload_msg(dt_pipe_t *pipe);

HMODULE WINAPI GetRemoteModuleHandle(HANDLE hProcess, LPCSTR lpModuleName);
FARPROC WINAPI GetRemoteProcAddress(HANDLE hProcess, HMODULE hModule,
    LPCSTR lpProcName, UINT Ordinal, BOOL UseOrdinal);

#define	MAX_SYM_NAME 2000
#define	AGENTDLL64 L"agent64.dll"
#define	AGENTDLL32 L"agent32.dll"

#pragma pack(1)
struct ftetw_event_entry {
	uint32_t stacksz; 	/* total bytes */
	uint64_t addr;
	uint64_t arg0;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3;
	uint64_t arg4;
	uint64_t stack[1];
};

struct ftetw_event_return {
	uint32_t stacksz; 	/* total bytes */
	uint64_t addr;
	uint64_t ax;
	uint64_t stack[1];
};

struct ftetw_blob {
	uint32_t samples;	/* number of events in blob */
	uint32_t count;		/* total bytes in blob */
	uint64_t arr[1];	/* blob */
};
typedef struct ftetw_msg {
	uint32_t type;
	uint64_t time;
	uint32_t tid;
	uint32_t pid;
	uint32_t cpuno;
	uint32_t stacksz;
	uint64_t addr;
	uint64_t stack[1];	/* ARGS + stack */
} ftetw_msg_t;
#pragma pack()


#ifdef __cplusplus
}
#endif

#endif /* _INJECT_H_ */