#ifndef COMMON_H
#define COMMON_H

#ifdef __cplusplus
extern "C" {
#endif


extern int _m_debug;
void dprintf(const char *format, ...);

/* mutex helper functions */
void wmutex_init(HANDLE *m);
void wmutex_enter(HANDLE *m);
void wmutex_exit(HANDLE *m);
void wmutex_destroy(HANDLE *m);
int wmutex_owned(HANDLE *m);

/* memory helper functions */
void mem_free(void *buf);
void *mem_zalloc(size_t size);

int guidcmp(const GUID *g0, const GUID *g1);
BOOL setpriv(LPCTSTR priv);
HANDLE init_symbols(HANDLE h, int inv, PSYMBOL_REGISTERED_CALLBACK64 cb);

#define NET_STR_VERSION_20	0
#define NET_STR_VERSION_40	1
#define NET_STR_VERSION_30	2
#define NET_STR_VERSION_35	2

int filetype(char *name, int *arch, int *isnet);
int runcmd(char *cmd);
int ngenpath(char *path, int len, int ver, int arch);
int isguideq(GUID *g0, GUID *g1);
char *set_syms_path(char *path);
/* if 64 bit os, *arch == 1 x86 */
int is64bitos(BOOL *parch);

#ifdef __cplusplus
}
#endif

#endif

