#if !defined(_DTRACE_PRIVATE)
#define	_DTRACE_PRIVATE

extern hrtime_t Hertz;
extern cpu_data_t *CPU;
extern cpu_core_t *cpu_core;
extern struct modctl *modules;
extern HANDLE dtrace_etw_handle;
#endif