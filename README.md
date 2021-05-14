# Dtrace for Windows - Frontend to ETW

The [DTrace](https://www.freebsd.org/cgi/man.cgi?query=dtrace) for Windows port acts as a frontend to [ETW](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-). Additionaly there is support for ```pid provider``` for native and .net applications.  

Since the pid provider uses the debugger interface, it will slow down the application being traced to unusable level, when tracing for large number of probes. An additional provider called as ```fpid``` (based on [ntrace](https://github.com/jpassing/ntrace) and [Orbitprofiler](https://github.com/pierricgimmig/orbitprofiler)) is provided, which uses function hooking <minihook>(https://github.com/TsudaKageyu/minhook) to implement the trace, to get function count and stacktrace. With **fpid provider**, dtrace wont be able to trace the memory of user process.

When run for the first time, **dtrace.exe** will get a list of all registered **etw** providers and saves it in a file ```dt_provlist.dat```, in the folder dtrace executable is found.The translator scripts are also read from the dtrace executable folder.

## Usage
[Dtrace](https://www.freebsd.org/cgi/man.cgi?query=dtrace)  
Additional options :
```
	-E <etlfile>
		If <etlfile> file exists then enable probes on this etlfile.
		If <etlfile> doesn't exist, then enables etw in realtime and logs to file.
		High frequency probes are not processed, but written to the log file for later processing.
		
	-g
		Process all probes in realtime when logging to file (Ex. -gE e:\test.etl).
```
### Examples 
**dtrace.exe -s dscripts\demo\randomascii.d -E "[2015-09-25_20-56-25 VS F8 short hang.etl](https://github.com/randomascii/bigfiles/blob/master/ETWTraces/2015-09-25_20-56-25%20VS%20F8%20short%20hang.zip)"**  
**dtrace.exe -s dscripts\bin\sched.d -E PerfViewData.etl**  
**dtrace.exe -s dscripts\bin\sched.d**  
**dtrace.exe -n "pid$target:a.out::entry {@[probefunc] = count();}" -c debug/amd64/obj/t_c_sim.exe**  
	When using poweshell replace `"` with `'`.  
**dtrace.exe -n 'pid$target:ntdll::entry {@[probefunc] = count();}' -c debug/amd64/obj/t_c_sim.exe**  
**dtrace.exe -n 'pid$target:mscorlib::entry {@[probefunc] = count();}' -c debug/amd64/obj/t_cs_str.exe**  

To stop tracing, press **CTRL C**.  
Program names are converted to lower case, so any comparision to `execname` , should have the program name in lowercase  
```/execname == "lowercase.exe"/```  

**scripts\demo** folder contains example scripts. **scripts\demo\dtracecmds[x64|x32].bat** shows example usage of this scripts.
**tests\dtrace** contains the dtrace testsuite. 

## Providers
------
The list of all providers found by dtrace can be displayed using  
```
dtrace -l
```
<br />

### ETW provider
Provider gives direct access to registered ETW provider. The descriptor format is as follows  
```provider-name:::keyword```.  
The provider name and keywords should be **lowercase** .The keywords and associated events and their meaning can be found using
```powershell``` using the  
```Get-WinEvent -ListProvider``` command.  
Ex. The following command will display all the events for ```Microsoft-Windows-DNS-Client provider```.
```
(Get-WinEvent -ListProvider *DNS-Client).events
(Get-WinEvent -ListProvider *DNS-Client).keywords
```
example:
```
dtrace -n "microsoft-windows-win32k:::win_responsetime { ustack(); }"
```  
This will enable the ```Microsoft-Windows-Win32k``` provider, with keyword ```win_ResponseTime```.

Probes | Description
------ | -----------
events | this enable all the events for the provider. <ul><li>*arg0* = event id</ul></li> <ul><li>*arg1* = opcode</ul></li> <ul><li>*arg2* = payload of the event</ul></li> <ul><li>*arg3* = size of payload</ul></li>
\<keywords\> | this will enable the events for the keyword. arguments same as above.<br>Note: A event may trigger mutiple probes, since it can have mutiple keywords associated with it.<br>ex. ``` microsoft-windows-dxgkrnl:::base```
capturestate | Requests that the provider log its state information<br> ex. ```microsoft-windows-dxgkrnl:::capturestate```
On top of each payload, 4 bytes are added.
```
arg2 - 1 => UCHAR* : 0 = 32 bit , 1 = 64 bit
arg2 - 2 => UCHAR* : version of event
arg2 - 4 => USHORT* : event id

ex. arch = *(uint8_t *) (arg2 - 1);
```
For an example see **dscripts\demo\randomascii.d**, **dscripts\demo\dns.d**.

## dnet
The dnet provider is a helper provider for Microsoft-Windows-DotNETRuntime provider.
Function | Probes | Description
----- | ------ | -----------
event | runtime | runtime information of .net instance
event | excp | Exception information, ExceptionKeyword
lock | lck-wait, lck-done | Thread contention events, ContentionKeyword
thread | thr-start, the-stop ... | Thread pool events, ThreadingKeyword
jit | method-jit-begin, method-load, method-unload ... | JITKeyword | NGenKeyword
gc | gc-start, gc-end ... | garbage collection events, GCKeyword
loader |... | Loader events, LoaderKeyword
security |... | security evenst, SecurityKeyword
arm |... | AppDomainResourceManagementKeyword
interop |... | interop events, InteropKeyword
```
arg0 = payload with header (see ETW provider)
arg1 = length of payload
arg2 = 0 => 32bit, 1 => 64 bit
arg3 = version
```
some of the probes have translators. Ex. ***dtrace -s dscripts\demo\dnet.d***

## hwconfig
Helper provider for hardware configuration **{0x01853a65,0x418f,0x4f36,{0xae,0xfc,0xdc,0x0f,0x1d,0x2f,0xd2,0x35}}**
The probes have translators.
```
arg0 = payload with header (see ETW provider) [translated args[0]]
arg1 = length of payload
arg2 = 0 => 32bit, 1 => 64 bit
arg3 = version
ex. print(*args[0]);
```
***Example : dtrace -s dscripts\demo\hwconfig.d -E PerfViewData.etl***

## PMC
ETW provides some support for Performance Monitoring Counters both sampling and counter type. There is limit to the number of pmc registers that can be configured at a time (ex 4).
for sampling a PMC provider is provided
Probes | Description
------ | -----------
sample-src | Name of the configured PMC register. <ul><li>arg0 = source id</li></ul> <ul><li>arg1 = name of the register (string)</li></ul><ul><li>arg2 = sample interval</li></ul>
[register name] | arg0 = (intptr_t) Intruction Pointer address when sampled<br>`Ex. pmc:::branchmispredictions`
[register name][-samplinginterval] | arg0 = (intptr_t) Intruction Pointer<br>`Ex. pmc:::branchmispredictions-1000000`
 | 
counter-src | Name of the configured PMC counter register. <ul><li>(int) args[0] = array count</li></ul> <ul><li>(wchar_t **) args[1] = array of pmc register names (string)</li></ul>
\<prov\>::pmc:\<probename\>-\<pmc register\> | (uint64_t) arg4 = pmc counter value<br>`Ex. sched::pmc:off-cpu-instructionretired`
\<prov\>::pmc:\<probename\> | xlate (etwext_t *)arg4 => (etw_pmc_t *) (dscripts\demo\pmc.d)<br> `Ex. isr::pmc:isr`

***Example : dtrace -s dscripts\demo\pmc.d***

## diag
Diagnostics 
Probes | Description
------ | -----------
events | all events. <ul><li>arg0 = name of the provider</li></ul> <ul><li>arg1 = event id</li></ul> <ul><li>arg2 = opcode</li></ul> <ul><li>arg3 = payload length</li></ul> <ul><li>arg4 = payload with header (see ETW provider)</li></ul>
ignored | events not probed.[args same as above]
missed-ustack | missed user stacks. use ustack() to get stack. [arg0 = (uint64_t) matchid]<br>[GUID- Microsoft-Windows-Kernel-Eventtracing - id 18]
missed-stack | missed kernel stack. use stack(). [arg0 = (uint64_t) timestamp]<br>[GUID-{def2fe46-7bd6-4b80-bd94f57fe20d0ce3}]
missed-dnet-stack | missed DotnetRuntime stack. [arg0 = (uint64_t) instance id]<br>[GUID-Microsoft-Windows-DotNETRuntime - id 82]
lostevent | ETW missed events
fpid | fpid provider event. <ul><li>arg0 = [0:entry][1:return]</li></ul> <ul><li>arg1 = (intrptr_t) address</li></ul> <ul><li>arg? = args to function / return value</li></ul>
***Example : dtrace -s dscripts\demo\diag.d -E PerfViewData.etl***

## io (disk io)
The io provider makes available probes related to disk input and output. 
ETW flags ==> EVENT_TRACE_FLAG_DISK_IO_INIT && EVENT_TRACE_FLAG_DRIVER 

Probes | Description
------ | -----------
start  | Initialize disk io. The bufinfo_t corresponding to the I/O request is pointed to by *args[0]*. The devinfo_t of the device to which the I/O is being issued is pointed to by *args[1]*. The fileinfo_t of the file that corresponds to the I/O request is pointed to by *args[2]*. The start event doesnt contain any useful information, other than the args[0]->b_addr, which is unique irp addr for this io transaction.
done | Probe that fires after an I/O request has been fulfilled. arguments same as above.
example. **dscripts\bin\iosnoop** (requires bash).

## sched (context switch)
The sched provider makes available probes related to CPU scheduling. 
ETW flags ==> EVENT_TRACE_FLAG_CSWITCH|EVENT_TRACE_FLAG_DISPATCHER.

Probes | Description
------ | -----------
off-cpu | Probe that fires when the current CPU is about to end execution of a thread.The curcpu variable indicates the current CPU. The curlwpsinfo variable indicates the thread that is ending execution. The curpsinfo variable describes the process containing the current thread. The lwpsinfo_t structure of the thread that the current CPU will next execute is pointed to by args[0]. The psinfo_t of the process containing the next thread is pointed to by args[1]. 
on-cpu | Probe that fires when a CPU has just begun execution of a thread. The curcpu variable indicates the current CPU. The curlwpsinfo variable indicates the thread that is beginning execution. The curpsinfo variable describes the process containing the current thread. 
wakeup | Probe that fires immediately before the current thread wakes a thread sleeping on a synchronization object. The lwpsinfo_t of the sleeping thread is pointed to by args[0]. The psinfo_t of the process containing the sleeping thread is pointed to by args[1]. 

## proc
The proc provider makes available probes for to the following activities: process creation and termination, thread creation and termination.
ETW flags ==> EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD.

Probes | Description
------ | -----------
start  | Start process event. The psinfo_t corresponding to the new process is pointed to by args[0].
exit   | End process event. args[0] corresponds to the exit code. exiting process - curpsinfo
lwp-start | Start thread event. args[0] lwpsinfo_t, arg[1] psinfo_t.
lwp-exit  | End Thread event. exiting thread - curlwpsinfo
module-load | load module. args[0] = (wchar_t *) module name, args[1] = module base address
module-unload | same as above

***Example : dtrace -s dscripts\demo\proc.d***

## fsinfo
The fsinfo provider makes available probes related to file input and output.
ETW flags ==> EVENT_TRACE_FLAG_DISK_FILE_IO|EVENT_TRACE_FLAG_FILE_IO|EVENT_TRACE_FLAG_FILE_IO_INIT

Probes | Description
------ | -----------
create | File create event. args[0]: fileinfo_t *. common to all probes.
cleanup | Clean up event. The event is generated when the last handle to the file is released.
close | Close event. The event is generated when the file object is freed.
read | File read event. 
write | File write event. 
setinfo | Set information event.
delete | Delete file event.
rename | Rename file event.
direnum | Directory enumeration event.
flush | Flush event. This event is generated when the file buffers are fully flushed to disk.
queryinfo | Query file information event.
fscontrol | File system control event. 
done | End of operation event. fi_irp member identifies the IO activity that is ending. fi_extinfo information returned by the file system for the operation. For example for a read request, the actual number of bytes that were read. fi_rstatus, Return value from the operation.
dirnotify | Directory notification event.
***Example : dtrace -s dscripts\demo\fileio.d***

# reg (registry)
The reg provider makes available probes related to registry operations.
ETW flags ==> EVENT_TRACE_FLAG_REGISTRY.

Probes | Description
------ | -----------
create | Create key event. args[0]: registry_t *. common to all probes.
open | Open key event.
delete | Delete key event.
query | Query key event.
setvalue | Set value event.
delvalue | Delete value event. 
queryvalue | Query value event.
enumkey | Enumerate key event.
enumvaluekey | Enumerate value key event. 
querymulvalue | Query multiple value event. 
setinfo | Set information event.
flush | Flush key event. 
kcbcreate | Create key event. Generated when a registry operation uses handles rather than strings to reference subkeys.
kcbdelete |
virtualize |
close |
***Example : dtrace -s dscripts\demo\reg.d***

## pf (pagefault)
Pagefault events.
ETW flags ==> EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS|EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS|EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS

Probes | Description
------ | -----------
hardflt | Hard page fault event. arg0-5:wchar_t *, va (void*), time (u32), offset (u64), tid (u32)
imgload | Image load in page file event. arg0-5:wchar_t *, flags (u16), devchar (u32), filechar (u16)
valloc | Virtual allocation event. arg0-3: addr (void*) (allocated or free base address), pid (u32), memory size (size_t), flags (u32)  
vfree | Virtual free event. same as above.
trans_flt | Transition fault event. args0-1: va (void*) Virtual address of the page that caused the page fault, pc (void*) program counter
dzero_flt | Virtual address of the page that caused the page fault 
cow_flt | Virtual address of the page that caused the page fault
gp_flt | Guard page fault event. 
hp_flt | Hard page fault event. 
av_flt | Hard page fault event. 
***Example : dtrace -s dscripts\demo\pf.d***

## tcpip
Provider for TCP/IP  events.
ETW flags ==> EVENT_TRACE_FLAG_NETWORK_TCPIP 

Probes | Description
------ | -----------
send | Send event for IPv4/IPv6 protocol. args[0]: ipinfo_t *, args[1]: tcpinfo_t *
receive | Receive event for IPv4/IPv6 protocol. 
connect | Connect event for IPv4/IPv6 protocol. 
disconnect | Disconnect event for IPv4/IPv6 protocol. 
retransmit | Retransmit event for IPv4/IPv6 protocol.
accept | Accept event for IPv4/IPv6 protocol. 
reconnect | Reconnect event for IPv4/IPv6 protocol. (A connect attempt failed and another attempt is made.) 
copy | TCP copy event 
fail | Fail event.

## udpip
Provider  UDP/IP events
ETW flags ==> EVENT_TRACE_FLAG_NETWORK_TCPIP 

Probes | Description
------ | -----------
send | Send event for IPv4/IPv6 protocol. args[0]: udpinfo_t*
receive | Receive event for IPv4/IPv6 protocol. 		
fail | Fail event. args[0] uint16_t (protocol), args[1] uint16_t (failure code)

## PERFINFO providers

Provider | ETW flag | Probe | Description
-------- | -------- | ----- | -----------
 profile | EVENT_TRACE_FLAG_PROFILE | profile-n | [profile provider](http://dtrace.org/guide/chp-profile.html).
 -|-|tick-n| 
 -|-| sample-n | triggers for every sample.
dpc | EVENT_TRACE_FLAG_DPC | thread | ThreadDPC event records when a threaded DPC executes. arg0-1: (u64) entry time, (void *) routine address.
 -|-| dpc | when a DPC is entered.
 -|- | timer | The TimerDPC event records when a DPC fires as a result of a timer expiration.
 isr | EVENT_TRACE_FLAG_INTERRUPT | isr | interrupt service routine. args0-3: entry time (u64), routine address, return val (u8), vector number (u8)
 syscall | EVENT_TRACE_FLAG_SYSTEMCALL | entry | arg0: Address of the NT function call that is being entered
  -|-| return | arg0: Status code returned by the NT system call.

```
Example :
	dtrace -s dscripts\demo\systemcall.d -E c:\systemcall.etl (* log to file *)
	dtrace -s dscripts\demo\systemcall.d -E c:\systemcall.etl (* read from the file *)
```

## [pid provider](http://dtrace.org/guide/chp-pid.html)
The [pid provider](http://dtrace.org/blogs/brendan/2011/02/09/dtrace-pid-provider/) allows for tracing of the entry and return of a function in a user process (native & .net) as well as any instruction as specified by an absolute address or function offset. For .net, function name is Namespace.Class.Function ex. 
```
pid$target:t_cs_str:Strings.Program.Function1:entry
```  
If you require stacktrace, or function usage count use the **fpid provider**. stacktrace slows the pid provider.
If have to modify or read from the traced process memory, use the **pid provider**.
## fpid provider
The fpid provider allows for tracing of the entry and return of a function, and collecting stack trace in a user process (native & .net).
```probefuncmodustack.d ```
```
fpid$target:t_cs_str::entry,
fpid$target:t_cs_str::return,
fpid$target:mscorlib::entry,
fpid$target:mscorlib::return
{
	@[probefunc, probemod, ustack()] = count();
}
```  
``` debug\amd64\bin\dtrace.exe -s probefuncmodustack.d -c debug\amd64\obj\t_cs_str.exe ```
## provider arguments ..
**Note. All the parameters are not used...**
```
typedef struct psinfo {
	pid_t	pr_ppid;	/* process id of parent */
	pid_t	pr_pid;		/* unique process id */
	pid_t	pr_pgid;	/* pid of process group leader */
	pid_t	pr_sid;		/* session id */
	int pr_arch;		/* process architecture */
	uintptr_t pr_addr;	/* address of process */
	string  pr_fname;	/* process name */
	string	pr_psargs;	/* process arguments */
	u_int	pr_arglen;	/* process argument length */
} psinfo_t;
```
```
typedef struct lwpsinfo {
	id_t	pr_lwpid;		/* thread ID. */
	int	pr_flag;			/* thread flags. */
	int	pr_pri;				/* thread priority. */
	char	pr_state;		/* numeric lwp state */
	char	pr_sname;		/* printable character for pr_state */
	short	pr_syscall;		/* system call number (if in syscall) */
	uintptr_t	pr_addr;	/* internal address of lwp */
	uintptr_t pr_wchan;		/* sleep address */
	char pr_waitr; 			/* thread wait reason */
	char pr_waitm;			/* wait mode */
	char pr_wipr; 			/* wait ideal processor */
	uint32_t pr_waittm; 	/* wait time */
	char pr_cpu; 			/* current cpu */
	uint32_t pr_affinity;	/* The set of processors on which the thread is allowed to run */ 
	char pr_iopri;			/* io priority */
	char pr_pagepri;		/* page priority */
} lwpsinfo_t;
```

```
typedef struct fileinfo {
	string fi_name;			/* name (basename of fi_pathname) */
	string fi_dirname;		/* directory (dirname of fi_pathname) */
	string fi_pathname;		/* full pathname */
	uint64_t fi_offset;		/* offset within file */
	string fi_fs;			/* filesystem */
	string fi_mount;		/* mount point of file system */
	int fi_oflags;			/* open(2) flags for file descriptor */
	int fi_cflags;			/* create options */
	int fi_aflags;			/* File attributes */
	int fi_sflags;			/* File share access flags */
	int fi_bcount;			/* number of bytes requested*/ 
	int fi_extinfo;			/* extra info */
	int fi_rstatus;			/* return (NTSTATUS) status */
	int fi_dbuflen;			/* directory enum buffer size */
	caddr_t fi_irp;         /* unique irp address */
	string fi_dpattern;		/* directory search pattern */
} fileinfo_t;
```

```
typedef struct bufinfo {
	int b_flags;			/* buffer status */
	int b_irpflags;			/* I/O request packet flags */
	size_t b_bcount;		/* number of bytes */
	caddr_t b_addr;			/* buffer address */
	uint64_t b_lblkno;		/* block # on device */
	uint64_t b_blkno;		/* expanded block # on device */
	size_t b_resid;			/* # of bytes not transferred */
	size_t b_bufsize;		/* size of allocated buffer */
	caddr_t b_iodone;		/* I/O completion routine */
	int b_error;			/* expanded error field */
	int b_edev;				/* extended device */
	uint64_t resp;			/* The time between I/O initiation and completion */
} bufinfo_t;
```

```
typedef struct ipinfo {
	uint8_t  ip_ver;		/* IP version (4, 6) */
	uint16_t ip_plength;		/* payload length */
	string   ip_saddr;		/* source address */
	string   ip_daddr;		/* destination address */
	uint32_t ip_connid;		/* A unique connection identifier to correlate events belonging to the same connection.*/
	uint64_t ip_stime;		/* Start send request time. */
	uint32_t ip_etime;		/* End send request time. */
} ipinfo_t;
```

```
typedef struct tcpinfo {
	uint16_t tcp_sport;	/* source port */
	uint16_t tcp_dport;	/* destination port */
	uint32_t tcp_seq;	/* sequence number */
	uint32_t tcp_ack;	/* acknowledgement number */
	uint8_t tcp_offset;	/* data offset, in bytes */
	uint8_t tcp_flags;	/* flags */
	uint16_t tcp_window;	/* window size */
	uint16_t tcp_checksum;	/* checksum */
	uint16_t tcp_urgent;	/* urgent data pointer */
	struct tcphdr *tcp_hdr;	/* raw TCP header */
	uint16_t tcp_mss;			/* Maximum segment size. */
	uint16_t tcp_sackopt;		/* Selective Acknowledgment (SACK) option in TCP header. */
	uint16_t tcp_tsopt;			/* Time Stamp option in TCP header. */
	uint16_t tcp_wsopt;			/* Window Scale option in TCP header. */
	uint16_t tcp_rcvws;			/* TCP Receive Window Scaling factor. */
	uint16_t tcp_sndws;			/* TCP Send Window Scaling factor. */
} tcpinfo_t;
```

```
typedef struct registry {
	int r_index;			/* The subkey index for the registry operation (such as EnumerateKey) */
	int r_status;			/* NTSTATUS value of the registry operation. */
	int64_t r_intime;		/* Initial time of the registry operation. */
	string r_rname;			/* Name of the registry key. */
} registry_t;
```
