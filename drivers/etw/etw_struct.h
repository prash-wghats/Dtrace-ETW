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
 */

#ifndef _ETW_STRUCT_H
#define	_ETW_STRUCT_H

typedef struct Etw_ClrRD_Module_154 etw_jit_module_t;
#pragma pack(1)
typedef struct etw_jit_symbol {
	uint64_t MethodID;
	uint64_t ModuleID;
	uint64_t MethodStartAddress;
	uint32_t MethodSize;
	uint32_t MethodToken;
	uint32_t MethodFlags;
	wchar_t MethodFullName[1]; /* classname\0method\0signature\0 */
} etw_jit_symbol_t;
#pragma pack()



#pragma pack(1)

//[EventType{32, 33, 34}, EventTypeName{"RTLostEvent", "RTLostBuffer", "RTLostFile"}]
/*struct RT_LostEvent
{
};
*/
// /struct Etw_ClrRD_Method_144
struct Etw_Clr_Method_143 {
	uint64_t MethodID;
	uint64_t ModuleID;
	uint64_t MethodStartAddress;
	uint32_t MethodSize;
	uint32_t MethodToken;
	uint32_t MethodFlags;
	wchar_t MethodNamespace[1];
	//wchar_t MethodName;
	//wchar_t MethodSignature;
};

// /LoaderKeyword Etw_Clr_Module_152
struct Etw_ClrRD_Module_154 {	//PerfTrackRundownKeyword, LoaderRundownKeyword
	uint64_t ModuleID;
	uint64_t AssemblyID;
	uint32_t ModuleFlags;
	uint32_t Reserved1;
	wchar_t *ModuleILPath;
	wchar_t *ModuleNativePath; //V0

	uint16_t ClrInstanceID;		//V1

	GUID ManagedPdbSignature;
	uint32_t ManagedPdbAge;
	wchar_t *ManagedPdbBuildPath;
	GUID NativePdbSignature;
	uint32_t NativePdbAge;
	wchar_t *NativePdbBuildPath;	//V2
};

struct Etw_ClrRD_Module_152 {	//LoaderRundownKeyword
uint64_t ModuleID;
uint64_t AssemblyID;
uint64_t AppDomainID;
uint32_t ModuleFlags;
uint32_t Reserved1;
wchar_t *ModuleILPath;
wchar_t *ModuleNativePath;	//V0
uint16_t ClrInstanceID;		//V1
};

struct ETWStackWalk {
	uint64_t EventTimeStamp;
	uint32_t StackProcess;
	uint32_t StackThread;
	uetwptr_t Stack1;
	//uetwptr_t Stack192;
};

//PerfInfo
//46
struct SampledProfile {
	uetwptr_t InstructionPointer;
	uint32_t ThreadId;
	uint16_t Count;
};

//73
struct SampledProfileInterval_V3 {
	uint32_t Source;
	uint32_t NewInterval;
	uint32_t OldInterval;
	wchar_t *SourceName;
};

//Process
// [EventType{1, 2, 3, 4, 39}, EventTypeName{"Start", "End", "DCStart", "DCEnd", "Defunct"}]
struct Process_V4_TypeGroup1 {
	uetwptr_t UniqueProcessKey;
	uint32_t ProcessId;
	uint32_t ParentId;
	uint32_t SessionId;
	int32_t ExitStatus;
	uetwptr_t DirectoryTableBase;
	uint32_t Flags;
	uetwptr_t UserSID;
	char * ImageFileName;
	wchar_t * CommandLine;
	wchar_t * PackageFullName;
	wchar_t * ApplicationId;
	//uint64_t ExitTime //Defunct 39
};

struct Process_V3_TypeGroup1 {
	uetwptr_t UniqueProcessKey;
	uint32_t ProcessId;
	uint32_t ParentId;
	uint32_t SessionId;
	int32_t ExitStatus;
	uetwptr_t DirectoryTableBase;
	uetwptr_t UserSID;
	char * ImageFileName;
	wchar_t * CommandLine;
};

struct Process_V2_TypeGroup1 { //: Process_V2
	uetwptr_t UniqueProcessKey;
	uint32_t ProcessId;
	uint32_t ParentId;
	uint32_t SessionId;
	int32_t ExitStatus;
	uetwptr_t UserSID;
	char * ImageFileName;
	wchar_t * CommandLine;
};

struct Process_V1_TypeGroup1 { //: Process_V1
	uint32_t PageDirectoryBase;
	uint32_t ProcessId;
	uint32_t ParentId;
	uint32_t SessionId;
	int32_t ExitStatus;
	uetwptr_t UserSID;
	char * ImageFileName;
};

struct Process_V0_TypeGroup1 { //: Process_V0
	uint32_t ProcessId;
	uint32_t ParentId;
	uetwptr_t UserSID;
	char * ImageFileName;
};

//EventType{32, 33}, EventTypeName{"PerfCtr", PerfCtrRundown"}
struct Process_V2_TypeGroup2 { //: Process_V2
	uint32_t ProcessId;
	uint32_t PageFaultCount;
	uint32_t HandleCount;
	uint32_t Reserved;
	uetwptr_t PeakVirtualSize;
	uetwptr_t PeakWorkingSetSize;
	uetwptr_t PeakPagefileUsage;
	uetwptr_t QuotaPeakPagedPoolUsage;
	uetwptr_t QuotaPeakNonPagedPoolUsage;
	uetwptr_t VirtualSize;
	uetwptr_t WorkingSetSize;
	uetwptr_t PagefileUsage;
	uetwptr_t QuotaPagedPoolUsage;
	uetwptr_t QuotaNonPagedPoolUsage;
	uetwptr_t PrivatePageCount;
};

//Thread
//EventType{1, 2, 3, 4}, EventTypeName{"Start", "End", "DCStart", "DCEnd"}
struct Thread_V3_TypeGroup1 { //: Thread
	uint32_t ProcessId;
	uint32_t TThreadId;
	uetwptr_t StackBase;
	uetwptr_t StackLimit;
	uetwptr_t UserStackBase;
	uetwptr_t UserStackLimit;
	uetwptr_t Affinity;
	uetwptr_t Win32StartAddr;
	uetwptr_t TebBase;
	uint32_t SubProcessTag;
	uint8_t  BasePriority;
	uint8_t  PagePriority;
	uint8_t  IoPriority;
	uint8_t  ThreadFlags;
	wchar_t ThreadName[1];
};

//EventType{72} EventTypeName{"SetName"}
struct Thread_V2_SetName {
	uint32_t ProcessId;
	uint32_t TThreadId;
	wchar_t ThreadName[1];
};

//[EventType{1, 2, 3, 4}, EventTypeName{"Start", "End", "DCStart", "DCEnd"}]
struct Thread_V2_TypeGroup1 { //: Thread_V2
	uint32_t ProcessId;
	uint32_t TThreadId;
	uetwptr_t StackBase;
	uetwptr_t StackLimit;
	uetwptr_t UserStackBase;
	uetwptr_t UserStackLimit;
	uetwptr_t StartAddr;
	uetwptr_t Win32StartAddr;
	uetwptr_t TebBase;
	uint32_t SubProcessTag;
};

//[EventType{1, 3}, EventTypeName{"Start", "DCStart"}]
struct Thread_V1_TypeGroup1 { //: Thread_V1
	uint32_t ProcessId;
	uint32_t TThreadId;
	uint32_t StackBase;
	uint32_t StackLimit;
	uint32_t UserStackBase;
	uint32_t UserStackLimit;
	uint32_t StartAddr;
	uint32_t Win32StartAddr;
	int8_t  WaitMode;
};

struct Thread_V0_TypeGroup1 { //: Thread_V0
	uint32_t TThreadId;
	uint32_t ProcessId;
};

//[EventType{2, 4}, EventTypeName{"End", "DCEnd"}]
struct Thread_V1_TypeGroup2 { //: Thread_V1
	uint32_t ProcessId;
	uint32_t TThreadId;
};

//[EventType{36}, EventTypeName{"CSwitch"}]
struct CSwitch { //: Thread_V2
	uint32_t NewThreadId;
	uint32_t OldThreadId;
	int8_t  NewThreadPriority;
	int8_t  OldThreadPriority;
	uint8_t  PreviousCState;
	int8_t  SpareByte;
	int8_t  OldThreadWaitReason;
	int8_t  OldThreadWaitMode;
	int8_t  OldThreadState;
	int8_t  OldThreadWaitIdealProcessor;
	uint32_t NewThreadWaitTime;
	uint32_t Reserved;
};

//[EventType{50}, EventTypeName{"ReadyThread"}]
struct ReadyThread { //: Thread_V2
	uint32_t TThreadId;
	int8_t  AdjustReason;
	int8_t  AdjustIncrement;
	int8_t  Flags;
	int8_t  Reserved;
};

//[EventType{66, 68, 69}, EventTypeName{"ThreadDPC", "DPC", "TimerDPC"}] PerfInfo
struct DPC {
	uint64_t InitialTime;
	uetwptr_t Routine;
};

//[EventType{67}, EventTypeName{"ISR"}] PerfInfo
struct ISR {
	uint64_t InitialTime;
	uetwptr_t Routine;
	uint8_t  ReturnValue;
	uint8_t  Vector;
	uint16_t Reserved;
};

//[EventType{51}, EventTypeName{"SysClEnter"}]
struct SysCallEnter {
	uetwptr_t SysCallAddress;
};

//[EventType{52}, EventTypeName{"SysClExit"}]
struct  SysCallExit {
	uint32_t SysCallNtStatus;
};

//Image Load
struct Image {
	uetwptr_t ImageBase;
	uetwptr_t ImageSize;
	uint32_t ProcessId;
	uint32_t ImageCheckSum;
	uint32_t TimeDateStamp;
	uint32_t Reserved0;
	uetwptr_t DefaultBase;
	uint32_t Reserved1;
	uint32_t Reserved2;
	uint32_t Reserved3;
	uint32_t Reserved4;
	wchar_t * FileName;
};

struct Image_V1 {
	uetwptr_t ImageBase;
	uetwptr_t ImageSize;
	uint32_t ProcessId;
	wchar_t *FileName;
};

struct Image_V0 {
	uetwptr_t BaseAddress;
	uetwptr_t ModuleSize;
	wchar_t * ImageFileName;
};
// DiskIO
//[EventType{10,11}, EventTypeName{"Read","Write"}]
struct DiskIo_TypeGroup1
{
	uint32_t DiskNumber;
	uint32_t IrpFlags;
	uint32_t TransferSize;
	uint32_t Reserved;
	uint64_t ByteOffset;
	uetwptr_t FileObject;
	uetwptr_t Irp;
	uint64_t HighResResponseTime;
	uint32_t IssuingThreadId;
};

// [EventType{12, 13, 15}, EventTypeName{"ReadInit", "WriteInit", "FlushInit"}]
struct DiskIo_TypeGroup2
{
	uetwptr_t Irp;
	uint32_t IssuingThreadId;
};

// This struct is the event type struct for disk I/O flush events.
struct DiskIo_TypeGroup3
{
	uint32_t DiskNumber;
	uint32_t IrpFlags;
	uint64_t HighResResponseTime; /*The time between I/O initiation and completion as
		measured by the partition manager (in the KeQueryPerformanceCounter tick units).*/
	uetwptr_t Irp;
	uint32_t IssuingThreadId;
};

//FileIO FileIo_Name
//[EventType{0, 32, 35, 36}, EventTypeName{"Name", "FileCreate", "FileDelete", "FileRundown"}]
struct FileIo_Name
{
	uetwptr_t FileObject;
	wchar_t *FileName;
};

//64 "Create"
struct FileIo_Create
{
	uetwptr_t IrpPtr;
	//uint32_t TTID; //version 2
	uetwptr_t FileObject;
	uint32_t TTID; //version 3
	uint32_t CreateOptions;
	uint32_t FileAttributes;
	uint32_t ShareAccess;
	wchar_t *OpenPath;
};

//[EventType{69, 70, 71, 74, 75}, EventTypeName{"SetInfo", "Delete", "Rename", "QueryInfo", "FSControl"}]
struct FileIo_Info
{
	uetwptr_t IrpPtr;
	//uint32_t TTID; Version 2 ???
	uetwptr_t FileObject; // == FileObject between create and close events.
	uetwptr_t FileKey;	// == FileObject property of a FileIo_Name
	uetwptr_t ExtraInfo;
	uint32_t TTID;	//Version 3
	uint32_t InfoClass;
};

//[EventType{76}, EventTypeName{"OperationEnd"}]
struct FileIo_OpEnd
{
	uetwptr_t IrpPtr;
	uetwptr_t ExtraInfo;
	uint32_t NtStatus;
};

//[EventType{65, 66, 73}, EventTypeName{"Cleanup", "Close", "Flush"}]
struct FileIo_SimpleOp
{
	uetwptr_t IrpPtr;
	//uint32_t TTID; Version 2
	uetwptr_t FileObject;
	uetwptr_t FileKey;
	uint32_t TTID; //Version 3
};

//[EventType{67, 68}, EventTypeName{"Read", "Write"}]
struct FileIo_ReadWrite
{
	uint64_t Offset;
	uetwptr_t IrpPtr;
	//uint32_t TTID;	//version 2
	uetwptr_t FileObject;
	uetwptr_t FileKey;
	uint32_t TTID;  //version 3 ??
	uint32_t IoSize;
	uint32_t IoFlags;
};

//[EventType{72, 77}, EventTypeName{"DirEnum", "DirNotify"}]
struct FileIo_DirEnum
{
	uetwptr_t IrpPtr;
	uint32_t TTID;
	uetwptr_t FileObject;
	uetwptr_t FileKey;
	uint32_t Length;
	uetwptr_t InfoClass;
	uint32_t FileIndex;
	wchar_t *PatternSpec;
};

// Network
//[EventType{11, 13, 14, 16, 18}, EventTypeName{"RecvIPV4", "DisconnectIPV4", "RetransmitIPV4", "ReconnectIPV4", "TCPCopyIPV4"}]
struct TcpIp_TypeGroup1
{
	uint32_t PID;
	uint32_t size;
	ipaddr_t daddr;
	ipaddr_t saddr;
	uint16_t dport;
	uint16_t sport;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{12, 15}, EventTypeName{"ConnectIPV4", "AcceptIPV4"}]
struct TcpIp_TypeGroup2
{
	uint32_t PID;
	uint32_t size;
	ipaddr_t daddr;
	ipaddr_t saddr;
	uint16_t dport;
	uint16_t sport;
	uint16_t mss;
	uint16_t sackopt;
	uint16_t tsopt;
	uint16_t wsopt;
	uint32_t rcvwin;
	int16_t rcvwinscale;
	int16_t sndwinscale;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{27, 29, 30, 32, 34}, EventTypeName{"RecvIPV6", "DisconnectIPV6", "RetransmitIPV6", "ReconnectIPV6", "TCPCopyIPV6"}]
struct TcpIp_TypeGroup3
{
	uint32_t PID;
	uint32_t size;
	struct in6_addr daddr;
	struct in6_addr saddr;
	uint16_t dport;
	uint16_t sport;
	uint32_t seqnum;
	uint32_t connid;
};
//[EventType{28, 31}, EventTypeName{"ConnectIPV6", "AcceptIPV6"}]
struct TcpIp_TypeGroup4
{
	uint32_t PID;
	uint32_t size;
	struct in6_addr daddr;
	struct in6_addr saddr;
	uint16_t dport;
	uint16_t sport;
	uint16_t mss;
	uint16_t sackopt;
	uint16_t tsopt;
	uint16_t wsopt;
	uint32_t rcvwin;
	int16_t rcvwinscale;
	int16_t sndwinscale;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{10, 11, 12, 13, 14, 15}, EventTypeName{"Send", "Recv", "Connect", "Disconnect", "Retransmit", "Accept"}]
struct TcpIp_V0_TypeGroup1
{
	ipaddr_t daddr;
	ipaddr_t saddr;
	uint16_t dport;
	uint16_t sport;
	uint32_t size;
	uint32_t PID;
};
//[EventType{10, 11, 12, 13, 14, 15, 16}, EventTypeName{"Send", "Recv", "Connect", "Disconnect", "Retransmit", "Accept", "Reconnect"}]
struct TcpIp_V1_TypeGroup1
{
	uint32_t PID;
	uint32_t size;
	ipaddr_t daddr;
	ipaddr_t saddr;
	uint16_t dport;
	uint16_t sport;
};

//[EventType{17}, EventTypeName{"Fail"}]
struct TcpIp_Fail
{
	uint16_t Proto;
	uint16_t FailureCode;
};

//[EventType{10}, EventTypeName{"SendIPV4"}]
struct TcpIp_SendIPV4
{
	uint32_t PID;
	uint32_t size;
	ipaddr_t daddr;
	ipaddr_t saddr;
	uint16_t dport;
	uint16_t sport;
	uint32_t starttime;
	uint32_t endtime;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{26}, EventTypeName{"SendIPV6"}]
struct TcpIp_SendIPV6
{
	uint32_t PID;
	uint32_t size;
	struct in6_addr daddr;
	struct in6_addr saddr;
	uint16_t dport;
	uint16_t sport;
	uint32_t starttime;
	uint32_t endtime;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{17}, EventTypeName{"Fail"}]
struct UdpIp_Fail
{
	uint16_t Proto;
	uint16_t FailureCode;
};

//[EventType{10, 11}, EventTypeName{"SendIPV4", "RecvIPV4"}]
struct UdpIp_TypeGroup1
{
	uint32_t PID;
	uint32_t size;
	ipaddr_t daddr;
	ipaddr_t saddr;
	uint32_t dport;
	uint32_t sport;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{26, 27}, EventTypeName{"SendIPV6", "RecvIPV6"}]
struct UdpIp_TypeGroup2
{
	uint32_t PID;
	uint32_t size;
	struct in6_addr daddr;
	struct in6_addr saddr;
	uint32_t dport;
	uint32_t sport;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{10, 11}, EventTypeName{"Send", "Recv"}]
struct UdpIp_V0_TypeGroup1
{
	uint32_t context; //pid
	ipaddr_t saddr;
	uint32_t sport;
	uint16_t size;
	ipaddr_t daddr;
	uint32_t dport;
	uint16_t dsize;
};

//[EventType{10, 11}, EventTypeName{"Send", "Recv"}]
struct UdpIp_V1_TypeGroup1
{
	uint32_t PID;
	uint32_t size;
	ipaddr_t daddr;
	ipaddr_t saddr;
	uint32_t dport;
	uint32_t sport;
};


//VM

//version 2
//[EventType{32}, EventTypeName{"HardFault"}]
struct PageFault_HardFault
{
	uint32_t InitialTime;
	uint64_t ReadOffset;
	uetwptr_t VirtualAddress;
	uetwptr_t FileObject;
	uint32_t TThreadId;
	uint32_t ByteCount;
};

//[EventType{105}, EventTypeName{"ImageLoadBacked"}]
struct PageFault_ImageLoadBacked
{
	uetwptr_t FileObject;
	uint32_t DeviceChar;
	uint16_t FileChar;
	uint16_t LoadFlags;
};

//[EventType{10, 11, 12, 13, 14}, EventTypeName{"TransitionFault", "DemandZeroFault", "CopyOnWrite", "GuardPageFault", "HardPageFault"}]
struct PageFault_TransitionFault
{
	uetwptr_t VirtualAddress;
	uetwptr_t ProgramCounter;
};

//[EventType{10, 11, 12, 13, 14, 15}, EventTypeName{"TransitionFault", "DemandZeroFault", "CopyOnWrite", "GuardPageFault", "HardPageFault", "AccessViolation"}]
struct PageFault_TypeGroup1
{
	uetwptr_t VirtualAddress;
	uetwptr_t ProgramCounter;
};

//[EventType{98, 99}, EventTypeName{"VirtualAlloc", "VirtualFree"}]
struct PageFault_VirtualAlloc
{
	uetwptr_t BaseAddress;
	SIZE_T RegionSize;
	uint32_t ProcessId;
	uint32_t Flags;
};

//Registry
//version 2
//[EventType{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}, EventTypeName{"Create", "Open", "Delete", "Query", "SetValue", "DeleteValue", "QueryValue", "EnumerateKey", "EnumerateValueKey", "QueryMultipleValue", "SetInformation", "Flush", "KCBCreate", "KCBDelete", "KCBRundownBegin", "KCBRundownEnd", "Virtualize", "Close"}]
struct Registry_TypeGroup1
{
	int64_t InitialTime;
	uint32_t Status;
	uint32_t Index;
	uetwptr_t KeyHandle;
	wchar_t *KeyName;
};

//version 0
//[EventType{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}, EventTypeName{"Create", "Open", "Delete", "Query", "SetValue", "DeleteValue", "QueryValue", "EnumerateKey", "EnumerateValueKey", "QueryMultipleValue", "SetInformation", "Flush"}]
struct Registry_V0_TypeGroup1
{
	uint32_t Status;
	uetwptr_t KeyHandle;
	int64_t ElapsedTime;
	wchar_t *KeyName;
};

//verion 1
//[EventType{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}, EventTypeName{"Create", "Open", "Delete", "Query", "SetValue", "DeleteValue", "QueryValue", "EnumerateKey", "EnumerateValueKey", "QueryMultipleValue", "SetInformation", "Flush", "RunDown"}]
struct Registry_V1_TypeGroup1
{
	uint32_t Status;
	uetwptr_t KeyHandle;
	int64_t ElapsedTime;
	uint32_t Index;
	wchar_t *KeyName;
};

// xperf image events
//opcode 36
struct DbgID_RSDS {
	uint64_t base;
	int pid;
	GUID sig;
	int age;
	char pdbfilename[1];
};
//opcode 37
struct DbgID_ILRSDS {
	uint64_t base;
	int pid;
	GUID sig;
	int age;
	char pdbfilename[1];
};

//opcode 0 = Image ID ???
struct DbgImageID {
	uint64_t base;
	long size;
	int pid;
	int timedatestamp;
	int BuildTime;
	wchar_t *OrgFileName;
};

/*
//Hardware config
// no need to set
//[Guid("{01853a65-418f-4f36-aefc-dc0f1d2fd235}")]
[EventType(10), EventTypeName("CPU")]
struct HWConfig_CPU
{
  uint32_t MHz;
  uint32_t NumberOfProcessors;
  uint32_t MemSize;
  uint32_t PageSize;
  uint32_t AllocationGranularity;
  string ComputerName;
};
[EventType(12), EventTypeName("LogDisk")]
struct HWConfig_LogDisk
{
  uint32_t DiskNumber;
  uint32_t Pad;
  uint64 StartOffset;
  uint64 PartitionSize;
};
EventType(13), EventTypeName("NIC")]
struct HWConfig_NIC
{
  string NICName;
};
[EventType(11), EventTypeName("PhyDisk")]
struct HWConfig_PhyDisk
{
  uint32_t DiskNumber;
  uint32_t BytesPerSector;
  uint32_t SectorsPerTrack;
  uint32_t TracksPerCylinder;
  uint64 Cylinders;
  uint32_t SCSIPort;
  uint32_t SCSIPath;
  uint32_t SCSITarget;
  uint32_t SCSILun;
  string Manufacturer;
};
//SystemConfig
//version 3
struct SystemConfig_CPU
{
  uint32_t MHz;
  uint32_t NumberOfProcessors;
  uint32_t MemSize;
  uint32_t PageSize;
  uint32_t AllocationGranularity;
  char16 ComputerName[256];
  char16 DomainName[132];
  uint64_t HyperThreadingFlag;
  uint64_t HighestUserAddress;
  uin16_t ProcessorArchitecture;
  uin16_t ProcessorLevel;
  uin16_t ProcessorRevision;
  uint8_t PaeEnabled;
  uint8_t NxEnabled;
  uint32_t MemorySpeed;
};
[EventType(10), EventTypeName("CPU")]
struct SystemConfig_CPU
{
  uint32_t MHz;
  uint32_t NumberOfProcessors;
  uint32_t MemSize;
  uint32_t PageSize;
  uint32_t AllocationGranularity;
  char16 ComputerName[];
  char16 DomainName[];
  uint32_t HyperThreadingFlag;
};
[EventType(10), EventTypeName("CPU")]
struct SystemConfig_V0_CPU
{
  uint32_t MHz;
  uint32_t NumberOfProcessors;
  uint32_t MemSize;
  uint32_t PageSize;
  uint32_t AllocationGranularity;
  char16 ComputerName[];
  char16 DomainName[];
};

[EventType(23), EventTypeName("IDEChannel")]
struct SystemConfig_IDEChannel
{
  uint32_t TargetId;
  uint32_t DeviceType;
  uint32_t DeviceTimingMode;
  uint32_t LocationInformationLen;
  string LocationInformation;
};
[EventType(21), EventTypeName("IRQ")]
struct SystemConfig_IRQ
{
  uint64 IRQAffinity;
  uint32_t IRQNum;
  uint32_t DeviceDescriptionLen;
  string DeviceDescription;
};
[EventType(12), EventTypeName("LogDisk")]
struct SystemConfig_LogDisk
{
  uint64 StartOffset;
  uint64 PartitionSize;
  uint32_t DiskNumber;
  uint32_t Size;
  uint32_t DriveType;
  char16 DriveLetterString[4];
  uint32_t Pad1;
  uint32_t PartitionNumber;
  uint32_t SectorsPerCluster;
  uint32_t BytesPerSector;
  uint32_t Pad2;
  sint64 NumberOfFreeClusters;
  sint64 TotalNumberOfClusters;
  char16 FileSystem;
  uint32_t VolumeExt;
  uint32_t Pad3;
};
[EventType(12), EventTypeName("LogDisk")]
struct SystemConfig_V0_LogDisk
{
  uint64 StartOffset;
  uint64 PartitionSize;
  uint32_t DiskNumber;
  uint32_t Size;
  uint32_t DriveType;
  char16 DriveLetterString[];
  uint32_t Pad;
  uint32_t PartitionNumber;
  uint32_t SectorsPerCluster;
  uint32_t BytesPerSector;
  sint64 NumberOfFreeClusters;
  sint64 TotalNumberOfClusters;
  char16 FileSystem;
  uint32_t VolumeExt;
};

[EventType(17), EventTypeName("Network")]
struct SystemConfig_Network
{
  uint32_t TcbTablePartitions;
  uint32_t MaxHashTableSize;
  uint32_t MaxUserPort;
  uint32_t TcpTimedWaitDelay;
};
[EventType(13), EventTypeName("NIC")]
struct SystemConfig_NIC
{
  uint64 PhysicalAddr;
  uint32_t PhysicalAddrLen;
  uint32_t Ipv4Index;
  uint32_t Ipv6Index;
  string NICDescription;
  string IpAddresses;
  string DnsServerAddresses;
};
[EventType(13), EventTypeName("NIC")]
struct SystemConfig_V0_NIC
{
  char16 NICName[];
  uint32_t Index;
  uint32_t PhysicalAddrLen;
  char16 PhysicalAddr;
  uint32_t Size;
  sint32 IpAddress;
  sint32 SubnetMask;
  sint32 DhcpServer;
  sint32 Gateway;
  sint32 PrimaryWinsServer;
  sint32 SecondaryWinsServer;
  sint32 DnsServer1;
  sint32 DnsServer2;
  sint32 DnsServer3;
  sint32 DnsServer4;
  uint32_t Data;
};

[EventType(11), EventTypeName("PhyDisk")]
struct SystemConfig_PhyDisk
{
  uint32_t DiskNumber;
  uint32_t BytesPerSector;
  uint32_t SectorsPerTrack;
  uint32_t TracksPerCylinder;
  uint64 Cylinders;
  uint32_t SCSIPort;
  uint32_t SCSIPath;
  uint32_t SCSITarget;
  uint32_t SCSILun;
  char16 Manufacturer[256];
  uint32_t PartitionCount;
  uint8  WriteCacheEnabled;
  uint8  Pad;
  char16 BootDriveLetter[3];
  char16 Spare[2];
};
[EventType(11), EventTypeName("PhyDisk")]
struct SystemConfig_V0_PhyDisk
{
  uint32_t  DiskNumber;
  uint32_t  BytesPerSector;
  uint32_t  SectorsPerTrack;
  uint32_t  TracksPerCylinder;
  uint64  Cylinders;
  uint32_t  SCSIPort;
  uint32_t  SCSIPath;
  uint32_t  SCSITarget;
  uint32_t  SCSILun;
  char16  Manufacturer[];
  uint32_t  PartitionCount;
  boolean WriteCacheEnabled;
  char16  BootDriveLetter[];
};

[EventType(22), EventTypeName("PnP")]
struct SystemConfig_PnP
{
  uint32_t IDLength;
  uint32_t DescriptionLength;
  uint32_t FriendlyNameLength;
  string DeviceID;
  string DeviceDescription;
  string FriendlyName;
};
[EventType(16), EventTypeName("Power")]
struct SystemConfig_Power
{
  uint8 s1;
  uint8 s2;
  uint8 s3;
  uint8 s4;
  uint8 s5;
  uint8 Pad1;
  uint8 Pad2;
  uint8 Pad3;
};
[EventType(16), EventTypeName("Power")]
struct SystemConfig_V0_Power
{
  boolean s1;
  boolean s2;
  boolean s3;
  boolean s4;
  boolean s5;
  uint8   Pad1;
  uint8   Pad2;
  uint8   Pad3;
};

[EventType(15), EventTypeName("Services")]
struct SystemConfig_Services
{
  uint32_t ProcessId;
  uint32_t ServiceState;
  uint32_t SubProcessTag;
  string ServiceName[];
  string DisplayName[];
  string ProcessName[];
};
[EventType(15), EventTypeName("Services")]
struct SystemConfig_V0_Services
{
  char16 ServiceName[];
  char16 DisplayName[];
  char16 ProcessName[];
  uint32_t ProcessId;
};

[EventType(14), EventTypeName("Video")]
struct SystemConfig_Video
{
  uint32_t MemorySize;
  uint32_t XResolution;
  uint32_t YResolution;
  uint32_t BitsPerPixel;
  uint32_t VRefresh;
  char16 ChipType[256];
  char16 DACType[256];
  char16 AdapterString[256];
  char16 BiosString[256];
  char16 DeviceId[256];
  uint32_t StateFlags;
};
[EventType(14), EventTypeName("Video")]
struct SystemConfig_V0_Video
{
  uint32_t MemorySize;
  uint32_t XResolution;
  uint32_t YResolution;
  uint32_t BitsPerPixel;
  uint32_t VRefresh;
  char16 ChipType[];
  char16 DACType[];
  char16 AdapterString[];
  char16 BiosString[];
  char16 DeviceId[];
  uint32_t StateFlags;
};

//version 2
struct SystemConfig_Processors {
	ProcessorIndex;
	FeatureSet;
	ProcessorSpeed;
	ProcessorName[64];
	VendorIdentifier[16];
	ProcessorIdentifier[128];
}
*/

#pragma pack()

#endif