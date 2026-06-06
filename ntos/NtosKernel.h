
#pragma once
#include <xtl.h>

// Additional includes:
#include "NtStatus.h"
#include "Ob.h"
#include "Io.h"


#ifdef __cplusplus
extern "C"
{
#endif

	// Hidden ppc intrinsics:
	unsigned int __getr13();

#ifdef __cplusplus
};
#endif


typedef enum _XBOX_HARDWARE_FLAGS {
    HW_FLAG_HDD                         = 0x20,
    HW_FLAG_KD_ENABLED                  = 0x80,
    HW_FLAG_KD_PRESENT                  = 0x100,
    HW_FLAG_CONSOLE_TYPE_SHIFT          = 28,
    HW_FLAG_CONSOLE_TYPE_MASK           = 0xF,
} XBOX_HARDWARE_FLAGS;

typedef enum _XBOX_CONSOLE_TYPE {
    HW_FLAG_CONSOLE_TYPE_XENON          = 0,
    HW_FLAG_CONSOLE_TYPE_ZEPHYR         = 1,
    HW_FLAG_CONSOLE_TYPE_FALCON         = 2,
    HW_FLAG_CONSOLE_TYPE_JASPER         = 3,
    HW_FLAG_CONSOLE_TYPE_TRINITY        = 4,
    HW_FLAG_CONSOLE_TYPE_CORONA         = 5,
    HW_FLAG_CONSOLE_TYPE_WINCHESTER     = 6,
} XBOX_CONSOLE_TYPE;

// sizeof = 0x10
typedef struct _XBOX_HARDWARE_INFO
{
	/* 0x00 */ XBOX_HARDWARE_FLAGS Flags;
	/* 0x04 */ BYTE NumberOfProcessors;
	/* 0x05 */ BYTE pad[7];
	/* 0x0C */ USHORT BldrMagic;
	/* 0x0E */ USHORT BldrFlags;
} XBOX_HARDWARE_INFO;

//#define BLDR_FLAG_KD_LITE_ONLY			0x100	// Used to determine if only kdlite is allowed (test kit flag?)

typedef struct _XBOX_KRNL_VERSION
{
	/* 0x00 */ USHORT Major;
	/* 0x02 */ USHORT Minor;
	/* 0x04 */ USHORT Build;
	/* 0x06 */ USHORT Qfe;
} XBOX_KRNL_VERSION;


typedef enum _PROCESS_TYPE {
    PROCESS_TYPE_TITLE          = 1,
    PROCESS_TYPE_SYSTEM         = 2,
} PROCESS_TYPE;

typedef enum _XBOX_PAGE_SIZE {
    PAGE_SIZE_4K                = 0x4000,
    PAGE_SIZE_64K               = 0x10000,
} XBOX_PAGE_SIZE;

// Memory region selectors. MEM_REGION_DETECT picks based on
// KeGetCurrentProcessType return value; the other two pin to a region.
typedef enum _MEM_REGION {
    MEM_REGION_DETECT           = 0,
    MEM_REGION_TITLE            = 1,
    MEM_REGION_SYSTEM           = 2,
} MEM_REGION;

typedef enum _POOL_TYPE
{
	PoolTypeThread = 0,
	PoolTypeTitle = 1,
	PoolTypeSystem = 2
} POOL_TYPE;


typedef enum _D3DFILTER_TYPE
{
	D3DFILTER_DEFAULT = 0x0,
	D3DFILTER_CATMULL = 0x1,
	D3DFILTER_KAISER = 0x2,
	D3DFILTER_GAUSSIAN = 0x3,
	D3DFILTER_MITCHELL = 0x4,
	D3DFILTER_LANCZOS = 0x5,
	D3DFILTER_BILINEAR = 0x6,
	D3DFILTER_POINT = 0x7,
	D3DFILTER_FORCE_DWORD = 0x7FFFFFF
} D3DFILTER_TYPE;

// sizeof = 0x0C
typedef struct _D3DFILTER_PARAMETERS
{
	/* 0x00 */ float Nyquist;
	/* 0x04 */ float FlickerFilter;
	union
	{
		/* 0x08 */ float Beta;
		/* 0x08 */ float Sigma;
		/* 0x08 */ float Lobe;
	};
} D3DFILTER_PARAMETERS, *PD3DFILTER_PARAMETERS;


// sizeof = 0x64
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY  InLoadOrderLinks; // Offset = this + 0x0 Length = 0x8
	LIST_ENTRY  InClosureOrderLinks; // Offset = this + 0x8 Length = 0x8
	LIST_ENTRY  InInitializationOrderLinks; // Offset = this + 0x10 Length = 0x8
	void* NtHeadersBase; // Offset = this + 0x18 Length = 0x4
	void* ImageBase; // Offset = this + 0x1C Length = 0x4
	unsigned long SizeOfNtImage; // Offset = this + 0x20 Length = 0x4
	UNICODE_STRING  FullDllName; // Offset = this + 0x24 Length = 0x8
	UNICODE_STRING  BaseDllName; // Offset = this + 0x2C Length = 0x8
	unsigned long Flags; // Offset = this + 0x34 Length = 0x4
	unsigned long SizeOfFullImage; // Offset = this + 0x38 Length = 0x4
	void* EntryPoint; // Offset = this + 0x3C Length = 0x4
	unsigned short LoadCount; // Offset = this + 0x40 Length = 0x2
	unsigned short ModuleIndex; // Offset = this + 0x42 Length = 0x2
	void* DllBaseOriginal; // Offset = this + 0x44 Length = 0x4
	unsigned long CheckSum; // Offset = this + 0x48 Length = 0x4
	unsigned long ModuleLoadFlags; // Offset = this + 0x4C Length = 0x4
	unsigned long TimeDateStamp; // Offset = this + 0x50 Length = 0x4
	void* LoadedImports; // Offset = this + 0x54 Length = 0x4
	void* XexHeaderBase; // Offset = this + 0x58 Length = 0x4
	ANSI_STRING  LoadFileName; // Offset = this + 0x5C Length = 0x8
	struct _LDR_DATA_TABLE_ENTRY* ClosureRoot; // Offset = this + 0x5C Length = 0x4
	struct _LDR_DATA_TABLE_ENTRY* TraversalParent; // Offset = this + 0x60 Length = 0x4
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


__forceinline struct _KPRCB* KeGetCurrentPrcb()
{
	return (KPRCB*)(__getr13() + 0x100);
}


typedef void (*EXECUTABLE_START_PROC)(void* pArg);


typedef struct _TIME_FIELDS
{
	WORD Year;
	WORD Month;
	WORD Day;
	WORD Hour;
	WORD Minute;
	WORD Second;
	WORD Milliseconds;
	WORD Weekday;
} TIME_FIELDS, *PTIME_FIELDS;


struct _HAL_POWER_DOWN_REGISTRATION;

typedef void (*HAL_POWER_DOWN_NOTIFICATION)(struct _HAL_POWER_DOWN_REGISTRATION* Registration);

typedef struct _HAL_POWER_DOWN_REGISTRATION
{
	/* 0x00 */ HAL_POWER_DOWN_NOTIFICATION NotificationRoutine;
	/* 0x04 */ LONG Priority;
	/* 0x08 */ LIST_ENTRY ListEntry;
} HAL_POWER_DOWN_REGISTRATION, *PHAL_POWER_DOWN_REGISTRATION;


struct _KDRIVER_NOTIFICATION_REGISTRATION;

typedef void (*KDRIVER_NOTIFICATION)(struct _KDRIVER_NOTIFICATION_REGISTRATION* Registration);

typedef struct _KDRIVER_NOTIFICATION_REGISTRATION
{
	/* 0x00 */ KDRIVER_NOTIFICATION NotificationRoutine;
	/* 0x04 */ LONG Priority;
	/* 0x08 */ LIST_ENTRY ListEntry;
} KDRIVER_NOTIFICATION_REGISTRATION, *PKDRIVER_NOTIFICATION_REGISTRATION;

enum KDRIVER_NOTIFICATION_TYPE
{
	DriverQuiesceRundown = 0x0,
	DriverQuiesceStartup = 0x1,
	DriverShutdown = 0x2
};


typedef UCHAR KIRQL;


// Kernel function imports:
#ifdef __cplusplus
extern "C"
{
#endif

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Dbg) Debug APIs
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void DbgBreakPoint();
	void DbgBreakPointWithStatus(ULONG Status);
	void DbgLoadImageSymbols(ANSI_STRING* ImageName, ULONG BaseAddress, ULONG ProcessId);
	ULONG DbgPrint(const char* format, ...);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Ex) Executive APIs
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void* ExAllocatePool(ULONG Size);
	void* ExAllocatePoolWithTag(ULONG Size, ULONG Tag);
	void* ExAllocatePoolTypeWithTag(ULONG Size, ULONG Tag, POOL_TYPE Type);
	void ExFreePool(void* Buffer);

	void ExInitializeReadWriteLock(PERWLOCK Lock);
	void ExAcquireReadWriteLockExclusive(PERWLOCK Lock);
	void ExAcquireReadWriteLockShared(PERWLOCK Lock);
	void ExReleaseReadWriteLock(PERWLOCK Lock);

	DWORD ExCreateThread(HANDLE* phHandle, DWORD StackSize, DWORD* pThreadId, void* pThreadStartup, LPTHREAD_START_ROUTINE lpStartAddress, void* lpParameter, DWORD Flags);
	void ExTerminateThread(DWORD ExitCode);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Hal) Hardware Access Layer
	////////////////////////////////////////////////////////////////////////////////////////////////////

	BOOL HalIsExecutingPowerDownDpc();

	void HalRegisterPowerDownNotification(HAL_POWER_DOWN_REGISTRATION* PowerDownRegistrationData, BOOL Unk);

	void HalSendSMCMessage(BYTE* pMessage, BYTE* pResponse);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Hvx) Hypervisor APIs
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void HvxFlushDCacheRange(ULONG PhysicalAddr, DWORD Size);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Ke)
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void KeAcquireSpinLockAtRaisedIrql(KSPIN_LOCK* SpinLock);
	void KeReleaseSpinLockFromRaisedIrql(KSPIN_LOCK* SpinLock);

	ULONG KfAcquireSpinLock(KSPIN_LOCK* pLock);
	void KfReleaseSpinLock(KSPIN_LOCK* pLock, ULONG OldIrql);

	void KeEnterCriticalRegion();
	void KeLeaveCriticalRegion();

	KIRQL KeRaiseIrqlToDpcLevel();
	KIRQL KfRaiseIrql(KIRQL NewIrql);
	void KfLowerIrql(KIRQL NewIrql);

	void KeFlushCacheRange(void *pAddress, DWORD Size);

	DWORD KeGetCurrentProcessType();

	void KeSetCurrentStackPointers(ULONG NewStackPointer, void* pOldThreadData, ULONG Unk, ULONG StackRegionBase, ULONG StackRegionEnd);

	void KeStallExecutionProcessor(ULONG Counter);

	ULONGLONG KeQueryPerformanceFrequency();

	extern KPROCESS KeTitleProcess;

	extern void* KeDebugMonitorData;

	extern ULONG KiBugCheckData[];

	ULONGLONG KiDisableInterrupts();
	void KiRestoreInterrupts(ULONGLONG OldMsr);

	DWORD KeSetBasePriorityThread(void* pThreadObj, DWORD Priority);
	DWORD KeSetAffinityThread(void* pThreadObj, DWORD NewAffinity, DWORD* pOldAffinity);

	LONG KeSetEvent(KEVENT* Event, ULONG Increment, BOOLEAN Wait);
	NTSTATUS KeWaitForSingleObject(void* Object, ULONG WaitReason, ULONG WaitMode, BOOL Alertable, LARGE_INTEGER* Timeout);

	void KeQuerySystemTime(LARGE_INTEGER* Time);

	ULONG KeLockL2(int index, void* address, ULONG size, ULONG mask1, ULONG mask2);
	void KeUnlockL2(int index);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Mm) Memory Manager APIs
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void* MmAllocatePhysicalMemoryEx(DWORD Region, DWORD AllocationSize, DWORD Flags, ULONG_PTR AddressLow, ULONG_PTR AddressHigh, DWORD Alignment);
	void MmFreePhysicalMemory(DWORD Region, void* pAlloc);

	ULONG MmGetPhysicalAddress(void* pAddress);

	ULONG MiFreeMappedMemory(void* PfnRegion, void* AllocAddress, ULONG AllocationSize, ULONG Unk);

	extern void* MmSystemPfnRegion;
	extern void* MmPfnDatabase;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Nt) NT APIs
	////////////////////////////////////////////////////////////////////////////////////////////////////

	NTSTATUS NtAllocateVirtualMemory(void** ppAllocAddress, DWORD* AllocSize, DWORD Flags, DWORD Protection, DWORD Region);
	NTSTATUS NtFreeVirtualMemory(void** ppAllocationAddress, DWORD* AllocSize, DWORD Flags, DWORD Region);

	NTSTATUS NtClose(HANDLE hHandle);
	NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions);
	NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, void* Buffer, ULONG Length, PLARGE_INTEGER ByteOffset);
	NTSTATUS NtWriteFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, void* Buffer, ULONG Length, PLARGE_INTEGER ByteOffset);
	NTSTATUS NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, void* FileInformation, ULONG Length, ULONG FileInformationClass);
	NTSTATUS NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, void* FileInformation, ULONG Length, ULONG FileInformationClass);
	NTSTATUS NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, void* InputBuffer, ULONG InputBufferLength, void* OutputBuffer, ULONG OutputBufferLength);

	NTSTATUS NtCreateDirectoryObject(HANDLE* pHandle, OBJECT_ATTRIBUTES* Attributes);

	DWORD NtCreateEvent(HANDLE* phHandle, void* pObjectAttr, DWORD EventType, BOOL bInitialState);
	DWORD NtSetEvent(HANDLE hEvent, DWORD* pOldStatus);

	NTSTATUS NtWaitForSingleObjectEx(HANDLE hObject, DWORD unk, BOOL bAlertable, ULONGLONG* pTimeout);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Rtl) Runtime Library APIs
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void RtlCopyString(ANSI_STRING* Destination, ANSI_STRING* Source);
	LONG RtlCompareString(const ANSI_STRING* String1, const ANSI_STRING* String2, BOOLEAN CaseInSensitive);
	LONG RtlCompareStringN(const CHAR* String1, LONG Length1, const char* String2, LONG Length2, BOOLEAN CaseInSensitive);
	LONG RtlCompareUnicodeStringN(const WCHAR* pString1, LONG String1Length, const WCHAR* pString2, LONG String2Length, BOOL bCaseInsensitiveCompare);

	CHAR RtlUpperChar(CHAR Character);

	void* RtlImageNtHeader(void* pAddress);

	void RtlInitAnsiString(ANSI_STRING* pAnsiStr, const char *String);
	void RtlInitUnicodeString(UNICODE_STRING* pUnicodeString, const WCHAR* String);

#ifdef _OBJLINK
	int _snprintf(char* Buffer, int Size, const char* Format, ...);
#endif

	//int RtlSnprintf(char* Buffer, int Size, const char* Format, ...);

	NTSTATUS RtlMultiByteToUnicodeN(WCHAR* UnicodeString, ULONG MaxBytesInUnicodeString, ULONG* BytesInUnicodeString, const CHAR* MultiByteString, ULONG BytesInMultiByteString);

	ULONG RtlUnicodeToUtf8Size(void* StringBuffer, ULONG MaxBytesInString, BOOL StringIsUnicode);
	ULONG RtlUnicodeToUtf8(void* StringBuffer, ULONG MaxBytesInUnicodeString, BOOL StringIsUnicode, CHAR* Ut8StringBuffer, ULONG BytesToCopy);

	BOOLEAN RtlTimeFieldsToTime(TIME_FIELDS* TimeFields, LARGE_INTEGER* Time);
	void RtlTimeToTimeFields(LARGE_INTEGER* Time, TIME_FIELDS* TimeFields);

	void RtlGetStackLimits(ULONG* Lowlimit, ULONG* HighLimit);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Vd)
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void VdDisplayFatalError(ULONG code);

	BOOL VdInitializeScaler(ULONG Unk1, ULONG Size1, ULONG Unk2, ULONG Size2, ULONG Size3, D3DFILTER_TYPE FilterType1, const D3DFILTER_PARAMETERS* pFilterParameters1, D3DFILTER_TYPE FilterType2, const D3DFILTER_PARAMETERS* pFilterParameters2);

	void VdSetDisplayMode(ULONG Flags);

	BOOL VdSetDisplayModeOverride(ULONG Width, ULONG Height, float RefreshRate, ULONG Flags, void* pExtraInfo);

	void VdSetWSSOption(ULONG Flags);

	void VdTurnDisplayOn();

	void VdpGetCurrentAVInformation(ULONG* pdwAVPack, ULONG* pdwRegion, ULONG* pdwFlags);

	extern LONG VdpCurrentVideoModeIndex;
	extern ULONG VdpVideoPortType;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Xex)
	////////////////////////////////////////////////////////////////////////////////////////////////////

	NTSTATUS XexGetModuleHandle(LPCSTR ModuleName, HANDLE* pHandle);

	NTSTATUS XexLoadExecutable(const char* psImagePath, const char* psCommandLine, DWORD Flags, DWORD VersionReq);
	NTSTATUS XexLoadImage(const char* psImagePath, DWORD Flags, DWORD VersionReq, HANDLE* hModule);

	NTSTATUS XexStartExecutable(EXECUTABLE_START_PROC lpStartAddress);

	void XexUnloadImage(HANDLE ModuleHandle);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Xe) Xenon Crypto/Security APIs
	////////////////////////////////////////////////////////////////////////////////////////////////////

	ULONG XeKeysGetKeyProperties(ULONG KeyId);
	NTSTATUS XeKeysGetKey(ULONG KeyId, void* pKeyBuffer, ULONG* pKeySize);

	void XeCryptRandom(BYTE *pBuffer, DWORD BufferLength);
	void XeCryptRc4(BYTE* pKey, DWORD KeyLength, BYTE* pInput, DWORD InputLength);
	void XeCryptSha(BYTE* pInput1, DWORD InputLength1, BYTE* pInput2, DWORD InputLength2, BYTE* pInput3, DWORD InputLength3, BYTE* pHash, DWORD HashLength);
	void XeCryptHmacSha(BYTE* pKey, DWORD KeyLength, BYTE* pInput1, DWORD InputLength1, BYTE* pInput2, DWORD InputLength2, BYTE* pInput3, DWORD InputLength3, BYTE* pHash, DWORD HashLength);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// XInput
	////////////////////////////////////////////////////////////////////////////////////////////////////

	HRESULT XInputdReadState(ULONG ulDeviceContext, DWORD* pdwPacketNumber, XINPUT_GAMEPAD* pGamepad, ULONG* pUnk);



	extern XBOX_HARDWARE_INFO SPECIAL_LINKAGE XboxHardwareInfo;
	extern XBOX_KRNL_VERSION SPECIAL_LINKAGE XboxKrnlVersion;
	extern XBOX_KRNL_VERSION SPECIAL_LINKAGE XboxKrnlBaseVersion;

	extern LIST_ENTRY PsLoadedModuleList;

#ifdef __cplusplus
};
#endif