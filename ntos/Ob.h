
#pragma once

// Forward declarations:
struct _FILE_OBJECT;

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	WCHAR* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef enum _OBJECT_ATTRIBUTE_FLAGS {
    OBJ_PERMANENT               = 0x00000010,
    OBJ_CASE_INSENSITIVE        = 0x00000040,
} OBJECT_ATTRIBUTE_FLAGS;

typedef struct _OBJECT_ATTRIBUTES
{
	HANDLE                  RootDirectory;
	PANSI_STRING            ObjectName;
	OBJECT_ATTRIBUTE_FLAGS  Attributes;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


// sizeof = 0x10
typedef struct _DISPATCHER_HEADER
{
	/* 0x00 */ BYTE Type;
	/* 0x01 */ BYTE Absolute;
	/* 0x02 */ BYTE ProcessType;
	/* 0x03 */ BOOLEAN Inserted;
	/* 0x04 */ LONG SignalState;
	/* 0x08 */ LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

// sizeof = 0x10
typedef struct _KEVENT
{
	/* 0x00 */ DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT;

// sizeof = 0x14
typedef struct _KSEMAPHORE
{
	/* 0x00 */ DISPATCHER_HEADER Header;
	/* 0x10 */ LONG Limit;
} KSEMAPHORE, *PKSEMAPHORE;

// sizeof = 0x10
typedef struct _KDEVICE_QUEUE
{
	/* 0x00 */ SHORT Type;
	/* 0x02 */ BYTE Padding;
	/* 0x03 */ BOOLEAN Busy;
	/* 0x04 */ ULONG Lock;
	/* 0x08 */ LIST_ENTRY DeviceListHead;
} KDEVICE_QUEUE, *PKDEVICE_QUEUE;

// sizeof = 0x10
typedef struct _KDEVICE_QUEUE_ENTRY
{
	/* 0x00 */ LIST_ENTRY DeviceListEntry;
	/* 0x08 */ ULONG SortKey;
	/* 0x0C */ BOOLEAN Inserted;
} KDEVICE_QUEUE_ENTRY, *PKDEVICE_QUEUE_ENTRY;


typedef ULONG_PTR KSPIN_LOCK;
typedef KSPIN_LOCK *PKSPIN_LOCK;

// sizeof = 0x38
typedef struct _ERWLOCK
{
	/* 0x00 */ LONG LockCount;
	/* 0x04 */ ULONG WritersWaitingCount;
	/* 0x08 */ ULONG ReadersWaitingCount;
	/* 0x0C */ ULONG ReadersEntryCount;
	/* 0x10 */ KEVENT WriterEvent;
	/* 0x20 */ KSEMAPHORE ReaderSemaphore;
	/* 0x34 */ KSPIN_LOCK SpinLock;
} ERWLOCK, *PERWLOCK;

#pragma warning(push)
#pragma warning(disable: 4200) // nonstandard extension used : zero-sized array in struct/union

// sizeof = 0x60
typedef struct _KPROCESS
{
	BYTE _[0];
} KPROCESS, *PKPROCESS;

typedef struct _KPRCB
{
	BYTE _[0];
} KPRCB, *PKPRCB;

typedef struct _OBJECT_TYPE
{
	BYTE _[0];
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _OBJECT_DIRECTORY
{
	BYTE _[0];
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

#pragma warning(pop)


#ifdef __cplusplus
extern "C"
{
#endif

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Ob) Object Manager APIs
	////////////////////////////////////////////////////////////////////////////////////////////////////

	// Object types:
	extern OBJECT_TYPE SPECIAL_LINKAGE ExThreadObjectType;
	extern OBJECT_TYPE SPECIAL_LINKAGE IoDeviceObjectType;

	NTSTATUS ObCreateSymbolicLink(ANSI_STRING* SymbolicLinkName, ANSI_STRING* DeviceName);

	void ObDereferenceObject(void* pObject);
	void ObReferenceObject(void* pObject);
	NTSTATUS ObReferenceObjectByHandle(HANDLE hObject, void* pObjectType, void** ppObject);
	NTSTATUS ObReferenceObjectByName(ANSI_STRING* pObjectName, DWORD Attributes, void* pObjectType, DWORD Unk, void** ppObject);

	BOOL ObIsTitleObject(struct _FILE_OBJECT* FileObject);

#ifdef __cplusplus
};
#endif