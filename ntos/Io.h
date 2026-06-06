
#pragma once
#include "Ioctl.h"

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef NTSTATUS (*IO_COMPLETION_ROUTINE)(struct _DEVICE_OBJECT* DeviceObject, struct _IRP* Irp, void* Context);

// sizeof = 0x8
typedef struct _IO_COMPLETION_CONTEXT
{
	/* 0x00 */ void* Port;
	/* 0x04 */ void* Key;
} IO_COMPLETION_CONTEXT, *PIO_COMPLETION_CONTEXT;

// Irp stack location flags. Several of these alias on the same bit because the
// IO_STACK_LOCATION.Flags byte is interpreted per-major-function: SL_RESTART_SCAN
// (QueryDirectory) and SL_USE_FS_CACHE (Read/Write) both reuse 0x01.
typedef enum _IO_STACK_LOCATION_FLAGS {
    SL_PENDING_RETURNED         = 0x01,
    SL_MUST_COMPLETE            = 0x02,
    SL_OPEN_TARGET_DIRECTORY    = 0x04,
    SL_RESTART_SCAN             = 0x01,
    SL_USE_FS_CACHE             = 0x01,
    SL_INVOKE_ON_CANCEL         = 0x20,
    SL_INVOKE_ON_SUCCESS        = 0x40,
    SL_INVOKE_ON_ERROR          = 0x80,
} IO_STACK_LOCATION_FLAGS;

// CreateFile access rights. File / directory / pipe variants share bit values.
typedef enum _FILE_ACCESS_RIGHTS {
    FILE_READ_DATA              = 0x0001,
    FILE_LIST_DIRECTORY         = 0x0001,
    FILE_WRITE_DATA             = 0x0002,
    FILE_ADD_FILE               = 0x0002,
    FILE_APPEND_DATA            = 0x0004,
    FILE_ADD_SUBDIRECTORY       = 0x0004,
    FILE_CREATE_PIPE_INSTANCE   = 0x0004,
    FILE_READ_EA                = 0x0008,
    FILE_WRITE_EA               = 0x0010,
    FILE_EXECUTE                = 0x0020,
    FILE_TRAVERSE               = 0x0020,
    FILE_DELETE_CHILD           = 0x0040,
    FILE_READ_ATTRIBUTES        = 0x0080,
    FILE_WRITE_ATTRIBUTES       = 0x0100,
} FILE_ACCESS_RIGHTS;

typedef enum _FILE_CREATE_DISPOSITION {
    FILE_SUPERSEDE              = 0x00000000,
    FILE_OPEN                   = 0x00000001,
    FILE_CREATE                 = 0x00000002,
    FILE_OPEN_IF                = 0x00000003,
    FILE_OVERWRITE              = 0x00000004,
    FILE_OVERWRITE_IF           = 0x00000005,
    FILE_MAXIMUM_DISPOSITION    = 0x00000005,
} FILE_CREATE_DISPOSITION;

typedef enum _FILE_SHARE_FLAGS {
    FILE_SHARE_READ             = 0x00000001,
    FILE_SHARE_WRITE            = 0x00000002,
    FILE_SHARE_DELETE           = 0x00000004,
    FILE_SHARE_VALID_FLAGS      = 0x00000007,
} FILE_SHARE_FLAGS;

typedef enum _FILE_CREATE_OPTIONS {
    FILE_DIRECTORY_FILE             = 0x00000001,
    FILE_NO_INTERMEDIATE_BUFFERING  = 0x00000008,
    FILE_SYNCHRONOUS_IO_NONALERT    = 0x00000020,
    FILE_NON_DIRECTORY_FILE         = 0x00000040,
    FILE_DELETE_ON_CLOSE            = 0x00001000,
} FILE_CREATE_OPTIONS;

// IO status information return values for CreateFile/OpenFile.
typedef enum _FILE_IO_STATUS_INFORMATION {
    FILE_SUPERSEDED             = 0x00000000,
    FILE_OPENED                 = 0x00000001,
    FILE_CREATED                = 0x00000002,
    FILE_OVERWRITTEN            = 0x00000003,
    FILE_EXISTS                 = 0x00000004,
    FILE_DOES_NOT_EXIST         = 0x00000005,
} FILE_IO_STATUS_INFORMATION;

#pragma pack(push, 1)

// sizeof = 0x24
typedef struct _IO_STACK_LOCATION
{
	/* 0x00 */ BYTE MajorFunction;
	/* 0x01 */ BYTE MinorFunction;
	/* 0x02 */ BYTE Flags;
	/* 0x03 */ BYTE Control;
	/* 0x04 */
	union
	{
		// sizeof = 0x10
		struct
		{
			FILE_ACCESS_RIGHTS DesiredAccess;
			FILE_CREATE_OPTIONS Options;
			USHORT FileAttributes;
			USHORT ShareAccess;
			PANSI_STRING RemainingName;
		} Create;

		// sizeof = 0x10
		struct
		{
			ULONG Length;
			union
			{
				ULONG BufferOffset;
				void* CacheBuffer;
			};
			LARGE_INTEGER ByteOffset;
		} Read;

		// sizeof = 0x10
		struct
		{
			ULONG Length;
			union
			{
				ULONG BufferOffset;
				void* CacheBuffer;
			};
			LARGE_INTEGER ByteOffset;
		} Write;

		// sizeof = 0x8
		struct
		{
			ULONG Length;
			PANSI_STRING FileName;
		} QueryDirectory;

		// sizeof = 0x8
		struct
		{
			ULONG Length;
			FILE_INFORMATION_CLASS FileInformationClass;
		} QueryFile;

		// sizeof = 0xC
		struct
		{
			ULONG Length;
			FILE_INFORMATION_CLASS FileInformationClass;
			struct _FILE_OBJECT* FileObject;
		} SetFile;

		// sizeof = 0x8
		struct
		{
			ULONG Length;
			FS_INFORMATION_CLASS FsInformationClass;
		} QueryVolume;

		// sizeof = 0x8
		struct
		{
			ULONG Length;
			FS_INFORMATION_CLASS FsInformationClass;
		} SetVolume;

		// sizeof = 0x10
		struct
		{
			ULONG OutputBufferLength;
			void* InputBuffer;
			ULONG InputBufferLength;
			ULONG IoControlCode;
		} DeviceIoControl;

		// sizeof = 0x10
		struct
		{
			ULONG Length;
			UCHAR* Buffer;
			ULONG SectorNumber;
			ULONG BufferOffset;
		} SectorIo;

		// sizeof = 0x10
		struct
		{
			void* Argument1;
			void* Argument2;
			void* Argument3;
			void* Argument4;
		} Others;
	} Parameters;
	/* 0x14 */ struct _DEVICE_OBJECT* DeviceObject;
	/* 0x18 */ struct _FILE_OBJECT* FileObject;
	/* 0x1C */ IO_COMPLETION_ROUTINE CompletionRoutine;
	/* 0x20 */ void* Context;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

// sizeof = 0x58
typedef struct _IRP
{
	/* 0x00 */ SHORT Type;
	/* 0x02 */ USHORT Size;
	/* 0x04 */ ULONG Flags;
	/* 0x08 */ LIST_ENTRY ThreadListEntry;
	/* 0x10 */ IO_STATUS_BLOCK IoStatus;
	/* 0x18 */ CHAR StackCount;
	/* 0x19 */ CHAR CurrentLocation;
	/* 0x1A */ BOOLEAN PendingReturned;
	/* 0x1B */ BOOLEAN Cancel;
	/* 0x1C */ void* UserBuffer;
	/* 0x20 */ PIO_STATUS_BLOCK UserIosb;
	/* 0x24 */ PKEVENT UserEvent;
	/* 0x28 */
	union
	{
		struct
		{
			union
			{
				void* UserApcRoutine;
				void* IssuingProcess;
			};
			union
			{
				void* UserApcContext;
				void* IoRing;
			};
		} AsynchronousParameters;
		LARGE_INTEGER AllocationSize;
	} Overlay;

	/* 0x30 */
	union
	{
		struct
		{
			union
			{
				KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
				struct
				{
					void* DriverContext[4];
				};
			};
			ULONG LockedBufferLength;
			void* Thread;
			struct
			{
				LIST_ENTRY ListEntry;
				union
				{
					PIO_STACK_LOCATION CurrentStackLocation;
					ULONG PacketType;
				};
			};
			struct _FILE_OBJECT* OriginalFileObject;
		} Overlay;
		// KAPC Apc;
		void* CompletionKey;
	} Tail;
} IRP, *PIRP;

#pragma pack(pop)


typedef enum _FILE_DEVICE_TYPE {
    FILE_DEVICE_CD_ROM              = 0x00000002,
    FILE_DEVICE_CONTROLLER          = 0x00000004,
    FILE_DEVICE_DISK                = 0x00000007,
    FILE_DEVICE_DISK_FILE_SYSTEM    = 0x00000008,
    FILE_DEVICE_MASS_STORAGE        = 0x0000002D,
    FILE_DEVICE_FLASH               = 0x0000003C,
    FILE_DEVICE_SVOD                = 0x00000040,
    FILE_DEVICE_MMC                 = 0x00000048,
} FILE_DEVICE_TYPE;

typedef enum _DEVICE_OBJECT_FLAGS {
    DO_RAW_MOUNT_ONLY           = 0x00000001,
    DO_DIRECT_IO                = 0x00000004,
    DO_DEVICE_INITIALIZING      = 0x00000010,
} DEVICE_OBJECT_FLAGS;

typedef enum _FILE_ALIGNMENT_REQUIREMENT {
    FILE_BYTE_ALIGNMENT         = 0x00000000,
    FILE_WORD_ALIGNMENT         = 0x00000001,
    FILE_LONG_ALIGNMENT         = 0x00000003,
    FILE_QUAD_ALIGNMENT         = 0x00000007,
    FILE_OCTA_ALIGNMENT         = 0x0000000f,
    FILE_32_BYTE_ALIGNMENT      = 0x0000001f,
    FILE_64_BYTE_ALIGNMENT      = 0x0000003f,
    FILE_128_BYTE_ALIGNMENT     = 0x0000007f,
    FILE_256_BYTE_ALIGNMENT     = 0x000000ff,
    FILE_512_BYTE_ALIGNMENT     = 0x000001ff,
} FILE_ALIGNMENT_REQUIREMENT;

// sizeof = 0x50
typedef struct _DEVICE_OBJECT
{
	/* 0x00 */ SHORT Type;
	/* 0x02 */ USHORT Size;
	/* 0x04 */ LONG ReferenceCount;
	/* 0x08 */ struct _DRIVER_OBJECT* DriverObject;
	/* 0x0C */ struct _DEVICE_OBJECT* MountedOrSelfDevice;
	/* 0x10 */ PIRP CurrentIrp;
	/* 0x14 */ DEVICE_OBJECT_FLAGS Flags;
	/* 0x18 */ void* DeviceExtension;
	/* 0x1C */ BYTE DeviceType;
	/* 0x1D */ BYTE StartIoFlags;
	/* 0x1E */ CHAR StackSize;
	/* 0x1F */ BOOLEAN DeletePending;
	/* 0x20 */ ULONG SectorSize;
	/* 0x24 */ FILE_ALIGNMENT_REQUIREMENT AlignmentRequirement;
	/* 0x28 */ KDEVICE_QUEUE DeviceQueue;
	/* 0x38 */ KEVENT DeviceLock;
	/* 0x48 */ ULONG StartIoCount;
	/* 0x4C */ ULONG StartIoKey;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef void (*DRIVER_STARTIO)(PDEVICE_OBJECT DeviceObject, PIRP Irp);
typedef void (*DRIVER_DELETEDEVICE)(PDEVICE_OBJECT DeviceObject);
typedef NTSTATUS (*DRIVER_DISMOUNTVOLUME)(PDEVICE_OBJECT DeviceObject);
typedef NTSTATUS (*DRIVER_DISPATCH)(PDEVICE_OBJECT DeviceObject, PIRP Irp);

typedef enum _IRP_MAJOR_FUNCTION {
    IRP_MJ_CREATE                       = 0,
    IRP_MJ_CLOSE                        = 1,
    IRP_MJ_READ                         = 2,
    IRP_MJ_WRITE                        = 3,
    IRP_MJ_QUERY_INFORMATION            = 4,
    IRP_MJ_SET_INFORMATION              = 5,
    IRP_MJ_FLUSH_BUFFERS                = 6,
    IRP_MJ_QUERY_VOLUME_INFORMATION     = 7,
    IRP_MJ_FILE_SYSTEM_CONTROL          = 8,
    IRP_MJ_DEVICE_CONTROL               = 9,
    IRP_MJ_CLEANUP                      = 10,
    IRP_MJ_MAXIMUM_FUNCTION             = 10,
} IRP_MAJOR_FUNCTION;


// sizeof = 0x38
typedef struct _DRIVER_OBJECT
{
	/* 0x00 */ DRIVER_STARTIO DriverStartIo;
	/* 0x04 */ DRIVER_DELETEDEVICE DriverDeleteDevice;
	/* 0x08 */ DRIVER_DISMOUNTVOLUME DriverDismountVolume;
	/* 0x0C */ DRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef enum _FILE_OBJECT_FLAGS {
    FO_SYNCHRONOUS_IO               = 0x00000001,
    FO_ALERTABLE_IO                 = 0x00000002,
    FO_NO_INTERMEDIATE_BUFFERING    = 0x00000004,
    FO_SEQUENTIAL_ONLY              = 0x00000008,
    FO_CLEANUP_COMPLETE             = 0x00000010,
    FO_HANDLE_CREATED               = 0x00000020,
    FO_RANDOM_ACCESS                = 0x00000040,
    FO_VOLUME_DISMOUNTED            = 0x00000080,
} FILE_OBJECT_FLAGS;

#pragma pack(push, 1)

// sizeof = 0x58
typedef struct _FILE_OBJECT
{
	/* 0x00 */ SHORT Type;
	/* 0x02 */ BYTE Flags;
	/* 0x03 */ BYTE Flags2;
	/* 0x04 */ PDEVICE_OBJECT DeviceObject;
	/* 0x08 */ void* FsContext;
	/* 0x0C */ void* FsContext2;
	/* 0x10 */ NTSTATUS FinalStatus;
	/* 0x14 */ LARGE_INTEGER CurrentByteOffset;
	/* 0x1C */ struct _FILE_OBJECT* RelatedFileObject;
	/* 0x20 */ PIO_COMPLETION_CONTEXT CompletionContext;
	/* 0x24 */ LONG LockCount;
	/* 0x28 */ KEVENT Lock;
	/* 0x38 */ KEVENT Event;
	/* 0x48 */ LIST_ENTRY ProcessListEntry;
	/* 0x50 */ LIST_ENTRY FileSystemListEntry;
} FILE_OBJECT, *PFILE_OBJECT;

#pragma pack(pop)

// Priority boost values for IoCompleteRequest.
typedef enum _IO_PRIORITY_BOOST {
    IO_NO_INCREMENT             = 0,
    IO_DISK_INCREMENT           = 1,
} IO_PRIORITY_BOOST;

// sizeof = 0x7
typedef struct _SHARE_ACCESS
{
	/* 0x00 */ UCHAR OpenCount;
	/* 0x01 */ UCHAR Readers;
	/* 0x02 */ UCHAR Writers;
	/* 0x03 */ UCHAR Deleters;
	/* 0x04 */ UCHAR SharedRead;
	/* 0x05 */ UCHAR SharedWrite;
	/* 0x06 */ UCHAR SharedDelete;
} SHARE_ACCESS, *PSHARE_ACCESS;


typedef enum _KIRQL {
    PASSIVE_LEVEL               = 0,
    APC_LEVEL                   = 1,
    DISPATCH_LEVEL              = 2,
} KIRQL;


#ifdef __cplusplus
extern "C"
{
#endif

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// (Io) I/O Manager APIs
	////////////////////////////////////////////////////////////////////////////////////////////////////

	PIRP IoAllocateIrp(CHAR StackSize);
	void IoFreeIrp(PIRP Irp);

	NTSTATUS IoDismountVolume(DEVICE_OBJECT* DeviceObject);
	NTSTATUS IoDismountVolumeByName(ANSI_STRING* VolumeName);

	NTSTATUS IoCreateDevice(DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize, ANSI_STRING* DeviceName, ULONG DeviceType, BOOLEAN Exclusive, DEVICE_OBJECT** DeviceObject);
	void IoDeleteDevice(DEVICE_OBJECT* DeviceObject);

	NTSTATUS IoInvalidDeviceRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp);
	void IoCompleteRequest(PIRP Irp, CHAR PriorityBoost);

	NTSTATUS IoCallDriver(DEVICE_OBJECT* DeviceObject, IRP* Irp);
	NTSTATUS IoSynchronousDeviceIoControlRequest(ULONG IoControlCode, DEVICE_OBJECT* DeviceObject, void* InputBuffer, ULONG InputBufferLength, void* OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnedOutputBufferLength);
	NTSTATUS IoSynchronousFsdRequest(ULONG MajorFunction, DEVICE_OBJECT* Device, void* pBuffer, ULONG Length, LARGE_INTEGER* StartingOffset);

	void IoSetShareAccess(ACCESS_MASK DesiredAccess, ULONG DesiredShareAccess, FILE_OBJECT* FileObject, SHARE_ACCESS* ShareAccess);
	void IoRemoveShareAccess(FILE_OBJECT* FileObject, SHARE_ACCESS* ShareAccess);

#ifdef __cplusplus
};
#endif