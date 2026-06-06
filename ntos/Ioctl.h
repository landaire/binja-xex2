
#pragma once

// Method codes for how buffers are passed for I/O and FS controls.
typedef enum _IOCTL_METHOD {
    METHOD_BUFFERED             = 0,
    METHOD_IN_DIRECT            = 1,
    METHOD_OUT_DIRECT           = 2,
    METHOD_NEITHER              = 3,
} IOCTL_METHOD;

// IOCTL access check values. FILE_READ_ACCESS / FILE_WRITE_ACCESS are also
// defined in ntioapi.h as FILE_READ_DATA / FILE_WRITE_DATA — values must
// stay in sync.
typedef enum _IOCTL_ACCESS {
    FILE_ANY_ACCESS             = 0,
    FILE_READ_ACCESS            = 0x0001,
    FILE_WRITE_ACCESS           = 0x0002,
} IOCTL_ACCESS;


typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 0x1,
	FileFullDirectoryInformation = 0x2,
	FileBothDirectoryInformation = 0x3,
	FileBasicInformation = 0x4,
	FileStandardInformation = 0x5,
	FileInternalInformation = 0x6,
	FileEaInformation = 0x7,
	FileAccessInformation = 0x8,
	FileNameInformation = 0x9,
	FileRenameInformation = 0xA,
	FileLinkInformation = 0xB,
	FileNamesInformation = 0xC,
	FileDispositionInformation = 0xD,
	FilePositionInformation = 0xE,
	FileFullEaInformation = 0xF,
	FileModeInformation = 0x10,
	FileAlignmentInformation = 0x11,
	FileAllInformation = 0x12,
	FileAllocationInformation = 0x13,
	FileEndOfFileInformation = 0x14,
	FileAlternateNameInformation = 0x15,
	FileStreamInformation = 0x16,

	// Values from here on are custom defined on Xbox 360:
	FileMountPartitionsInformation = 0x18,			// Not sure what this is, maybe for mounting GoD packages?

	FileNetworkOpenInformation = 0x22,

	/*FilePipeInformation = 0x17,
	FilePipeLocalInformation = 0x18,
	FilePipeRemoteInformation = 0x19,
	FileMailslotQueryInformation = 0x1A,
	FileMailslotSetInformation = 0x1B,
	FileCompressionInformation = 0x1C,
	FileObjectIdInformation = 0x1D,
	FileCompletionInformation = 0x1E,
	FileMoveClusterInformation = 0x1F,
	FileQuotaInformation = 0x20,
	FileReparsePointInformation = 0x21,
	FileNetworkOpenInformation = 0x22,
	FileAttributeTagInformation = 0x23,
	FileTrackingInformation = 0x24,
	FileMaximumInformation = 0x25*/
} FILE_INFORMATION_CLASS;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 0x1,
	FileFsLabelInformation = 0x2,
	FileFsSizeInformation = 0x3,
	FileFsDeviceInformation = 0x4,
	FileFsAttributeInformation = 0x5,
	FileFsControlInformation = 0x6,
	FileFsFullSizeInformation = 0x7,
	FileFsObjectIdInformation = 0x8,
	FileFsMaximumInformation = 0x9
} FS_INFORMATION_CLASS;

typedef struct _FILE_INTERNAL_INFORMATION
{
	LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION
{
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_ALLOCATION_INFORMATION
{
	LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	CHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FS_VOLUME_INFORMATION
{
	LARGE_INTEGER VolumeCreationTime;
	ULONG VolumeSerialNumber;
	ULONG VolumeLabelLength;
	ULONG SupportsObjects;
	CHAR VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

typedef struct _FILE_FS_SIZE_INFORMATION
{
	LARGE_INTEGER TotalAllocationUnits;
	LARGE_INTEGER AvailableAllocationUnits;
	ULONG SectorsPerAllocationUnit;
	ULONG BytesPerSector;
} FILE_FS_SIZE_INFORMATION, *PFILE_FS_SIZE_INFORMATION;

typedef struct _FILE_FS_DEVICE_INFORMATION
{
	ULONG DeviceType;
	ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

typedef struct _FILE_FS_ATTRIBUTE_INFORMATION
{
	ULONG FileSystemAttributes;
	LONG MaximumComponentNameLength;
	ULONG FileSystemNameLength;
	CHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;


typedef struct _DIRECTORY_ENUM_CONTEXT
{
	ULONG QueryOffset;
	UNICODE_STRING TemplateFileName;
} DIRECTORY_ENUM_CONTEXT, *PDIRECTORY_ENUM_CONTEXT;