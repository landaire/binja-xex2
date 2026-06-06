// Xbox 360 base type definitions for Binary Ninja (replaces Xbox SDK xtl.h)
#pragma once

typedef uint8_t BYTE;
typedef uint8_t UCHAR;
typedef uint8_t BOOLEAN;
typedef int8_t CHAR;

typedef uint16_t WORD;
typedef uint16_t USHORT;
typedef uint16_t WCHAR;
typedef int16_t SHORT;

typedef uint32_t DWORD;
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef int32_t BOOL;
typedef int32_t HRESULT;

typedef uint32_t ULONG_PTR;
typedef int32_t LONG_PTR;
typedef uint32_t SIZE_T;
typedef uint32_t ACCESS_MASK;

typedef int64_t LARGE_INTEGER;
typedef uint64_t ULARGE_INTEGER;
typedef int64_t LONGLONG;
typedef uint64_t ULONGLONG;

typedef void* PVOID;
typedef void* HANDLE;
typedef HANDLE* PHANDLE;
typedef char* PCHAR;
typedef char* LPSTR;
typedef const char* LPCSTR;
typedef WCHAR* PWCHAR;
typedef UCHAR* PUCHAR;
typedef USHORT* PUSHORT;
typedef ULONG* PULONG;
typedef LARGE_INTEGER* PLARGE_INTEGER;

struct LIST_ENTRY {
    struct LIST_ENTRY* Flink;
    struct LIST_ENTRY* Blink;
};
typedef struct LIST_ENTRY* PLIST_ENTRY;

struct XINPUT_GAMEPAD {
    uint16_t wButtons;
    uint8_t bLeftTrigger;
    uint8_t bRightTrigger;
    int16_t sThumbLX;
    int16_t sThumbLY;
    int16_t sThumbRX;
    int16_t sThumbRY;
};

typedef void* LPTHREAD_START_ROUTINE;
