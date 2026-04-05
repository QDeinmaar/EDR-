#include "MinHook.h"
#include "NativeType.h"

// Global Variables 

extern pNtWriteVirtualMemory g_NtWriteVirtualMemory;
extern pNtAllocateVirtualMemory g_NtAllocateVirtualMemory;
extern pNtProtectVirtualMemory g_NtProtectVirtualMemory;
extern pNtReadVirtualMemory g_NtReadVirtualMemory;
extern pNtCreateThreadEx g_NtCreateThreadEx;

// this is Original pointer to the function

extern pNtAllocateVirtualMemory OriginalNtAllocateVirtualMemory;

NTSTATUS NTAPI HookNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// this is Our Hook function 

extern pNtWriteVirtualMemory OriginalNtWriteVirtualMemory;

NTSTATUS NTAPI HookNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

extern pNtReadVirtualMemory OriginalNtReadVirtualMemory;

NTSTATUS NTAPI HookNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

extern pNtProtectVirtualMemory OriginalNtProtectVirtualMemory;

NTSTATUS NTAPI HookNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);


extern pNtCreateThreadEx OriginalNtCreateThreadEx;

NTSTATUS NTAPI HookNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAcces,
    POBJECT_ATTRIBUTES ObjectAtrributes,
    HANDLE ProcessHandle,
    PVOID StartAddress,
    PVOID Parameter,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// Installation fucntion

bool InstallHooks();

