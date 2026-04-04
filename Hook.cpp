#include "MinHook.h"
#include "NativeType.h"

pNtAllocateVirtualMemory OriginalNtAllocateVirtualMemory = nullptr;

NTSTATUS NTAPI HookNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);


pNtWriteVirtualMemory OriginalNtWriteVirtualMemory = nullptr;

NTSTATUS NTAPI HookNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

pNtReadVirtualMemory OriginalNtReadVirtualMemory = nullptr;

NTSTATUS NTAPI HookNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

pNtAllocateVirtualMemory OriginalNtAllocateVirtualMemory = nullptr;

NTSTATUS NTAPI HookNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

pNtCreateThreadEx OriginalNtCreateThreadEx = nullptr;

NTSTATUS NTAPI HookNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartAddress,
    PVOID Parameter,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);