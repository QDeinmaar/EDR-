#pragma once
#include <windows.h>
#include <winternl.h>

// i created this file to declare typedefs here cleaner code ;)


//  ====== Process Operations ======

// NtOpenProcess
typedef NTSTATUS (NTAPI* pNtOpenProcess)
(
    PHANDLE ProcessHandle, 
    ACCESS_MASK DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes, 
    PCLIENT_ID ClientId 
);


// NtClose

typedef NTSTATUS (NTAPI* pNtClose)
(
    HANDLE Handle
);

// NtQuerySystemInformation

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)
(
    SYSTEM_INFORMATION_CLASS systemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    PULONG ReturnLength 
);


// ====== Memory Operations ======

// NtWriteVirtualMemory

typedef NTSTATUS (NTAPI* pNtWriteVirtualMemory)
(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

// M using this to detect if one process is writting in another Process's memory

// NtProtectVirtualMemory

typedef NTSTATUS (NTAPI* pNtProtectVirtualMemory)
(
    HANDLE ProcessHandle,
    PVOID *BaseAddress, // pointer to the base address that the protection need to be changed
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

// this is for changing the protection on a region od virtual memory 

// NtAllocateVirtualMemory

typedef NTSTATUS (NTAPI* pNtAllocateVirtualMemory)
(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits, // high-order adress, must be less than 21 , is used when BaseAdress in NULL
    PVOID RegionSize,
    ULONG AlloctionType, // contains the flag type of the Allocation that need to be performed 5 in total
    ULONG PageProtection // contains the flag that specify the protection desired 9 in total 
);

// this well help detect if a process is allocating memory inside another process --- we talk about code injection ----