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
    
);