#pragma once
#include <windows.h>
#include <winternl.h>

// i created this file to declare typedefs here cleaner code ;)

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

