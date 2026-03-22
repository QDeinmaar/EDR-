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

// I want to explain in but just go read to documentation :p

// NtClose

typedef NTSTATUS (NTAPI* pNtClose)
(
    HANDLE Handle
);

// NtQuerySystemInformation

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)
(
    SYSTEM_INFORMATION_CLASS systemInformationClass, // It specify what information were going to retrieve
    PVOID SystemInformation, // defining a pointer to use 
    ULONG SystemInformationLength, // just the size of the buffer
    PULONG ReturnLength // this is a parameter that get the actual size of the data returned 
);