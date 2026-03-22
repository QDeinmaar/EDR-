#pragma once
#include <windows.h>
#include <winternl.h>

// i created this file to declare typedefs here cleaner code ;)

// NtOpenProcess
typedef NTSTATUS (NTAPI* pNtOpenProcess)
(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES objectAttributes,
    PCLIENT_ID clientId
);

// I want to explain in but just go read to documentation :p

// NtClose

typedef NTSTATUS (NTAPI* pNTClose)
(
    HANDLE handle
);

// NtQuerySystemInformation

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)
(
    SYSTEM_INFORMATION_CLASS systemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLenght
);