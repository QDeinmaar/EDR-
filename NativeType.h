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