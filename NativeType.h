#pragma once
#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include <ntdef.h>

#include "Workers.h"

// i created this file to declare typedefs here cleaner code ;)


//  ====== Process Operations ======

// NtOpenProcess
typedef NTSTATUS (NTAPI* pNtOpenProcess)
(
    _Out_ PHANDLE ProcessHandle, 
    _In_ ACCESS_MASK DesiredAccess, 
    _In_ POBJECT_ATTRIBUTES ObjectAttributes, 
    _In_opt_ PCLIENT_ID ClientId 
);

// NtCreateProcess

typedef NTSTATUS (NTAPI* pNtCreateProcess)
(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesireAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritObjectTable,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle
);

// This will help me see hidden or suspicious process creation -- it might be malware spawning hidden process

// NtCreateUserProcess

typedef NTSTATUS (NTAPI* pNtCreateUserProcess)
(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ PCOBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
    _In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
    _In_opt_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

// NtTerminateProcess

typedef NTSTATUS (NTAPI* pNtTerminateProcess)
(
    _In_opt_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
);

// this will help detect or block attempts to kill processes, often used by malware to disable security tools

// ====== Handel Management ======

// NtClose

typedef NTSTATUS (NTAPI* pNtClose)
(
    _In_ _Post_ptr_invalid_ HANDLE Handle
);

// ====== System Information ======

// NtQuerySystemInformation

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)
(
    _In_ SYSTEM_INFORMATION_CLASS systemInformationClass, 
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation, 
    _In_ ULONG SystemInformationLength, 
    _Out_opt_ PULONG ReturnLength 
);


// ====== Memory Operations ======

// NtWriteVirtualMemory

typedef NTSTATUS (NTAPI* pNtWriteVirtualMemory)
(
    _In_ HANDLE ProcessHandle,
    _Out_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

// M using this to detect if one process is writting in another Process's memory

// NtProtectVirtualMemory

typedef NTSTATUS (NTAPI* pNtProtectVirtualMemory)
(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress, // pointer to the base address that the protection need to be changed
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_opt_ PULONG OldProtection
);

// this is for changing the protection on a region od virtual memory 

// NtAllocateVirtualMemory

typedef NTSTATUS (NTAPI* pNtAllocateVirtualMemory)
(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits, // high-order adress, must be less than 21 , is used when BaseAdress in NULL
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AlloctionType, // contains the flag type of the Allocation that need to be performed 5 in total
    _In_ ULONG PageProtection // contains the flag that specify the protection desired 9 in total 
);

// this well help detect if a process is allocating memory inside another process --- we talk about code injection ----

// NtReadVirtualMemory

typedef NTSTATUS (NTAPI* pNtReadVirtualMemory)
(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesToRead) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToRead,
    _Out_opt_ PSIZE_T NumberOfBytesRead
);

// this well help us detect when a process is reading memory from another process -- can be a theft or data extraction  

//  ====== Threads Operations ======

// NtCreateThreadEx

typedef NTSTATUS (NTAPI* pNtCreateThreadEx)
(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAcces,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAtrributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // These Flags are defined as THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttrributeList
);

/* 
this well help to detect when a process creates a thread in another process -- it can be for a key step for attackers to
                            for code injection or stealthy injection
*/

// NtResumeThread

typedef NTSTATUS (NTAPI* pNtResumeThread)
(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
);

// This will help to detect when a thread is being resumed in another process , wich can mean injected or hidden malicous code
// Optionally alert or block  on suspious resume to prevent the malware from doing damage

// ====== Registry =======

// NtSetValueKey

typedef NTSTATUS (NTAPI* pNtSetValueKey)
(
    _In_ HANDLE KeyHandle,
    _In_ PCUNICODE_STRING ValueName,
    _In_opt_ ULONG TitleName,
    _In_ ULONG Type,
    _In_reads_bytes_opt_(DataSize) PVOID Data,
    _In_ ULONG DataSize
);

// It can detect or clock suspicious registry changes , it s often used by malwares for persistence