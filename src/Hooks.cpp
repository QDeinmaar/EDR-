#include "Hooks.h"
#include "DetectionEvents.h" 
#include "NativeAPI.h"
#include <iostream>
#include <ntstatus.h>
#include <windows.h>

// ===========================
// ===========================

pNtWriteVirtualMemory OriginalNtWriteVirtualMemory = nullptr;
pNtAllocateVirtualMemory OriginalNtAllocateVirtualMemory = nullptr;
pNtProtectVirtualMemory OriginalNtProtectVirtualMemory = nullptr;
pNtReadVirtualMemory OriginalNtReadVirtualMemory = nullptr;
pNtCreateThreadEx OriginalNtCreateThreadEx = nullptr;

// ===========================
// ===========================
NTSTATUS NTAPI HookNtWriteVirtualMemory
(   HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
        // Source
        DWORD sourcePid = GetCurrentProcessId();

        // Target
        DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(ProcessHandle);

        //

        bool IsMalicious = false;

        if(targetPid == g_lsassPid)
        {
            printf("EDR BLOCKED : Read from lsass.exe (PID %lu)", targetPid);
            IsMalicious = true;
        }

        // Create Evenement for the IA

        DetectionEvent event;
        event.timestamp = GetTickCount64();
        event.sourcePid = sourcePid;
        event.targetPid = targetPid;
        event.operationType = 1; // 1 = WriteVirtualMemory
        event.address = BaseAddress;
        event.size = NumberOfBytesToWrite;

        // We send the event to AI

        EventCallback callback = NativeAPI::Instance().GetEventCallback();
        if(callback)
        {
            callback(event);
        }

        if(IsMalicious)
        {
            return STATUS_ACCESS_DENIED;
        }

        // Here we call the original function

        NTSTATUS status = OriginalNtWriteVirtualMemory(
            ProcessHandle,
            BaseAddress,
            Buffer,
            NumberOfBytesToWrite,
            NumberOfBytesWritten
        );
        
        return status;
}

NTSTATUS NTAPI HookNtCreateThreadEx
(   
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAcces,
    POBJECT_ATTRIBUTES ObjectAtrributes, HANDLE ProcessHandle,
    PVOID StartAddress, PVOID Parameter,
    ULONG CreateFlags, SIZE_T ZeroBits,
    SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttrributeList)
{

    DWORD sourcePid = GetCurrentProcessId();

    DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(ProcessHandle);

    // event

    DetectionEvent event;
    event.timestamp = GetTickCount64();
    event.sourcePid = sourcePid;
    event.targetPid = targetPid;
    event.operationType = 2; // 2 = CreateThreadEx
    event.access = DesiredAcces;
    event.address = StartAddress ? StartAddress : nullptr;
    event.createFlags = CreateFlags;

    EventCallback callback = NativeAPI::Instance().GetEventCallback();
        if(callback)
        {
            callback(event);
        }

    // Original

    NTSTATUS status = OriginalNtCreateThreadEx(
        ThreadHandle, DesiredAcces,
        ObjectAtrributes, ProcessHandle,
        (PUSER_THREAD_START_ROUTINE)StartAddress, Parameter,
        CreateFlags, ZeroBits, StackSize,
        MaximumStackSize, (PPS_ATTRIBUTE_LIST)AttrributeList // i used explisit cast to match our typedef

    );

    return status;
}

NTSTATUS NTAPI HookNtAllocateVirtualMemory
(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize,
    ULONG AllocationType, ULONG PageProtection) 
{
    DWORD sourcePid = GetCurrentProcessId();

    DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(ProcessHandle);

    // event 

    DetectionEvent event;
    event.timestamp = GetTickCount64();
    event.sourcePid = sourcePid;
    event.targetPid = targetPid;
    event.operationType = 3; // 3 = AllocateVirtualMemory
    event.address = BaseAddress ? *BaseAddress : nullptr;
    event.size = RegionSize ? *RegionSize : 0;
    event.allocationType = AllocationType;
    event.pageProtection = PageProtection;

    //

    EventCallback callback = NativeAPI::Instance().GetEventCallback();
        if(callback)
        {
            callback(event);
        }
    
    NTSTATUS status = OriginalNtAllocateVirtualMemory (
        ProcessHandle, BaseAddress,
        ZeroBits, RegionSize, AllocationType,
        PageProtection
    );

    return status;
}

NTSTATUS NTAPI HookNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect,
    PULONG OldProtect
)
{
    DWORD sourcePid = GetCurrentProcessId();

    DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(ProcessHandle);

    // this is a FILTER the ignore the normal protection from popping up

    if(NewProtect != PAGE_EXECUTE_READWRITE && NewProtect != PAGE_EXECUTE_READ)
    {
        // we go directly to the original function

        return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }

    bool IsMalicious = false;

    if(NewProtect == PAGE_EXECUTE_READWRITE)
    {
        printf("EDR BLOCKED : RWX protection has been detected !\n");
        IsMalicious = true;
    }

    // event 

    DetectionEvent event;
    event.timestamp = GetTickCount64();
    event.sourcePid = sourcePid;
    event.targetPid = targetPid;
    event.operationType = 4; // 4 = ProtectVirtualMemory
    event.address = BaseAddress ? *BaseAddress : nullptr;
    event.size = RegionSize ? *RegionSize : 0;
    event.pageProtection = NewProtect;

    //

    EventCallback callback = NativeAPI::Instance().GetEventCallback();
    if(callback)
        {
            callback(event);
        }

    if(IsMalicious)
    {
        return STATUS_ACCESS_DENIED;
    }
    
    //

    NTSTATUS status = OriginalNtProtectVirtualMemory(
        ProcessHandle, BaseAddress,
        RegionSize, NewProtect,
        OldProtect
    );

    return status;
}

NTSTATUS NTAPI HookNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead)
{
    
    DWORD sourcePid = GetCurrentProcessId();

    DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(ProcessHandle);

    // event 

    DetectionEvent event;
    event.timestamp = GetTickCount64();
    event.sourcePid = sourcePid;
    event.targetPid = targetPid;
    event.operationType = 5; // 5 = ReadVirtualMemory
    event.address = BaseAddress;
    event.size = NumberOfBytesToRead;

    //

    EventCallback callback = NativeAPI::Instance().GetEventCallback();
    if(callback)
        {
            callback(event);
        }

    //

    NTSTATUS status = OriginalNtReadVirtualMemory(
        ProcessHandle, BaseAddress,
        Buffer, NumberOfBytesToRead,
        NumberOfBytesRead
    );
    
    return status;
}

// ===================================
// ===================================

bool InstallHooks()
{
    // We Initialize MinHook

    if(MH_Initialize() != MH_OK)
    {
        printf("EDR failed to Initialize MinHook !\n");
        return false;
    }

    // Global Variables defined in NativeAPI.cpp

    OriginalNtWriteVirtualMemory = g_NtWriteVirtualMemory;
    OriginalNtAllocateVirtualMemory = g_NtAllocateVirtualMemory;
    OriginalNtProtectVirtualMemory = g_NtProtectVirtualMemory;
    OriginalNtReadVirtualMemory = g_NtReadVirtualMemory;
    OriginalNtCreateThreadEx = g_NtCreateThreadEx;

    // We create instance of the hooks

    if(MH_CreateHook((LPVOID)OriginalNtWriteVirtualMemory, (LPVOID)&HookNtWriteVirtualMemory, NULL) != MH_OK)
    {
        printf("EDR failed to Hook: NtWriteVirtualMemory !\n");
        return false;
    }
    if(MH_CreateHook((LPVOID)OriginalNtCreateThreadEx, (LPVOID)&HookNtCreateThreadEx, NULL) != MH_OK)
    {
        printf("EDR failed to Hook : NtCreateThreadEx !\n");
        return false;
    }

    if(MH_CreateHook((LPVOID)OriginalNtAllocateVirtualMemory, (LPVOID)&HookNtAllocateVirtualMemory, NULL) != MH_OK)
    {
        printf("EDR failed to Hook : NtAllocateVirtualMemory !\n");
        return false;
    }

    if(MH_CreateHook((LPVOID)OriginalNtProtectVirtualMemory, (LPVOID)&HookNtProtectVirtualMemory, NULL) != MH_OK)
    {
        printf("EDR failed to Hook : NtProtectVirtualMemory !\n");
        return false;
    }

    if(MH_CreateHook((LPVOID)OriginalNtReadVirtualMemory, (LPVOID)&HookNtReadVirtualMemory, NULL) != MH_OK)
    {
        printf("EDR failed to Hook : NtReadVirtualMemory !\n");
        return false;
    }

    if(MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        printf("EDR failed to enable the Hooks !\n");
        return false;
    }

    printf("EDR: All the Hooks installed successfully !\n");
    return true;
}