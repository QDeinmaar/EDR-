#include "Hooks.h"
#include "DetectionEvents.h" 
#include "NativeAPI.h"
#include <iostream>
#include <ntstatus.h>
#include <windows.h>


extern pNtWriteVirtualMemory g_NtWriteVirtualMemory;
// extern pNtAllocateVirtualMemory g_NtAllocateVirtualMemory;
// extern pNtProtectVirtualMemory g_NtProtectVirtualMemory;
extern pNtReadVirtualMemory g_NtReadVirtualMemory;
extern pNtCreateThreadEx g_NtCreateThreadEx;

// ===========================
// ===========================

pNtWriteVirtualMemory OriginalNtWriteVirtualMemory = nullptr;
pNtAllocateVirtualMemory OriginalNtAllocateVirtualMemory = nullptr;
// pNtProtectVirtualMemory OriginalNtProtectVirtualMemory = nullptr; we dont use it no more (maybe in the future)
// pNtReadVirtualMemory OriginalNtReadVirtualMemory = nullptr; we dont use it no more ( maybe in the future)
pNtCreateThreadEx OriginalNtCreateThreadEx = nullptr;
pReadProcessMemory OriginalReadProcessMemory = nullptr;
pVirtualProtectEx OriginalVirtualProtectEx = nullptr;

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
            printf("EDR BLOCKED : Write from lsass.exe (PID %lu)", targetPid);
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

    bool IsMalicious = false;

    if(sourcePid != targetPid)
    {
        printf("EDR BLOCKED : Remote thread creation (source : %lu , target : %lu) !\n");
        IsMalicious = true;
    }

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

        if(IsMalicious)
        {
            return STATUS_ACCESS_DENIED;
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

    bool IsMalicious = false;

    if(PageProtection == PAGE_EXECUTE_READWRITE)
    {
        printf("EDR BLOCKED : RWX memory allocation ( size : %llu bytes) !\n", RegionSize ? *RegionSize : 0);
        IsMalicious = true;
    }

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

        if(IsMalicious)
        {
            return STATUS_ACCESS_DENIED;
        }
    
    NTSTATUS status = OriginalNtAllocateVirtualMemory (
        ProcessHandle, BaseAddress,
        ZeroBits, RegionSize, AllocationType,
        PageProtection
    );

    return status;
}
/*
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

    bool IsMalicious = false;
    if(targetPid == g_lsassPid)
    {
        printf("EDR BLOCKED : Read from lsass.exe (PID %lu) !\n", targetPid);
        IsMalicious = true;
    }

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

    if(IsMalicious)
    {
        return STATUS_ACCESS_DENIED;
    }

    //

    NTSTATUS status = OriginalNtReadVirtualMemory(
        ProcessHandle, BaseAddress,
        Buffer, NumberOfBytesToRead,
        NumberOfBytesRead
    );
    
    return status;
}
*/

// ===================================
// I Addes this ones to try to fix the problem in Proect and Read
// ===================================

BOOL WINAPI HookReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead
)
{
    DWORD sourcePid = GetCurrentProcessId();
    DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(hProcess);

    bool IsMalicious = (targetPid == g_lsassPid);

    if(IsMalicious)
    {
        printf("EDR BLOCKED: ReadProcessMemory on lsass.exe\n");
    }

    DetectionEvent event{};
    event.timestamp = GetTickCount64();
    event.sourcePid = sourcePid;
    event.targetPid = targetPid;
    event.operationType = 5;
    event.address = (PVOID)lpBaseAddress;
    event.size = nSize;

    auto callback = NativeAPI::Instance().GetEventCallback();
    if(callback) callback(event);

    if(IsMalicious)
        return FALSE;

    return OriginalReadProcessMemory(
        hProcess, lpBaseAddress,
        lpBuffer, nSize,
        lpNumberOfBytesRead
    );
}

BOOL WINAPI HookVirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
)
{
    DWORD sourcePid = GetCurrentProcessId();
    DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(hProcess);

    bool IsMalicious = (flNewProtect == PAGE_EXECUTE_READWRITE);

    if(IsMalicious)
    {
        printf("EDR BLOCKED: RWX via VirtualProtectEx\n");
    }

    DetectionEvent event{};
    event.timestamp = GetTickCount64();
    event.sourcePid = sourcePid;
    event.targetPid = targetPid;
    event.operationType = 4;
    event.address = lpAddress;
    event.size = dwSize;
    event.pageProtection = flNewProtect;

    auto callback = NativeAPI::Instance().GetEventCallback();
    if(callback) callback(event);

    if(IsMalicious)
        return FALSE;

    return OriginalVirtualProtectEx(
        hProcess, lpAddress,
        dwSize, flNewProtect,
        lpflOldProtect
    );
}

// ===================================
// ===================================

bool InstallHooks()
{

    if(MH_Initialize() != MH_OK)
    {
        printf("EDR failed to Initialize MinHook !\n");
        return false;
    }

    // Original Nt

    OriginalNtWriteVirtualMemory = g_NtWriteVirtualMemory;
    OriginalNtAllocateVirtualMemory = g_NtAllocateVirtualMemory;
    OriginalNtCreateThreadEx = g_NtCreateThreadEx;
    
    // Load Kernel32 (New Hooks)

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    if (!hKernel32)
{
    printf("Failed to get kernel32.dll\n");
    return false;
}

    OriginalReadProcessMemory = (pReadProcessMemory)GetProcAddress(hKernel32, "ReadProcessMemory");
    OriginalVirtualProtectEx = (pVirtualProtectEx)GetProcAddress(hKernel32, "VirtualProtectEx");

    if (!OriginalReadProcessMemory || !OriginalVirtualProtectEx)
    {
        printf("Kernel32 load failed\n");
        return false;
    }

    // Hook NtWriteVirtualMemory
    
    if(MH_CreateHook((LPVOID)OriginalNtWriteVirtualMemory, (LPVOID)&HookNtWriteVirtualMemory, NULL) != MH_OK)
    {
        printf("EDR failed to Hook: NtWriteVirtualMemory !\n");
        return false;
    }
    printf("InstallHooks: Hook NtWriteVirtualMemory OK\n");
    fflush(stdout);

    // Hook NtCreateThreadEx
    if(MH_CreateHook((LPVOID)OriginalNtCreateThreadEx, (LPVOID)&HookNtCreateThreadEx, NULL) != MH_OK)
    {
        printf("EDR failed to Hook : NtCreateThreadEx !\n");
        return false;
    }
    printf("InstallHooks: Hook NtCreateThreadEx OK\n");
    fflush(stdout);

    // Hook NtAllocateVirtualMemory
    if(MH_CreateHook((LPVOID)OriginalNtAllocateVirtualMemory, (LPVOID)&HookNtAllocateVirtualMemory, NULL) != MH_OK)
    {
        printf("EDR failed to Hook : NtAllocateVirtualMemory !\n");
        return false;
    }
    printf("InstallHooks: Hook NtAllocateVirtualMemory OK\n");
    fflush(stdout);
    printf("InstallHooks: OriginalNtAllocateVirtualMemory = %p\n", OriginalNtAllocateVirtualMemory);
    fflush(stdout);

    // =======
    /*
    if(MH_CreateHook((LPVOID)OriginalReadProcessMemory, (LPVOID)&HookReadProcessMemory, NULL) != MH_OK)
    {
        printf("EDR failed to Hook : ReadProcessMemory !\n");
        return false;
    }

    if(MH_CreateHook((LPVOID)OriginalVirtualProtectEx, (LPVOID)&HookVirtualProtectEx, NULL) != MH_OK)
    {
        printf("EDR failed to Hook : VirtualProtectEx !\n");
        return false;
    }
*/
    // Activation des hooks

    if(MH_EnableHook((LPVOID)OriginalNtWriteVirtualMemory) != MH_OK)
    {
        printf("EDR failed to enable NtWriteVirtualMemory !\n");
        return false;
    }

    if(MH_EnableHook((LPVOID)OriginalNtCreateThreadEx) != MH_OK)
    {
        printf("EDR failed to enable NtCreateThreadEx !\n");
        return false;
    }

    if(MH_EnableHook((LPVOID)OriginalNtAllocateVirtualMemory) != MH_OK)
    {
        printf("EDR failed to enable NtAllocateVirtualMemory !\n");
        return false;
    }
/*
    if(MH_EnableHook((LPVOID)OriginalReadProcessMemory) != MH_OK)
    {
        printf("EDR failed to enable ReadProcessMemory !\n");
        return false;
    }

    if(MH_EnableHook((LPVOID)OriginalVirtualProtectEx) != MH_OK)
    {
        printf("EDR failed to enable VirtualProtectMemory !\n");
        return false;
    }
*/
    printf("EDR: All the Hooks installed successfully !\n");
    return true;
}