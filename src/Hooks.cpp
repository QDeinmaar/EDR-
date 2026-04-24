#include "Hooks.h"
#include "DetectionEvents.h" 
#include "NativeAPI.h"
#include <iostream>
#include <ntstatus.h>
#include <windows.h>

static bool g_inHookAlloc = false; // to prevent infinite loop in Alloc
static bool g_inHookWrite = false;
static bool g_inHookThread = false;

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

    if(g_inHookWrite)
    {
        return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    }
        g_inHookWrite = true;

        // Source
        DWORD sourcePid = GetCurrentProcessId();

        // Target
        DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(ProcessHandle);

        if (targetPid == 0 || targetPid == 4)
    {
        return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
                                             NumberOfBytesToWrite, NumberOfBytesWritten);
    }

        // Scoring System

        int score = 0;
    
        if(targetPid == g_lsassPid) score += 80;        // Credential dumping
        if(sourcePid != targetPid) score += 20;         // Remote write
        if(NumberOfBytesToWrite > 1024) score += 10;    // Large write


        // Create Evenement for the IA

        DetectionEvent event;
        event.timestamp = GetTickCount64();
        event.sourcePid = sourcePid;
        event.targetPid = targetPid;
        event.operationType = 1; // 1 = WriteVirtualMemory
        event.address = BaseAddress;
        event.size = NumberOfBytesToWrite;
        event.score = score;

        // We send the event to AI

        EventCallback callback = NativeAPI::Instance().GetEventCallback();
        if(callback) callback(event);

         // BLOCK BASED ON THE SCORE 

        if(score >= 70)
        {

        printf("EDR BLOCKED: Write operation (score=%d)\n", score);
        return STATUS_ACCESS_DENIED;
        // we Block

        }
        else if(score >= 30)
        {

        printf("EDR ALERT: Write operation (score=%d)\n", score);
        // We only alert !

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

    if(g_inHookThread)
    {
        return OriginalNtCreateThreadEx(ThreadHandle, DesiredAcces, ObjectAtrributes, ProcessHandle, (PUSER_THREAD_START_ROUTINE)StartAddress, Parameter, CreateFlags, ZeroBits, StackSize, MaximumStackSize, (PPS_ATTRIBUTE_LIST)AttrributeList);
    }
    g_inHookThread = true;

    DWORD sourcePid = GetCurrentProcessId();

    DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(ProcessHandle);


    if (targetPid == 0 || targetPid == 4)
    {
        return OriginalNtCreateThreadEx(ThreadHandle, DesiredAcces, ObjectAtrributes,
                                         ProcessHandle, (PUSER_THREAD_START_ROUTINE)StartAddress,
                                         Parameter, CreateFlags, ZeroBits, StackSize,
                                         MaximumStackSize, (PPS_ATTRIBUTE_LIST)AttrributeList);
    }
      

    // Scoring System

    int score = 0;
    
    if(sourcePid != targetPid) score += 40;         // Remote thread = injection
    if(targetPid == g_lsassPid) score += 80;        // Thread dans lsass
    if(CreateFlags & 0x1) score += 10;              // CREATE_SUSPENDED = suspect

    // event

    DetectionEvent event;
    event.timestamp = GetTickCount64();
    event.sourcePid = sourcePid;
    event.targetPid = targetPid;
    event.operationType = 2; // 2 = CreateThreadEx
    event.access = DesiredAcces;
    event.address = StartAddress ? StartAddress : nullptr;
    event.createFlags = CreateFlags;
    event.score = score;

    EventCallback callback = NativeAPI::Instance().GetEventCallback();
        if(callback) callback(event);
        
    // Block Based on the Score

    if(score >= 70)
    {
        printf("EDR BLOCKED: Thread creation (score=%d)\n", score);
        return STATUS_ACCESS_DENIED;
    }
    else if(score >= 30)
    {
        printf("EDR ALERT: Thread creation (score=%d)\n", score);
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

    if(g_inHookAlloc)
    {
        return OriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, PageProtection);
    }
    
    g_inHookAlloc = true;

    DWORD sourcePid = GetCurrentProcessId();

    DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(ProcessHandle);

    if (targetPid == 0 || targetPid == 4)
    {
        // Appel direct sans logging ni blocage
        g_inHookAlloc = false;
        return OriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, 
                                                RegionSize, AllocationType, PageProtection);
    }

    // ===== Scoring System =====

    int score = 0;
    
    if(PageProtection == PAGE_EXECUTE_READWRITE) score += 30;  // RWX = shellcode
    if(sourcePid != targetPid) score += 20; // Remote allocation
    if(AllocationType == MEM_COMMIT) score += 10;  // Real allocation

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
    event.score = score;

    //

    EventCallback callback = NativeAPI::Instance().GetEventCallback();
        if(callback) callback(event);

        // We Block Based on  the Score !!
        if(score >= 70)
    {
        printf("EDR BLOCKED: RWX allocation (score=%d)\n", score);
        g_inHookAlloc = false;
        return STATUS_ACCESS_DENIED;
    }
    else if(score >= 30)
    {
        g_inHookAlloc = false;
        printf("EDR ALERT: RWX allocation (score=%d)\n", score);
    }

    
    NTSTATUS status = OriginalNtAllocateVirtualMemory (
        ProcessHandle, BaseAddress,
        ZeroBits, RegionSize, AllocationType,
        PageProtection
    );

    g_inHookAlloc = false; // i forgot this one :)
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
// I Addes this ones to try to fix the problem in Protect and Read
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
    // 1. Initialisation de MinHook
    if(MH_Initialize() != MH_OK)
    {
        LogEDR("[EDR] failed to Initialize MinHook !");
        return false;
    }

    // 2. Récupération des adresses (Kernel32)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        LogEDR("[EDR] Failed to get kernel32.dll");
        return false;
    }

    OriginalReadProcessMemory = (pReadProcessMemory)GetProcAddress(hKernel32, "ReadProcessMemory");
    OriginalVirtualProtectEx = (pVirtualProtectEx)GetProcAddress(hKernel32, "VirtualProtectEx");

    // 3. Création des Hooks
    // IMPORTANT : On passe l'adresse de notre pointeur Original... en 3ème argument (au lieu de NULL)
    // pour que MinHook le remplisse avec l'adresse du TRAMPOLINE.
    
    if(MH_CreateHook((LPVOID)g_NtWriteVirtualMemory, (LPVOID)HookNtWriteVirtualMemory, (LPVOID*)&OriginalNtWriteVirtualMemory) != MH_OK)
    {
        LogEDR("[EDR] failed to Hook: NtWriteVirtualMemory");
        return false;
    }

    if(MH_CreateHook((LPVOID)g_NtCreateThreadEx, (LPVOID)HookNtCreateThreadEx, (LPVOID*)&OriginalNtCreateThreadEx) != MH_OK)
    {
        LogEDR("[EDR] failed to Hook: NtCreateThreadEx");
        return false;
    }

    if(MH_CreateHook((LPVOID)g_NtAllocateVirtualMemory, (LPVOID)HookNtAllocateVirtualMemory, (LPVOID*)&OriginalNtAllocateVirtualMemory) != MH_OK)
    {
        LogEDR("[EDR] failed to Hook: NtAllocateVirtualMemory");
        return false;
    }

    // 4. Activation des hooks
    // Utiliser MH_ALL_HOOKS est plus propre pour tout activer d'un coup
    if(MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        LogEDR("[EDR] failed to enable all hooks !");
        return false;
    }

    LogEDR("[EDR] All hooks installed successfully in PID %lu!", GetCurrentProcessId());
    return true;
}