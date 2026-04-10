#pragma once
#include <windows.h>

// Global variable to track lsass.exe PID
extern DWORD g_lsassPid;
extern pReadProcessMemory OriginalReadProcessMemory;
extern pVirtualProtectEx OriginalVirtualProtectEx;

struct DetectionEvent
{
    ULONGLONG timestamp;     // When it happened
    DWORD sourcePid;         // Who called the API
    DWORD targetPid;         // What process was targeted
    DWORD operationType;     // 1=Write, 2=CreateThread, 3=Allocate, etc.
    PVOID address;           // Memory address
    SIZE_T size;             // Size of operation
    ACCESS_MASK access;      // Access flags for OpenProcess
    NTSTATUS status;         // Did it succeed?
    
    // For WriteVirtualMemory
    PVOID bufferAddress;     // Where data came from
    SIZE_T bufferSize;       // How much data
    
    // For CreateThreadEx
    PVOID startAddress;      // Thread entry point
    ULONG createFlags;       // CREATE_SUSPENDED flag

    ULONG pageProtection;          // Memory protection flags
    ULONG allocationType;   // Allocation type (MEM_COMMIT, etc.)

    const wchar_t* registryValueName;  // Name of registry value
    ULONG registryType;    // REG_SZ, REG_DWORD, etc.
    ULONG registryDataSize; // Size of data
};