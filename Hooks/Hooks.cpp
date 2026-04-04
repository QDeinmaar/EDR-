#include "Hooks.h"

NTSTATUS NTAPI HookNtWriteVirtualMemory
(   HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite,
    SIZE_T NumberOfBytesWritten)
{
        // Source
        DWORD sourcePid = GetCurrentProcessId();

        // Target
        DWORD targetPid = GetProcessIdFromHandle(ProcessHandle);

        // 
}