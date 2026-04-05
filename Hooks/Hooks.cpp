#include "Hooks.h"
#include "DetectionEvents.h" 
#include "NativeAPI.h"

NTSTATUS NTAPI HookNtWriteVirtualMemory
(   HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
        // Source
        DWORD sourcePid = GetCurrentProcessId();

        // Target
        DWORD targetPid = NativeAPI::Instance().GetProcessIdFromHandle(ProcessHandle);

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