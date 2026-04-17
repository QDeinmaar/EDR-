/*
#include "EtwBridge.h"
#include "MinHook.h"
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <stdio.h>
#include <evntrace.h>

#pragma comment(lib, "tdh.lib")


static const GUID KERNEL_TRACE_CONTROL_GUID =
{ 0x9e814aad, 0x3204, 0x11d2,{ 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };


// Kernel Process Provider (stable)
static const GUID KernelProcessGuid =
{ 0x3d6fa8d1, 0xfe05, 0x11d0,{ 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };

// GUID Microsoft-Windows-Threat-Intelligence
static const GUID g_TI = {0xf4e1897c, 0xbb5d, 0x5668, {0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44}};

TRACEHANDLE EtwBridge::s_hTrace = 0;
HANDLE EtwBridge::s_hThread = NULL;
std::atomic<bool> EtwBridge::s_running{ false };
EventCallback EtwBridge::s_userCallback = nullptr;

DWORD WINAPI EtwBridge::EtwThreadProcStatic(LPVOID param)
{
    EtwBridge* pThis = (EtwBridge*)param;
    if (pThis)
        pThis->EtwThreadProc();
        
    return 0;
}

bool EtwBridge::Start(EventCallback callback)
{
    printf("[ETW] EtwBridge::Start() called\n");
    fflush(stdout);
    
    if (!callback) return false;
    s_userCallback = callback;
    s_running = true;
    
    s_hThread = (HANDLE)_beginthreadex(NULL, 0, [](void* param) -> unsigned int {
        EtwBridge* pThis = (EtwBridge*)param;
        pThis->EtwThreadProc();
        return 0;
    }, this, 0, NULL);
    
    if (!s_hThread)
    {
        printf("[ETW] Thread creation failed: %d\n", errno);
        return false;
    }
    
    printf("[ETW] Thread started\n");
    return true;
}

void EtwBridge::Stop()
{
    s_running = false;

    if (s_hTrace)
    {
        CloseTrace(s_hTrace);
        s_hTrace = 0;
    }

    if (s_hThread)
    {
        WaitForSingleObject(s_hThread, INFINITE);
        CloseHandle(s_hThread);
        s_hThread = NULL;
    }

    printf("[ETW] Stopped\n");
}

void EtwBridge::EtwThreadProc()
{
    ULONG status;
    TRACEHANDLE hSession = 0;

    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 256] = {};
    EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)buffer;

    // =========================
    // SESSION CONFIG
    // =========================
    pProps->Wnode.BufferSize = sizeof(buffer);
    pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProps->Wnode.ClientContext = 1;

    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    const char* sessionName = "NT Kernel Logger";
    strcpy_s((char*)buffer + pProps->LoggerNameOffset, 256, sessionName);

    // =========================
    // START SESSION
    // =========================
    status = StartTraceA(&hSession, sessionName, pProps);

    if (status == ERROR_ALREADY_EXISTS)
    {
        ControlTraceA(0, sessionName, pProps, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceA(&hSession, sessionName, pProps);
    }

    if (status != ERROR_SUCCESS)
    {
        printf("[ETW] StartTrace failed: %lu\n", status);
        return;
    }

    printf("[ETW] Session started\n");

    // =========================
    // ENABLE KERNEL EVENTS
    // =========================
   EnableTraceEx2(
    hSession,
    &KERNEL_TRACE_CONTROL_GUID,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    TRACE_LEVEL_INFORMATION,
    0,
    EVENT_TRACE_FLAG_PROCESS |
    EVENT_TRACE_FLAG_THREAD |
    EVENT_TRACE_FLAG_IMAGE_LOAD,
    0,
    NULL
);

    // =========================
    // OPEN TRACE
    // =========================
    EVENT_TRACE_LOGFILEA log = {};
    log.LoggerName = (LPSTR)sessionName;
    log.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME |
        PROCESS_TRACE_MODE_EVENT_RECORD;

    log.EventRecordCallback = EventRecordCallback;

    s_hTrace = OpenTraceA(&log);

    if (s_hTrace == INVALID_PROCESSTRACE_HANDLE)
    {
        printf("[ETW] OpenTrace failed\n");
        ControlTraceA(hSession, sessionName, pProps, EVENT_TRACE_CONTROL_STOP);
        return;
    }

    printf("[ETW] Listening...\n");
    fflush(stdout);

    // =========================
    // PROCESS EVENTS (BLOCKING)
    // =========================
    TRACEHANDLE handles[] = { s_hTrace };

    ProcessTrace(handles, 1, NULL, NULL);

    // =========================
    // CLEAN EXIT
    // =========================
    ControlTraceA(hSession, sessionName, pProps, EVENT_TRACE_CONTROL_STOP);
    printf("[ETW] Thread stopped\n");
}

void WINAPI EtwBridge::EventRecordCallback(PEVENT_RECORD pEvent)
{
    printf("[ETW RAW] PID=%lu EVENT=%u\n",
    pEvent->EventHeader.ProcessId,
    pEvent->EventHeader.EventDescriptor.Id);

    fflush(stdout);

     printf("[ETW] RAW EVENT: Provider=%08x-%04x-%04x\n",
           pEvent->EventHeader.ProviderId.Data1,
           pEvent->EventHeader.ProviderId.Data2,
           pEvent->EventHeader.ProviderId.Data3);
    fflush(stdout);

    if (!s_userCallback)
        return;

    const EVENT_HEADER& hdr = pEvent->EventHeader;
    
    // Ne traiter que les événements Threat-Intelligence
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, g_TI))
        return;

    printf("[ETW] Threat-Intelligence Event: PID=%lu, Id=%u\n", 
           hdr.ProcessId, hdr.EventDescriptor.Id);

    DetectionEvent evt = {};
    evt.timestamp = GetTickCount64();
    evt.sourcePid = hdr.ProcessId;
    evt.fromEtw = true;

    // Mapping des Event IDs Threat-Intelligence
    switch (hdr.EventDescriptor.Id)
    {
    case 1: // AllocateVirtualMemoryRemote
        evt.operationType = 3;  // Allocate
        evt.score = 30;
        evt.pageProtection = PAGE_EXECUTE_READWRITE;
        printf("[ETW] Remote memory allocation detected!\n");
        break;
        
    case 2: // WriteVirtualMemoryRemote
        evt.operationType = 1;  // Write
        evt.score = 20;
        printf("[ETW] Remote memory write detected!\n");
        break;
        
    case 3: // ProtectVirtualMemoryRemote
        evt.operationType = 4;  // Protect
        evt.score = 35;
        printf("[ETW] Remote memory protection change detected!\n");
        break;
        
    case 5: // QueueUserAPC
    case 6: // SetThreadContext
        evt.operationType = 2;  // Thread
        evt.score = 45;
        printf("[ETW] Remote thread/APC detected!\n");
        break;
        
    default:
        return;
    }
    
    s_userCallback(evt);
}
    
*/