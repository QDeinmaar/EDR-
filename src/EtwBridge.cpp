#include "EtwBridge.h"
#include "MinHook.h"
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <stdio.h>

#pragma comment(lib, "tdh.lib")

// 🔥 Kernel Process Provider (stable)
static const GUID KernelProcessGuid =
{ 0x3d6fa8d1, 0xfe05, 0x11d0,{ 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };

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

    pProps->Wnode.BufferSize = sizeof(buffer);
    pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProps->Wnode.ClientContext = 1;

    // 🔥 CRITIQUE
    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProps->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD;

    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    const char* sessionName = "EDRSession";
    strcpy_s((char*)buffer + pProps->LoggerNameOffset, 256, sessionName);

    // 🔥 Start session
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

    // 🔥 Open trace
    EVENT_TRACE_LOGFILEA log = {};
    log.LoggerName = (LPSTR)sessionName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EventRecordCallback;

    s_hTrace = OpenTraceA(&log);

    if (s_hTrace == INVALID_PROCESSTRACE_HANDLE)
    {
        printf("[ETW] OpenTrace failed\n");
        return;
    }

    printf("[ETW] Listening...\n");

    TRACEHANDLE handles[] = { s_hTrace };

    // 🔥 LOOP contrôlée
    while (s_running)
    {
        ProcessTrace(handles, 1, NULL, NULL);
        Sleep(10);
    }

    ControlTraceA(hSession, sessionName, pProps, EVENT_TRACE_CONTROL_STOP);
}

void WINAPI EtwBridge::EventRecordCallback(PEVENT_RECORD pEvent)
{
    if (!s_userCallback)
        return;

    const EVENT_HEADER& hdr = pEvent->EventHeader;

    printf("[ETW] PID:%lu Opcode:%u ID:%u\n",
        hdr.ProcessId,
        hdr.EventDescriptor.Opcode,
        hdr.EventDescriptor.Id);

    DetectionEvent evt = {};
    evt.timestamp = GetTickCount64();
    evt.sourcePid = hdr.ProcessId;
    evt.fromEtw = true;

    // 🔥 Mapping simple fiable
    switch (hdr.EventDescriptor.Opcode)
    {
    case 1: // start
        evt.operationType = 10;
        evt.score = 10;
        break;

    case 2: // stop
        evt.operationType = 11;
        evt.score = 5;
        break;

    default:
        return;
    }

    s_userCallback(evt);
}