#include "EtwBridge.h"
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <stdio.h>
#include <strsafe.h>

#pragma comment(lib, "tdh.lib")

// ✅ Provider correct (Kernel Process)
static const GUID g_Provider =
{ 0x22fb2cd6, 0x0e7b, 0x422b,{ 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };

// Variables statiques
TRACEHANDLE EtwBridge::s_hTrace = 0;
HANDLE EtwBridge::s_hThread = NULL;
std::atomic<bool> EtwBridge::s_running{ false };
EventCallback EtwBridge::s_userCallback = nullptr;

DWORD WINAPI EtwBridge::EtwThreadProcStatic(LPVOID param)
{
    printf("[ETW] STATIC THREAD ENTRY\n");

    EtwBridge* pThis = (EtwBridge*)param;

    if (!pThis)
    {
        printf("[ETW] pThis is NULL!\n");
        return 0;
    }

    pThis->EtwThreadProc();
    return 0;
}

bool EtwBridge::Start(EventCallback callback)
{
    if (!callback) return false;

    s_userCallback = callback;
    s_running = true;

    s_hThread = CreateThread(NULL, 0, EtwThreadProcStatic, this, 0, NULL);

    if (!s_hThread)
    {
        printf("[ETW] Thread creation failed: %lu\n", GetLastError());
        return false;
    }

    printf("[ETW] Thread handle: %p\n", s_hThread);

    // petit délai debug
    Sleep(200);

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
}

void EtwBridge::EtwThreadProc()
{

    printf("[ETW] THREAD STARTED\n");

    ULONG status;
    TRACEHANDLE hSession = 0;

    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 256] = { 0 };
    EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)buffer;

    pProps->Wnode.BufferSize = sizeof(buffer);
    pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProps->Wnode.ClientContext = 1;
    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    const char* sessionName = "EDRSession";
    strcpy_s((char*)buffer + pProps->LoggerNameOffset, 256, sessionName);

    printf("[ETW] Starting session...\n");

    status = StartTraceA(&hSession, sessionName, pProps);

    if (status == ERROR_ALREADY_EXISTS)
    {
        printf("[ETW] Session exists, stopping...\n");

        ULONG stopStatus = ControlTraceA(0, sessionName, pProps, EVENT_TRACE_CONTROL_STOP);

        if (stopStatus != ERROR_SUCCESS)
        {
            printf("[ETW] Failed to stop existing session: %lu\n", stopStatus);
            return;
        }

        status = StartTraceA(&hSession, sessionName, pProps);
    }

    if (status != ERROR_SUCCESS)
    {
        printf("[ETW] StartTrace failed: %lu\n", status);
        return;
    }

    printf("[ETW] Session started!\n");

    // ✅ Enable provider
    status = EnableTraceEx2(
        hSession,
        &g_Provider,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    );

    if (status != ERROR_SUCCESS)
    {
        printf("[ETW] EnableTraceEx2 failed: %lu\n", status);
        return;
    }

    printf("[ETW] Provider enabled!\n");

    // ✅ Open trace
    EVENT_TRACE_LOGFILEA log = { 0 };
    log.LoggerName = (LPSTR)sessionName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EventRecordCallback;

    s_hTrace = OpenTraceA(&log);

    if (s_hTrace == INVALID_PROCESSTRACE_HANDLE)
    {
        printf("[ETW] OpenTrace failed\n");
        return;
    }

    printf("[ETW] Listening for events...\n");

    ProcessTrace(&s_hTrace, 1, NULL, NULL);

    ControlTraceA(hSession, sessionName, pProps, EVENT_TRACE_CONTROL_STOP);
}

void WINAPI EtwBridge::EventRecordCallback(PEVENT_RECORD pEvent)
{
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, g_Provider))
        return;

    if (!s_userCallback)
        return;

    DWORD pid = pEvent->EventHeader.ProcessId;

    DetectionEvent evt = {};
    evt.timestamp = GetTickCount64();
    evt.sourcePid = pid;
    evt.fromEtw = true;

    // 🔥 Mapping simple (Kernel Process events)
    switch (pEvent->EventHeader.EventDescriptor.Id)
    {
    case 1: // Process Start
        evt.operationType = 10;
        evt.score = 10;
        break;

    case 2: // Process Stop
        evt.operationType = 11;
        evt.score = 5;
        break;

    case 3: // Thread Start
        evt.operationType = 2;
        evt.score = 20;
        break;

    default:
        return;
    }

    s_userCallback(evt);
}