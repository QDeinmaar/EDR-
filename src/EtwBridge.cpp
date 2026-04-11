#include "EtwBridge.h"
#include <stdio.h>
#include <strsafe.h>
#include <ntstatus.h>

#pragma comment(lib, "tdh.lib")

// GUID Microsoft-Windows-Threat-Intelligence
// {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
static const GUID g_TI = {0xf4e1897c, 0xbb5d, 0x5668, {0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44}};

// Variables statiques
EventCallback EtwBridge::s_userCallback = nullptr;
std::atomic<bool> EtwBridge::s_running{false};
TRACEHANDLE EtwBridge::s_hTrace = 0;

// Variable externe pour lsass
extern DWORD g_lsassPid;

bool EtwBridge::Start(EventCallback callback) {
    if (!callback) return false;
    s_userCallback = callback;
    s_running = true;
    m_running = true;
    
    try {
        m_thread = std::thread(&EtwBridge::EtwThreadProc, this);
        return true;
    } catch (...) {
        printf("[ETW] Failed to create thread\n");
        return false;
    }
}

void EtwBridge::Stop() {
    s_running = false;
    m_running = false;
    if (s_hTrace) {
        CloseTrace(s_hTrace);
        s_hTrace = 0;
    }
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

void EtwBridge::EtwThreadProc() {
    TRACEHANDLE hSession = 0;
    ULONG status;
    
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 256] = {0};
    EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)buffer;
    
    pProps->Wnode.BufferSize = sizeof(buffer);
    pProps->Wnode.ClientContext = 1;
    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    
    char loggerName[] = "EDR-TI";
    strcpy_s((char*)buffer + pProps->LoggerNameOffset, 256, loggerName);
    
    // Démarrer la session ETW
    status = StartTraceA(&hSession, "EDR-TI", pProps);
    if (status == ERROR_ALREADY_EXISTS) {
        ControlTraceA(0, "EDR-TI", pProps, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceA(&hSession, "EDR-TI", pProps);
    }
    
    if (status != ERROR_SUCCESS) {
        printf("[ETW] StartTrace failed: %lu\n", status);
        return;
    }
    
    // Activer le provider Threat Intelligence
    EnableTraceEx2(hSession, &g_TI, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0, 0xFFFFFFFFFFFFFFFFULL, 0, NULL);
    
    // Ouvrir la trace pour recevoir les événements
    EVENT_TRACE_LOGFILEA log = {0};
    char loggerNameTrace[] = "EDR-TI";
    log.LoggerName = loggerNameTrace;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EventRecordCallback;
    
    s_hTrace = OpenTraceA(&log);
    if (s_hTrace == INVALID_PROCESSTRACE_HANDLE) {
        printf("[ETW] OpenTrace failed\n");
        ControlTraceA(hSession, "EDR-TI", pProps, EVENT_TRACE_CONTROL_STOP);
        return;
    }
    
    printf("[ETW] Monitor started successfully!\n");
    ProcessTrace(&s_hTrace, 1, 0, 0);
    
    ControlTraceA(hSession, "EDR-TI", pProps, EVENT_TRACE_CONTROL_STOP);
}

void WINAPI EtwBridge::EventRecordCallback(PEVENT_RECORD pEvent) {
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, g_TI)) return;
    if (!s_userCallback) return;
    
    const EVENT_HEADER& hdr = pEvent->EventHeader;
    DWORD sourcePid = hdr.ProcessId;
    DWORD targetPid = 0;
    
    // Extraction du PID cible depuis UserData
    // La structure TI contient généralement [PID source, PID cible]
    if (pEvent->UserDataLength >= 8) {
        targetPid = *(DWORD*)((BYTE*)pEvent->UserData + 4);
    }
    
    DetectionEvent evt = {};
    evt.timestamp = GetTickCount64();
    evt.sourcePid = sourcePid;
    evt.targetPid = targetPid;
    evt.fromEtw = true;
    
    // Mapping des Event ID vers ton operationType
    switch(hdr.EventDescriptor.Id) {
        case 1: // AllocateVirtualMemoryRemote
            evt.operationType = 3;
            evt.score = 30;
            evt.pageProtection = PAGE_EXECUTE_READWRITE;
            break;
            
        case 2: // WriteVirtualMemoryRemote
            evt.operationType = 1;
            evt.score = 20;
            break;
            
        case 3: // ProtectVirtualMemoryRemote
            evt.operationType = 4;
            evt.score = 35;
            break;
            
        case 5: // QueueUserAPC
        case 6: // SetThreadContext
            evt.operationType = 2;
            evt.score = 45;
            evt.createFlags = 0;
            break;
            
        default:
            return; // Ignorer les autres événements
    }
    
    // Bonus LSASS
    if (targetPid == g_lsassPid) {
        evt.score += 80;
    }
    
    s_userCallback(evt);
}