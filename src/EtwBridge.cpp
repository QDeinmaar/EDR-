#include "EtwBridge.h"
#include <stdio.h>
#include <strsafe.h>

#pragma comment(lib, "tdh.lib")

// GUID Microsoft-Windows-Threat-Intelligence
static const GUID g_TI = {0xf4e1897c, 0xbb5d, 0x5668, {0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xb3, 0x46}};

EventCallback EtwBridge::s_userCallback = nullptr;
bool EtwBridge::s_running = false;
HANDLE EtwBridge::s_hThread = NULL;
TRACEHANDLE EtwBridge::s_hTrace = 0;

bool EtwBridge::Start(EventCallback callback) {
    if (!callback) return false;
    s_userCallback = callback;
    s_running = true;
    
    s_hThread = CreateThread(NULL, 0, EtwThreadProc, NULL, 0, NULL);
    return s_hThread != NULL;
}

void EtwBridge::Stop() {
    s_running = false;
    if (s_hTrace) {
        CloseTrace(s_hTrace);
        s_hTrace = 0;
    }
    if (s_hThread) {
        WaitForSingleObject(s_hThread, 3000);
        CloseHandle(s_hThread);
        s_hThread = NULL;
    }
}

DWORD WINAPI EtwBridge::EtwThreadProc(LPVOID) {
    // Démarrer session
    TRACEHANDLE hSession = 0;
    ULONG status;
    
    // Buffer pour propriétés + nom
    BYTE buffer[sizeof(EVENT_TRACE_PROPERTIES) + 256] = {0};
    EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)buffer;
    
    pProps->Wnode.BufferSize = sizeof(buffer);
    pProps->Wnode.ClientContext = 1;
    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    StringCbCopyW((wchar_t*)(buffer + pProps->LoggerNameOffset), 256, L"EDR-TI");
    
    status = StartTrace(&hSession, L"EDR-TI", pProps);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        printf("[ETW] StartTrace failed: %lu\n", status);
        return 1;
    }
    
    // Activer provider TI
    EnableTraceEx2(hSession, &g_TI, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0, 0xFFFFFFFFFFFFFFFFULL, 0, NULL);
    
    // Consumer
    EVENT_TRACE_LOGFILE log = {0};
    log.LoggerName = (LPWSTR)L"EDR-TI";
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EventRecordCallback;
    
    s_hTrace = OpenTrace(&log);
    if (s_hTrace == INVALID_PROCESSTRACE_HANDLE) {
        printf("[ETW] OpenTrace failed\n");
        ControlTrace(hSession, L"EDR-TI", pProps, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }
    
    printf("[ETW] Monitor started\n");
    ProcessTrace(&s_hTrace, 1, 0, 0);
    
    ControlTrace(hSession, L"EDR-TI", pProps, EVENT_TRACE_CONTROL_STOP);
    return 0;
}

void WINAPI EtwBridge::EventRecordCallback(PEVENT_RECORD pEvent) {
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, g_TI)) return;
    if (!s_userCallback) return;
    
    const EVENT_HEADER& hdr = pEvent->EventHeader;
    DWORD sourcePid = hdr.ProcessId;
    DWORD targetPid = 0;
    
    // Extraction PID cible depuis UserData
    // Structure TI: [SourcePID][TargetPID][...]
    if (pEvent->UserDataLength >= 8) {
        targetPid = *(DWORD*)((BYTE*)pEvent->UserData + 4);
    }
    
    // Mapper vers TON DetectionEvent
    DetectionEvent evt = {};
    evt.timestamp = GetTickCount64();
    evt.sourcePid = sourcePid;        //  L'attaquant (connu via ETW)
    evt.targetPid = targetPid;        //  La victime
    evt.status = STATUS_SUCCESS;      // L'opération a eu lieu (on kill après)
    
    // Mapping Event ID TI → ton operationType
    switch(hdr.EventDescriptor.Id) {
        case 1: // AllocVMRemote
            evt.operationType = 3;    // 3=Allocate dans ta convention
            evt.score = 30;
            evt.pageProtection = PAGE_EXECUTE_READWRITE; // Souvent RWX
            break;
            
        case 2: // WriteVMRemote  
            evt.operationType = 1;    // 1=Write
            evt.score = 20;
            break;
            
        case 3: // ProtectVMRemote
            evt.operationType = 4;    // 4=Protect (si tu as ce type)
            evt.score = 35;
            break;
            
        case 5: // QueueUserAPC
        case 6: // SetThreadContext (souvent utilisé pour hijack)
            evt.operationType = 2;    // 2=CreateThread/Execution
            evt.score = 45;
            evt.createFlags = 0;      // Pas un vrai thread mais exécution
            break;
            
        default:
            return; // Ignorer
    }
    
    // Bonus LSASS (utilise ta variable globale)
    if (targetPid == g_lsassPid) {
        evt.score += 80;
    }
    
    // Appeler TON callback existant
    s_userCallback(evt);
}