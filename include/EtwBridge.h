#pragma once
#include "DetectionEvents.h"
#include <windows.h>
#include <evntcons.h>
#include <tdh.h>

// Thread ETW qui alimente ton DetectionEvent existant
class EtwBridge {
public:
    bool Start(EventCallback callback);  // Ton callback existant
    void Stop();
    bool IsRunning() const { return m_running; }
    
private:
    static DWORD WINAPI EtwThreadProc(LPVOID param);
    static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent);
    
    static EventCallback s_userCallback;  // Ton callback DetectionEvent
    static bool s_running;
    static HANDLE s_hThread;
    static TRACEHANDLE s_hTrace;

    bool m_running;
};