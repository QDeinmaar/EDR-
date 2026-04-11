#pragma once
#include "DetectionEvents.h"
#include <windows.h>
#include <evntcons.h>
#include <tdh.h>
#include <thread>
#include <atomic>

class EtwBridge {
public:

    bool Start(EventCallback callback);
    void Stop();
    bool IsRunning() const { return m_running; }
    
private:

    static DWORD WINAPI EtwThreadProcStatic(LPVOID param);
    void EtwThreadProc();
    static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent);
    
    static EventCallback s_userCallback;
    static std::atomic<bool> s_running;
    static TRACEHANDLE s_hTrace;
    
    std::thread m_thread;
    bool m_running;
    static HANDLE s_hThread;

};