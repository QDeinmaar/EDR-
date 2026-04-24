#include <windows.h>
#include <tlhelp32.h>
#include "NativeAPI.h"
#include "Hooks.h"
#include "DetectionEvents.h"
#include <stdio.h>

DWORD g_lsassPid = 0;

DWORD FindLsassPid()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &pe32))
    {
        do
        {
            if (_stricmp(pe32.szExeFile, "lsass.exe") == 0)
            {
                CloseHandle(snapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    CloseHandle(snapshot);
    return 0;
}

void MyDetectionCallback(const DetectionEvent& event)
{
    printf("[EDR] PID %lu -> %lu | Score: %d\n", 
           event.sourcePid, event.targetPid, event.score);
    fflush(stdout);
}

DWORD WINAPI InitEDR(LPVOID lpParam)
{
    Sleep(1000);
    
    printf("[EDR] Initializing in process %lu\n", GetCurrentProcessId());
    fflush(stdout);
    
    g_lsassPid = FindLsassPid();
    
    NativeAPI& nt = NativeAPI::Instance();
    if (!nt.IsInitialized())
    {
        printf("[EDR] NativeAPI failed to initialize\n");
        return 0;
    }
    
    nt.SetEventCallback(MyDetectionCallback);
    
    if (!InstallHooks())
    {
        printf("[EDR] Failed to install hooks\n");
        return 0;
    }
    
    printf("[EDR] Ready in process %lu\n", GetCurrentProcessId());
    fflush(stdout);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        CreateThread(NULL, 0, InitEDR, NULL, 0, NULL);
    }
    return TRUE;
}