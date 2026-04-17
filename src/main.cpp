#include "DetectionEvents.h"
#include "NativeAPI.h"
#include "Hooks.h"
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

DWORD g_lsassPid = 0;

// Find lsass.exe PID
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

void OnDetection(const DetectionEvent& evt) {
    int finalScore = evt.score;
    
    printf("[DETECT] PID %d -> %d | Op:%d | Score:%d\n",
           evt.sourcePid, evt.targetPid, evt.operationType, finalScore);
    
    if (finalScore >= 70) {
        if (evt.sourcePid != 0 && evt.sourcePid != GetCurrentProcessId()) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, evt.sourcePid);
            if (h) {
                TerminateProcess(h, 1);
                CloseHandle(h);
                printf("[KILL] Terminated PID %d\n", evt.sourcePid);
            }
        }
    }
}

int main() {
    printf("========================================\n");
    printf("       EDR - Endpoint Detection Response\n");
    printf("========================================\n\n");
    
    g_lsassPid = FindLsassPid();
    printf("[+] lsass.exe PID: %lu\n", g_lsassPid);
    
    NativeAPI& nt = NativeAPI::Instance();
    if (!nt.IsInitialized()) {
        printf("[-] ERROR: NativeAPI failed to initialize!\n");
        return 1;
    }
    printf("[+] NativeAPI initialized successfully!\n");
    
    nt.SetEventCallback(OnDetection);
    printf("[+] Detection callback registered\n");
    
    if (!InstallHooks()) {
        printf("[-] ERROR: Failed to install hooks!\n");
        return 1;
    }
    printf("[+] Hooks installed successfully!\n");
    
    printf("\n[+] EDR is RUNNING and protecting the system...\n");
    printf("[+] Press Enter to stop.\n\n");
    
    getchar();
    printf("[+] EDR stopped.\n");
    
    return 0;
}
    