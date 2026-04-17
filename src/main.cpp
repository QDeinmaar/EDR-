#include "DetectionEvents.h"
#include "EtwBridge.h"
#include "NativeAPI.h"
#include "Hooks.h"
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

DWORD g_lsassPid = 0;

// Élever les privilèges pour ETW
bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return success && GetLastError() == ERROR_SUCCESS;
}

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
    
    printf("[DETECT] PID %d -> %d | Op:%d | Score:%d | %s\n",
           evt.sourcePid, evt.targetPid, evt.operationType, 
           finalScore, evt.fromEtw ? "ETW" : "HOOK");
    
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
    // Élever les privilèges
    if (!EnableDebugPrivilege()) {
        printf("[-] Failed to enable debug privilege\n");
    } else {
        printf("[+] Debug privilege enabled\n");
    }
    
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
    
    // ============================================
    // TEST 1 : ETW AVANT les hooks
    // ============================================
    printf("\n=== Starting ETW first ===\n");
    
    EtwBridge etw;
    if (!etw.Start(OnDetection)) {
        printf("[-] WARNING: ETW failed to start\n");
    } else {
        printf("[+] ETW monitoring started\n");
    }
    
    // Ensuite les hooks
    printf("\n=== Installing hooks ===\n");
    if (!InstallHooks()) {
        printf("[-] ERROR: Failed to install hooks!\n");
        return 1;
    }
    printf("[+] Hooks installed successfully!\n");
    
    printf("\n[+] EDR is RUNNING and protecting the system...\n");
    printf("[+] Press Enter to stop.\n\n");
    
    getchar();
    
    etw.Stop();
    printf("[+] EDR stopped.\n");
    
    return 0;
}
    