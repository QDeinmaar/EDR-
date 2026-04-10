#include "NativeAPI.h"
#include "DetectionEvents.h"
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

// AI callback - detection
void MyDetectionCallback(const DetectionEvent& event)
{
    bool isSelf = (event.sourcePid == event.targetPid);
    bool isCritical = (event.targetPid == g_lsassPid);
    
    printf("\n========================================\n");
    printf("[EDR] %s\n", isSelf ? "Self-operation" : "Cross-process operation");
    printf("========================================\n");
    printf("Source PID: %lu | Target PID: %lu\n", event.sourcePid, event.targetPid);
    printf("Score: %d\n", event.score);
    
    switch(event.operationType)
    {
        case 1: printf("Operation: WriteVirtualMemory\n"); break;
        case 2: printf("Operation: CreateThreadEx\n"); break;
        case 3: printf("Operation: AllocateVirtualMemory\n"); break;
        case 4: printf("Operation: ProtectVirtualMemory\n"); break;
        case 5: printf("Operation: ReadVirtualMemory\n"); break;
        default: printf("Operation: Unknown\n");
    }
    
    if (event.size > 0) printf("Size: %llu bytes\n", event.size);
    if (event.address) printf("Address: 0x%p\n", event.address);
    if (event.pageProtection) printf("Protection: 0x%X\n", event.pageProtection);
    
    if (event.score >= 70)
        printf("\n[!!!] BLOCKED by hook\n");
    else if (event.score >= 40)
        printf("\n[!!!] ALERT: Suspicious activity\n");
    else
        printf("\n[INFO] Monitored\n");
    
    printf("========================================\n\n");
    fflush(stdout);
}

int main()
{
    printf("========================================\n");
    printf("       EDR - Endpoint Detection Response\n");
    printf("========================================\n\n");
    
    // Find lsass.exe PID
    g_lsassPid = FindLsassPid();
    printf("[+] lsass.exe PID: %lu\n", g_lsassPid);
    
    // Get NativeAPI instance
    NativeAPI& nt = NativeAPI::Instance();
    
    if (!nt.IsInitialized())
    {
        printf("[-] ERROR: NativeAPI failed to initialize!\n");
        return 1;
    }
    
    printf("[+] NativeAPI initialized successfully!\n");
    
    // Register detection callback
    nt.SetEventCallback(MyDetectionCallback);
    printf("[+] Detection callback registered\n");
    
    // Install hooks
    if (!InstallHooks())
    {
        printf("[-] ERROR: Failed to install hooks!\n");
        return 1;
    }
    
    printf("\n[+] EDR is RUNNING and protecting the system...\n");
    printf("[+] Press Ctrl+C to stop.\n\n");
    
    // Boucle infinie - EDR reste actif
    while(true)
    {
        Sleep(1000);  // Attendre 1 seconde
        // Tu peux ajouter des vérifications périodiques ici
        // Ex: vérifier si lsass.exe a changé de PID, etc.
    }
    
    return 0;
}