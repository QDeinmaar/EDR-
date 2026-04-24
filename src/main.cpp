#include "DetectionEvents.h"
#include "NativeAPI.h"
#include "Hooks.h"
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

DWORD g_lsassPid = 0;

// Recherche LSASS
DWORD FindLsassPid() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, "lsass.exe") == 0) {
                CloseHandle(snapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    CloseHandle(snapshot);
    return 0;
}

// Injection automatique dans un processus
void InjectIntoProcess(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess) return;
    
    SIZE_T size = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (remoteMem) {
        WriteProcessMemory(hProcess, remoteMem, dllPath, size, NULL);
        CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMem, 0, NULL);
        printf("[WATCHER] EDR.dll injectee dans PID %lu\n", pid);
    }
    CloseHandle(hProcess);
}

// Watcher : surveille les nouveaux notepad.exe
DWORD WINAPI InjectionWatcher(LPVOID) {
    char dllPath[MAX_PATH];
    GetFullPathNameA("EDR.dll", MAX_PATH, dllPath, NULL);
    
    while (true) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(snapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "notepad.exe") == 0) {
                    InjectIntoProcess(pe.th32ProcessID, dllPath);
                }
            } while (Process32Next(snapshot, &pe));
        }
        CloseHandle(snapshot);
        Sleep(3000);
    }
    return 0;
}

// Callback de détection
void OnDetection(const DetectionEvent& evt) {
    printf("\n[ALERT] PID %lu -> %lu | Op:%d | Score:%d\n",
           evt.sourcePid, evt.targetPid, evt.operationType, evt.score);

    if (evt.score >= 70) {
        if (evt.sourcePid != GetCurrentProcessId() && evt.sourcePid != 0) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, evt.sourcePid);
            if (h) {
                TerminateProcess(h, 1);
                CloseHandle(h);
                printf("[KILL] Processus %lu neutralise.\n", evt.sourcePid);
            }
        }
    }
}

int main() {
    printf("========================================\n");
    printf("       EDR - ACTIVE MONITORING          \n");
    printf("========================================\n\n");

    g_lsassPid = FindLsassPid();
    printf("[+] lsass.exe PID: %lu\n", g_lsassPid);

    NativeAPI& nt = NativeAPI::Instance();
    if (!nt.IsInitialized()) {
        printf("[-] ERROR: NativeAPI failed!\n");
        return 1;
    }

    nt.SetEventCallback(OnDetection);
    printf("[+] Callback enregistré.\n");

    if (!InstallHooks()) {
        printf("[-] ERROR: Hooking failed!\n");
        return 1;
    }
<<<<<<< HEAD
    printf("[+] Hooks installes.\n");

    // Lance le watcher d'injection
    CreateThread(NULL, 0, InjectionWatcher, NULL, 0, NULL);
    printf("[+] Watcher actif : tout nouveau Notepad sera protege.\n");

    // ========== BOUCLE INFINIE ==========
    printf("\n[+] EDR en attente d'attaques... (Ctrl+C pour quitter)\n");
    while (true) {
        Sleep(10000);
        // Optionnel : message périodique
        // printf("[*] EDR veille...\n");
    }

=======
    printf("[+] Hooks installés.\n");

    // --- SECTION TEST ---
    printf("\n[*] TEST D'AUTO-DETECTION : Tentative d'allocation RWX...\n");
    
    PVOID baseAddr = nullptr;
    SIZE_T size = 4096;
    
    // Appel du wrapper (5 arguments comme défini dans ton NativeWrapper.cpp)
    NTSTATUS status = nt.AllocateVirtualMemory(
        GetCurrentProcess(), 
        &baseAddr, 
        size,           
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE 
    );

    if (status == 0xC0000022) { 
        printf("[SUCCESS] L'EDR a BLOQUÉ l'allocation suspecte.\n");
    } else {
        printf("[!] Retour : 0x%lx\n", status);
    }

    printf("\n[+] EDR en cours... Appuyez sur Entrée pour quitter.\n");
    getchar();

>>>>>>> parent of 055fed5 (EDR Allocate Working !)
    return 0;
}