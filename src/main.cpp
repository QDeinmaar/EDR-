#include "DetectionEvents.h"
#include "NativeAPI.h"
#include "Hooks.h"
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

// Variable globale pour le scoring (sera utilisée par Hooks.cpp via 'extern')
DWORD g_lsassPid = 0;

<<<<<<< HEAD
// Recherche LSASS
=======
// Fonction de recherche du processus LSASS
>>>>>>> parent of ed4e3fb (EDR working just need a quick debug)
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

<<<<<<< HEAD
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
=======
// Fonction de réponse : ce qui se passe quand l'EDR détecte une menace
>>>>>>> parent of ed4e3fb (EDR working just need a quick debug)
void OnDetection(const DetectionEvent& evt) {
    printf("\n[ALERT] PID %lu -> %lu | Op:%d | Score:%d\n",
           evt.sourcePid, evt.targetPid, evt.operationType, evt.score);

    if (evt.score >= 70) {
        if (evt.sourcePid != GetCurrentProcessId() && evt.sourcePid != 0) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, evt.sourcePid);
            if (h) {
                TerminateProcess(h, 1);
                CloseHandle(h);
                printf("[KILL] Processus %lu neutralisé.\n", evt.sourcePid);
            }
        }
    }
}

int main() {
    printf("========================================\n");
    printf("       EDR - ACTIVE MONITORING          \n");
    printf("========================================\n\n");

    // 1. Identification de LSASS
    g_lsassPid = FindLsassPid();
    printf("[+] lsass.exe PID: %lu\n", g_lsassPid);

    // 2. Initialisation NativeAPI
    NativeAPI& nt = NativeAPI::Instance();
    if (!nt.IsInitialized()) {
        printf("[-] ERROR: NativeAPI failed!\n");
        return 1;
    }

    // 3. Configuration du Callback
    nt.SetEventCallback(OnDetection);
    printf("[+] Callback enregistre.\n");

    // 4. Pose des Hooks
    if (!InstallHooks()) {
        printf("[-] ERROR: Hooking failed!\n");
        return 1;
    }
<<<<<<< HEAD
    printf("[+] Hooks installes.\n");

    // Lance le watcher d'injection
    CreateThread(NULL, 0, InjectionWatcher, NULL, 0, NULL);
    printf("[+] Watcher actif : tout nouveau Notepad sera protege.\n");

    // Petit test rapide (sur le processus courant, pas d'injection)
    printf("\n[*] TEST RAPIDE (auto-allocation, pas bloquante normalement)...\n");
    PVOID baseAddr = nullptr;
=======
    printf("[+] Hooks installe.\n");

// --- TEST D'INJECTION DISTANTE ---
printf("\n[*] TEST D'INJECTION : Recherche de notepad.exe...\n");

// Tu peux utiliser une fonction FindProcess ou entrer le PID manuellement depuis le gestionnaire des tâches
DWORD targetPid; 
printf("Entrez le PID de Notepad : ");
scanf("%lu", &targetPid);

// On ouvre un handle vers Notepad
HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);

if (hTarget) {
    printf("[*] Tentative d'allocation RWX dans le processus %lu...\n", targetPid);
    
    PVOID remoteAddr = nullptr;
>>>>>>> parent of ed4e3fb (EDR working just need a quick debug)
    SIZE_T size = 4096;

    // Cet appel passera par ton Wrapper -> Ton Hook -> Et sera analysé
    NTSTATUS status = nt.AllocateVirtualMemory(
<<<<<<< HEAD
        GetCurrentProcess(),
        &baseAddr,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (NT_SUCCESS(status)) {
        printf("[INFO] Allocation locale reussie (normal, pas bloque).\n");
        nt.CloseHandle(GetCurrentProcess());
    } else if (status == STATUS_ACCESS_DENIED) {
        printf("[INFO] Allocation locale BLOQUEE (score >= seuil).\n");
    } else {
        printf("[!] Retour : 0x%lx\n", status);
    }

    // Boucle infinie de surveillance
    printf("\n[+] EDR en attente d'attaques... (Ctrl+C pour quitter)\n");
    while (true) {
        Sleep(10000);
    }
=======
        hTarget, 
        &remoteAddr,  
        size, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );

    if (status == 0xC0000022) {
        printf("\n[VICTOIRE] L'EDR a detecte et BLOQUE l'injection distante dans Notepad !\n");
    } else {
        printf("\n[!] Echec du blocage. Retour : 0x%lx\n", status);
    }

    CloseHandle(hTarget);
} else {
    printf("[-] Impossible d'ouvrir Notepad. Lance-le en admin ?\n");
}

    printf("\n[+] EDR en cours... Appuyez sur Entree pour quitter.\n");
    getchar();
>>>>>>> parent of ed4e3fb (EDR working just need a quick debug)

    return 0;
}