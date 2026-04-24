#include "DetectionEvents.h"
#include "NativeAPI.h"
#include "Hooks.h"
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

// Variable globale pour le scoring (sera utilisée par Hooks.cpp via 'extern')
DWORD g_lsassPid = 0;

// Fonction de recherche du processus LSASS
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

// Fonction de réponse : ce qui se passe quand l'EDR détecte une menace
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
    SIZE_T size = 4096;

    // Cet appel passera par ton Wrapper -> Ton Hook -> Et sera analysé
    NTSTATUS status = nt.AllocateVirtualMemory(
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

    return 0;
} 