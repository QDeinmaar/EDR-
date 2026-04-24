#include "DetectionEvents.h"
#include "NativeAPI.h"
#include "Hooks.h"
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <ntstatus.h>

DWORD g_lsassPid = 0;

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

DWORD FindProcessId(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    CloseHandle(snapshot);
    return 0;
}

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
    printf("[+] Callback enregistre.\n");

    if (!InstallHooks()) {
        printf("[-] ERROR: Hooking failed!\n");
        return 1;
    }
    printf("[+] Hooks installes.\n\n");

    // ========== ATTENDRE NOTEPAD.EXE ==========
    printf("[*] En attente de notepad.exe...\n");
    DWORD pid = 0;
    while (pid == 0) {
        pid = FindProcessId("notepad.exe");
        Sleep(1000);
    }
    printf("[+] notepad.exe trouve (PID: %lu)\n", pid);

    // ========== TEST COMPLET ==========
    HANDLE hProcess = nt.OpenProcess(pid, PROCESS_ALL_ACCESS);
    if (!hProcess) {
        printf("[-] Impossible d'ouvrir le processus %lu\n", pid);
        return 1;
    }

    printf("\n[*] TEST D'INJECTION COMPLET\n");

    // 1. Allocation RWX
    printf("\n[1] Allocation RWX...\n");
    PVOID baseAddr = nullptr;
    SIZE_T size = 4096;
    NTSTATUS status = nt.AllocateVirtualMemory(
        hProcess, &baseAddr, size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    printf("    Retour : 0x%08lX %s\n", status,
           status == STATUS_ACCESS_DENIED ? "(BLOQUE)" : "");

    // 2. Écriture mémoire (seulement si allocation réussie)
    if (NT_SUCCESS(status)) {
        printf("\n[2] Ecriture dans la memoire allouee...\n");
        unsigned char shellcode[] = {0x90, 0x90, 0xCC, 0x90};
        SIZE_T written = 0;
        status = nt.WriteVirtualMemory(
            hProcess, baseAddr, shellcode,
            sizeof(shellcode), &written
        );
        printf("    Retour : 0x%08lX %s\n", status,
               status == STATUS_ACCESS_DENIED ? "(BLOQUE)" : "");
    }

    // 3. Création de thread (seulement si écriture réussie)
    if (NT_SUCCESS(status) && baseAddr) {
        printf("\n[3] Creation de thread distant...\n");
        HANDLE hThread = nullptr;
        status = nt.CreateThreadEx(
            &hThread, THREAD_ALL_ACCESS, hProcess,
            baseAddr, nullptr, 0
        );
        printf("    Retour : 0x%08lX %s\n", status,
               status == STATUS_ACCESS_DENIED ? "(BLOQUE)" : "");
        if (hThread) nt.CloseHandle(hThread);
    }

    nt.CloseHandle(hProcess);

    // ========== BOUCLE INFINIE ==========
    printf("\n[+] EDR reste actif. Appuyez sur Ctrl+C pour arreter.\n");
    while (true) {
        Sleep(10000);
    }

    return 0;
} 