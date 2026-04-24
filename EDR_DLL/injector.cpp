#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindProcessId(const char* processName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(snapshot, &pe))
    {
        do
        {
            if (_stricmp(pe.szExeFile, processName) == 0)
            {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return 0;
}

bool InjectDLL(DWORD pid, const char* dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess)
    {
        printf("[-] OpenProcess failed\n");
        return false;
    }

    SIZE_T size = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem)
    {
        printf("[-] VirtualAllocEx failed\n");
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, remoteMem, dllPath, size, NULL);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMem, 0, NULL);
    if (!hThread)
    {
        printf("[-] CreateRemoteThread failed\n");
        CloseHandle(hProcess);
        return false;
    }

    printf("[+] DLL injected successfully!\n");
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

int main()
{
    char dllPath[MAX_PATH];
    GetFullPathNameA("EDR.dll", MAX_PATH, dllPath, NULL);

    printf("[*] Target: notepad.exe\n");
    printf("[*] DLL: %s\n\n", dllPath);

    while (true)
    {
        DWORD pid = FindProcessId("notepad.exe");

        if (pid != 0)
        {
            printf("[+] Notepad found PID: %lu\n", pid);

            if (InjectDLL(pid, dllPath))
            {
                printf("[+] Injection done!\n");
            }
            else
            {
                printf("[-] Injection failed\n");
            }
            break;
        }

        printf("[*] Waiting for notepad...\n");
        Sleep(2000);
    }

    printf("\nDone.\n");
    getchar();
    return 0;
}