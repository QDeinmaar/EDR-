#include "NativeAPI.h"
#include "DetectionEvents.h"
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

// Global variable to track lsass.exe PID

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

// Your AI callback - this is where detection happens

void MyDetectionCallback(const DetectionEvent& event)
{
    printf("\n========================================\n");
    printf("[EDR] Detection Event\n");
    printf("========================================\n");
    printf("Time: %llu ms\n", event.timestamp);
    printf("Source PID: %lu\n", event.sourcePid);
    printf("Target PID: %lu\n", event.targetPid);
    printf("Operation: ");
    
    switch(event.operationType)
    {
        case 1: printf("WriteVirtualMemory\n"); break;
        case 2: printf("CreateThreadEx\n"); break;
        case 3: printf("AllocateVirtualMemory\n"); break;
        case 4: printf("ProtectVirtualMemory\n"); break;
        case 5: printf("ReadVirtualMemory\n"); break;
        case 6: printf("SetValueKey (Registry)\n"); break;
        default: printf("Unknown (%d)\n", event.operationType);
    }
    
    if (event.size > 0)
        printf("Size: %llu bytes\n", event.size);
    
    if (event.address)
        printf("Address: 0x%p\n", event.address);
    
    if (event.pageProtection)
        printf("Protection: 0x%X\n", event.pageProtection);
    
    // DETECTION RULES

    bool alert = false;
    
    // Rule 1: RWX memory allocation (shellcode)

    if (event.operationType == 3 && event.pageProtection == PAGE_EXECUTE_READWRITE)
    {
        printf("\n[!!!] ALERT: RWX memory allocation detected! Possible shellcode preparation!\n");
        alert = true;
    }
    
    // Rule 2: Write to lsass.exe (credential dumping)

    if (event.operationType == 1 && event.targetPid == g_lsassPid)
    {
        printf("\n[!!!] ALERT: Write to lsass.exe! Possible credential dumping!\n");
        alert = true;
    }
    
    // Rule 3: Read from lsass.exe (credential dumping)

    if (event.operationType == 5 && event.targetPid == g_lsassPid)
    {
        printf("\n[!!!] ALERT: Read from lsass.exe! Possible credential dumping!\n");
        alert = true;
    }
    
    // Rule 4: Remote thread creation (code injection)

    if (event.operationType == 2 && event.sourcePid != event.targetPid)
    {
        printf("\n[!!!] ALERT: Remote thread creation detected! Possible code injection!\n");
        alert = true;
    }
    
    // Rule 5: Registry persistence

    if (event.operationType == 6)
    {
        printf("\n[!!!] ALERT: Registry modification detected! Possible persistence!\n");
        alert = true;
    }
    
    if (!alert)
        printf("\n[INFO] No immediate threat detected\n");
    
    printf("========================================\n\n");
    fflush(stdout);
}

int main()
{
    printf("Starting EDR...\n");
    fflush(stdout);
    
    // Find lsass.exe PID

    g_lsassPid = FindLsassPid();
    printf("lsass.exe PID: %lu\n", g_lsassPid);
    fflush(stdout);
    
    // Get NativeAPI instance

    NativeAPI& nt = NativeAPI::Instance();
    
    if (!nt.IsInitialized())
    {
        printf("ERROR: NativeAPI failed to initialize!\n");
        return 1;
    }
    
    printf("NativeAPI initialized successfully!\n");
    fflush(stdout);
    
    // Register detection callback

    nt.SetEventCallback(MyDetectionCallback);
    printf("DEBUG: Callback registered at address %p\n", MyDetectionCallback);
    fflush(stdout);
    printf("Detection callback registered\n\n");
    fflush(stdout);
    
    // TEST 1: Open current process (normal operation)

    printf("=== TEST 1: Opening current process ===\n");
    fflush(stdout);
    
    HANDLE hCurrentProcess = nt.OpenProcess(GetCurrentProcessId(), PROCESS_ALL_ACCESS);
    if (!hCurrentProcess)
    {
        printf("Failed to open current process! Error: %lu\n", GetLastError());
        fflush(stdout);
        return 1;
    }
    printf("Successfully opened current process (handle: 0x%p)\n", hCurrentProcess);
    fflush(stdout);
    
    // TEST 2: Allocate RWX memory (simulates shellcode)

    printf("\n=== TEST 2: Allocating RWX memory (simulates shellcode) ===\n");
    fflush(stdout);
    
    PVOID memAddress = nullptr;
    SIZE_T memSize = 4096;
    NTSTATUS status = nt.AllocateVirtualMemory(
        hCurrentProcess,
        &memAddress,
        memSize,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );
    
    if (NT_SUCCESS(status))
    {
        printf("RWX memory allocated at 0x%p (size: %llu bytes)\n", memAddress, memSize);
        fflush(stdout);
        
        // TEST 3: Write shellcode to allocated memory
        
        printf("\n=== TEST 3: Writing to allocated memory ===\n");
        fflush(stdout);
        
        unsigned char shellcode[] = {0x90, 0x90, 0x90, 0xCC}; // NOPs and int3
        SIZE_T written = 0;
        status = nt.WriteVirtualMemory(
            hCurrentProcess,
            memAddress,
            shellcode,
            sizeof(shellcode),
            &written
        );
        
        if (NT_SUCCESS(status))
        {
            printf("Wrote %llu bytes to memory at 0x%p\n", written, memAddress);
            fflush(stdout);
        }
        else
        {
            printf("WriteVirtualMemory failed: 0x%08X\n", status);
            fflush(stdout);
        }
        
        // TEST 4: Create thread to execute shellcode
      
        printf("\n=== TEST 4: Creating thread (simulates execution) ===\n");
        fflush(stdout);
        
        HANDLE hThread = nullptr;
        status = nt.CreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            hCurrentProcess,
            memAddress,
            nullptr,
            0
        );
        
        if (NT_SUCCESS(status))
        {
            printf("Thread created at entry point 0x%p\n", memAddress);
            fflush(stdout);
            
            // Wait a bit for thread to execute

            WaitForSingleObject(hThread, 100);
            nt.CloseHandle(hThread);
            printf("Thread executed and closed\n");
            fflush(stdout);
        }
        else
        {
            printf("CreateThreadEx failed: 0x%08X\n", status);
            fflush(stdout);
        }
    }
    else
    {
        printf("AllocateVirtualMemory failed: 0x%08X\n", status);
        fflush(stdout);
    }
    
    // Cleanup
  
    printf("\n=== Cleanup ===\n");
    fflush(stdout);
    nt.CloseHandle(hCurrentProcess);
    printf("Closed process handle\n");
    fflush(stdout);
    
    printf("\n=== Test Complete ===\n");
    printf("Press Enter to exit...\n");
    getchar();
    
    return 0;
}