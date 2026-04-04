#include "NativeAPI.h"
#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include <ntdef.h>
#include <iostream>

NativeAPI& NativeAPI::Instance()
{
    static NativeAPI instance;
    return instance;
}

NativeAPI::NativeAPI() : m_hNtdll(nullptr) , m_initialized(false) 
{
    m_NtOpenProcess = nullptr;
    m_NtCreateProcessEx = nullptr;
    m_NtCreateUserProcess = nullptr;
    m_NtTerminateProcess = nullptr;

    m_NtClose = nullptr;

    m_NtQuerySystemInformation = nullptr;
    m_NtWriteVirtualMemory = nullptr;
    m_NtProtectVirtualMemory = nullptr;
    m_NtAllocateVirtualMemory = nullptr;
    m_NtReadVirtualMemory = nullptr;

    m_NtCreateThreadEx = nullptr;
    m_NtResumeThread = nullptr;

    m_NtSetValueKey = nullptr;

    m_callback = nullptr;

    printf("Calling Initialize...\n");
    fflush(stdout);
    
    if (!Initialize())
    {
        printf("ERROR: Initialize() failed!\n");
        fflush(stdout);
    }
    else
    {
        printf("Initialize() succeeded!\n");
        fflush(stdout);
    }

}

// Destructeur
NativeAPI::~NativeAPI(){}

bool NativeAPI::Initialize()
{
    m_initialized = true;

    m_hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!m_hNtdll)
    {
        m_hNtdll = LoadLibraryW(L"ntdll.dll");
        if (!m_hNtdll)
        {
            printf("ERROR: Failed to load ntdll.dll\n");
            return false;
        }
    }

    printf("ntdll.dll loaded at 0x%p\n", m_hNtdll);

    m_NtOpenProcess = (pNtOpenProcess)GetProcAddress(m_hNtdll, "NtOpenProcess");
    if (!m_NtOpenProcess) { printf("FAILED: NtOpenProcess\n"); return false; }
    printf("OK: NtOpenProcess\n");

    m_NtClose = (pNtClose)GetProcAddress(m_hNtdll, "NtClose");
    if (!m_NtClose) { printf("FAILED: NtClose\n"); return false; }
    printf("OK: NtClose\n");

    m_NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(m_hNtdll, "NtCreateProcessEx");
    if (!m_NtCreateProcessEx) { printf("FAILED: NtCreateProcessEx\n"); return false; }
    printf("OK: NtCreateProcessEx\n");

    m_NtCreateUserProcess = (pNtCreateUserProcess)GetProcAddress(m_hNtdll, "NtCreateUserProcess");
    if (!m_NtCreateUserProcess) { printf("FAILED: NtCreateUserProcess\n"); return false; }
    printf("OK: NtCreateUserProcess\n");

    m_NtTerminateProcess = (pNtTerminateProcess)GetProcAddress(m_hNtdll, "NtTerminateProcess");
    if (!m_NtTerminateProcess) { printf("FAILED: NtTerminateProcess\n"); return false; }
    printf("OK: NtTerminateProcess\n");

    m_NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(m_hNtdll, "NtQuerySystemInformation");
    if (!m_NtQuerySystemInformation) { printf("FAILED: NtQuerySystemInformation\n"); return false; }
    printf("OK: NtQuerySystemInformation\n");

    m_NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(m_hNtdll, "NtWriteVirtualMemory");
    if (!m_NtWriteVirtualMemory) { printf("FAILED: NtWriteVirtualMemory\n"); return false; }
    printf("OK: NtWriteVirtualMemory\n");

    m_NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(m_hNtdll, "NtProtectVirtualMemory");
    if (!m_NtProtectVirtualMemory) { printf("FAILED: NtProtectVirtualMemory\n"); return false; }
    printf("OK: NtProtectVirtualMemory\n");

    m_NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(m_hNtdll, "NtAllocateVirtualMemory");
    if (!m_NtAllocateVirtualMemory) { printf("FAILED: NtAllocateVirtualMemory\n"); return false; }
    printf("OK: NtAllocateVirtualMemory\n");

    m_NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(m_hNtdll, "NtReadVirtualMemory");
    if (!m_NtReadVirtualMemory) { printf("FAILED: NtReadVirtualMemory\n"); return false; }
    printf("OK: NtReadVirtualMemory\n");

    m_NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(m_hNtdll, "NtCreateThreadEx");
    if (!m_NtCreateThreadEx) { printf("FAILED: NtCreateThreadEx\n"); return false; }
    printf("OK: NtCreateThreadEx\n");

    m_NtResumeThread = (pNtResumeThread)GetProcAddress(m_hNtdll, "NtResumeThread");
    if (!m_NtResumeThread) { printf("FAILED: NtResumeThread\n"); return false; }
    printf("OK: NtResumeThread\n");

    m_NtSetValueKey = (pNtSetValueKey)GetProcAddress(m_hNtdll, "NtSetValueKey");
    if (!m_NtSetValueKey) { printf("FAILED: NtSetValueKey\n"); return false; }
    printf("OK: NtSetValueKey\n");

    m_NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(m_hNtdll, "NtQueryInformationProcess");
    if (!m_NtQueryInformationProcess) { printf("FAILED: NtQueryInformationProcess\n"); return false; }
    printf("OK: NtQueryInformationProcess\n");

    m_RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(m_hNtdll, "RtlInitUnicodeString");
    if (!m_RtlInitUnicodeString) { printf("FAILED: RtLInitUnicodeString\n"); return false; }
    printf("OK: RtLInitUnicodeString\n");

    m_initialized = true;
    printf("ALL FUNCTIONS LOADED SUCCESSFULLY!\n");
    return true;
}

bool NativeAPI::IsInitialized() const
{
    return m_initialized;
}



