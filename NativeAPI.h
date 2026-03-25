#pragma once 
#include "NativeType.h"


class NativeAPI {
    public:
    static NativeAPI& Instance(); // Singleton access

    private:
        NativeAPI();
        ~NativeAPI();

        // did this to prevent coping 
        NativeAPI(const NativeAPI&) = delete;
        NativeAPI& operator=(const NativeAPI&) = delete;

        bool Initialize();

        // Function pointers to all our typedefs
        pNtOpenProcess m_NtOpenProcess;
        pNtCreateProcessEx m_NtCreateProcessEx;
        pNtCreateUserProcess m_NtCreateUserProcess;
        pNtTerminateProcess m_NtTerminateProcess;

        pNtClose m_NtClose;

        pNtQuerySystemInformation m_NtQuerySystemInformation;

        pNtWriteVirtualMemory m_NtWriteVirtualMemory;
        pNtProtectVirtualMemory m_NtProtectVirtualMemory;
        pNtAllocateVirtualMemory m_NtAllocateVirtualMemory;
        pNtReadVirtualMemory m_NtReadVirtualMemory;

        pNtCreateThreadEx m_NtCreateThreadEx;
        pNtResumeThread m_NtResumeThread;

        pNtSetValueKey m_NtSetValueKey;

        // Handle and state
        HMODULE m_hNtdll;
        bool m_initialized;

};