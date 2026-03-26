#include "NativeAPI.h"
#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include <ntdef.h>

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
}

// Destructeur
NativeAPI::~NativeAPI(){}

bool NativeAPI::Initialize()
{
    // Getting ntdll handle
    m_hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!m_hNtdll)
    {
        m_hNtdll = LoadLibraryW(L"ntdll.dll");
        if (!m_hNtdll)
        {
            return false;
        }
    }

    // We Load all our typedef
    m_NtOpenProcess = (pNtOpenProcess)GetProcAddress(m_hNtdll, "NtOpenProcess");
    if (!m_NtOpenProcess) return false;

    m_NtClose = (pNtClose)GetProcAddress(m_hNtdll, "NtClose");
    if(!m_NtClose) return false;

    m_NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(m_hNtdll, "NtCreateProcessEx");
    if(!m_NtCreateProcessEx) return false;

    m_NtCreateUserProcess = (pNtCreateUserProcess)GetProcAddress(m_hNtdll, "NtCreateUserProcess");
    if(!m_NtCreateUserProcess) return false;

    m_NtTerminateProcess = (pNtTerminateProcess)GetProcAddress(m_hNtdll, "NtTerminateProcess");
    if(!m_NtTerminateProcess) return false;

    m_NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(m_hNtdll, "NtQuerySystemInformation");
    if(!m_NtQuerySystemInformation) return false;

    m_NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(m_hNtdll, "NtQueryInformationProcess");
    if (!m_NtQueryInformationProcess) return false;

    m_NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(m_hNtdll, "NtWriteVirtualMemory");
    if(!m_NtWriteVirtualMemory) return false;

     m_NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(m_hNtdll, "NtProtectVirtualMemory");
    if (!m_NtProtectVirtualMemory) return false;

    m_NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(m_hNtdll, "NtAllocateVirtualMemory");
    if (!m_NtAllocateVirtualMemory) return false;

    m_NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(m_hNtdll, "NtReadVirtualMemory");
    if (!m_NtReadVirtualMemory) return false;

    m_NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(m_hNtdll, "NtCreateThreadEx");
    if (!m_NtCreateThreadEx) return false;

    m_NtResumeThread = (pNtResumeThread)GetProcAddress(m_hNtdll, "NtResumeThread");
    if (!m_NtResumeThread) return false;

    m_NtSetValueKey = (pNtSetValueKey)GetProcAddress(m_hNtdll, "NtSetValueKey");
    if (!m_NtSetValueKey) return false;

    m_initialized = true;
    return true;
}   

bool NativeAPI::IsInitialized() const
{
    return m_initialized;
}
    

