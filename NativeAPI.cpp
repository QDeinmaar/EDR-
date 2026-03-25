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

    m_NtClose = (pNtClose)GetProcAddress(m_hNtdll, "NtCloseProcess");
    if(!m_NtClose) return false;

    m_NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(m_hNtdll, "NtCreateProcessEx");
    if(!m_NtCreateProcessEx) return false;



}