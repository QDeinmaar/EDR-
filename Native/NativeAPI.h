#pragma once 
#include "NativeType.h"
#include "DetectionEvents.h"

class NativeAPI {
    public:
    static NativeAPI& Instance(); // Singleton access
    bool IsInitialized() const;

    DWORD GetProcessIdFromHandle(HANDLE hProcess);
    

    // public methods 

    bool CloseHandle(HANDLE handle);

    NTSTATUS WriteVirtualMemory(
    HANDLE processHandle,
    PVOID baseAddress,
    PVOID buffer,
    SIZE_T bufferSize,
    PSIZE_T bytesWritten);
    
    NTSTATUS CreateThreadEx(
    PHANDLE threadHandle,
    ACCESS_MASK desiredAddress,
    HANDLE processHandle,
    PVOID startAddress,
    PVOID parameter,
    ULONG createFlags);
    
    NTSTATUS AllocateVirtualMemory(
    HANDLE processHandle,
    PVOID* baseAddress,
    SIZE_T regionSize,
    ULONG allocationType,
    ULONG pageProtection);

    NTSTATUS ProtectVirtualMemory(
    HANDLE processHandle,
    PVOID* baseAddress,
    SIZE_T* regionSize,
    ULONG newProtect,
    PULONG oldProtect);

    NTSTATUS ReadVirtualMemory(
    HANDLE processHandle,
    PVOID baseAddress,
    PVOID buffer,
    SIZE_T bufferSize, // NumberOfBytesToRead 
    PSIZE_T bytesRead); // NUmberOfBytesRead

    NTSTATUS SetValueKey(
    HANDLE keyHandle,
    const wchar_t* valueName,
    ULONG type,
    PVOID data,
    ULONG dataSize);

    typedef void (*EventCallback)(const DetectionEvent& event);
    void SetEventCallback(EventCallback callback);

    // Adding HANDLES

    HANDLE OpenProcess(DWORD processId, ACCESS_MASK desiredAccess);

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
        pNtQueryInformationProcess m_NtQueryInformationProcess;

        pNtWriteVirtualMemory m_NtWriteVirtualMemory;
        pNtProtectVirtualMemory m_NtProtectVirtualMemory;
        pNtAllocateVirtualMemory m_NtAllocateVirtualMemory;
        pNtReadVirtualMemory m_NtReadVirtualMemory;

        pNtCreateThreadEx m_NtCreateThreadEx;
        pNtResumeThread m_NtResumeThread;

        pNtSetValueKey m_NtSetValueKey;

        EventCallback m_callback;

        pRtlInitUnicodeString m_RtlInitUnicodeString; // for string convenrsion

        // Handle and state
        HMODULE m_hNtdll;
        bool m_initialized;

};