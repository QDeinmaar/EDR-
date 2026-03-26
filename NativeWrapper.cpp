#include "NativeAPI.h"
#include <ntstatus.h>

HANDLE NativeAPI::OpenProcess(DWORD processid, ACCESS_MASK DesiredAccess)
{
    if(!IsInitialized())
    {
        SetLastError(ERROR_NOT_READY);
        return nullptr;
    }

    HANDLE hProcess = nullptr;
    CLIENT_ID clientid;
    OBJECT_ATTRIBUTES objectAttributes;

    clientid.UniqueProcess = ULongToHandle(processid);
    clientid.UniqueThread = nullptr;

    InitializeObjectAttributes(&objectAttributes, nullptr, 0, nullptr,  nullptr);

    NTSTATUS status = m_NtOpenProcess(&hProcess,DesiredAccess, &objectAttributes, &clientid);

    if(!NT_SUCCESS(status))
    {
        SetLastError(RtlNtStatusToDosError(status)); // Convert the error to Win32 byt using (RtlNtStatusToDosError) and store it 
        return nullptr;
    }

    return hProcess;
}

bool NativeAPI::CloseHandle(HANDLE handle)
{
    if(!IsInitialized())
    {
        SetLastError(ERROR_NOT_READY);
        return false;
    }

    if(!handle || handle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    NTSTATUS status = m_NtClose(handle);

    if(!NT_SUCCESS(status))
    {
        SetLastError(RtlNtStatusToDosError(status));
        return false;
    }

    return true;
}

DWORD NativeAPI::GetProcessIdFromHandle(HANDLE hProcess)
{
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;

    NTSTATUS status = m_NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (NT_SUCCESS(status))
    {
        return (DWORD)(ULONG_PTR)pbi.UniqueProcessId;
    }

    return 0;
}


NTSTATUS NativeAPI::WriteVirtualMemory(
    HANDLE processHandle,
    PVOID baseAddress,
    PVOID buffer,
    SIZE_T bufferSize,
    PSIZE_T bytesWritten)
{

    if(!IsInitialized())
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    if(!processHandle || processHandle == INVALID_HANDLE_VALUE)
    {
        return STATUS_INVALID_HANDLE;
    }

    if(!buffer || bufferSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DWORD sourcePid = GetCurrentProcessId();
    DWORD targetid = GetProcessIdFromHandle(processHandle);

    if(m_callback)
    {
        DetectionEvent event;
        event.timestamp = GetTickCount64();
        event.sourcePid = sourcePid;
        event.targetPid = targetid;
        event.operationType = 1;
        event.address = baseAddress;
        event.size = bufferSize;

        m_callback(event);
    }

    NTSTATUS status = m_NtWriteVirtualMemory(
        processHandle,
        baseAddress,
        buffer,
        bufferSize,
        bytesWritten
    );

    if(m_callback)
    {
        DetectionEvent resultEvent;
        resultEvent.timestamp = GetTickCount64();
        resultEvent.sourcePid = sourcePid;
        resultEvent.targetPid = targetid;
        resultEvent.operationType = 1;
        resultEvent.status = status;

        m_callback(resultEvent);
    }

    return status;
}

NTSTATUS NativeAPI::CreateThreadEx(
    PHANDLE threadHandle,
    ACCESS_MASK desiredAccess,
    HANDLE processHandle,
    PVOID startAddress,
    PVOID parameter,
    ULONG createFlags)
{
    if(!IsInitialized())
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    if(!threadHandle || !processHandle || processHandle == INVALID_HANDLE_VALUE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PUSER_THREAD_START_ROUTINE startRoutine = (PUSER_THREAD_START_ROUTINE)startAddress; // Cast to do function pointer type

    DWORD sourcePid = GetCurrentProcessId();
    DWORD targetid = GetProcessIdFromHandle(threadHandle);

    if(m_callback)
    {
        DetectionEvent event;
        event.timestamp = GetTickCount64();
        event.sourcePid = sourcePid;
        event.targetPid = targetid;
        event.operationType = 2; // 2 for Creating Threads
        event.startAddress = startAddress;
        event.createFlags = createFlags;

        m_callback(event);

    }

    NTSTATUS status = m_NtCreateThreadEx(
        threadHandle,
        desiredAccess,
        nullptr,
        processHandle,
        startRoutine,
        parameter,
        createFlags,
        0,
        0,
        0,
        nullptr
    );

    if(m_callback)
    {
        DetectionEvent resultEvent;
        resultEvent.timestamp = GetTickCount64();
        resultEvent.sourcePid = sourcePid;
        resultEvent.targetPid = targetid;
        resultEvent.operationType = 2;
        resultEvent.status = status;

        m_callback(resultEvent);
    }

        return status;
}

NTSTATUS NativeAPI::AllocateVirtualMemory(
    HANDLE processHandle,
    PVOID* baseAddress,
    SIZE_T regionSize,
    ULONG allocationType,
    ULONG protect)
{
    if (!IsInitialized())
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!processHandle || processHandle == INVALID_HANDLE_VALUE)
    {
        return STATUS_INVALID_HANDLE;
    }

    DWORD sourcePid = GetCurrentProcessId();
    DWORD targetPid = GetProcessIdFromHandle(processHandle);

    
    if (m_callback)
    {
        DetectionEvent event;
        event.timestamp = GetTickCount64();
        event.sourcePid = sourcePid;
        event.targetPid = targetPid;
        event.operationType = 3;  // 3 = AllocateVirtualMemory
        event.address = baseAddress ? *baseAddress : nullptr;
        event.size = regionSize;
        event.pageProtection = protect;
        event.allocationType = allocationType;

        m_callback(event);
    }

    SIZE_T regionSizeCopy = regionSize;
    NTSTATUS status = m_NtAllocateVirtualMemory(
        processHandle,
        baseAddress,
        0,          // ZeroBits
        &regionSizeCopy,
        allocationType,
        protect
    );

    if (m_callback)
    {
        DetectionEvent resultEvent;
        resultEvent.timestamp = GetTickCount64();
        resultEvent.sourcePid = sourcePid;
        resultEvent.targetPid = targetPid;
        resultEvent.operationType = 3;
        resultEvent.address = baseAddress ? *baseAddress : nullptr;
        resultEvent.size = regionSizeCopy;
        resultEvent.status = status;

        m_callback(resultEvent);
    }

    return status;
}

NTSTATUS NativeAPI::ProtectVirtualMemory(
    HANDLE processHandle,
    PVOID* baseAddress,
    SIZE_T* regionSize,
    ULONG newProtect,
    PULONG oldProtect)
{
    if (!IsInitialized())
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!processHandle || processHandle == INVALID_HANDLE_VALUE)
    {
        return STATUS_INVALID_HANDLE;
    }

    DWORD sourcePid = GetCurrentProcessId();
    DWORD targetPid = GetProcessIdFromHandle(processHandle);

    if (m_callback)
    {
        DetectionEvent event;
        event.timestamp = GetTickCount64();
        event.sourcePid = sourcePid;
        event.targetPid = targetPid;
        event.operationType = 4;  // 4 = ProtectVirtualMemory
        event.address = baseAddress ? *baseAddress : nullptr;
        event.size = regionSize ? *regionSize : 0;
        event.pageProtection = newProtect;

        m_callback(event);
    }

    NTSTATUS status = m_NtProtectVirtualMemory(
        processHandle,
        baseAddress,
        regionSize,
        newProtect,
        oldProtect
    );

    if (m_callback)
    {
        DetectionEvent resultEvent;
        resultEvent.timestamp = GetTickCount64();
        resultEvent.sourcePid = sourcePid;
        resultEvent.targetPid = targetPid;
        resultEvent.operationType = 4;
        resultEvent.status = status;

        m_callback(resultEvent);
    }

    return status;
}

NTSTATUS NativeAPI::ReadVirtualMemory(
    HANDLE processHandle,
    PVOID baseAddress,
    PVOID buffer,
    SIZE_T bufferSize,
    PSIZE_T bytesRead)
{
    if (!IsInitialized())
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!processHandle || processHandle == INVALID_HANDLE_VALUE)
    {
        return STATUS_INVALID_HANDLE;
    }

    if (!buffer || bufferSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DWORD sourcePid = GetCurrentProcessId();
    DWORD targetPid = GetProcessIdFromHandle(processHandle);

    if (m_callback)
    {
        DetectionEvent event;
        event.timestamp = GetTickCount64();
        event.sourcePid = sourcePid;
        event.targetPid = targetPid;
        event.operationType = 5;  // 5 = ReadVirtualMemory
        event.address = baseAddress;
        event.size = bufferSize;

        m_callback(event);
    }

    NTSTATUS status = m_NtReadVirtualMemory(
        processHandle,
        baseAddress,
        buffer,
        bufferSize,
        bytesRead
    );

    if (m_callback)
    {
        DetectionEvent resultEvent;
        resultEvent.timestamp = GetTickCount64();
        resultEvent.sourcePid = sourcePid;
        resultEvent.targetPid = targetPid;
        resultEvent.operationType = 5;
        resultEvent.status = status;

        m_callback(resultEvent);
    }

    return status;
}

void NativeAPI::SetEventCallback(EventCallback callback)
{
    m_callback = callback;
}