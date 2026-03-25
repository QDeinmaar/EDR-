#include "NativeAPI.h"

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
        SetLastError(RtlNtStatusToDosError(status)); // // Convert the error to Win32 byt using (RtlNtStatusToDosError) and store it 
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