#include "NativeAPI.h"

HANDLE NativeAPI::OpenProcess(DWORD processid, ACCESS_MASK DesiredAccess)
{
    if(!IsInitialized)
    {
        SetLastError(ERROR_NOT_READY);
        return nullptr;
    }

    HANDLE hProcess = nullptr;
    CLIENT_ID clientid;
    POBJECT_ATTRIBUTES ObjectAttributes;

    clientid.UniqueProcess = UlongToHandle(processid);
    clientid.UniqueThread = nullptr;

}