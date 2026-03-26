#include "NativeAPI.h"
#include <stdio.h>
#include <windows.h>

// just to test is everything working ( everything is working )
int main()
{
    printf("Starting EDR...\n");

    NativeAPI& nt = NativeAPI::Instance();

    printf("Checking initialization...\n");

    if (!nt.IsInitialized())
    {
        printf("ERROR: NativeAPI failed to initialize!\n");
        return 1;
    }

    printf("NativeAPI initialized successfully!\n");
    return 0;
}