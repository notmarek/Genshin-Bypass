// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <iostream>

unsigned long main_thread(void*)
{
    if (!AllocConsole())
    {
        return 1;
    }

    freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);
    freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
    SetConsoleTitle(TEXT("Genshin [Corrupted]"));

    printf("\nHello World.\n\n");
    printf("[+] base address: 0x%llX\n", GetModuleHandle(0));

    MessageBox(NULL, TEXT("Hello World"), TEXT("Hello World"), MB_OK);

    FreeConsole();
    return 0;
}


BOOL APIENTRY DllMain(HMODULE module_handle, DWORD call_reason, LPVOID reserved)
{
    if (call_reason == DLL_PROCESS_ATTACH)
    {
        if (const auto handle = CreateThread(nullptr, 0, &main_thread, nullptr, 0, nullptr); handle != nullptr)
        {
            CloseHandle(handle);
        }

        return TRUE;
    }

    return TRUE;
}
