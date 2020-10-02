#pragma once
#include <Windows.h>
#include <iostream>
#include <Psapi.h>
#include <TlHelp32.h>
#include <memory>

#include "main.h"

namespace filesystem
{
    bool is_file_exists(const std::string& file_path);
}

namespace process
{
    using unique_handle = std::unique_ptr<void, decltype(&CloseHandle)>;

    __forceinline uint32_t find_process_id(const std::string& process_name)
    {
        PROCESSENTRY32 process_entry{ sizeof(PROCESSENTRY32W) };

        unique_handle snap_shot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL), &CloseHandle };

        if (snap_shot.get() == INVALID_HANDLE_VALUE)
        {
            return NULL;
        }

        Process32First(snap_shot.get(), &process_entry);

        if (!process_name.compare(process_entry.szExeFile))
        {
            return process_entry.th32ProcessID;
        }

        while (Process32Next(snap_shot.get(), &process_entry))
        {
            if (!process_name.compare(process_entry.szExeFile))
            {
                return process_entry.th32ProcessID;
            }
        }

        return NULL;
    }

    __forceinline uint32_t get_process_id(const std::string& process_name)
    {
        DWORD process_id;
        GetWindowThreadProcessId(FindWindow(NULL, process_name.c_str()), &process_id);
        return process_id;
    }

    __forceinline HMODULE get_base_address(const HANDLE& process_handle, bool close_handle = false)
    {
        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(process_handle, hMods, sizeof(hMods), &cbNeeded))
        {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                TCHAR szModName[MAX_PATH];
                if (GetModuleFileNameEx(process_handle, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
                {
                    std::string module_name(szModName);
                    if (module_name.find(PROCESS_NAME) != std::string::npos)
                    {
                        if (close_handle)
                            CloseHandle(process_handle);
                        return hMods[i];
                    }
                }
            }
        }

        return nullptr;
    }
}