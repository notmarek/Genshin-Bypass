#pragma once

#include "memory_utils.hpp"

#define END_OF_FUNCTION(x) void x ## _eof_marker() { }
#define FUNCTION_SIZE(x) ((unsigned long long)&x ## _eof_marker - (unsigned long long)&x)

namespace injector
{
	typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
	typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);
	typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

	typedef struct _LOADER_CONTEXT
	{
		LPVOID image_base;

		PIMAGE_NT_HEADERS nt_headers;
		PIMAGE_BASE_RELOCATION base_relocation;
		PIMAGE_IMPORT_DESCRIPTOR import_directory;

		pLoadLibraryA fnLoadLibraryA;
		pGetProcAddress fnGetProcAddress;
	} LOADER_CONTEXT, *PLOADER_CONTEXT;

	bool inject(const std::string& dll_path);
}