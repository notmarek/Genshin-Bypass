#pragma once
#include "main.h"

#define ENTER_FUNC() printf("[>] entering %s\n", __FUNCTION__)
#define LEAVE_FUNC() printf("[<] leaving %s\n", __FUNCTION__)

namespace mem_utils
{
	inline uint32_t process_id;
	inline HANDLE process_handle;
	inline uint64_t base_address;

	bool init();

	template<class T>
	__forceinline T read(uint64_t address)
	{
		T buffer;

		ReadProcessMemory(
			process_handle,
			(LPCVOID)(address),
			buffer,
			sizeof(T),
			nullptr
		);

		return buffer;
	}

	template<class T>
	__forceinline bool write(uint64_t address, T value)
	{
		return WriteProcessMemory(
			process_handle,
			(LPVOID)(address),
			&value,
			sizeof(T),
			nullptr
		);
	}

	__forceinline bool write_raw(uint64_t address, void* buffer, size_t size)
	{
		return WriteProcessMemory(
			process_handle,
			(LPVOID)(address),
			buffer,
			size,
			nullptr
		);
	}

	__forceinline LPVOID alloc(LPVOID base_address, SIZE_T size, DWORD alloc_type, DWORD protection)
	{
		return VirtualAllocEx(
			process_handle,
			base_address,
			size,
			alloc_type,
			protection
		);
	}
}