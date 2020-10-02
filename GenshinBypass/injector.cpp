#include "injector.hpp"

DWORD __stdcall load_library(LPVOID memory)
{
    injector::PLOADER_CONTEXT loader_context = (injector::PLOADER_CONTEXT)memory;

    PIMAGE_BASE_RELOCATION base_relocation = loader_context->base_relocation;

    DWORD64 size_of_relocation = (DWORD64)(
        (LPBYTE)loader_context->image_base
        -
        loader_context->nt_headers->OptionalHeader.ImageBase
        );

    /* image relocations */
    while (base_relocation->VirtualAddress)
    {
        if (base_relocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            PWORD relocation_list = (PWORD)(base_relocation + 1);
            
            for (int i = 0; i < 
                ( base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof(DWORD);
                i++)
            {
                if (relocation_list[i])
                {
                    PDWORD ptr = (PDWORD)((
                        (LPBYTE)loader_context->image_base
                        +
                        ( (uint64_t)base_relocation->VirtualAddress + (relocation_list[i] & 0xFFF) )
                    ));
                    *ptr += size_of_relocation;
                }
            }
        }

        base_relocation = (PIMAGE_BASE_RELOCATION)
            ( (LPBYTE)base_relocation + base_relocation->SizeOfBlock );
    }

    PIMAGE_IMPORT_DESCRIPTOR image_import_discriptor = loader_context->import_directory;

    /* resolve imports */
    while (image_import_discriptor->Characteristics)
    {
        PIMAGE_THUNK_DATA first_thunk_ordinal = (PIMAGE_THUNK_DATA)
            ( (LPBYTE)loader_context->image_base + image_import_discriptor->OriginalFirstThunk );
        
        PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)
            ( (LPBYTE)loader_context->image_base + image_import_discriptor->FirstThunk );

        HMODULE module_handle = loader_context->fnLoadLibraryA(
            (LPCSTR)loader_context->image_base + image_import_discriptor->Name
        );

        if (!module_handle)
            return FALSE;

        while (first_thunk_ordinal->u1.AddressOfData)
        {
            uint64_t func_address;

            if (first_thunk_ordinal->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                func_address = (uint64_t)loader_context->fnGetProcAddress(
                    module_handle,
                    (LPCSTR)(first_thunk_ordinal->u1.Ordinal & 0xFFFF)
                );
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME image_import_by_name = (PIMAGE_IMPORT_BY_NAME)
                    ( (LPBYTE)loader_context->image_base + first_thunk_ordinal->u1.AddressOfData );
                
                func_address = (uint64_t)loader_context->fnGetProcAddress(
                    module_handle,
                    (LPCSTR)image_import_by_name->Name
                );
            }

            if (!func_address)
                return FALSE;

            first_thunk->u1.Function = func_address;

            first_thunk_ordinal++;
            first_thunk++;
        }

        image_import_discriptor++;
    }

    if (loader_context->nt_headers->OptionalHeader.AddressOfEntryPoint)
    {
        injector::dllmain entry_point = (injector::dllmain)
            (
                (LPBYTE)loader_context->image_base 
                + 
                loader_context->nt_headers->OptionalHeader.AddressOfEntryPoint
            );

        /* call the entry point (dllmain) */
        return entry_point(
            (HMODULE)loader_context->image_base, // module_handle
            DLL_PROCESS_ATTACH,               // call_reason
            NULL                              // reserved
        );
    }

    return TRUE;
} END_OF_FUNCTION(load_library);

bool injector::inject(const std::string& dll_path)
{
    ENTER_FUNC();

    const HANDLE file_handle = CreateFile(dll_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (!file_handle || file_handle == INVALID_HANDLE_VALUE)
    {
        printf("[!] failed to obtain file handle. GetLastError: 0x%lX\n",
            GetLastError());
        return false;
    }

    const DWORD file_size = GetFileSize(file_handle, NULL);

    if (!file_size)
    {
        printf("[!] failed to get file size. GetLastError: 0x%lX\n",
            GetLastError());
        return false;
    }

    /* prepare file buffer for the dll */
    PVOID file_buffer = VirtualAlloc(NULL,
        file_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!file_buffer)
    {
        printf("[!] failed to allocate file buffer. GetLastError: 0x%lX\n",
            GetLastError());
        return false;
    }

    printf("[+] file buffer allocated @ 0x%llX\n", file_buffer);
    printf("[-] copying file into memory...\n");

    /* copy dll file into the buffer */
    if (!ReadFile(file_handle, file_buffer, file_size, NULL, NULL))
    {
        printf("[!] failed to prepare file buffer. GetLastError: 0x%lX\n",
            GetLastError());
        return false;
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buffer;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)file_buffer + dos_header->e_lfanew);

    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[!] invalid dos header signature.\n");
        return false;
    }

    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[!] invalid nt header signature.\n");
        return false;
    }

    /* allocate memory in target process for our dll */
    void* executable_image = mem_utils::alloc(
        NULL,
        nt_headers->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    printf("[+] size of image: 0x%X\n", nt_headers->OptionalHeader.SizeOfImage);
    printf("[+] executable image allocated @ 0x%llX\n", executable_image);
    printf("[-] copying dll memory into the target process...\n");

    if (!mem_utils::write_raw(
        (uint64_t)executable_image,
        file_buffer,
        nt_headers->OptionalHeader.SizeOfHeaders)
    )
    {
        printf("[!] failed to write memory\n");
        return false;
    }

    PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)(nt_headers + 1);

    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        if (!mem_utils::write_raw(
            (uint64_t)((LPBYTE)executable_image + section_header[i].VirtualAddress),
            (PVOID)((LPBYTE)file_buffer + section_header[i].PointerToRawData),
            section_header[i].SizeOfRawData
        ))
        {
            printf("[!] failed to write memory\n");
            return false;
        }
    }

    void* loader_memory = mem_utils::alloc(
        NULL,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!loader_memory)
    {
        printf("[!] failed to allocate memory for loader. GetLastError: 0x%lX\n",
            GetLastError());
        return false;
    }

    printf("[+] loader allocated @ 0x%llX\n", loader_memory);

    LOADER_CONTEXT loader_context;
    loader_context.image_base = executable_image;
    loader_context.nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)executable_image + dos_header->e_lfanew);
    
    loader_context.base_relocation = 
        (PIMAGE_BASE_RELOCATION)((LPBYTE)executable_image
        +
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    
    loader_context.import_directory = 
        (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)executable_image
        +
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    loader_context.fnLoadLibraryA = LoadLibraryA;
    loader_context.fnGetProcAddress = GetProcAddress;

    if (!mem_utils::write_raw(
        (uint64_t)loader_memory,
        &loader_context,
        sizeof(loader_context)
    ))
    {
        printf("[!] failed to write memory\n");
        return false;
    }

    if (!mem_utils::write_raw(
        (uint64_t)((PLOADER_CONTEXT)loader_memory + 1),
        load_library,
        FUNCTION_SIZE(load_library)
    ))
    {
        printf("[!] failed to write memory\n");
        return false;
    }

    printf("[-] creating remote thread...\n");

    const HANDLE thread_handle = CreateRemoteThread(mem_utils::process_handle,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)((LOADER_CONTEXT*)loader_memory + 1),
        loader_memory,
        0,
        NULL
    );

    if (!thread_handle || thread_handle == INVALID_HANDLE_VALUE)
    {
        printf("[!] failed to create remote thread. GetLastError: 0x%lx\n",
            GetLastError());
        return false;
    }

    printf("[-] remote thread created (0x%X)\n", thread_handle);
    printf("[+] address of loader: 0x%llX\n[+] address of image: 0x%llX\n",
        loader_memory,
        executable_image);

    LEAVE_FUNC();

    return true;
}
