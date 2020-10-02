#include "main.h"

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("[!] incorrect usage.\n[>] usage: %s example.dll\n", argv[0]);
        return 1;
    }

    const char* dll_path = argv[1];

    if (std::string str(dll_path);
        str.substr( str.find_last_of(".") + 1 ) != "dll"
       )
    {
        printf("[!] input file must be library\n");
        return 1;
    }

    if (!filesystem::is_file_exists(dll_path))
    {
        printf("[!] dll does not exists in \"%s\"\n", dll_path);
        return 1;
    }

    if (!mem_utils::init())
    {
        printf("[!] failed to initialize memory utility\n");
        return 1;
    }

    if (!injector::inject(dll_path))
    {
        printf("[!] failed to inject\n");
        return 1;
    }

    return 0;
}