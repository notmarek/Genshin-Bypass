#include "win.hpp"

bool filesystem::is_file_exists(const std::string& file_path)
{
    DWORD attribute = GetFileAttributes(file_path.c_str());

    return (attribute != INVALID_FILE_ATTRIBUTES &&
        !(attribute & FILE_ATTRIBUTE_DIRECTORY));
}
