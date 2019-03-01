#include "cstring.h"

std::string &CString::ReplaceAll(std::string &str, const std::string &old_value, const std::string &new_value)
{
    std::string::size_type pos(0);
    while(true)
    {
        if((pos = str.find(old_value, pos+1)) != std::string::npos)
            str.replace(pos, old_value.length(), new_value);
        else
            break;
    }
    return str;
}
