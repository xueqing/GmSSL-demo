#ifndef CSTRING_H
#define CSTRING_H

#include <string>

namespace CString
{
    std::string& ReplaceAll(std::string& str, const std::string& old_value, const std::string& new_value);
}//namespace CString

#endif // CSTRING_H
