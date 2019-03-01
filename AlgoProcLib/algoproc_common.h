#ifndef ALGOPROC_COMMON_H
#define ALGOPROC_COMMON_H

#include <string>

namespace GB {

struct AlgorithmParams {
    std::string key;
    std::string strIn;
    std::string strOut;
    int lenOut = -1;
};

}//namespace GB

#endif // ALGOPROC_COMMON_H
