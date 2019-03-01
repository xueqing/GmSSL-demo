#ifndef ALGOPROCLIB_H
#define ALGOPROCLIB_H

#include "algoproc_common.h"

namespace GB {

class AlgoProcLib
{
public:
    AlgoProcLib();
    virtual ~AlgoProcLib();

    static void Initialize(); // must be called before using it
    static void Deinitialize(); // must be called after using it

    virtual bool ProcessAlgorithm(AlgorithmParams &param) = 0;
    static bool Base64Encode(std::string &inStr, std::string &outStr, int lenOut = -1);
    static bool Base64Decode(std::string &inStr, std::string &outStr, int lenOut = -1);
    static void ReleaseAlgoProcLib(AlgoProcLib *pAlgoProcLib);
};

}//namespace GB

#endif // ALGOPROCLIB_H
