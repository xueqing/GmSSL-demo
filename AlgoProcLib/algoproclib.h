#ifndef ALGOPROCLIB_H
#define ALGOPROCLIB_H

#include "algoproc_common.h"

namespace GB {

class AlgoProcLib
{
#define UNUSED_ARGUMENT(x) (void)x
public:
    enum PROC_RES
    {
        RES_OK = 0,
        RES_NOT_SUPPORTED,
        RES_SERVER_ERROR,
        RES_VERIFY_FAILURE,
    };

    AlgoProcLib();
    virtual ~AlgoProcLib();

    static void Initialize(); // must be called before using it
    static void Deinitialize(); // must be called after using it

    virtual int ProcessAlgorithm(AlgorithmParams &param); //ref PROC_RES
    static int Base64Encode(std::string &inStr, std::string &outStr, int lenOut = -1);
    static int Base64Decode(std::string &inStr, std::string &outStr, int lenOut = -1);
    static void ReleaseAlgoProcLib(AlgoProcLib *pAlgoProcLib);
};

}//namespace GB

#endif // ALGOPROCLIB_H
