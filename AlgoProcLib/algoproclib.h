#ifndef ALGOPROCLIB_H
#define ALGOPROCLIB_H

#include "algoproc_common.h"

namespace GB {

class AlgoProcLib
{
#define MAX_BUF_SIZE 512
#define UNUSED_ARGUMENT(x) (void)x
public:
    enum PROC_RES
    {
        RES_OK = 0,
        RES_NOT_SUPPORTED,
        RES_SERVER_ERROR,
        RES_VERIFY_FAILURE,
    };

    enum CRPT_TYPE
    {
        CRYP_DEC = 0,
        CRYP_ENC = 1,
    };

    AlgoProcLib();
    virtual ~AlgoProcLib();

    static void Initialize(); // must be called before using it
    static void Deinitialize(); // must be called after using it

    virtual int ProcessAlgorithm(AlgorithmParams &param); //ref PROC_RES
    static int HexStr2Buffer(AlgorithmParams &param);
    static int Buffer2HexStr(AlgorithmParams &param);
    static int Base64Encode(AlgorithmParams &param);
    static int Base64Decode(AlgorithmParams &param);
    static void ReleaseAlgoProcLib(AlgoProcLib *pAlgoProcLib);
};

}//namespace GB

#endif // ALGOPROCLIB_H
