#ifndef ALGOPROC_COMMON_H
#define ALGOPROC_COMMON_H

#include <string>

namespace GB {

enum ALGO_TYPE {
    ALGO_UNKNOWN = 0,
    ALGO_HEX2BUF,
    ALGO_BUF2HEX,
    ALGO_ENC_BASE64,
    ALGO_DEC_BASE64,
    ALGO_RANDOM,
    ALGO_ENC_SM2,
    ALGO_DEC_SM2,
    ALGO_HASH_SM3,
    ALGO_ENC_SM4_ECB,
    ALGO_DEC_SM4_ECB,
};

struct AlgorithmParams {
    std::string key;
    std::string strIn;
    std::string strOut;
    unsigned int lenOut = 0;
};

}//namespace GB

#endif // ALGOPROC_COMMON_H
