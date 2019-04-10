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
    ALGO_GET_KEY_EC,
    ALGO_GET_KEY_SYMM,
};

struct AlgorithmParams {
    std::string strIn;
    std::string strOut;
    unsigned int lenOut = 0;
    std::string sm4_ecb_key;
    std::string ec_pub_key;
    std::string ec_pri_key;
};

}//namespace GB

#endif // ALGOPROC_COMMON_H
