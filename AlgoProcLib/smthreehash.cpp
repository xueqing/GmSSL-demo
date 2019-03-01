#include "smthreehash.h"

#include <openssl/evp.h>
#include <openssl/sm3.h>
#include <openssl/err.h>

using namespace std;
using namespace GB;

SMThreeHash::SMThreeHash()
{

}

int SMThreeHash::ProcessAlgorithm(AlgorithmParams &param)
{
    unsigned char inBuf[param.strIn.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, param.strIn.c_str(), param.strIn.length());

    unsigned char outBuf[MAX_BUF_SIZE];
    memset(outBuf, 0, sizeof(outBuf));

    if(!EVP_Digest(inBuf, param.strIn.length(), outBuf, &param.lenOut, EVP_sm3(), NULL))
    {
        ERR_print_errors_fp(stderr);
        return RES_SERVER_ERROR;
    }

    param.strOut = std::string(reinterpret_cast<const char*>(outBuf));
    return RES_OK;
}
