#include "algoproclib.h"

#include <string.h>
#include <limits.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/saf.h>

using namespace GB;

AlgoProcLib::AlgoProcLib()
{
}

AlgoProcLib::~AlgoProcLib()
{
}

void GB::AlgoProcLib::Initialize()
{
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
//    OPENSSL_config(NULL);//deprecated
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    /* ... Do some crypto stuff here ... */
}

void AlgoProcLib::Deinitialize()
{
    /* Clean up */

    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();
}

int AlgoProcLib::ProcessAlgorithm(AlgorithmParams &param)
{
    UNUSED_ARGUMENT(param);
    return RES_NOT_SUPPORTED;
}

int AlgoProcLib::Base64Encode(std::string &inStr, std::string &outStr, int lenOut)
{
    unsigned char inBuf[inStr.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, inStr.c_str(), inStr.length());
    unsigned int inLen = sizeof(inBuf) & INT_MAX;

    const int BUFFER_SIZE = (lenOut == -1 ? 512 : lenOut);
    unsigned char outBuf[BUFFER_SIZE];
    memset(outBuf, 0, sizeof(outBuf));
    unsigned int outLen = BUFFER_SIZE + UINT_MAX + 1;

    if(SAF_Base64_Encode(inBuf, inLen, outBuf, &outLen) != SAR_Ok)
    {
        ERR_print_errors_fp(stderr);
        return RES_SERVER_ERROR;
    }

    outStr = std::string(reinterpret_cast<const char*>(outBuf));
    return RES_OK;
}

int AlgoProcLib::Base64Decode(std::string &inStr, std::string &outStr, int lenOut)
{
    unsigned char inBuf[inStr.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, inStr.c_str(), inStr.length());
    unsigned int inLen = sizeof(inBuf) & INT_MAX;

    const int BUFFER_SIZE = (lenOut == -1 ? 512 : lenOut);
    unsigned char outBuf[BUFFER_SIZE];
    memset(outBuf, 0, sizeof(outBuf));
    unsigned int outLen = BUFFER_SIZE + UINT_MAX + 1;

    if(SAF_Base64_Decode(inBuf, inLen, outBuf, &outLen) != SAR_Ok)
    {
        ERR_print_errors_fp(stderr);
        return RES_SERVER_ERROR;
    }

    outStr = std::string(reinterpret_cast<const char*>(outBuf));
    return RES_OK;
}

void AlgoProcLib::ReleaseAlgoProcLib(AlgoProcLib *pAlgoProcLib)
{
    if(pAlgoProcLib)
        delete pAlgoProcLib;
    pAlgoProcLib = nullptr;
}
