#include "algoproclib.h"

#include <string.h>
#include <limits.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/saf.h>

#include "cstring.h"

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

int AlgoProcLib::HexStr2Buffer(AlgorithmParams &param)
{
    unsigned char *outBuf = nullptr;
    long *outLen = reinterpret_cast<long*>(&(param.lenOut));
    if(!(outBuf = OPENSSL_hexstr2buf(param.strIn.c_str(), outLen)))
    {
        ERR_print_errors_fp(stderr);
        return RES_SERVER_ERROR;
    }

    param.strOut = std::string(reinterpret_cast<const char*>(outBuf));
    return RES_OK;
}

int AlgoProcLib::Buffer2HexStr(AlgorithmParams &param)
{
    unsigned char inBuf[param.strIn.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, param.strIn.c_str(), param.strIn.length());

    char *outBuf = nullptr;
    if(!(outBuf = OPENSSL_buf2hexstr(inBuf, param.strIn.length())))
    {
        ERR_print_errors_fp(stderr);
        return RES_SERVER_ERROR;
    }

    param.strOut = std::string(outBuf);

    // remove redundant ':', added by OPENSSL_buf2hexstr between digits
    std::string oldstr = ":";
    std::string newstr = "";
    param.strOut = CString::ReplaceAll(param.strOut, oldstr, newstr);
    param.lenOut = param.strOut.length();

    return RES_OK;
}

int AlgoProcLib::Base64Encode(AlgorithmParams &param)
{
    unsigned char inBuf[param.strIn.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, param.strIn.c_str(), param.strIn.length());

    unsigned char outBuf[MAX_BUF_SIZE];
    memset(outBuf, 0, sizeof(outBuf));

    if(SAF_Base64_Encode(inBuf, param.strIn.length(), outBuf, &param.lenOut) != SAR_Ok)
    {
        ERR_print_errors_fp(stderr);
        return RES_SERVER_ERROR;
    }

    param.strOut = std::string(reinterpret_cast<const char*>(outBuf));
    return RES_OK;
}

int AlgoProcLib::Base64Decode(AlgorithmParams &param)
{
    unsigned char inBuf[param.strIn.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, param.strIn.c_str(), param.strIn.length());

    unsigned char outBuf[MAX_BUF_SIZE];
    memset(outBuf, 0, sizeof(outBuf));

    if(SAF_Base64_Decode(inBuf, param.strIn.length(), outBuf, &param.lenOut) != SAR_Ok)
    {
        ERR_print_errors_fp(stderr);
        return RES_SERVER_ERROR;
    }

    param.strOut = std::string(reinterpret_cast<const char*>(outBuf));
    return RES_OK;
}

void AlgoProcLib::ReleaseAlgoProcLib(AlgoProcLib *pAlgoProcLib)
{
    if(pAlgoProcLib)
        delete pAlgoProcLib;
    pAlgoProcLib = nullptr;
}
