#include "algoproclib.h"

#include <string.h>
#include <limits.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "cstring.h"

using namespace GB;

AlgoProcLib::AlgoProcLib(ALGO_TYPE algotype)
    : m_algotype(algotype)
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
    int nret = RES_OK;
    switch (m_algotype) {
    case ALGO_HEX2BUF:
        nret = HexStr2Buffer(param);
        break;
    case ALGO_BUF2HEX:
        nret = Buffer2HexStr(param);
        break;
    case ALGO_ENC_BASE64:
        nret = Base64Encode(param);
        break;
    case ALGO_DEC_BASE64:
        nret = Base64Decode(param);
        break;
    default:
        nret = RES_NOT_SUPPORTED;
        break;
    }
    return nret;
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
    char *outBuf=nullptr;
    BIO *pbio=nullptr, *pb64=nullptr;
    BUF_MEM *pbuf=nullptr;

    int nret = RES_SERVER_ERROR;
    do
    {
        pb64 = BIO_new(BIO_f_base64());
        pbio = BIO_new(BIO_s_mem());
        pbio = BIO_push(pb64, pbio);
        if(!pbio || !pb64)
        {
            fprintf(stderr, "%s() failed to call BIO_NEW\n", __func__);
            break;
        }

        //Ignore newlines - write everything in one line
        BIO_set_flags(pbio, BIO_FLAGS_BASE64_NO_NL);
        if(BIO_set_close(pbio, BIO_NOCLOSE) <= 0)
        {
            ERR_print_errors_fp(stderr);
            break;
        }

        if(BIO_write(pbio, param.strIn.c_str(), param.strIn.length()) <=0 )
        {
            fprintf(stderr, "%s() failed to call BIO_write\n", __func__);
            break;
        }

        if(BIO_flush(pbio) <=0 || BIO_get_mem_ptr(pbio, &pbuf) <= 0)
        {
            ERR_print_errors_fp(stderr);
            break;
        }

        outBuf = (char*)malloc(pbuf->length+1);
        memset(outBuf, 0, pbuf->length+1);
        memcpy(outBuf, pbuf->data, pbuf->length);

        param.strOut = std::string(outBuf);
        nret = RES_OK;
    }while(false);

    free(outBuf);
    BIO_free_all(pbio);
//    BIO_free_all(pb64);//error if add this
    BUF_MEM_free(pbuf);

    return nret;
}

int AlgoProcLib::Base64Decode(AlgorithmParams &param)
{
    unsigned char *outBuf=nullptr;
    BIO *pbio=nullptr, *pb64=nullptr;

    int nret = RES_SERVER_ERROR;
    do
    {
        //Calculates the length of a decoded string
        size_t lenIn = param.strIn.length(), padding=0;
        if((param.strIn[lenIn-1] == '=')
                && (param.strIn[lenIn-2] == '='))//last two chars are =
            padding = 2;
        else if(param.strIn[lenIn-1] == '=')//last char is =
            padding = 1;

        int lenDecoded = (lenIn * 3) / 4 - padding;
        outBuf = (unsigned char*)malloc(lenDecoded+1);
        memset(outBuf, 0, lenDecoded+1);

        pb64 = BIO_new(BIO_f_base64());
        pbio = BIO_new_mem_buf(param.strIn.c_str(), -1);
        pbio = BIO_push(pb64, pbio);
        if(!pbio || !pb64)
        {
            fprintf(stderr, "%s() failed to call BIO_NEW\n", __func__);
            break;
        }

        BIO_set_flags(pbio, BIO_FLAGS_BASE64_NO_NL);
        int lenRead=0;
        if((lenRead=BIO_read(pbio, outBuf, param.strIn.length())) <= 0)
        {
            fprintf(stderr, "%s() failed to call BIO_read [err=%d]\n", __func__, lenRead);
            break;
        }
        if(lenDecoded != lenRead)//length should equal decodeLen, else something went horribly wrong
        {
            fprintf(stderr, "%s() failed to decode base64 [%d!=%d]\n", __func__, lenDecoded, lenRead);
            break;
        }

        param.lenOut = lenRead;
        param.strOut = std::string(reinterpret_cast<const char*>(outBuf));
        nret = RES_OK;
    }while(false);

    free(outBuf);
    BIO_free_all(pbio);
//    BIO_free_all(pb64);//error if add this

    return nret;
}

void AlgoProcLib::ReleaseAlgoProcLib(AlgoProcLib *pAlgoProcLib)
{
    if(pAlgoProcLib)
        delete pAlgoProcLib;
    pAlgoProcLib = nullptr;
}
