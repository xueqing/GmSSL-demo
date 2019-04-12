#include "smtwoecsign.h"

#include <openssl/sm2.h>
#include <openssl/pem.h>

#ifndef __NO_GMSSL__
#include <openssl/evp.h>
#endif

using namespace std;
using namespace GB;

SMTwoECSign::SMTwoECSign()
    : AlgoProcLib()
{

}

int SMTwoECSign::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;

    unsigned char dgst[param.strIn.length()];
    memset(dgst, 0, sizeof(dgst));
    memcpy(dgst, param.strIn.c_str(), param.strIn.length());

    unsigned char sig[MAX_BUF_SIZE];
    memset(sig, 0, MAX_BUF_SIZE);

#if __NO_GMSSL__
    int type = NID_undef;
    EC_KEY *ecKey = nullptr;

    do
    {
        if(!(ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
        {
            fprintf(stderr, "%s() failed to call EC_KEY_new_by_curve_name\n", __func__);
            break;
        }

        unsigned char key[param.ec_pri_key.length()];
        memset(key, 0, sizeof(key));
        memcpy(key, param.ec_pri_key.c_str(), param.ec_pri_key.length());
        if(!EC_KEY_oct2priv(ecKey, key, param.ec_pri_key.length()))
        {
            fprintf(stderr, "%s() failed to call EC_KEY_oct2priv [lib=%s] [func=%s] [reason=%s]\n", __func__,
                    ERR_lib_error_string(ERR_get_error()), ERR_func_error_string(ERR_get_error()),
                    ERR_reason_error_string(ERR_get_error()));
            break;
        }

        if(!SM2_sign(type, dgst, param.strIn.length(), sig, &param.lenOut, ecKey))
        {
            fprintf(stderr, "%s() failed to SM2_sign\n", __func__);
            break;
        }
        nret = RES_OK;
    }while(false);
#else
    EVP_PKEY *pkey = nullptr;
    BIO *pbio = nullptr;
    EVP_MD_CTX *mdctx = nullptr;

    do
    {
        // Create the Input/Output BIO's
        if(!(pbio = BIO_new(BIO_s_file()))
                || !(pbio = BIO_new_file(param.filePath.c_str(), "r")))
        {
            fprintf(stderr, "%s() failed to new bio\n", __func__);
            break;
        }

        if(!(pkey = EVP_PKEY_new()))
        {
            fprintf(stderr, "%s() failed to call EVP_PKEY_new\n", __func__);
            break;
        }
        if(!(pkey=PEM_read_bio_PrivateKey(pbio, NULL, 0, NULL)))
        {
            BIO_printf(pbio, "Error call PEM_read_bio_PrivateKey [lib=%s] [func=%s] [reason=%s]\n",
                       ERR_lib_error_string(ERR_get_error()), ERR_func_error_string(ERR_get_error()),
                       ERR_reason_error_string(ERR_get_error()));
            break;
        }

        if(!(mdctx=EVP_MD_CTX_new()))
        {
            fprintf(stderr, "%s() failed to call EVP_MD_CTX_new\n", __func__);
            break;
        }
        if(!EVP_DigestSignInit(mdctx, NULL, EVP_sm3(), NULL, pkey))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestSignInit\n", __func__);
            break;
        }
        if(!EVP_DigestSignUpdate(mdctx, dgst, param.strIn.length()))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestSignUpdate\n", __func__);
            break;
        }

        size_t lenout = 0;
        if(!EVP_DigestSignFinal(mdctx, NULL, &lenout))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestSignFinal\n", __func__);
            break;
        }
        if(!EVP_DigestSignFinal(mdctx, sig, &lenout))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestSignFinal\n", __func__);
            break;
        }
        param.lenOut = lenout;
        nret = RES_OK;
    }while(false);

    EVP_PKEY_free(pkey);
    BIO_free_all(pbio);
    EVP_MD_CTX_destroy(mdctx);
#endif

    if(nret == RES_OK)
        param.strOut = string(reinterpret_cast<const char*>(sig));

    return nret;
}
