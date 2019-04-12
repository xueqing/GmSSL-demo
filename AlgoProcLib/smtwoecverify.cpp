#include "smtwoecverify.h"

#include <openssl/sm2.h>
#include <openssl/pem.h>
#ifndef __NO_GMSSL__
#include <openssl/evp.h>
#endif

using namespace std;
using namespace GB;

SMTwoECVerify::SMTwoECVerify()
    : AlgoProcLib()
{

}

int SMTwoECVerify::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;
#if __NO_GMSSL__
    int type = NID_undef;
    EC_KEY *ecKey = nullptr;
#endif
    EVP_PKEY *pkey = nullptr;
    BIO *pbio = nullptr;
    EVP_MD_CTX *mdctx = nullptr;

    unsigned char dgst[param.strIn.length()];
    memset(dgst, 0, sizeof(dgst));
    memcpy(dgst, param.strIn.c_str(), param.strIn.length());

    unsigned char sig[param.strOut.length()];
    memset(sig, 0, sizeof(sig));
    memcpy(sig, param.strOut.c_str(), param.strOut.length());

    do
    {
#if __NO_GMSSL__
        if(!(ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
        {
            fprintf(stderr, "%s() failed to call EC_KEY_new_by_curve_name\n", __func__);
            break;
        }

        unsigned char key[param.ec_pub_key.length()];
        memset(key, 0, sizeof(key));
        memcpy(key, param.ec_pub_key.c_str(), param.ec_pub_key.length());
        if(!EC_KEY_oct2key(ecKey, key, param.ec_pub_key.length(), NULL))
        {
            fprintf(stderr, "%s() failed to call EC_KEY_oct2key [lib=%s] [func=%s] [reason=%s]\n", __func__,
                    ERR_lib_error_string(ERR_get_error()), ERR_func_error_string(ERR_get_error()),
                    ERR_reason_error_string(ERR_get_error()));
            break;
        }

        if(1 != SM2_verify(type, dgst, param.strIn.length(), sig, param.strOut.length(), ecKey))
        {
            fprintf(stderr, "%s() failed to SM2_verify [lib=%s] [func=%s] [reason=%s]\n", __func__,
                    ERR_lib_error_string(ERR_get_error()), ERR_func_error_string(ERR_get_error()),
                    ERR_reason_error_string(ERR_get_error()));
            nret = RES_VERIFY_FAILURE;
            break;
        }
#else
        // Create the Input/Output BIO's
        if(!(pbio = BIO_new(BIO_s_file()))
                || !(pbio = BIO_new_file(param.filePath.c_str(), "rr")))
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
        if(!EVP_DigestVerifyInit(mdctx, NULL, EVP_sm3(), NULL, pkey))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestVerifyInit\n", __func__);
            break;
        }
        if(!EVP_DigestVerifyUpdate(mdctx, dgst, param.strIn.length()))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestVerifyUpdate\n", __func__);
            break;
        }

        if(!EVP_DigestVerifyFinal(mdctx, sig, param.lenOut))
        {
            fprintf(stderr, "%s() failed to call EVP_DigestVerifyFinal\n", __func__);
            break;
        }
#endif
        nret = RES_OK;
    }while(false);

    EVP_PKEY_free(pkey);
    BIO_free_all(pbio);
    EVP_MD_CTX_destroy(mdctx);

    return nret;
}
