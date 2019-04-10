#include "smfourecbcrypt.h"

#include <string.h>

#if __NO_GMSSL__
#include <openssl/sms4.h>
#else
#include <openssl/evp.h>
#include <openssl/err.h>
#include <crypto/evp/evp_locl.h>
#include <openssl/ossl_typ.h>
#include <crypto/internal/evp_int.h>
#endif

using namespace std;
using namespace GB;

SMFourECBCrypt::SMFourECBCrypt(CRPT_TYPE cryptype)
    : AlgoProcLib()
    , m_crypType(cryptype)
{

}

int SMFourECBCrypt::ProcessAlgorithm(AlgorithmParams &param)
{
    const unsigned KEYLEN = 16;

    unsigned char key[KEYLEN];
    memset(key, 0, sizeof(key));
    memcpy(key, param.sm4_ecb_key.c_str(), param.sm4_ecb_key.length());

#if __NO_GMSSL__

    sms4_key_t pubkey;

    unsigned char inBuf[param.strIn.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, param.strIn.c_str(), param.strIn.length());

    unsigned char outBuf[MAX_BUF_SIZE];
    memset(outBuf, 0, MAX_BUF_SIZE);

    printf("before sm4:\n");
    for(unsigned i = 0; i < KEYLEN; i++)
        printf("%02x ", inBuf[i]);
    printf("\n");

    if(m_crypType == CRYP_ENC)
    {
        sms4_set_encrypt_key(&pubkey, key);
    }
    else
    {
        sms4_set_decrypt_key(&pubkey, key);
    }

    sms4_ecb_encrypt(inBuf, outBuf, &pubkey, m_crypType);

    printf("after  sm4:\n");
    for(unsigned i = 0; i < KEYLEN; i++)
        printf("%02x ", outBuf[i]);
    printf("\n");

    param.strOut = string(reinterpret_cast<const char*>(outBuf));
    return RES_OK;
#else
    int nret = RES_SERVER_ERROR;

    unsigned char inBuf[param.strIn.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, param.strIn.c_str(), param.strIn.length());

    unsigned char outBuf[MAX_BUF_SIZE];
    memset(outBuf, 0, MAX_BUF_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    do
    {
        printf("before sm4:\n");
        for(unsigned i = 0; i < KEYLEN; i++)
            printf("%02x ", inBuf[i]);
        printf("\n");

        if(!ctx)
        {
            fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
            break;
        }

        if(EVP_CipherInit(ctx, EVP_sm4_ecb(), key, nullptr, m_crypType) == 0)
        {
            ERR_print_errors_fp(stderr);
            break;
        }

        int lenOut = 0;
        if(EVP_CipherUpdate(ctx, outBuf, &lenOut, inBuf, param.strIn.length()) == 0
                || EVP_CipherFinal(ctx, outBuf, &lenOut) == 0)
        {
            ERR_print_errors_fp(stderr);
            break;
        }

        printf("after  sm4:\n");
        for(unsigned i = 0; i < KEYLEN; i++)
            printf("%02x ", outBuf[i]);
        printf("\n");

        param.lenOut = lenOut;
        nret = RES_OK;
    }while(false);

    EVP_CIPHER_CTX_free(ctx);
    param.strOut = string(reinterpret_cast<const char*>(outBuf));
    return nret;
#endif
}
