#include "randomgenerator.h"

#include <string.h>

#if __NO_GMSSL__
#include <openssl/rand.h>
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

using namespace std;
using namespace GB;

RandomGenerator::RandomGenerator()
    : AlgoProcLib()
{

}

int RandomGenerator::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;
    unsigned char buf[MAX_BUF_SIZE];
    memset(buf, 0, MAX_BUF_SIZE);

    if(param.lenOut > sizeof(buf))
    {
        fprintf(stderr, "%s() len overflow\n", __func__);
        return nret;
    }

#if __NO_GMSSL__
    printf("no gmssl\n");
    if(RAND_bytes(buf, param.lenOut) > 0)
    {
        param.strOut = string(reinterpret_cast<const char*>(buf));
        nret = RES_OK;
    }
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    do
    {
        if(!ctx)
        {
            fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
            break;
        }

        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_RAND_KEY);
        EVP_CIPHER_CTX_set_key_length(ctx, MAX_BUF_SIZE);
        if(EVP_CIPHER_CTX_rand_key(ctx, buf) == 0)
        {
            fprintf(stderr, "%s() failed to EVP_CIPHER_CTX_rand_key\n", __func__);
            break;
        }
        param.strOut = string(reinterpret_cast<const char*>(buf));
        nret = RES_OK;
    }while(false);
    EVP_CIPHER_CTX_free(ctx);
#endif

    return nret;
}
