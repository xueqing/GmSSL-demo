#include "randomgenerator.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

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
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    do
    {
        if(ctx == NULL)
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
        nret = RES_OK;
    }while(false);

    EVP_CIPHER_CTX_free(ctx);
    param.strOut = string(reinterpret_cast<const char*>(buf));
    return nret;
}
