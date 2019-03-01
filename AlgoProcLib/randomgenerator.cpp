#include "randomgenerator.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;
using namespace GB;

RandomGenerator::RandomGenerator()
{

}

int RandomGenerator::ProcessAlgorithm(AlgorithmParams &param)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL)
    {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return RES_SERVER_ERROR;
    }
    unsigned char buf[MAX_BUF_SIZE];
    memset(buf, 0, MAX_BUF_SIZE);
    RAND_bytes(buf, MAX_BUF_SIZE);
    param.strOut = string(reinterpret_cast<const char*>(buf));
    EVP_CIPHER_CTX_free(ctx);
    return RES_OK;
}
