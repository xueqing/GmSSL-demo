#include "randomgenerator.h"

#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;
using namespace GB;

RandomGenerator::RandomGenerator()
{

}

bool RandomGenerator::ProcessAlgorithm(AlgorithmParams &param)
{
    const int BUFFER_SIZE = (param.lenOut == -1 ? (8 * 1024) - 13 : param.lenOut);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "%s() failed to allocate ctx\n", __func__);
        return false;
    }
    unsigned char buf[BUFFER_SIZE];
    memset(buf, 0, BUFFER_SIZE);
    RAND_bytes(buf, BUFFER_SIZE);
    param.strOut = string(reinterpret_cast<const char*>(buf));
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
