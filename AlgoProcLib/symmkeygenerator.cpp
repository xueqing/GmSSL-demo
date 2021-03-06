#include "symmkeygenerator.h"

#include <string.h>

#include <openssl/rand.h>

using namespace std;
using namespace GB;

SymmKeyGenerator::SymmKeyGenerator()
    : AlgoProcLib()
{

}

int SymmKeyGenerator::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;

    unsigned char buf[MAX_BUF_SIZE];
    memset(buf, 0, MAX_BUF_SIZE);

    if(param.lenOut > sizeof(buf))
    {
        fprintf(stderr, "%s() len overflow\n", __func__);
        return nret;
    }

    if(RAND_bytes(buf, param.lenOut) > 0)
    {
        param.sm4_ecb_key = string(reinterpret_cast<const char*>(buf));
        nret = RES_OK;
    }

    printf("%s [symm_key=%s]\n", __func__, param.sm4_ecb_key.c_str());

    return nret;
}
