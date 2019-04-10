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
        nret = RES_OK;

    if(nret == RES_OK)
    {
        param.strOut = string(reinterpret_cast<const char*>(buf));
    }
    return nret;
}
