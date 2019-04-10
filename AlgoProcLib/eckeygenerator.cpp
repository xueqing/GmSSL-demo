#include "eckeygenerator.h"

#include <string.h>

#include <openssl/sm2.h>

using namespace std;
using namespace GB;

ECKeyGenerator::ECKeyGenerator()
    : AlgoProcLib()
{

}

int ECKeyGenerator::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;
    EC_KEY *ecKey=nullptr;

    do
    {
        if(!(ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
        {
            fprintf(stderr, "%s() failed to call EC_KEY_new_by_curve_name\n", __func__);
            break;
        }

        if(EC_KEY_generate_key(ecKey) != 1)
        {
            fprintf(stderr, "%s() failed to call EC_KEY_generate_key\n", __func__);
            break;
        }

        nret = RES_OK;
    }while(false);

    if(nret == RES_OK)
    {
        unsigned char *ptrPub=nullptr, *ptrPri=nullptr;
        if(EC_KEY_key2buf(ecKey, EC_KEY_get_conv_form(ecKey), &ptrPub, nullptr) != 0)
            param.ec_pub_key = string(reinterpret_cast<char*>(ptrPub));
        if(EC_KEY_priv2buf(ecKey, &ptrPri) != 0)
            param.ec_pri_key = string(reinterpret_cast<char*>(ptrPri));
        OPENSSL_free(ptrPub);
        OPENSSL_free(ptrPri);
    }
    else if(ecKey)
    {
        EC_KEY_free(ecKey);
        ecKey = nullptr;
    }
    return nret;
}
