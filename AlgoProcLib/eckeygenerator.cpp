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

    EC_GROUP *group=nullptr;//TODO: initialize group, sk, xp, yp
    char *sk=nullptr, *xP=nullptr, *yP=nullptr;
    EC_KEY *ecKey=nullptr;
    BIGNUM *d=nullptr, *x=nullptr, *y=nullptr;

    OPENSSL_assert(group);
    OPENSSL_assert(xP);
    OPENSSL_assert(yP);

    do
    {
        if(!(ecKey = EC_KEY_new()))
        {
            fprintf(stderr, "%s() failed to new ec_key\n", __func__);
            break;
        }

        if(!EC_KEY_set_group(ecKey, group))
        {
            fprintf(stderr, "%s() failed to call EC_KEY_set_group\n", __func__);
            break;
        }

        if(sk)
        {
            if(!BN_hex2bn(&d, sk))
            {
                fprintf(stderr, "%s() failed to call BN_hex2bn\n", __func__);
                break;
            }
            if(!EC_KEY_set_private_key(ecKey, d))
            {
                fprintf(stderr, "%s() failed to call EC_KEY_set_private_key\n", __func__);
                break;
            }
        }

        if(xP && yP)
        {
            if(!BN_hex2bn(&x, xP) || !BN_hex2bn(&y, yP))
            {
                fprintf(stderr, "%s() failed to call BN_hex2bn\n", __func__);
                break;
            }
            if(!EC_KEY_set_public_key_affine_coordinates(ecKey, x, y))
            {
                fprintf(stderr, "%s() failed to call EC_KEY_set_public_key_affine_coordinates\n", __func__);
                break;
            }
        }

        nret = RES_OK;
    }while(false);

    if(d) BN_free(d);
    if(x) BN_free(x);
    if(y) BN_free(y);

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
