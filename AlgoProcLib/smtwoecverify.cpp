#include "smtwoecverify.h"

#include <openssl/sm2.h>

using namespace std;
using namespace GB;

SMTwoECVerify::SMTwoECVerify()
    : AlgoProcLib()
{

}

int SMTwoECVerify::ProcessAlgorithm(AlgorithmParams &param)
{
    /* longest known is SHA512 */
    int nret = RES_SERVER_ERROR;
    int type = NID_undef;
    EC_KEY *ecKey = nullptr;

    unsigned char dgst[param.strIn.length()];
    memset(dgst, 0, sizeof(dgst));
    memcpy(dgst, param.strIn.c_str(), param.strIn.length());

    unsigned char sig[param.strOut.length()];
    memset(sig, 0, sizeof(sig));
    memcpy(sig, param.strOut.c_str(), param.strOut.length());

    do
    {
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
            fprintf(stderr, "%s() failed to call EC_KEY_oct2key\n", __func__);
            break;
        }

        if(1 != SM2_verify(type, dgst, param.strIn.length(), sig, param.strOut.length(), ecKey))
        {
            fprintf(stderr, "%s() failed to SM2_verify\n", __func__);
            nret = RES_VERIFY_FAILURE;
            break;
        }

        nret = RES_OK;
    }while(false);

    return nret;
}

