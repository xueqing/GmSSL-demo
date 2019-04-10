#include "smtwoecsign.h"

#include <openssl/sm2.h>

using namespace std;
using namespace GB;

SMTwoECSign::SMTwoECSign()
    : AlgoProcLib()
{

}

int SMTwoECSign::ProcessAlgorithm(AlgorithmParams &param)
{
    /* longest known is SHA512 */
    int nret = RES_SERVER_ERROR;
    int type = NID_undef;
    EC_KEY *ecKey = nullptr;

    unsigned char dgst[param.strIn.length()];
    memset(dgst, 0, sizeof(dgst));
    memcpy(dgst, param.strIn.c_str(), param.strIn.length());

    unsigned char sig[MAX_BUF_SIZE];
    memset(sig, 0, MAX_BUF_SIZE);

    do
    {
        if(!(ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
        {
            fprintf(stderr, "%s() failed to call EC_KEY_new_by_curve_name\n", __func__);
            break;
        }

        unsigned char key[param.ec_pri_key.length()];
        memset(key, 0, sizeof(key));
        memcpy(key, param.ec_pri_key.c_str(), param.ec_pri_key.length());
        if(!EC_KEY_oct2priv(ecKey, key, param.ec_pri_key.length()))
        {
            fprintf(stderr, "%s() failed to call EC_KEY_oct2priv\n", __func__);
            break;
        }

        if(!SM2_sign(type, dgst, param.strIn.length(), sig, &param.lenOut, ecKey))
        {
            fprintf(stderr, "%s() failed to SM2_sign\n", __func__);
            break;
        }

        nret = RES_OK;
    }while(false);

    EC_KEY_free(ecKey);

    if(nret == RES_OK)
        param.strOut = string(reinterpret_cast<const char*>(sig));
    return nret;
}

