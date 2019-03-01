#include "smtwoellipticcurvesign.h"

#include <openssl/sm2.h>

using namespace std;
using namespace GB;

SMTwoEllipticCurveSign::SMTwoEllipticCurveSign()
{

}

int SMTwoEllipticCurveSign::ProcessAlgorithm(AlgorithmParams &param)
{
    /* longest known is SHA512 */
    int type = NID_undef;
    EC_KEY *prikey = NULL;

    unsigned char dgst[param.strIn.length()];
    memset(dgst, 0, sizeof(dgst));
    memcpy(dgst, param.strIn.c_str(), param.strIn.length());

    unsigned char sig[MAX_BUF_SIZE];
    memset(sig, 0, MAX_BUF_SIZE);

    if(!SM2_sign(type, dgst, param.strIn.length(), sig, &param.lenOut, prikey))
    {
        fprintf(stderr, "%s() failed to SM2_sign\n", __func__);
        return RES_SERVER_ERROR;
    }

    param.strOut = string(reinterpret_cast<const char*>(sig));
    return RES_OK;
}
