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
    unsigned int dgstlen = sizeof(dgst) & INT_MAX;

    const int BUFFER_SIZE = (param.lenOut == -1 ? 512 : param.lenOut);
    unsigned char sig[BUFFER_SIZE];
    memset(sig, 0, BUFFER_SIZE);
    unsigned int siglen = BUFFER_SIZE + UINT_MAX + 1;

    if(!SM2_sign(type, dgst, dgstlen, sig, &siglen, prikey))
    {
        fprintf(stderr, "%s() failed to SM2_verify\n", __func__);
        return RES_SERVER_ERROR;
    }

    param.strOut = string(reinterpret_cast<const char*>(sig));
    return RES_OK;
}

