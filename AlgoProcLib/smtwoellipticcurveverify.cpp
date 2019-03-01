#include "smtwoellipticcurveverify.h"

#include <openssl/sm2.h>

using namespace std;
using namespace GB;

SMTwoEllipticCurveVerify::SMTwoEllipticCurveVerify()
{

}

int SMTwoEllipticCurveVerify::ProcessAlgorithm(AlgorithmParams &param)
{
    /* longest known is SHA512 */
    int type = NID_undef;
    EC_KEY *pubkey = NULL;

    unsigned char dgst[param.strIn.length()];
    memset(dgst, 0, sizeof(dgst));
    memcpy(dgst, param.strIn.c_str(), param.strIn.length());
    unsigned int dgstlen = sizeof(dgst) & INT_MAX;

    unsigned char sig[param.strOut.length()];
    memset(sig, 0, sizeof(sig));
    memcpy(sig, param.strOut.c_str(), param.strOut.length());
    unsigned int siglen = sizeof(sig) & INT_MAX;

    if(1 != SM2_verify(type, dgst, dgstlen, sig, siglen, pubkey))
    {
        fprintf(stderr, "%s() failed to SM2_verify\n", __func__);
        return RES_VERIFY_FAILURE;
    }

    param.strOut = string(reinterpret_cast<const char*>(sig));
    return RES_OK;
}
