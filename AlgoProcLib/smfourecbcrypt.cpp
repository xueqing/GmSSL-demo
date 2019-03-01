#include "smfourecbcrypt.h"

#include <openssl/evp.h>
#include <openssl/sms4.h>

using namespace std;
using namespace GB;

SMFourECBCrypt::SMFourECBCrypt(CRPT_TYPE cryptype)
    : m_crypType(cryptype)
{

}

int SMFourECBCrypt::ProcessAlgorithm(AlgorithmParams &param)
{
    sms4_key_t *pubkey = NULL;

    unsigned char inBuf[param.strIn.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, param.strIn.c_str(), param.strIn.length());

    unsigned char outBuf[MAX_BUF_SIZE];
    memset(outBuf, 0, MAX_BUF_SIZE);

    sms4_ecb_encrypt(inBuf, outBuf, pubkey, m_crypType);
    {
        fprintf(stderr, "%s() failed to SM4_ECB_Encrypt\n", __func__);
        return RES_SERVER_ERROR;
    }

    param.strOut = string(reinterpret_cast<const char*>(outBuf));
    return RES_OK;
}
