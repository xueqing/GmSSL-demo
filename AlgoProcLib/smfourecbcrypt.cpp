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
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    sms4_key_t pubkey;

    unsigned char inBuf[param.strIn.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, param.strIn.c_str(), param.strIn.length());

    unsigned char outBuf[MAX_BUF_SIZE];
    memset(outBuf, 0, MAX_BUF_SIZE);

    printf("before sm4:\n");
    for(int i = 0; i < 16; i++)
        printf("%02x ", inBuf[i]);
    printf("\n");

    if(m_crypType == CRYP_ENC)
    {
        sms4_set_encrypt_key(&pubkey, key);
    }
    else
    {
        sms4_set_decrypt_key(&pubkey, key);
    }
    sms4_ecb_encrypt(inBuf, outBuf, &pubkey, m_crypType);

    printf("after  sm4:\n");
    for(int i = 0; i < 16; i++)
        printf("%02x ", outBuf[i]);
    printf("\n");

    param.strOut = string(reinterpret_cast<const char*>(outBuf));
    return RES_OK;
}
