#include "smfourecbcrypt.h"

#include <string.h>

#include "mysm4.h"

using namespace std;
using namespace GB;

SMFourECBCrypt::SMFourECBCrypt(CRPT_TYPE cryptype)
    : m_crypType(cryptype)
{

}

int SMFourECBCrypt::ProcessAlgorithm(AlgorithmParams &param)
{
    unsigned char inBuf[param.strIn.length()];
    memset(inBuf, 0, sizeof(inBuf));
    memcpy(inBuf, param.strIn.c_str(), param.strIn.length());

    unsigned char outBuf[MAX_BUF_SIZE];
    memset(outBuf, 0, sizeof(outBuf));
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    printf("original:\n");
    for(int i = 0; i < 16; i++)
        printf("%02x ", inBuf[i]);
    printf("\n");

    sm4_context ctx;
    sm4_setkey(&ctx, key, m_crypType);
    sm4_crypt_ecb(&ctx, m_crypType, 16, inBuf, outBuf);

    printf("crypted:\n");
    for (int i = 0; i < 16; i++)
        printf("%02x ", outBuf[i]);
    printf("\n");

    param.strOut = string(reinterpret_cast<const char*>(outBuf));
    return RES_OK;
}
