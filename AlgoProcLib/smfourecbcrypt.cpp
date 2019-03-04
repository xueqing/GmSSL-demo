#include "smfourecbcrypt.h"

#include <openssl/evp.h>
#include <openssl/sms4.h>
#include <openssl/ffx.h>
#include <openssl/err.h>

using namespace std;
using namespace GB;

SMFourECBCrypt::SMFourECBCrypt(CRPT_TYPE cryptype)
    : m_crypType(cryptype)
{

}

int SMFourECBCrypt::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;

    char outBuf[MAX_BUF_SIZE];
    memset(outBuf, 0, MAX_BUF_SIZE);
    FFX_CTX *ctx = NULL;

    do
    {
        const EVP_CIPHER *cipher = EVP_sms4_ecb();

        unsigned char key[32];
        memset(key, 0, sizeof(key));
        unsigned char tweak[8] = {
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
        };

        if(!(ctx = FFX_CTX_new()))
        {
            fprintf(stderr, "%s() failed to allocate ffx_ctx\n", __func__);
            break;
        }

        if(!FFX_init(ctx, cipher, key, 0))
        {
            ERR_print_errors_fp(stderr);
            break;
        }
        if(m_crypType == CRYP_ENC && !FFX_encrypt(ctx, param.strIn.c_str(), outBuf, param.strIn.length(), tweak, sizeof(tweak)))
        {
            ERR_print_errors_fp(stderr);
            break;
        }
        if(m_crypType == CRYP_DEC && !FFX_decrypt(ctx, param.strIn.c_str(), outBuf, param.strIn.length(), tweak, sizeof(tweak)))
        {
            ERR_print_errors_fp(stderr);
            break;
        }

        nret = RES_OK;
    }while(false);

    FFX_CTX_free(ctx);
    param.strOut = string(outBuf);
    return nret;
}
