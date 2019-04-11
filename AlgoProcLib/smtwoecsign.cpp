#include "smtwoecsign.h"

#include <openssl/sm2.h>
#include <openssl/pem.h>

using namespace std;
using namespace GB;

#define PRINT_KEY 1

#if PRINT_KEY
static void printByPem(EC_KEY *ecKey);
#endif

SMTwoECSign::SMTwoECSign()
    : AlgoProcLib()
{

}

int SMTwoECSign::ProcessAlgorithm(AlgorithmParams &param)
{
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
            fprintf(stderr, "%s() failed to call EC_KEY_oct2priv [lib=%s] [func=%s] [reason=%s]\n", __func__,
                    ERR_lib_error_string(ERR_get_error()), ERR_func_error_string(ERR_get_error()),
                    ERR_reason_error_string(ERR_get_error()));
            break;
        }

#if PRINT_KEY
        printByPem(ecKey);
#endif

        if(!SM2_sign(type, dgst, param.strIn.length(), sig, &param.lenOut, ecKey))
        {
            fprintf(stderr, "%s() failed to SM2_sign\n", __func__);
            break;
        }

        nret = RES_OK;
    }while(false);

    if(nret == RES_OK)
        param.strOut = string(reinterpret_cast<const char*>(sig));
    return nret;
}

#if PRINT_KEY
static void printByPem(EC_KEY *ecKey)
{
    BIO *outbio = nullptr;
    do
    {
        // Create the Input/Output BIO's
        if(!(outbio = BIO_new(BIO_s_file()))
                || !(outbio = BIO_new_fp(stdout, BIO_NOCLOSE)))
        {
            fprintf(stderr, "%s() failed to new bio\n", __func__);
            break;
        }

        if(!PEM_write_bio_ECPrivateKey(outbio, ecKey, NULL, NULL, 0, NULL, NULL))
        {
            BIO_printf(outbio, "Error call PEM_write_bio_ECPrivateKey [lib=%s] [func=%s] [reason=%s]\n",
                       ERR_lib_error_string(ERR_get_error()), ERR_func_error_string(ERR_get_error()),
                       ERR_reason_error_string(ERR_get_error()));
        }
    }while(false);

    // Free up all structures
    BIO_free_all(outbio);
}
#endif
