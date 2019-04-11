#include "eckeygenerator.h"

#include <string.h>

#include <openssl/sm2.h>
#include <openssl/pem.h>

using namespace std;
using namespace GB;

#define PRINT_KEY 0
#define SELF_SIGN_AND_VERIFY 0

#if PRINT_KEY
static void printByPem(EC_KEY *ecKey);
#endif
#if SELF_SIGN_AND_VERIFY
static void testSignAndVerify(EC_KEY *ecKey);
#endif

static void saveToPem(EC_KEY *ecKey, const string &filePath);

ECKeyGenerator::ECKeyGenerator()
    : AlgoProcLib()
{

}

int ECKeyGenerator::ProcessAlgorithm(AlgorithmParams &param)
{
    int nret = RES_SERVER_ERROR;
    EC_KEY *ecKey=nullptr;

    do
    {
        /*
         * SM2标准文本中提供了四个测试用椭圆曲线域参数:
         *  192比特素数域椭圆曲线域参数（sm2p192test)
         *  256比特素数域椭圆曲线域参数（sm2p256test)
         *  193比特二进制域椭圆曲线域参数 (sm2b193test)
         *  257比特二进制域椭圆曲线域参数 (sm2b257test)
         */
        if(!(ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
        {
            fprintf(stderr, "%s() failed to call EC_KEY_new_by_curve_name\n", __func__);
            break;
        }

        // For cert signing, if not, will result in a SSL error of 0x1408a0c1 (no shared cipher)
        EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);

        if(EC_KEY_generate_key(ecKey) != 1)
        {
            fprintf(stderr, "%s() failed to call EC_KEY_generate_key\n", __func__);
            break;
        }

        nret = RES_OK;
    }while(false);

    if(nret == RES_OK)
    {
#if PRINT_KEY
        printByPem(ecKey);
#endif
#if SELF_SIGN_AND_VERIFY
        testSignAndVerify(ecKey);
#endif
        saveToPem(ecKey, param.filePath);
        unsigned char buf[MAX_BUF_SIZE];
        memset(buf, 0, MAX_BUF_SIZE);
        unsigned char *ptrPub=nullptr, *ptrPri=nullptr;
        if(EC_KEY_key2buf(ecKey, EC_KEY_get_conv_form(ecKey), &ptrPub, nullptr) != 0)
            param.ec_pub_key = string(reinterpret_cast<char*>(ptrPub));
        if(EC_KEY_priv2oct(ecKey, buf, MAX_BUF_SIZE) != 0)
            param.ec_pri_key = string(reinterpret_cast<char*>(buf));
        OPENSSL_free(ptrPub);
        OPENSSL_free(ptrPri);
    }

    EC_KEY_free(ecKey);

    return nret;
}

#if PRINT_KEY
static void printByPem(EC_KEY *ecKey)
{
    BIO *pbio = nullptr;
    EVP_PKEY *pkey = nullptr;
    do
    {
        // Create the Input/Output BIO's
        if(!(pbio = BIO_new(BIO_s_file()))
                || !(pbio = BIO_new_fp(stdout, BIO_NOCLOSE)))
        {
            fprintf(stderr, "%s() failed to new bio\n", __func__);
            break;
        }

        if(!PEM_write_bio_ECPrivateKey(pbio, ecKey, NULL, NULL, 0, NULL, NULL))
        {
            BIO_printf(pbio, "Error call PEM_write_bio_ECPrivateKey [lib=%s] [func=%s] [reason=%s]\n",
                       ERR_lib_error_string(ERR_get_error()), ERR_func_error_string(ERR_get_error()),
                       ERR_reason_error_string(ERR_get_error()));
        }
        if(!PEM_write_bio_EC_PUBKEY(pbio, ecKey))
        {
            BIO_printf(pbio, "Error call PEM_write_bio_EC_PUBKEY [lib=%s] [func=%s] [reason=%s]\n",
                       ERR_lib_error_string(ERR_get_error()), ERR_func_error_string(ERR_get_error()),
                       ERR_reason_error_string(ERR_get_error()));
        }

//        // Converting the EC key into a PKEY structure
//        if(!(pkey = EVP_PKEY_new()))
//        {
//            fprintf(stderr, "%s() failed to call EVP_PKEY_new\n", __func__);
//            break;
//        }
//        if(!EVP_PKEY_assign_EC_KEY(pkey, ecKey))
//        {
//            fprintf(stderr, "%s() failed to call EVP_PKEY_assign_EC_KEY\n", __func__);
//            break;
//        }

//        // print the key length
//        BIO_printf(pbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));

//        // print the private/public key data in PEM format
//        if(!PEM_write_bio_PrivateKey(pbio, pkey, NULL, NULL, 0, 0, NULL))
//            BIO_printf(pbio, "Error call PEM_write_bio_PrivateKey");
//        if(!PEM_write_bio_PUBKEY(pbio, pkey))
//            BIO_printf(pbio, "Error call PEM_write_bio_PUBKEY");
    }while(false);

    // Free up all structures
    BIO_free_all(pbio);
    EVP_PKEY_free(pkey); // will release ecKey structure
}
#endif

#if SELF_SIGN_AND_VERIFY
static void testSignAndVerify(EC_KEY *ecKey)
{
    int type = NID_undef;
    string msg = "I am a message to test sm2 sign and verify.";
    unsigned int lenOut = 0;

    unsigned char dgst[msg.length()];
    memset(dgst, 0, sizeof(dgst));
    memcpy(dgst, msg.c_str(), msg.length());

    unsigned char sig[MAX_BUF_SIZE];
    memset(sig, 0, MAX_BUF_SIZE);

    do
    {
        if(!SM2_sign(type, dgst, msg.length(), sig, &lenOut, ecKey))
        {
            fprintf(stderr, "%s() failed to SM2_sign\n", __func__);
            break;
        }

        fprintf(stdout, "%s() succeed to SM2_sign\n", __func__);

        if(1 != SM2_verify(type, dgst, msg.length(), sig, lenOut, ecKey))
        {
            fprintf(stderr, "%s() failed to SM2_verify\n", __func__);
            break;
        }
        fprintf(stdout, "%s() succeed to SM2_verify\n", __func__);
    }while(false);
}
#endif

static void saveToPem(EC_KEY *ecKey, const string &filePath)
{
    BIO *pbio = nullptr;
    EVP_PKEY *pkey = nullptr;
    do
    {
        if(filePath.empty())
            break;

        // if exist, break
        FILE *pFile = fopen(filePath.c_str(), "r");
        if(pFile)
        {
            fclose(pFile);
            break;
        }

        // Create the Input/Output BIO's
        if(!(pbio = BIO_new(BIO_s_file()))
                || !(pbio = BIO_new_file(filePath.c_str(), "w")))
        {
            fprintf(stderr, "%s() failed to new bio\n", __func__);
            break;
        }

        if(!PEM_write_bio_ECPrivateKey(pbio, ecKey, NULL, NULL, 0, NULL, NULL))
        {
            BIO_printf(pbio, "Error call PEM_write_bio_ECPrivateKey [lib=%s] [func=%s] [reason=%s]\n",
                       ERR_lib_error_string(ERR_get_error()), ERR_func_error_string(ERR_get_error()),
                       ERR_reason_error_string(ERR_get_error()));
        }
        if(!PEM_write_bio_EC_PUBKEY(pbio, ecKey))
        {
            BIO_printf(pbio, "Error call PEM_write_bio_EC_PUBKEY [lib=%s] [func=%s] [reason=%s]\n",
                       ERR_lib_error_string(ERR_get_error()), ERR_func_error_string(ERR_get_error()),
                       ERR_reason_error_string(ERR_get_error()));
        }
    }while(false);

    // Free up all structures
    BIO_free_all(pbio);
    EVP_PKEY_free(pkey); // will release ecKey structure
}
