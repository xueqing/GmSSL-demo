#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "algoprocinterface.h"
#include "algoproclib.h"

using namespace std;

#define TEST_BASE64 0
#define TEST_RANDOM 0
#define TEST_CONV_HEX_BUF 0
#define TEST_HASH_SM3 0
#define TEST_SM4_ECB 1
#define TEST_EC_KEY_GEN 0
#define TEST_SM2_SIGN_VERIFY 0

void TestRandom();
void TestBase64();
void TestBase64Encode(GB::AlgorithmParams &param);
void TestBase64Decode(GB::AlgorithmParams &param);
void TestHexStr2Buffer(GB::AlgorithmParams &param);
void TestBuffer2HexStr(GB::AlgorithmParams &param);
void TestHashSM3();
void TestSM4ECB();
void TestEncryptBySM4ECB(GB::AlgorithmParams &param);
void TestDecryptBySM4ECB(GB::AlgorithmParams &param);
void TestECKeyGenerator();
void TestSM2SignAndVerify();

int main()
{
//    GB::AlgoProcLib::Initialize();
#if TEST_BASE64
    {
        TestBase64();
    }
#endif

#if TEST_RANDOM
    {
        TestRandom();
    }
#endif

#if TEST_CONV_HEX_BUF
    {
        GB::AlgorithmParams paramHex;
        paramHex.strIn = "616263";
        TestHexStr2Buffer(paramHex);

        GB::AlgorithmParams paramBuf;
        paramBuf.strIn = paramHex.strOut;
        TestBuffer2HexStr(paramBuf);

        if(paramHex.strIn == paramBuf.strOut)
            printf("Convert buffer and hex string test success\n");
        else
        {
            printf("Convert buffer and hex string failure\n");
            assert(false);
        }
    }
#endif

#if TEST_HASH_SM3
    {
        TestHashSM3();
    }
#endif

#if TEST_SM4_ECB
    {
        TestSM4ECB();
    }
#endif

#if TEST_EC_KEY_GEN
    {
        TestECKeyGenerator();
    }
#endif

#if TEST_SM2_SIGN_VERIFY
    {
        TestSM2SignAndVerify();
    }
#endif

//    GB::AlgoProcLib::Deinitialize();
    return 0;
}

void TestRandom()
{
    GB::AlgorithmParams param;
    param.lenOut = 10;
    if(!AlgoProcInterface::GetInstance()->GenerateRandom(param))
    {
        printf("Generate random error\n");
        assert(false);
    }
    printf("Generate random success [str=%s]\n", param.strOut.c_str());
}

void TestBase64()
{
    GB::AlgorithmParams param;
    param.lenOut = 10;
    if(!AlgoProcInterface::GetInstance()->GenerateRandom(param))
    {
        printf("Generate random error\n");
        assert(false);
    }
    printf("Base64 test [rand_str=%s]\n", param.strOut.c_str());

    GB::AlgorithmParams paramEn;
    paramEn.strIn = param.strOut;
    paramEn.lenOut = 128;
    TestBase64Encode(paramEn);
    printf("Base64 test [base64_encode_str=%s]\n", paramEn.strOut.c_str());

    GB::AlgorithmParams paramDe;
    paramDe.strIn = paramEn.strOut;
    paramDe.lenOut = 128;
    TestBase64Decode(paramDe);

    if(paramEn.strIn == paramDe.strOut)
        printf("Base64 test success\n");
    else
    {
        printf("Base64 test failure\n");
        assert(false);
    }
}

void TestBase64Encode(GB::AlgorithmParams &param)
{
    if(!AlgoProcInterface::GetInstance()->Base64Encode(param))
    {
        printf("Base64 encode error\n");
        assert(false);
    }
    printf("Base64 encode success [str_in=%s] [str_out=%s]\n",
           param.strIn.c_str(), param.strOut.c_str());
}

void TestBase64Decode(GB::AlgorithmParams &param)
{
    if(!AlgoProcInterface::GetInstance()->Base64Decode(param))
    {
        printf("Base64 decode error\n");
        assert(false);
    }
    printf("Base64 decode success [str_in=%s] [str_out=%s]\n",
           param.strIn.c_str(), param.strOut.c_str());
}

void TestHexStr2Buffer(GB::AlgorithmParams &param)
{
    if(!AlgoProcInterface::GetInstance()->HexStr2Buffer(param))
    {
        printf("HexStr2Buffer error\n");
        assert(false);
    }
    printf("HexStr2Buffer success [str_in=%s] [str_out=%s]\n",
           param.strIn.c_str(), param.strOut.c_str());
}

void TestBuffer2HexStr(GB::AlgorithmParams &param)
{
    if(!AlgoProcInterface::GetInstance()->Buffer2HexStr(param))
    {
        printf("Buffer2HexStr error\n");
        assert(false);
    }
    printf("Buffer2HexStr success [str_in=%s] [str_out=%s]\n",
           param.strIn.c_str(), param.strOut.c_str());

}

void TestHashSM3()
{
    /*
     * in_1:
     * "6162636461626364616263646162636461626364616263646162636461626364"
     * "6162636461626364616263646162636461626364616263646162636461626364"
     * out_1: debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
     * in_2: 616263
     * out_2: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
    */
    GB::AlgorithmParams paramhex;
    paramhex.strIn = "6162636461626364616263646162636461626364616263646162636461626364"
                     "6162636461626364616263646162636461626364616263646162636461626364";
    TestHexStr2Buffer(paramhex);

    GB::AlgorithmParams param;
    param.strIn = paramhex.strOut;
    if(!AlgoProcInterface::GetInstance()->HashBySM3(param))
    {
        printf("Hash by SM3 error [server orror]\n");
        assert(false);
    }

    GB::AlgorithmParams paramHash;
    paramHash.strIn = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";
    TestHexStr2Buffer(paramHash);

    GB::AlgorithmParams param64;
    param64.strIn = paramHash.strOut;
    TestBase64Encode(param64);

    if(param.strOut != param64.strOut)
    {
        printf("Hash by SM3 error [gen_str=%s] [dst_str=%s]\n",
               param.strOut.c_str(), param64.strOut.c_str());
        assert(false);
    }
    else
    {
        printf("Hash by SM3 success\n");
    }
}

void TestSM4ECB()
{
    GB::AlgorithmParams paramKey;
    paramKey.lenOut = 128 / 8;
    if(!AlgoProcInterface::GetInstance()->GenerateSymmKey(paramKey))
    {
        printf("Generate symm key error\n");
        assert(false);
    }
    printf("Generate symm key success [key=%s]\n", paramKey.sm4_ecb_key.c_str());

    GB::AlgorithmParams paramEn;
    paramEn.strIn = "qweasdzxcrtyfghvddd";
    paramEn.lenOut = 128;
    paramEn.sm4_ecb_key = paramKey.sm4_ecb_key;
    if(!AlgoProcInterface::GetInstance()->EncryptBySM4ECB(paramEn))
    {
        printf("SM4_ECB encode error\n");
        assert(false);
    }
    printf("SM4_ECB encode success [str_in=%s] [str_out=%s]\n",
           paramEn.strIn.c_str(), paramEn.strOut.c_str());


    GB::AlgorithmParams paramDe;
    paramDe.strIn = paramEn.strOut;
    paramDe.sm4_ecb_key = paramKey.sm4_ecb_key;
    if(!AlgoProcInterface::GetInstance()->DecryptBySM4ECB(paramDe))
    {
        printf("SM4_ECB decode error\n");
        assert(false);
    }
    printf("SM4_ECB decode success [str_in=%s] [str_out=%s]\n",
           paramDe.strIn.c_str(), paramDe.strOut.c_str());

    if(paramEn.strIn == paramDe.strOut)
        printf("SM4_ECB test success\n");
    else
    {
        printf("SM4_ECB test failure\n");
        assert(false);
    }

}

void TestECKeyGenerator()
{
    GB::AlgorithmParams param;
    if(!AlgoProcInterface::GetInstance()->GenerateECKey(param))
    {
        printf("Generate ec key error\n");
        assert(false);
    }

    {
        GB::AlgorithmParams paramEn;
        paramEn.strIn = param.ec_pub_key;
        paramEn.lenOut = 512;
        TestBuffer2HexStr(paramEn);
        printf("Generate ec key success [pubkey=%s]\n", param.ec_pub_key.c_str());
        printf("Generate ec key success [pubkey_hexstr=%s]\n", paramEn.strOut.c_str());
    }

    {
        GB::AlgorithmParams paramEn;
        paramEn.strIn = param.ec_pri_key;
        paramEn.lenOut = 256;
        TestBuffer2HexStr(paramEn);
        printf("Generate ec key success [prikey=%s]\n", param.ec_pri_key.c_str());
        printf("Generate ec key success [prikey_hexstr=%s]\n", paramEn.strOut.c_str());
    }
}

void TestSM2SignAndVerify()
{
    GB::AlgorithmParams param;
    param.uid = "qweasdzxc123";
    if(!AlgoProcInterface::GetInstance()->GenerateECKey(param))
    {
        printf("Generate ec key error\n");
        assert(false);
    }

    string msg = "I am a message to test sm2 sign and verify.";

    GB::AlgorithmParams paramEn;
    paramEn.strIn = msg;
    paramEn.ec_pri_key = param.ec_pri_key;
    if(!AlgoProcInterface::GetInstance()->SignBySM2(paramEn))
    {
        printf("Sign by SM2 error\n");
        assert(false);
    }
    printf("Sign by SM2 success [enc_msg=%s]\n", paramEn.strOut.c_str());

    paramEn.ec_pub_key = param.ec_pub_key;
    if(!AlgoProcInterface::GetInstance()->VerifySignBySM2(paramEn))
    {
        printf("Verify sign by SM2 error\n");
        assert(false);
    }
    printf("Verify sign by SM2 success\n");
}
