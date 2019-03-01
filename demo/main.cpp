#include <stdio.h>

#include "algoprocinterface.h"

#define TEST_BASE64 0
#define TEST_RANDOM 0
#define TEST_CONV_HEX_BUF 0

void TestRandom();
void TestBase64Encode(GB::AlgorithmParams &param);
void TestBase64Decode(GB::AlgorithmParams &param);
void TestHexStr2Buffer(GB::AlgorithmParams &param);
void TestBuffer2HexStr(GB::AlgorithmParams &param);

int main()
{
#if TEST_BASE64
    {
        GB::AlgorithmParams paramEn;
        paramEn.strIn = "aaaaa";
        paramEn.lenOut = 128;
        TestBase64Encode(paramEn);

        GB::AlgorithmParams paramDe;
        paramDe.strIn = paramEn.strOut;
        paramDe.lenOut = 128;
        TestBase64Decode(paramDe);

        if(paramEn.strIn == paramDe.strOut)
            printf("Base64 test success\n");
        else
            printf("Base64 test failure\n");
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
            printf("Convert buffer and hex string failure\n");
    }
#endif

    return 0;
}

void TestRandom()
{
    GB::AlgorithmParams param;
    param.lenOut = 10;
    if(!AlgoProcInterface::GetInstance()->GenerateRandom(param))
    {
        printf("Generate random error\n");
        return;
    }
    printf("Generate random success [str=%s]\n", param.strOut.c_str());

    GB::AlgorithmParams paramEn;
    paramEn.strIn = param.strOut;
    paramEn.lenOut = 128;
    TestBase64Encode(paramEn);
    printf("Generate random success [base64_encode_str=%s]\n", paramEn.strOut.c_str());
}

void TestBase64Encode(GB::AlgorithmParams &param)
{
    if(!AlgoProcInterface::GetInstance()->Base64Encode(param))
    {
        printf("Base64 encode error\n");
        return;
    }
    printf("Base64 encode success [str_in=%s] [str_out=%s]\n",
           param.strIn.c_str(), param.strOut.c_str());
}

void TestBase64Decode(GB::AlgorithmParams &param)
{
    if(!AlgoProcInterface::GetInstance()->Base64Decode(param))
    {
        printf("Base64 decode error\n");
        return;
    }
    printf("Base64 decode success [str_in=%s] [str_out=%s]\n",
           param.strIn.c_str(), param.strOut.c_str());
}

void TestHexStr2Buffer(GB::AlgorithmParams &param)
{
    if(!AlgoProcInterface::GetInstance()->HexStr2Buffer(param))
    {
        printf("HexStr2Buffer error\n");
        return;
    }
    printf("HexStr2Buffer success [str_in=%s] [str_out=%s]\n",
           param.strIn.c_str(), param.strOut.c_str());
}

void TestBuffer2HexStr(GB::AlgorithmParams &param)
{
    if(!AlgoProcInterface::GetInstance()->Buffer2HexStr(param))
    {
        printf("Buffer2HexStr error\n");
        return;
    }
    printf("Buffer2HexStr success [str_in=%s] [str_out=%s]\n",
           param.strIn.c_str(), param.strOut.c_str());
}
