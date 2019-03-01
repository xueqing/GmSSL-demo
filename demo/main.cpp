#include <stdio.h>

#include "algoprocinterface.h"

#define TEST_BASE64 0
#define TEST_RANDOM 0

void TestRandom();
void TestBase64Encode(GB::AlgorithmParams &param);
void TestBase64Decode(GB::AlgorithmParams &param);

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
