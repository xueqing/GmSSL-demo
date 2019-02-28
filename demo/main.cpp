#include <stdio.h>

#include "algoprocinterface.h"

void TestRandom();

int main()
{
    TestRandom();
    return 0;
}

void TestRandom()
{
    GB::AlgorithmParams param;
    if(!AlgoProcInterface::GetInstance()->GenerateRandom(param))
    {
        printf("Generate random error\n");
        return;
    }
    printf("Generate random success [str=%s]\n", param.strOut.c_str());
}
