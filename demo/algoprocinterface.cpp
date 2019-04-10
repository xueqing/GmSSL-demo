#include "algoprocinterface.h"

#include <stdlib.h>

#include "algoprocfactory.h"

using namespace std;
using namespace GB;

AlgoProcInterface*  AlgoProcInterface::m_pInstance = nullptr;
std::mutex          AlgoProcInterface::m_instanceMutex;
AlgoProcInterface::AlgoProcInterfaceDestruct AlgoProcInterface::m_destruct;

AlgoProcInterface *AlgoProcInterface::GetInstance()
{
    if(nullptr == m_pInstance)
    {
        std::unique_lock<std::mutex> locker(m_instanceMutex);
        if(nullptr == m_pInstance)
        {
            m_pInstance = new AlgoProcInterface();
        }
    }
    return m_pInstance;
}

bool AlgoProcInterface::GenerateRandom(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_RANDOM);
}

bool AlgoProcInterface::SignBySM2(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_ENC_SM2);
}

bool AlgoProcInterface::VerifySignBySM2(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_DEC_SM2);
}

bool AlgoProcInterface::HashBySM3(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_HASH_SM3);
}

bool AlgoProcInterface::EncryptBySM4ECB(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_ENC_SM4_ECB);
}

bool AlgoProcInterface::DecryptBySM4ECB(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_DEC_SM4_ECB);
}

bool AlgoProcInterface::GenerateECkey(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_GET_KEY_EC);
}

bool AlgoProcInterface::HexStr2Buffer(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_HEX2BUF);
}

bool AlgoProcInterface::Buffer2HexStr(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_BUF2HEX);
}

bool AlgoProcInterface::Base64Encode(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_ENC_BASE64);
}

bool AlgoProcInterface::Base64Decode(AlgorithmParams &param)
{
   return dispatchAlgoProcLib(param, ALGO_DEC_BASE64);
}

AlgoProcInterface::AlgoProcInterface()
{

}

bool AlgoProcInterface::dispatchAlgoProcLib(AlgorithmParams &param, ALGO_TYPE algotype)
{
    printf("%s begin\n", __func__);
    AlgoProcLib *pAlgoProcLib = AlgoProcFactory::GetInstance()->CreateAlgoProc(algotype);
    int nret = pAlgoProcLib->ProcessAlgorithm(param);
    AlgoProcLib::ReleaseAlgoProcLib(pAlgoProcLib);

    printf("%s finish [res=%s] [err=%d]\n", __func__,
           (nret == AlgoProcLib::RES_OK ? "success" : "failure"), nret);
    return (nret == AlgoProcLib::RES_OK);
}
