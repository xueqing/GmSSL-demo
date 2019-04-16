#include "algoprocinterface.h"

#include <stdlib.h>

#include "algoprocfactory.h"

using namespace std;
using namespace GB;

AlgoProcInterface*  AlgoProcInterface::m_pInstance = nullptr;
std::mutex          AlgoProcInterface::m_instanceMutex;
map<ALGO_TYPE, string> AlgoProcInterface::m_algoMap = {
    {ALGO_UNKNOWN, "ALGO_UNKNOWN"},
    {ALGO_HEX2BUF, "ALGO_HEX2BUF"},
    {ALGO_BUF2HEX, "ALGO_BUF2HEX"},
    {ALGO_ENC_BASE64, "ALGO_ENC_BASE64"},
    {ALGO_DEC_BASE64, "ALGO_DEC_BASE64"},
    {ALGO_RANDOM, "ALGO_RANDOM"},
    {ALGO_ENC_SM2, "ALGO_ENC_SM2"},
    {ALGO_DEC_SM2, "ALGO_DEC_SM2"},
    {ALGO_HASH_SM3, "ALGO_HASH_SM3"},
    {ALGO_ENC_SM4_ECB, "ALGO_ENC_SM4_ECB"},
    {ALGO_DEC_SM4_ECB, "ALGO_DEC_SM4_ECB"},
    {ALGO_GET_KEY_EC, "ALGO_GET_KEY_EC"},
    {ALGO_GET_KEY_SYMM, "ALGO_GET_KEY_SYMM"},
};

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

bool AlgoProcInterface::GenerateSymmKey(AlgorithmParams &param)
{
    return dispatchAlgoProcLib(param, ALGO_GET_KEY_SYMM);
}

bool AlgoProcInterface::GenerateECKey(AlgorithmParams &param)
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
    printf("%s begin [algotype=%s]\n", __func__, m_algoMap.at(algotype).c_str());
    AlgoProcLib *pAlgoProcLib = AlgoProcFactory::GetInstance()->CreateAlgoProc(algotype);
    int nret = pAlgoProcLib->ProcessAlgorithm(param);
    AlgoProcLib::ReleaseAlgoProcLib(pAlgoProcLib);

    printf("%s finish [algotype=%s] [res=%s] [err=%d]\n", __func__, m_algoMap.at(algotype).c_str(),
           (nret == AlgoProcLib::RES_OK ? "success" : "failure"), nret);
    return (nret == AlgoProcLib::RES_OK);
}
