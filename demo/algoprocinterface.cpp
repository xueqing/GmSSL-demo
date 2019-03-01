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
    printf("%s begin\n", __func__);
    AlgoProcLib *pAlgoProcLib = AlgoProcFactory::GetInstance()->CreateAlgoProc(ALGO_RANDOM);
    int nret = pAlgoProcLib->ProcessAlgorithm(param);
    AlgoProcLib::ReleaseAlgoProcLib(pAlgoProcLib);

    printf("%s finish [res=%s] [err=%n]\n", __func__,
           (nret == AlgoProcLib::RES_OK ? "success" : "failure"), &nret);
    return (nret == AlgoProcLib::RES_OK);
}

bool AlgoProcInterface::Base64Encode(AlgorithmParams &param)
{
    printf("%s begin\n", __func__);
    int nret = AlgoProcLib::Base64Encode(param.strIn, param.strOut);
    printf("%s finish [res=%s] [err=%n]\n", __func__,
           (nret == AlgoProcLib::RES_OK ? "success" : "failure"), &nret);
    return (nret == AlgoProcLib::RES_OK);
}

bool AlgoProcInterface::Base64Decode(AlgorithmParams &param)
{
    printf("%s begin\n", __func__);
    int nret = AlgoProcLib::Base64Decode(param.strIn, param.strOut);
    printf("%s finish [res=%s] [err=%n]\n", __func__,
           (nret == AlgoProcLib::RES_OK ? "success" : "failure"), &nret);
    return (nret == AlgoProcLib::RES_OK);
}

AlgoProcInterface::AlgoProcInterface()
{

}
