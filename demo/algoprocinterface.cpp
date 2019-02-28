#include "algoprocinterface.h"

#include <stdlib.h>

#include "algoprocfactory.h"

using namespace std;

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

bool AlgoProcInterface::GenerateRandom(GB::AlgorithmParams &param)
{
    printf("Generate random begin\n");
    bool bret = false;
    using namespace GB;
    AlgoProcLib *pAlgoProcLib = AlgoProcFactory::GetInstance()->CreateAlgoProc(ALGO_RANDOM);
    bret = (pAlgoProcLib && pAlgoProcLib->ProcessAlgorithm(param));
    AlgoProcLib::ReleaseAlgoProcLib(pAlgoProcLib);

    printf("Generate random finish [res=%s]\n", (bret ? "success" : "failure"));
    return bret;
}

AlgoProcInterface::AlgoProcInterface()
{

}
