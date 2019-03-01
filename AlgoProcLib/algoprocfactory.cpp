#include "algoprocfactory.h"

#include "randomgenerator.h"
#include "smtwoellipticcurvesign.h"
#include "smtwoellipticcurveverify.h"
#include <smthreehash.h>

using namespace GB;

AlgoProcFactory* AlgoProcFactory::m_pInstance = nullptr;
std::mutex AlgoProcFactory::m_instanceMutex;
AlgoProcFactory::AlgoProcFactoryDestruct AlgoProcFactory::m_destruct;

AlgoProcFactory *AlgoProcFactory::GetInstance()
{
    if(m_pInstance == nullptr)
    {
        std::lock_guard<std::mutex> lock(m_instanceMutex);
        if(m_pInstance == nullptr)
        {
            m_pInstance = new AlgoProcFactory;
        }
    }

    return m_pInstance;
}

AlgoProcLib *AlgoProcFactory::CreateAlgoProc(ALGO_TYPE algotype)
{
    AlgoProcLib *pAlgoProcLib = nullptr;
    switch (algotype) {
    case ALGO_RANDOM:
        pAlgoProcLib = new RandomGenerator;
        break;
    case ALGO_ENC_SM2:
        pAlgoProcLib = new SMTwoEllipticCurveSign;
        break;
    case ALGO_DEC_SM2:
        pAlgoProcLib = new SMTwoEllipticCurveVerify;
        break;
    case ALGO_HASH_SM3:
        pAlgoProcLib = new SMThreeHash;
        break;
    default:
        pAlgoProcLib = new AlgoProcLib;
        break;
    }
    return pAlgoProcLib;
}

AlgoProcFactory::AlgoProcFactory()
{

}
