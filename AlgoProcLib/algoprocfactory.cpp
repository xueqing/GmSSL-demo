#include "algoprocfactory.h"

#include "randomgenerator.h"
#include "smtwoecsign.h"
#include "smtwoecverify.h"
#include "smthreehash.h"
#include "smfourecbcrypt.h"
#include "eckeygenerator.h"
#include "symmkeygenerator.h"

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
        pAlgoProcLib = new SMTwoECSign;
        break;
    case ALGO_DEC_SM2:
        pAlgoProcLib = new SMTwoECVerify;
        break;
    case ALGO_HASH_SM3:
        pAlgoProcLib = new SMThreeHash;
        break;
    case ALGO_ENC_SM4_ECB:
        pAlgoProcLib = new SMFourECBCrypt(AlgoProcLib::CRYP_ENC);
        break;
    case ALGO_DEC_SM4_ECB:
        pAlgoProcLib = new SMFourECBCrypt(AlgoProcLib::CRYP_DEC);
        break;
    case ALGO_GET_KEY_EC:
        pAlgoProcLib = new ECKeyGenerator;
        break;
    case ALGO_GET_KEY_SYMM:
        pAlgoProcLib = new SymmKeyGenerator;
        break;
    default:
        pAlgoProcLib = new AlgoProcLib(algotype);
        break;
    }
    return pAlgoProcLib;
}

AlgoProcFactory::AlgoProcFactory()
{

}
