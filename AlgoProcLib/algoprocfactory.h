#ifndef ALGOPROCFACTORY_H
#define ALGOPROCFACTORY_H

#include <mutex>

#include "algoproclib.h"

namespace GB {

enum ALGO_TYPE {
    ALGO_RANDOM = 0,
    ALGO_ENC_SM2,
    ALGO_DEC_SM2,
    ALGO_HASH_SM3,
};

class AlgoProcFactory
{
public:
    static AlgoProcFactory *GetInstance();

    AlgoProcLib *CreateAlgoProc(GB::ALGO_TYPE algotype);

private:
    AlgoProcFactory();

    static AlgoProcFactory *m_pInstance;
    static std::mutex m_instanceMutex;

    class AlgoProcFactoryDestruct
    {
    public:
        ~AlgoProcFactoryDestruct()
        {
            if(AlgoProcFactory::m_pInstance)
                delete AlgoProcFactory::m_pInstance;
            AlgoProcFactory::m_pInstance = nullptr;
        }
    };
    static AlgoProcFactoryDestruct m_destruct;
};

}//namespace GB

#endif // ALGOPROCFACTORY_H
