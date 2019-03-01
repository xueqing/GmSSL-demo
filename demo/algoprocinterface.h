#ifndef ALGOPROCINTERFACE_H
#define ALGOPROCINTERFACE_H

#include <mutex>

#include "algoproc_common.h"

class AlgoProcInterface
{
public:
    static AlgoProcInterface* GetInstance();

    bool GenerateRandom(GB::AlgorithmParams &param);
    bool SignBySM2(GB::AlgorithmParams &param);
    bool VerifySignBySM2(GB::AlgorithmParams &param);
    bool HashBySM3(GB::AlgorithmParams &param);

    bool HexStr2Buffer(GB::AlgorithmParams &param);
    bool Buffer2HexStr(GB::AlgorithmParams &param);
    bool Base64Encode(GB::AlgorithmParams &param);
    bool Base64Decode(GB::AlgorithmParams &param);

private:
    AlgoProcInterface();
    static AlgoProcInterface* m_pInstance;
    static std::mutex         m_instanceMutex;

    class AlgoProcInterfaceDestruct
    {
    public:
        ~AlgoProcInterfaceDestruct()
        {
            if(AlgoProcInterface::m_pInstance)
                delete AlgoProcInterface::m_pInstance;
            AlgoProcInterface::m_pInstance = nullptr;
        }
    };
    static AlgoProcInterfaceDestruct m_destruct;
};


#endif // ALGOPROCINTERFACE_H
