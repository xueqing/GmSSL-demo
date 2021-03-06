#ifndef ALGOPROCINTERFACE_H
#define ALGOPROCINTERFACE_H

#include <mutex>
#include <map>

#include "algoproc_common.h"

class AlgoProcInterface
{
public:
    static AlgoProcInterface* GetInstance();

    bool GenerateRandom(GB::AlgorithmParams &param);
    bool SignBySM2(GB::AlgorithmParams &param);
    bool VerifySignBySM2(GB::AlgorithmParams &param);
    bool HashBySM3(GB::AlgorithmParams &param);
    bool EncryptBySM4ECB(GB::AlgorithmParams &param);
    bool DecryptBySM4ECB(GB::AlgorithmParams &param);

    bool GenerateSymmKey(GB::AlgorithmParams &param);
    bool GenerateECKey(GB::AlgorithmParams &param);

    bool HexStr2Buffer(GB::AlgorithmParams &param);
    bool Buffer2HexStr(GB::AlgorithmParams &param);
    bool Base64Encode(GB::AlgorithmParams &param);
    bool Base64Decode(GB::AlgorithmParams &param);

private:
    AlgoProcInterface();
    static AlgoProcInterface* m_pInstance;
    static std::mutex         m_instanceMutex;

    static std::map<GB::ALGO_TYPE, std::string> m_algoMap;

    bool dispatchAlgoProcLib(GB::AlgorithmParams &param, GB::ALGO_TYPE algotype);

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
