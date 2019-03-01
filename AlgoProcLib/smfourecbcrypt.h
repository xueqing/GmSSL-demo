#ifndef SMFOURECBCRYPT_H
#define SMFOURECBCRYPT_H

#include "algoproclib.h"

namespace GB {

class SMFourECBCrypt : public AlgoProcLib
{
public:
    SMFourECBCrypt(CRPT_TYPE cryptype);

    int ProcessAlgorithm(AlgorithmParams &param) override;

private:
    CRPT_TYPE m_crypType;
};

}//namespace GB

#endif // SMFOURECBCRYPT_H
