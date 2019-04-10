#ifndef SMTWOECSIGN_H
#define SMTWOECSIGN_H

#include "algoproclib.h"

namespace GB {

class SMTwoECSign : public AlgoProcLib
{
public:
    SMTwoECSign();

    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace GB

#endif // SMTWOECSIGN_H
