#ifndef SMTWOECVERIFY_H
#define SMTWOECVERIFY_H

#include "algoproclib.h"

namespace GB {

class SMTwoECVerify : public AlgoProcLib
{
public:
    SMTwoECVerify();

    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace GB

#endif // SMTWOECVERIFY_H
