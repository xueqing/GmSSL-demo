#ifndef SMTWOELLIPTICCURVEVERIFY_H
#define SMTWOELLIPTICCURVEVERIFY_H

#include "algoproclib.h"

namespace GB {

class SMTwoEllipticCurveVerify : public AlgoProcLib
{
public:
    SMTwoEllipticCurveVerify();

    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace GB

#endif // SMTWOELLIPTICCURVEVERIFY_H
