#ifndef SMTWOELLIPTICCURVESIGN_H
#define SMTWOELLIPTICCURVESIGN_H

#include "algoproclib.h"

namespace GB {

class SMTwoEllipticCurveSign : public AlgoProcLib
{
public:
    SMTwoEllipticCurveSign();

    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace GB

#endif // SMTWOELLIPTICCURVESIGN_H
