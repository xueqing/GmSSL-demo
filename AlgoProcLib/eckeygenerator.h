#ifndef ECKEYGENERATOR_H
#define ECKEYGENERATOR_H

#include "algoproclib.h"

namespace GB {

class ECKeyGenerator : public AlgoProcLib
{
public:
    ECKeyGenerator();

    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace GB

#endif // ECKEYGENERATOR_H
