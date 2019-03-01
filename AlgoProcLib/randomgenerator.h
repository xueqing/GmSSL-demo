#ifndef RANDOMGENERATOR_H
#define RANDOMGENERATOR_H

#include "algoproclib.h"

namespace GB {

class RandomGenerator : public AlgoProcLib
{
public:
    RandomGenerator();

    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace GB

#endif // RANDOMGENERATOR_H
