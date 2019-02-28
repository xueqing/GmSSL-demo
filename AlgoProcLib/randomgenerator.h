#ifndef RANDOMGENERATOR_H
#define RANDOMGENERATOR_H

#include "algoproclib.h"

namespace GB {

class RandomGenerator : public AlgoProcLib
{
public:
    RandomGenerator();

    bool ProcessAlgorithm(AlgorithmParams &param);
};

}//namespace GB

#endif // RANDOMGENERATOR_H
