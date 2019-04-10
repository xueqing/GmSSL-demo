#ifndef SYMMKEYGENERATOR_H
#define SYMMKEYGENERATOR_H

#include "algoproclib.h"

namespace GB {

class SymmKeyGenerator : public AlgoProcLib
{
public:
    SymmKeyGenerator();

    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace GB

#endif // SYMMKEYGENERATOR_H
