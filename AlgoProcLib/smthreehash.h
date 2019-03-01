#ifndef SMTHREEHASH_H
#define SMTHREEHASH_H

#include "algoproclib.h"

namespace GB {

class SMThreeHash : public AlgoProcLib
{
public:
    SMThreeHash();

    int ProcessAlgorithm(AlgorithmParams &param) override;
};

}//namespace GB

#endif // SMTHREEHASH_H
