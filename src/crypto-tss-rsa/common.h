#ifndef SAFEHERON_TSS_RSA_COMMON_H
#define SAFEHERON_TSS_RSA_COMMON_H

#include <iostream>
#include <vector>
#include "crypto-bn/bn.h"

namespace safeheron {
namespace tss_rsa{

static inline safeheron::bignum::BN lambda(const safeheron::bignum::BN &i,
                                           const safeheron::bignum::BN &j,
                                           const std::vector<safeheron::bignum::BN> &S,
                                           const safeheron::bignum::BN &delta){
    safeheron::bignum::BN num(1);
    safeheron::bignum::BN den(1);
    for(const auto &item : S){
        if(j != item){
            num *= (i - item);
            den *= (j - item);
        }
    }
    return delta * num / den;
}

};
};

#endif //SAFEHERON_TSS_RSA_COMMON_H