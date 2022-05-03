//
// Created by 何剑虹 on 2020/8/31.
//

#ifndef SAFEHERON_RSA_KEY_SHARE_H
#define SAFEHERON_RSA_KEY_SHARE_H

#include <iostream>
#include <vector>
#include "crypto-bn/bn.h"

namespace safeheron {
namespace tss_rsa{

class RSASigShare{
public:
    RSASigShare(){ index_ = 0; sig_share_ = safeheron::bignum::BN::ZERO;}
    RSASigShare(int index, const safeheron::bignum::BN &sig_share);

    int index() const;
    void set_index(int index);

    const bignum::BN &sig_share() const;
    void set_sig_share(const bignum::BN &sig_share);

private:
    int index_;
    safeheron::bignum::BN sig_share_;
};

};
};

#endif //SAFEHERON_RSA_KEY_SHARE_H