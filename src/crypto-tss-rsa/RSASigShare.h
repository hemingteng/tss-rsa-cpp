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
    RSASigShare();
    RSASigShare(int index,
                const safeheron::bignum::BN &sig_share,
                const safeheron::bignum::BN &z,
                const safeheron::bignum::BN &c);

    int index() const;
    void set_index(int index);

    const bignum::BN &sig_share() const;
    void set_sig_share(const bignum::BN &sig_share);

    const bignum::BN &z() const;
    void set_z(const bignum::BN &z);

    const bignum::BN &c() const;
    void set_c(const bignum::BN &c);

private:
    int index_;
    safeheron::bignum::BN sig_share_;
    safeheron::bignum::BN z_;
    safeheron::bignum::BN c_;
};

};
};

#endif //SAFEHERON_RSA_KEY_SHARE_H