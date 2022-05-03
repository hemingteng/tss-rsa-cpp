//
// Created by 何剑虹 on 2020/8/31.
//

#ifndef SAFEHERON_TSS_RSA_KEY_GEN_PARAM_SHARE_H
#define SAFEHERON_TSS_RSA_KEY_GEN_PARAM_SHARE_H

#include <iostream>
#include <vector>
#include "crypto-bn/bn.h"

namespace safeheron {
namespace tss_rsa{

class KeyGenParam{
public:
    KeyGenParam();
    KeyGenParam(int e,
                const safeheron::bignum::BN &p,
                const safeheron::bignum::BN &q,
                const safeheron::bignum::BN &f,
                const safeheron::bignum::BN &vku);

public:
    int e() const;

    void set_e(int e);

    const bignum::BN &p() const;

    void set_p(const bignum::BN &p);

    const bignum::BN &q() const;

    void set_q(const bignum::BN &q);

    const bignum::BN &f() const;

    void set_f(const bignum::BN &f);

    const bignum::BN &vku() const;

    void set_vku(const bignum::BN &vku);

private:
    int e_;
    safeheron::bignum::BN p_;
    safeheron::bignum::BN q_;
    safeheron::bignum::BN f_;
    safeheron::bignum::BN vku_;
};

};
};

#endif //SAFEHERON_TSS_RSA_KEY_GEN_PARAM_SHARE_H