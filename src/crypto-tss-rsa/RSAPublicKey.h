//
// Created by 何剑虹 on 2020/8/31.
//

#ifndef SAFEHERON_RSA_PUBLIC_KEY_H
#define SAFEHERON_RSA_PUBLIC_KEY_H

#include <iostream>
#include "crypto-bn/bn.h"


namespace safeheron {
namespace tss_rsa{


class RSAPublicKey{
public:
    RSAPublicKey(){}
    RSAPublicKey(const safeheron::bignum::BN &n, const safeheron::bignum::BN &e);

    bool VerifySignature(const safeheron::bignum::BN &m, const safeheron::bignum::BN &sig);

    const bignum::BN &n() const;
    void set_n(const bignum::BN &n);

    const bignum::BN &e() const;
    void set_e(const bignum::BN &e);

private:
    safeheron::bignum::BN n_;
    safeheron::bignum::BN e_;
};


};
};

#endif //SAFEHERON_RSA_PUBLIC_KEY_H