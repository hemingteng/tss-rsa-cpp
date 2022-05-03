//
// Created by 何剑虹 on 2020/8/31.
//

#include "RSAPublicKey.h"
#include <cassert>
#include <cstring>
#include <sstream>
#include <string>
#include "exception/safeheron_exceptions.h"

using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;


namespace safeheron {
namespace tss_rsa{


RSAPublicKey::RSAPublicKey(const safeheron::bignum::BN &n, const safeheron::bignum::BN &e){
    this->n_ = n;
    this->e_ = e;
}

bool RSAPublicKey::VerifySignature(const safeheron::bignum::BN &m, const safeheron::bignum::BN &y){
    return y.PowM(e_, n_) == m;
}

const bignum::BN &RSAPublicKey::n() const {
    return n_;
}

void RSAPublicKey::set_n(const bignum::BN &n) {
    n_ = n;
}

const bignum::BN &RSAPublicKey::e() const {
    return e_;
}

void RSAPublicKey::set_e(const bignum::BN &e) {
    e_ = e;
}


};
};
