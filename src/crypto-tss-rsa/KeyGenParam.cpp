#include "KeyGenParam.h"

using safeheron::bignum::BN;

namespace safeheron {
namespace tss_rsa{

KeyGenParam::KeyGenParam(){
    e_ = 0;
    p_ = BN::ZERO;
    q_ = BN::ZERO;
    f_ = BN::ZERO;
    vku_ = BN::ZERO;
}

KeyGenParam::KeyGenParam(int e,
                         const safeheron::bignum::BN &p,
                         const safeheron::bignum::BN &q,
                         const safeheron::bignum::BN &f,
                         const safeheron::bignum::BN &vku){
    e_ = e;
    p_ = p;
    q_ = q;
    f_ = f;
    vku_ = vku;
}

int KeyGenParam::e() const {
    return e_;
}

void KeyGenParam::set_e(int e) {
    e_ = e;
}

const BN &KeyGenParam::p() const {
    return p_;
}

void KeyGenParam::set_p(const BN &p) {
    p_ = p;
}

const BN &KeyGenParam::q() const {
    return q_;
}

void KeyGenParam::set_q(const BN &q) {
    q_ = q;
}

const BN &KeyGenParam::f() const {
    return f_;
}

void KeyGenParam::set_f(const BN &f) {
    f_ = f;
}

const BN &KeyGenParam::vku() const {
    return vku_;
}

void KeyGenParam::set_vku(const BN &vku) {
    vku_ = vku;
}

};
};
