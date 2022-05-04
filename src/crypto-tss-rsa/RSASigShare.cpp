#include "RSASigShare.h"

namespace safeheron {
namespace tss_rsa{

RSASigShare::RSASigShare(): index_(0), sig_share_(bignum::BN::ZERO), z_(bignum::BN::ZERO), c_(bignum::BN::ZERO){}

RSASigShare::RSASigShare(int index,
                         const safeheron::bignum::BN &sig_share,
                         const safeheron::bignum::BN &z,
                         const safeheron::bignum::BN &c){
    this->index_ = index;
    this->sig_share_ = sig_share;
    this->z_ = z;
    this->c_ = c;
}

int RSASigShare::index() const {
    return index_;
}

void RSASigShare::set_index(int index) {
    index_ = index;
}

const bignum::BN &RSASigShare::sig_share() const {
    return sig_share_;
}

void RSASigShare::set_sig_share(const bignum::BN &sig_share) {
    sig_share_ = sig_share;
}

const bignum::BN &RSASigShare::z() const {
    return z_;
}

void RSASigShare::set_z(const bignum::BN &z) {
    z_ = z;
}

const bignum::BN &RSASigShare::c() const {
    return c_;
}

void RSASigShare::set_c(const bignum::BN &c) {
    c_ = c;
}

};
};
