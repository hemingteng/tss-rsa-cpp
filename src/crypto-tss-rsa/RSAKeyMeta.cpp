#include "RSAKeyMeta.h"

namespace safeheron {
namespace tss_rsa{

RSAKeyMeta::RSAKeyMeta(int k,
           int l,
           const safeheron::bignum::BN &vkv,
           const std::vector<safeheron::bignum::BN> &vki_arr,
           const safeheron::bignum::BN &vku){
    this->k_ = k;
    this->l_ = l;
    this->vkv_ = vkv;
    this->vki_arr_.insert(this->vki_arr_.begin(), vki_arr.begin(), vki_arr.end());
    this->vku_ = vku;
}

int RSAKeyMeta::k() const {
    return k_;
}

void RSAKeyMeta::set_k(int k) {
    k_ = k;
}

int RSAKeyMeta::l() const {
    return l_;
}

void RSAKeyMeta::set_l(int l) {
    l_ = l;
}

const bignum::BN &RSAKeyMeta::vkv() const {
    return vkv_;
}

void RSAKeyMeta::set_vkv(const bignum::BN &vkv) {
    vkv_ = vkv;
}

const std::vector<safeheron::bignum::BN> &RSAKeyMeta::vki_arr() const {
    return vki_arr_;
}

void RSAKeyMeta::set_vki_arr(const std::vector<safeheron::bignum::BN> &vki_arr) {
    this->vki_arr_.clear();
    this->vki_arr_.insert(this->vki_arr_.begin(), vki_arr.begin(), vki_arr.end());
}

const safeheron::bignum::BN &RSAKeyMeta::vki(size_t index) const {
    return vki_arr_.at(index);
}

const bignum::BN &RSAKeyMeta::vku() const {
    return vku_;
}

void RSAKeyMeta::set_vku(const bignum::BN &vku) {
    vku_ = vku;
}


};
};
