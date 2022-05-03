#include "RSASigShare.h"

namespace safeheron {
namespace tss_rsa{

RSASigShare::RSASigShare(int index, const safeheron::bignum::BN &sig_share){
    this->index_ = index;
    this->sig_share_ = sig_share;
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

};
};
