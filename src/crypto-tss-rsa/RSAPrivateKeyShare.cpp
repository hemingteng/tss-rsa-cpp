#include "RSAPrivateKeyShare.h"
#include "RSASigShare.h"
#include "common.h"

using safeheron::bignum::BN;

namespace safeheron {
namespace tss_rsa{

RSAPrivateKeyShare::RSAPrivateKeyShare(int i,
                                       const safeheron::bignum::BN &si){
    this->si_ = si;
    this->i_ = i;
}

const bignum::BN &RSAPrivateKeyShare::si() const {
    return si_;
}

void RSAPrivateKeyShare::set_si(const bignum::BN &s) {
    si_ = s;
}

int RSAPrivateKeyShare::i() const {
    return i_;
}

void RSAPrivateKeyShare::set_i(int i) {
    i_ = i;
}

RSASigShare RSAPrivateKeyShare::Sign(const safeheron::bignum::BN &m,
                                     const safeheron::tss_rsa::RSAKeyMeta &key_meta,
                                     const safeheron::tss_rsa::RSAPublicKey &public_key){
    // x = m    , if (m, n) == 1
    // x = m*u^e, if (m, n) == -1
    BN x = m;
    std::cout << "x: " << x.Inspect() << std::endl;
    if(BN::JacobiSymbol(m, public_key.n()) == -1){
        x = (x * key_meta.vku().PowM(public_key.e(), public_key.n())) % public_key.n();
        std::cout << "JacobiSymbol == 1" << std::endl;
    }

    // x_i = x^{2 * s_i}
    BN xi = x.PowM(si_ * 2, public_key.n());

    return {i_, xi};
}


};
};
