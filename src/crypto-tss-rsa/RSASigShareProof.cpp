//
// Created by 何剑虹 on 2020/8/31.
//

#include "RSASigShareProof.h"
#include <cassert>
#include <cstring>
#include <sstream>
#include <string>
#include "exception/safeheron_exceptions.h"
#include "crypto-bn/rand.h"
#include "crypto-hash/sha256.h"

using safeheron::bignum::BN;
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;
using safeheron::hash::CSHA256;

namespace safeheron {
namespace tss_rsa{

// Output of SHA256 is 256
static int L1 = 256;

RSASigShareProof::RSASigShareProof() : z_(bignum::BN::ZERO), c_(bignum::BN::ZERO) {}

RSASigShareProof::RSASigShareProof(const bignum::BN &z, const bignum::BN &c) : z_(z), c_(c) {}

const bignum::BN &RSASigShareProof::z() const {
    return z_;
}

void RSASigShareProof::set_z(const bignum::BN &z) {
    z_ = z;
}

const bignum::BN &RSASigShareProof::c() const {
    return c_;
}

void RSASigShareProof::set_c(const bignum::BN &c) {
    c_ = c;
}

void RSASigShareProof::Prove(const safeheron::bignum::BN &si,
                             const safeheron::bignum::BN &v,
                             const safeheron::bignum::BN &vi,
                             const safeheron::bignum::BN &x,
                             const safeheron::bignum::BN &n,
                             const safeheron::bignum::BN &sig_i){
    // sample random r in (0, 2^(L(N) + 2*L1 + 1) )
    BN upper_bound = BN::TWO << (n.BitLength() + L1 * 2);
    BN r = safeheron::rand::RandomBNLt(upper_bound);
    // v' = v^r
    BN vp = v.PowM(r, n);
    // x_tilde = x^4
    BN x_tilde = x.PowM(BN::FOUR, n);
    // x' = x_tilde^r
    BN xp = x_tilde.PowM(r, n);
    // sig^2
    BN sig2 = sig_i.PowM(BN::TWO, n);

    // c = H(v, x_tilde, vi, x^2, v', x')
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    std::string buf;
    v.ToBytesBE(buf);         sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    x_tilde.ToBytesBE(buf);   sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    vi.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    sig2.ToBytesBE(buf);      sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    vp.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    xp.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    std::cout << "\n\nr = 0x" << r.Inspect() << std::endl;
    std::cout << "v = 0x" << v.Inspect() << std::endl;
    std::cout << "x_tilde = 0x" << x_tilde.Inspect() << std::endl;
    std::cout << "vi = 0x" << vi.Inspect() << std::endl;
    std::cout << "sig2 = 0x" << sig2.Inspect() << std::endl;
    std::cout << "vp = 0x" << vp.Inspect() << std::endl;
    std::cout << "xp = 0x" << xp.Inspect() << std::endl;
    sha256.Finalize(digest);
    BN c = BN::FromBytesBE(digest, CSHA256::OUTPUT_SIZE);

    // z = si * c + r
    BN z = si * c + r;

    z_ = z;
    c_ = c;
}

bool RSASigShareProof::Verify(const safeheron::bignum::BN &v,
                              const safeheron::bignum::BN &vi,
                              const safeheron::bignum::BN &x,
                              const safeheron::bignum::BN &n,
                              const safeheron::bignum::BN &sig_i){
    // v' = v^z * vi^(-c)  mod n
    BN vp = ( v.PowM(z_, n) * vi.PowM(c_ * (-1), n) ) % n;
    // x_tilde = x^4  mod n
    BN x_tilde = x.PowM(BN::FOUR, n);
    // x' = x_tilde^z * x^(-2c)  mod n
    BN xp = ( x_tilde.PowM(z_, n) * sig_i.PowM(c_ * (-2), n) ) % n;
    // sig^2  mod n
    BN sig2 = sig_i.PowM(BN::TWO, n);

    std::cout << "\n\nv = 0x" << v.Inspect() << std::endl;
    std::cout << "x_tilde = 0x" << x_tilde.Inspect() << std::endl;
    std::cout << "vi = 0x" << vi.Inspect() << std::endl;
    std::cout << "sig2 = 0x" << sig2.Inspect() << std::endl;
    std::cout << "vp = 0x" << vp.Inspect() << std::endl;
    std::cout << "xp = 0x" << xp.Inspect() << std::endl;

    // c = H(v, x_tilde, vi, x^2, v', x')
    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256 sha256;
    std::string buf;
    v.ToBytesBE(buf);         sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    x_tilde.ToBytesBE(buf);   sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    vi.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    sig2.ToBytesBE(buf);      sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    vp.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    xp.ToBytesBE(buf);        sha256.Write((const uint8_t *)buf.c_str(), buf.size());
    sha256.Finalize(digest);
    BN c = BN::FromBytesBE(digest, CSHA256::OUTPUT_SIZE);

    // check c == c_
    return c == c_;
}


}
}
