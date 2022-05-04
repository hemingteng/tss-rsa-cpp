//
// Created by 何剑虹 on 2020/10/25.
//
#include "tss_rsa.h"
#include <unistd.h>
#include "crypto-bn/rand.h"
#include "exception/located_exception.h"
#include "crypto-sss/vsss.h"
#include "common.h"
#include "RSASigShareProof.h"

using safeheron::bignum::BN;
using safeheron::exception::LocatedException;

// Fermat fourth number
// Default e value.
const int f4 = 65537;

namespace safeheron {
namespace tss_rsa {

static bool InternalGenerateKey(size_t key_bits_length, int l, int k,
                                std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                                RSAPublicKey &public_key,
                                RSAKeyMeta &key_meta,
                                KeyGenParam &param){
    const BN e(param.e());
    const BN &p = param.p();
    const BN &q = param.q();
    const BN &f = param.f();
    const BN &vku = param.vku();

    // n
    BN n = p * q;

    // m = p' * q'
    BN m = (p - 1) * (q - 1) / 4;

    // d:  de = 1 mod m
    BN d = e.InvM(m);

    std::cout << "p = 0x" << p.Inspect() << std::endl;
    std::cout << "q = 0x" << q.Inspect() << std::endl;
    std::cout << "n = 0x" << n.Inspect() << std::endl;
    std::cout << "m = 0x" << m.Inspect() << std::endl;
    std::cout << "e = 0x" << e.Inspect() << std::endl;
    std::cout << "d = 0x" << d.Inspect() << std::endl;

    // generate shares of d
    std::vector<sss::Point> share_arr;
    std::vector<BN> index_arr;
    for(int i = 1; i <= l; i++){
        index_arr.emplace_back(BN(i));
    }
    sss::vsss::MakeShares(share_arr, d, k, index_arr, m);
    BN secret;
    sss::vsss::RecoverSecret(secret, share_arr, m);
    std::cout << "secret = 0x" << secret.Inspect() << std::endl;


    // Compute \Delta = l!
    BN delta(1);
    for(int i = 1; i <= l; i++){
        delta *= i;
    }
    BN delta_inv = delta.InvM(m);
    std::cout << "delta = 0x" << delta.Inspect() << std::endl;
    std::cout << "delta_inv = 0x" << delta_inv.Inspect() << std::endl;

    for(int i = 1; i <= l; i++){
        BN si = (share_arr[i-1].y * delta_inv) % m;
        private_key_share_arr.emplace_back(RSAPrivateKeyShare(i, si));
        std::cout << "s" << i << " = 0x" << si.Inspect() << std::endl;
    }


    // Public key
    public_key.set_n(n);
    public_key.set_e(e);


    // Validate Key
    std::cout << "f = 0x" << f.Inspect() << std::endl;
    BN vkv = (f * f) % n;
    std::cout << "vkv = 0x" << vkv.Inspect() << std::endl;
    std::vector<BN> vki_arr;
    for(int i = 1; i <= l; i++){
        std::cout << "=> vkv = 0x" << vkv.Inspect() << std::endl;
        std::cout << "=> private_key_share_arr[i-1].si() = 0x" << private_key_share_arr[i-1].si().Inspect() << std::endl;
        BN t_vki = vkv.PowM(private_key_share_arr[i-1].si(), n);
        vki_arr.push_back(t_vki);
        std::cout << "vkv" << i << " = 0x" << t_vki.Inspect() << std::endl;
    }
    std::cout << "vkv = 0x" << vkv.Inspect() << std::endl;

    std::cout << "vku = 0x" << vku.Inspect() << std::endl;
    // Key meta data
    key_meta.set_k(k);
    key_meta.set_l(l);
    key_meta.set_vkv(vkv);
    key_meta.set_vki_arr(vki_arr);
    key_meta.set_vku(vku);


    // S is a subset of (1, ... ,l)
    std::vector<BN> S;
    for(int i = 1; i <= l; i++){
        S.emplace_back(BN(i));
    }

    BN lambda1 = lambda(BN::ZERO, BN(1), S, delta);
    BN lambda2 = lambda(BN::ZERO, BN(2), S, delta);
    BN lambda3 = lambda(BN::ZERO, BN(3), S, delta);
    BN dd = (private_key_share_arr[0].si() * lambda1 + private_key_share_arr[1].si() * lambda2 + private_key_share_arr[2].si() * lambda3) % m;

    BN d_delta = (share_arr[0].y * lambda1 + share_arr[1].y * lambda2 + share_arr[2].y * lambda3) % m;
    BN expected_d_delta = (d * delta) % m;

    std::cout << "dd = 0x" << dd.Inspect() << std::endl;
    std::cout << "d_delta = 0x" << d_delta.Inspect() << std::endl;
    std::cout << "expected_d_delta = 0x" << expected_d_delta.Inspect() << std::endl;


    BN exp = (private_key_share_arr[0].si() * lambda1 + private_key_share_arr[1].si() * lambda2 + private_key_share_arr[2].si() * lambda3) * 4;
    std::cout << "lambda1 = " << lambda1.Inspect(10) << std::endl;
    std::cout << "lambda2 = " << lambda2.Inspect(10) << std::endl;
    std::cout << "lambda3 = " << lambda3.Inspect(10) << std::endl;
    std::cout << "exp = 0x" << exp.Inspect() << std::endl;
    //exp = exp % n;
    std::cout << "exp = 0x" << exp.Inspect() << std::endl;
    BN some = m.PowM(exp, n);
    std::cout << "some = 0x" << some.Inspect() << std::endl;

    return true;
}


bool GenerateKey(size_t key_bits_length, int l, int k,
                 std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                 RSAPublicKey &public_key,
                 RSAKeyMeta &key_meta){
    // default value
    int e = f4;

    size_t key_bytes = key_bits_length / 8;
    // p = 2p' + 1
    BN p = safeheron::rand::RandomSafePrime(key_bytes / 2);

    // q = 2q' + 1, make sure: p != q
    BN q;
    do {
        q = safeheron::rand::RandomSafePrime(key_bytes / 2);
    } while (p == q);

    // n = p * q
    BN n = p * q;
    BN f = safeheron::rand::RandomBNLtCoPrime(n);

    // vku
    BN vku;
    do{
        vku = safeheron::rand::RandomBNLtGcd(n);
    } while (safeheron::bignum::BN::JacobiSymbol(vku, n) != -1);

    KeyGenParam param(e, p, q, f, vku);
    return InternalGenerateKey(key_bits_length, l, k, private_key_share_arr, public_key, key_meta, param);
}

bool GenerateKeyEx(size_t key_bits_length, int l, int k,
                 std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                 RSAPublicKey &public_key,
                 RSAKeyMeta &key_meta,
                 const KeyGenParam &_param){
    size_t key_bytes = key_bits_length / 8;

    // check k, l
    if(l <= 1 || k <= 0 || k < (l/2+1) || k > l){
        return false;
    }

    // check e
    KeyGenParam param = _param;
    BN e(param.e());
    if(e == 0){
        param.set_e(f4);
    }else{
        if(!e.IsProbablyPrime()){
            return false;
        }
    }

    // check p: p = 2p' + 1
    if(param.p() == 0){
        BN p = safeheron::rand::RandomSafePrime(key_bytes / 2);
        param.set_p(p);
    }else{
        BN pp = (param.p() - 1)/2;
        if(!param.p().IsProbablyPrime() || !pp.IsProbablyPrime()){
            return false;
        }
    }

    // check q: q = 2q' + 1
    // make sure: q != p
    if(param.q() == 0){
        BN q;
        do {
            q = safeheron::rand::RandomSafePrime(key_bytes / 2);
        }while (q == param.p());
        param.set_q(q);
    }else{
        BN qq = (param.q() - 1)/2;
        if(!param.q().IsProbablyPrime() || !qq.IsProbablyPrime()){
            return false;
        }
    }

    // n = pq
    BN n = param.p() * param.q();

    // check f: f < n , gcd(f, n) = 1
    if(param.f() == 0){
        BN f = safeheron::rand::RandomBNLtCoPrime(n);
        param.set_f(f);
    }else{
        const BN &f = param.f();
        if(f <= 0 || f >= n || f.Gcd(n) != 1){
            return false;
        }
    }

    // check vku: vku < n , gcd(vku, n) = 1, jacobi(vku, n) == -1
    if(param.vku() == 0){
        BN vku;
        do{
            vku = safeheron::rand::RandomBNLtGcd(n);
        } while (safeheron::bignum::BN::JacobiSymbol(vku, n) != -1);
        param.set_vku(vku);
    }else{
        const BN &vku = param.vku();
        if(vku <= 0 || vku >= n || vku.Gcd(n) != 1 || BN::JacobiSymbol(vku, n) != -1){
            return false;
        }
    }

    return InternalGenerateKey(key_bits_length, l, k, private_key_share_arr, public_key, key_meta, param);
}


bool CombineSignatures(const std::vector<RSASigShare> &sig_arr,
                       const safeheron::bignum::BN &m,
                       const RSAPublicKey &public_key,
                       const RSAKeyMeta &key_meta,
                       safeheron::bignum::BN &out_sig){
    std::cout<< "public_key.n(): " << public_key.n().Inspect() << std::endl;
    // e' is always set to 4.
    BN ep(4);

    // x = m    , if (m, n) == 1
    // x = m*u^e, if (m, n) == -1
    BN x = m;
    int jacobi_m_n = BN::JacobiSymbol(m, public_key.n());
    if( jacobi_m_n == -1){
        std::cout << "jacobi_m_n === -1" << std::endl;
        x = (x * key_meta.vku().PowM(public_key.e(), public_key.n())) % public_key.n();
    }

    // Validate signature share
    bool is_valid_sig = true;
    for(const auto &sig: sig_arr){
        RSASigShareProof proof(sig.z(), sig.c());
        is_valid_sig &= proof.Verify(key_meta.vkv(), key_meta.vki(sig.index()-1), x, public_key.n(), sig.sig_share());
        if(!is_valid_sig) return false;
    }

    // Compute \Delta = l!
    BN delta(1);
    for(int i = 1; i <= key_meta.l(); i++){
        delta *= i;
    }
    std::cout << "delta: " << delta.Inspect() << std::endl;

    // S is a subset of (1, ... ,l)
    std::vector<BN> S;
    for(const auto &item : sig_arr){
        S.emplace_back(BN(item.index()));
    }

    // w = x_{i_1}^{2 \lambda_{0,i_1}^S} \dots	x_{i_k}^{2 \lambda_{0,i_k}^S} \pmod n
    BN w(1);
    for(const auto &item : sig_arr){
        //BN t_x = (item.sig_share() * item.sig_share()) % public_key.n();
        //BN lam = lambda(BN(0), BN(item.index()), S, delta);
        //std::cout << "lam: " << lam.Inspect() << std::endl;
        //w = (w * t_x.PowM(lam, public_key.n())) % public_key.n();

        BN lam = lambda(BN(0), BN(item.index()), S, delta);
        std::cout << "lam: " << lam.Inspect() << std::endl;
        w = (w * item.sig_share().PowM(lam * 2, public_key.n())) % public_key.n();
    }
    std::cout << "w: " << w.Inspect() << std::endl;

    // y = w^a x^b \pmod n
    BN d, a, b;
    BN::ExtendedEuclidean(ep, public_key.e(), a, b, d);
    std::cout << "d: " << d.Inspect() << std::endl;
    BN y = w.PowM(a, public_key.n()) * x.PowM(b, public_key.n()) % public_key.n();
    if (jacobi_m_n == -1) {
        y = (y * key_meta.vku().InvM(public_key.n())) % public_key.n();
        std::cout << "******************" << std::endl;
    }
    out_sig = y;
    return true;
}

};
};
