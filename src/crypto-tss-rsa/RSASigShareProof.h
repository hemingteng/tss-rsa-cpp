//
// Created by 何剑虹 on 2020/8/31.
//

#ifndef SAFEHERON_RSA_SIGNATURE_SHARE_PROOF_H
#define SAFEHERON_RSA_SIGNATURE_SHARE_PROOF_H

#include <iostream>
#include "crypto-bn/bn.h"
#include "tss_rsa.pb.h"


namespace safeheron {
namespace tss_rsa{

class RSASigShareProof{
public:
    RSASigShareProof();

    RSASigShareProof(const bignum::BN &z, const bignum::BN &c);

    const bignum::BN &z() const;

    void set_z(const bignum::BN &z);

    const bignum::BN &c() const;

    void set_c(const bignum::BN &c);

    void Prove(const safeheron::bignum::BN &si,
               const safeheron::bignum::BN &vkv,
               const safeheron::bignum::BN &vki,
               const safeheron::bignum::BN &x,
               const safeheron::bignum::BN &n,
               const safeheron::bignum::BN &sig_i);

    bool Verify(const safeheron::bignum::BN &vkv,
                const safeheron::bignum::BN &vki,
                const safeheron::bignum::BN &x,
                const safeheron::bignum::BN &n,
                const safeheron::bignum::BN &sig_i);

    bool ToProtoObject(safeheron::proto::RSASigShareProof &proof) const;
    bool FromProtoObject(const safeheron::proto::RSASigShareProof &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
private:
    safeheron::bignum::BN z_;
    safeheron::bignum::BN c_;
};


};
};

#endif //SAFEHERON_RSA_SIGNATURE_SHARE_PROOF_H