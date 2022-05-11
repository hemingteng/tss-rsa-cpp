//
// Created by 何剑虹 on 2020/8/31.
//

#ifndef SAFEHERON_RSA_PRIVATE_KEY_SHARE_H
#define SAFEHERON_RSA_PRIVATE_KEY_SHARE_H

#include <iostream>
#include <vector>
#include "crypto-bn/bn.h"
#include "RSAKeyMeta.h"
#include "RSAPrivateKeyShare.h"
#include "RSAPublicKey.h"
#include "RSASigShare.h"
#include "tss_rsa.pb.h"

namespace safeheron {
namespace tss_rsa{

class RSAPrivateKeyShare{
public:
    RSAPrivateKeyShare(int i, const safeheron::bignum::BN &si);

public:
    const bignum::BN &si() const;
    void set_si(const bignum::BN &si);

    int i() const;
    void set_i(int i);

    RSASigShare Sign(const uint8_t *msg, size_t msg_len,
                     const safeheron::tss_rsa::RSAKeyMeta &key_meta,
                     const safeheron::tss_rsa::RSAPublicKey &public_key);

    RSASigShare Sign(const std::string &msg,
                     const safeheron::tss_rsa::RSAKeyMeta &key_meta,
                     const safeheron::tss_rsa::RSAPublicKey &public_key);

    RSASigShare InternalSign(const safeheron::bignum::BN &x,
                             const safeheron::tss_rsa::RSAKeyMeta &key_meta,
                             const safeheron::tss_rsa::RSAPublicKey &public_key);

    bool ToProtoObject(safeheron::proto::RSAPrivateKeyShare &proof) const;
    bool FromProtoObject(const safeheron::proto::RSAPrivateKeyShare &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);

private:

private:
    int i_;
    safeheron::bignum::BN si_;
};

};
};

#endif //SAFEHERON_RSA_PRIVATE_KEY_SHARE_H