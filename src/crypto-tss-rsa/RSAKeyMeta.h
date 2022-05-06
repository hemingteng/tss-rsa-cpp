//
// Created by 何剑虹 on 2020/8/31.
//

#ifndef SAFEHERON_RSA_KEY_META_H
#define SAFEHERON_RSA_KEY_META_H

#include <iostream>
#include <vector>
#include "crypto-bn/bn.h"
#include "tss_rsa.pb.h"

namespace safeheron {
namespace tss_rsa{

class RSAKeyMeta{
public:
    RSAKeyMeta(){}
    RSAKeyMeta(int k,
               int l,
               const safeheron::bignum::BN &vkv,
               const std::vector<safeheron::bignum::BN> &vki_arr,
               const safeheron::bignum::BN &vku);

    int k() const;
    void set_k(int k);

    int l() const;
    void set_l(int l);

    const bignum::BN &vkv() const;
    void set_vkv(const bignum::BN &vkv);

    const std::vector<safeheron::bignum::BN> &vki_arr() const;
    void set_vki_arr(const std::vector<safeheron::bignum::BN> &vki_arr);
    const bignum::BN &vki(size_t index) const;

    const bignum::BN &vku() const;
    void set_vku(const bignum::BN &vku);

    bool ToProtoObject(safeheron::proto::RSAKeyMeta &proof) const;
    bool FromProtoObject(const safeheron::proto::RSAKeyMeta &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
private:
    int k_;
    int l_;
    safeheron::bignum::BN vkv_;
    std::vector<safeheron::bignum::BN> vki_arr_;
    safeheron::bignum::BN vku_;

};

};
};

#endif //SAFEHERON_RSA_KEY_META_H