/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */


#ifndef SAFEHERON_RSA_KEY_META_H
#define SAFEHERON_RSA_KEY_META_H

#include <vector>
#include "crypto-bn/bn.h"
#include "tss_rsa.pb.h"

namespace safeheron {
namespace tss_rsa{

class RSAKeyMeta{
public:
    /**
     * Constructor.
     */
    RSAKeyMeta(){}

    /**
     * Constructor.
     * @param k threshold
     * @param l number of parties
     * @param vkv validation key
     * @param vki_arr validation key array of all parties
     * @param vku safe parameter for protocol 2
     */
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
    int k_;  /**< threshold */
    int l_;  /**< number of parties */
    safeheron::bignum::BN vkv_;  /**< validation key */
    std::vector<safeheron::bignum::BN> vki_arr_;  /**< validation key array of all parties */
    safeheron::bignum::BN vku_;  /**< safe parameter for protocol 2 */

};

};
};

#endif //SAFEHERON_RSA_KEY_META_H