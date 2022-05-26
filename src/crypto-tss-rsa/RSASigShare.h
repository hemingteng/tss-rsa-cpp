/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#ifndef SAFEHERON_RSA_KEY_SHARE_H
#define SAFEHERON_RSA_KEY_SHARE_H

#include <iostream>
#include <vector>
#include "crypto-bn/bn.h"
#include "tss_rsa.pb.h"

namespace safeheron {
namespace tss_rsa{

class RSASigShare{
public:
    /**
     * Constructor.
     */
    RSASigShare();

    /**
     * Constructor.
     * @param index index of party
     * @param sig_share signature share
     * @param z a parameter of the proof
     * @param c a parameter of the proof
     */
    RSASigShare(int index,
                const safeheron::bignum::BN &sig_share,
                const safeheron::bignum::BN &z,
                const safeheron::bignum::BN &c);

    int index() const;
    void set_index(int index);

    const bignum::BN &sig_share() const;
    void set_sig_share(const bignum::BN &sig_share);

    const bignum::BN &z() const;
    void set_z(const bignum::BN &z);

    const bignum::BN &c() const;
    void set_c(const bignum::BN &c);

    bool ToProtoObject(safeheron::proto::RSASigShare &proof) const;
    bool FromProtoObject(const safeheron::proto::RSASigShare &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
private:
    int index_;  /**< index of party */
    safeheron::bignum::BN sig_share_;  /**< signature share */
    safeheron::bignum::BN z_;  /**< a parameter of the proof */
    safeheron::bignum::BN c_;  /**< a parameter of the proof */
};

};
};

#endif //SAFEHERON_RSA_KEY_SHARE_H