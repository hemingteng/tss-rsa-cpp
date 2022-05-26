/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

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
    /**
     * Constructor.
     * @param i index of party
     * @param si secret share of party i
     */
    RSAPrivateKeyShare(int i, const safeheron::bignum::BN &si);

public:
    const bignum::BN &si() const;
    void set_si(const bignum::BN &si);

    int i() const;
    void set_i(int i);

    /**
     * Sign the message and create the signature share.
     * @param doc message to sign.
     * @param key_meta meta data of key
     * @param public_key public key
     * @return a RSASigShare object.
     */
    RSASigShare Sign(const std::string &doc,
                     const safeheron::tss_rsa::RSAKeyMeta &key_meta,
                     const safeheron::tss_rsa::RSAPublicKey &public_key);

    bool ToProtoObject(safeheron::proto::RSAPrivateKeyShare &proof) const;
    bool FromProtoObject(const safeheron::proto::RSAPrivateKeyShare &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);

private:
    /**
     * Sign the message and create the signature share.
     * @param x a BN object which indicate the message to sign.
     * @param key_meta meta data of key
     * @param public_key public key
     * @return a RSASigShare object.
     */
    RSASigShare InternalSign(const safeheron::bignum::BN &x,
                             const safeheron::tss_rsa::RSAKeyMeta &key_meta,
                             const safeheron::tss_rsa::RSAPublicKey &public_key);

private:
    int i_;   /**< index of party. */
    safeheron::bignum::BN si_;  /**< secret share of party i. */
};

};
};

#endif //SAFEHERON_RSA_PRIVATE_KEY_SHARE_H