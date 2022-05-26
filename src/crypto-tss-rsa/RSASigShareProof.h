/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#ifndef SAFEHERON_RSA_SIGNATURE_SHARE_PROOF_H
#define SAFEHERON_RSA_SIGNATURE_SHARE_PROOF_H

#include <iostream>
#include "crypto-bn/bn.h"
#include "tss_rsa.pb.h"


namespace safeheron {
namespace tss_rsa{

class RSASigShareProof{
public:
    /**
     * Constructor.
     */
    RSASigShareProof();

    /**
     * Constructor.
     * @param z a parameter of the proof
     * @param c a parameter of the proof
     */
    RSASigShareProof(const bignum::BN &z, const bignum::BN &c);

    const bignum::BN &z() const;

    void set_z(const bignum::BN &z);

    const bignum::BN &c() const;

    void set_c(const bignum::BN &c);

    /**
     * Create a proof of the signature share.
     * @param si secret share of party i
     * @param vkv validation key
     * @param vki validation key of party i
     * @param x x which represents the message
     * @param n n = pq
     * @param sig_i signature share of party i
     */
    void Prove(const safeheron::bignum::BN &si,
               const safeheron::bignum::BN &vkv,
               const safeheron::bignum::BN &vki,
               const safeheron::bignum::BN &x,
               const safeheron::bignum::BN &n,
               const safeheron::bignum::BN &sig_i);

    /**
     * Verify the proof of the signature share.
     * @param vkv validation key
     * @param vki validation key of party i
     * @param x x which represents the message
     * @param n n = pq
     * @param sig_i signature share of party i
     * @return true on success, false on error.
     */
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