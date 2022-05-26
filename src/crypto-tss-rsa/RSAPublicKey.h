/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#ifndef SAFEHERON_RSA_PUBLIC_KEY_H
#define SAFEHERON_RSA_PUBLIC_KEY_H

#include <iostream>
#include "crypto-bn/bn.h"
#include "tss_rsa.pb.h"


namespace safeheron {
namespace tss_rsa{


class RSAPublicKey{
public:
    /**
     * Constructor.
     */
    RSAPublicKey(){}

    /**
     * Constructor.
     * @param n n=pq
     * @param e a prime
     */
    RSAPublicKey(const safeheron::bignum::BN &n, const safeheron::bignum::BN &e);

    /**
     * Verify the signature.
     * @param doc
     * @param sig
     * @return true on success, false on error.
     */
    bool VerifySignature(const std::string &doc, const safeheron::bignum::BN &sig);

    const bignum::BN &n() const;
    void set_n(const bignum::BN &n);

    const bignum::BN &e() const;
    void set_e(const bignum::BN &e);

    bool ToProtoObject(safeheron::proto::RSAPublicKey &proof) const;
    bool FromProtoObject(const safeheron::proto::RSAPublicKey &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);

private:
    /**
     * Verify the signature.
     * @param x
     * @param sig
     * @return true on success, false on error.
     */
    bool InternalVerifySignature(const safeheron::bignum::BN &x, const safeheron::bignum::BN &sig);
private:
    safeheron::bignum::BN n_;
    safeheron::bignum::BN e_;
};


};
};

#endif //SAFEHERON_RSA_PUBLIC_KEY_H