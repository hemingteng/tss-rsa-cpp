/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#ifndef SAFEHERON_TSS_RSA_H
#define SAFEHERON_TSS_RSA_H

#include "RSAPrivateKeyShare.h"
#include "RSAPublicKey.h"
#include "RSASigShare.h"
#include "RSAKeyMeta.h"
#include "KeyGenParam.h"
#include <vector>

namespace safeheron {
namespace tss_rsa {

/**
 * Generate private key shares, public key, key meta data.
 *
 * @param key_bits_length: 2048, 3072, 4096 is advised.
 * @param l: total number of private key shares.
 * @param k: threshold, k < l and k >= (l/2+1)
 * @param private_key_share_arr[out]: shares of private key.
 * @param public_key[out]: public key.
 * @param key_meta[out]: key meta data.
 * @return
 */
bool GenerateKey(size_t key_bits_length, int l, int k,
                 std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                 RSAPublicKey &public_key,
                 RSAKeyMeta &key_meta);

/**
 * Generate private key shares, public key, key meta data with specified parameters.
 *
 * @param key_bits_length: 2048, 3072, 4096 is advised.
 * @param l: total number of private key shares.
 * @param k: threshold, k < l and k >= (l/2+1)
 * @param param: specified parameters.
 * @param private_key_share_arr[out]: shares of private key.
 * @param public_key[out]: public key.
 * @param key_meta[out]: key meta data.
 * @return
 */
bool GenerateKeyEx(size_t key_bits_length, int l, int k,
                   const KeyGenParam &param,
                   std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                   RSAPublicKey &public_key,
                   RSAKeyMeta &key_meta);

/**
 * Combine all the shares of signature to make a real signature.
 * @param doc: doc
 * @param sig_arr : the shares of signature.
 * @param public_key: public key.
 * @param key_meta: key meta data.
 * @param out_sig[out]: a real signature.
 * @return
 */
bool CombineSignatures(const std::string &doc,
                       const std::vector<RSASigShare> &sig_arr,
                       const RSAPublicKey &public_key,
                       const RSAKeyMeta &key_meta,
                       safeheron::bignum::BN &out_sig);

};

};


#endif //SAFEHERON_TSS_RSA_H