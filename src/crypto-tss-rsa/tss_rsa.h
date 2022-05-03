//
// Created by 何剑虹 on 2020/10/25.
//

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

bool GenerateKey(size_t key_bits_length, int l, int k,
                 std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                 RSAPublicKey &public_key,
                 RSAKeyMeta &key_meta);

bool GenerateKeyEx(size_t key_bits_length, int l, int k,
                 std::vector<RSAPrivateKeyShare> &private_key_share_arr,
                 RSAPublicKey &public_key,
                 RSAKeyMeta &key_meta, const KeyGenParam &param);

safeheron::bignum::BN CombineSignatures(const std::vector<RSASigShare> &sig_arr,
                                        const safeheron::bignum::BN &m,
                                        const RSAPublicKey &public_key,
                                        const RSAKeyMeta &key_meta);

};
};


#endif //SAFEHERON_TSS_RSA_H