#include "gtest/gtest.h"
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include "exception/safeheron_exceptions.h"
#include "../src/crypto-tss-rsa/tss_rsa.h"
#include "../src/crypto-tss-rsa/emsa_pss.h"
#include "crypto-encode/hex.h"
using safeheron::bignum::BN;
using safeheron::tss_rsa::RSAPrivateKeyShare;
using safeheron::tss_rsa::RSAPublicKey;
using safeheron::tss_rsa::RSAKeyMeta;
using safeheron::tss_rsa::RSASigShare;
using safeheron::tss_rsa::KeyGenParam;
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::BadAllocException;
using safeheron::exception::RandomSourceException;

TEST(TSS_RSA, PSS) {
    std::string m = "hello world";
    int key_bits_length = 2048;
    int l = 5;
    int k = 3;
    RSAKeyMeta key_meta;
    RSAPublicKey pub;
    std::vector<RSAPrivateKeyShare> priv_arr;
    std::vector<RSASigShare> sig_arr;
    BN sig;
    safeheron::tss_rsa::GenerateKey(key_bits_length, l, k, priv_arr, pub, key_meta);
    std::cout << "pub.n: " << pub.n().Inspect() << std::endl;
    std::cout << "pub.e: " << pub.e().Inspect() << std::endl;

    std::string doc = safeheron::tss_rsa::EncodeEMSA_PSS(m, key_bits_length,
                                                         safeheron::tss_rsa::SaltLength::AutoLength);
    std::cout << "EM: " << safeheron::encode::hex::EncodeToHex(doc) << std::endl;
    EXPECT_TRUE(safeheron::tss_rsa::VerifyEMSA_PSS(m, key_bits_length, safeheron::tss_rsa::SaltLength::AutoLength, doc));
    for(int i = 0; i < l; i++) {
        sig_arr.emplace_back(priv_arr[i].Sign(doc, key_meta, pub));
    }
    safeheron::tss_rsa::CombineSignatures(doc, sig_arr, pub, key_meta, sig);
    std::cout << "signature: " << sig.Inspect() <<std::endl;
    EXPECT_TRUE(pub.VerifySignature(doc, sig));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
