#include "gtest/gtest.h"
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include "exception/safeheron_exceptions.h"
#include "crypto-tss-rsa/tss_rsa.h"

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
/*
TEST(BN, Add) {
    BN m("12345678123456781234567812345678", 16);

    // Key Generation
    int key_bits_length = 1024;
    int k = 2;
    int l = 3;
    std::vector<RSAPrivateKeyShare> priv_arr;
    RSAPublicKey pub;
    RSAKeyMeta key_meta;
    safeheron::tss_rsa::GenerateKey(key_bits_length, l, k, priv_arr, pub, key_meta);

    // Party 1 sign.
    RSASigShare sig_share0 = priv_arr[0].Sign(m, key_meta, pub);
    std::cout << "index:" << sig_share0.index() << std::endl;
    std::cout << "sig_share:" << sig_share0.sig_share().Inspect() << std::endl;
    // Party 2 sign.
    RSASigShare sig_share1 = priv_arr[1].Sign(m, key_meta, pub);
    std::cout << "index:" << sig_share1.index() << std::endl;
    std::cout << "sig_share:" << sig_share1.sig_share().Inspect() << std::endl;
    // Party 3 sign.
    RSASigShare sig_share2 = priv_arr[2].Sign(m, key_meta, pub);
    std::cout << "index:" << sig_share2.index() << std::endl;
    std::cout << "sig_share:" << sig_share2.sig_share().Inspect() << std::endl;
    std::vector<RSASigShare> sig_share_arr;
    sig_share_arr.push_back(sig_share0);
    sig_share_arr.push_back(sig_share1);
    sig_share_arr.push_back(sig_share2);

    // Combine signatures
    // Distributed signature
    BN sig = safeheron::tss_rsa::CombineSignatures(sig_share_arr, m, pub, key_meta);
    std::cout << "final signature:" << sig.Inspect() << std::endl;

    // Verify the final signature.
    EXPECT_TRUE(pub.VerifySignature(m, sig));
}
*/

TEST(BN, Add) {
    BN m("12345678123456781234567812345678", 16);

    KeyGenParam param(0,
                      BN("E4AAECAA632881A60D11813CC8379980C673BEFB959F44AA14BB15F141ADBE9E6B25FA3A8715435427B10AA608946D0A7B68A4F75BDC376E12010F813F480007", 16),
                      BN("C32F913ECDF403DB94B07A8D02AF2934A882226F3535E6436A6A2392A2C390E525D4531D6EFF2028AE8E16F856E0945348E007EDAC43B4CE9BE5E68D76E93E63", 16),
                      BN("77268D1F347AB0EE48741FBFFD3A052154B8FC614C0FD357F5D0E7B4119D24A4EC47FFFE68DD9BB097D2D7848B08070AEEB25C99EDAA95387F71D8589209973E538D4BC9E693963E485097EB0B8AE8ACD84A13385EC1DBEB070ABAB02E322C247DE70944B17CF3109CBF3DABAB9C66C579706C00CF719314F83A48224FF16DC9", 16),
                        BN("1E7989EBD93507193CE394263F7C32F434E67F1750A367EC725495899BEF99EBC8FCF41148B82D66BB03BAAA25625DD12B29BAA3B43807C15988278E4BD0E64BBCC133B5583431A48BB58BA188CFBDEA1B6170EDAA4D0B1E0AA0D4CCACDB3A66A7DE6A6AC31CB14B802F45AEB4FDBD9B3D621B9BE88050749A093A382EF914C1", 16));
                      //BN::ZERO);
                      //BN("4DC006B6F6A497813A75A6ED8B94EB48B312C1FBFAD63F29D22BC4F5ADE2E69F8C043A13FA63452D33631BE48AA5BF6B11394CC944E423D6A06BC94A1EB2533F54D5DF240C78CE99D286B47FF6C7E7175FA53031658B1B953BF641BCC5B3BF35B76F5339C0BEC53068790627349BFC8D2CF691480A47062976B9A4CC292FC01E", 16));

    // Key Generation
    int key_bits_length = 1024;
    int k = 2;
    int l = 3;
    std::vector<RSAPrivateKeyShare> priv_arr;
    RSAPublicKey pub;
    RSAKeyMeta key_meta;
    bool status = safeheron::tss_rsa::GenerateKeyEx(key_bits_length, l, k, priv_arr, pub, key_meta, param);
    EXPECT_TRUE(status);

    // Party 1 sign.
    RSASigShare sig_share0 = priv_arr[0].Sign(m, key_meta, pub);
    std::cout << "i = 0x" << sig_share0.index() << std::endl;
    std::cout << "sig1 = 0x" << sig_share0.sig_share().Inspect() << std::endl;
    // Party 2 sign.
    RSASigShare sig_share1 = priv_arr[1].Sign(m, key_meta, pub);
    std::cout << "i = 0x" << sig_share1.index() << std::endl;
    std::cout << "sig2 = 0x" << sig_share1.sig_share().Inspect() << std::endl;
    // Party 3 sign.
    RSASigShare sig_share2 = priv_arr[2].Sign(m, key_meta, pub);
    std::cout << "i = 0x" << sig_share2.index() << std::endl;
    std::cout << "sig3 = 0x" << sig_share2.sig_share().Inspect() << std::endl;
    std::vector<RSASigShare> sig_share_arr;
    sig_share_arr.push_back(sig_share0);
    sig_share_arr.push_back(sig_share1);
    sig_share_arr.push_back(sig_share2);

    // Combine signatures
    // Distributed signature
    BN sig = safeheron::tss_rsa::CombineSignatures(sig_share_arr, m, pub, key_meta);
    std::cout << "final signature = 0x" << sig.Inspect() << std::endl;

    // Verify the final signature.
    EXPECT_TRUE(pub.VerifySignature(m, sig));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
