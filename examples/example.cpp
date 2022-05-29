#include "crypto-bn/bn.h"
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

int main(int argc, char **argv) {
    std::string json_str;
    std::string doc("12345678123456781234567812345678");

    // Key Generation
    int key_bits_length = 1024;
    int k = 2;
    int l = 3;
    std::vector<RSAPrivateKeyShare> priv_arr;
    RSAPublicKey pub;
    RSAKeyMeta key_meta;
    bool status = safeheron::tss_rsa::GenerateKey(key_bits_length, l, k, priv_arr, pub, key_meta);
    key_meta.ToJsonString(json_str);
    std::cout << "key meta data: " << json_str << std::endl;

    pub.ToJsonString(json_str);
    std::cout << "public key: " << json_str << std::endl;

    priv_arr[0].ToJsonString(json_str);
    std::cout << "private key share 1: " << json_str << std::endl;
    priv_arr[2].ToJsonString(json_str);
    std::cout << "private key share 3: "  << json_str << std::endl;

    // Party 1 sign.
    RSASigShare sig_share0 = priv_arr[0].Sign(doc, key_meta, pub);
    sig_share0.ToJsonString(json_str);
    std::cout << "signature share 1: " << json_str << std::endl;
    // Party 3 sign.
    RSASigShare sig_share2 = priv_arr[2].Sign(doc, key_meta, pub);
    sig_share2.ToJsonString(json_str);
    std::cout << "signature share 3: " <<  json_str << std::endl;

    // Combine signatures
    // Distributed signature
    std::vector<RSASigShare> sig_share_arr;
    sig_share_arr.push_back(sig_share0);
    sig_share_arr.push_back(sig_share2);
    BN sig;
    status = safeheron::tss_rsa::CombineSignatures(doc, sig_share_arr, pub, key_meta, sig);
    std::cout << "final signature = 0x" << sig.Inspect() << std::endl;

    // Verify the final signature.
    std::cout<< "verify:" << pub.VerifySignature(doc, sig) << std::endl;
    return 0;
}
