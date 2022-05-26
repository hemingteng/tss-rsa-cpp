# tss-rsa-cpp

![img](doc/logo.png)

This software implements a library for tss-rsa.

The library comes with serialize/deserialize support to be used in higher level code to implement networking.

# Prerequisites

- [OpenSSL](https://github.com/openssl/openssl#documentation). See the [OpenSSL Installation Instructions](./doc/OpenSSL-Installation.md)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf.git). See the [Protocol Buffers Installation Instructions](./doc/Protocol-Buffers-Installation.md)
- [crypto-suites-cpp](https://github.com/safeheron/crypto-suites-cpp.git). See the [crypto-suites-cpp Installation Instructions](https://github.com/safeheron/crypto-suites-cpp/blob/main/README.md#build-and-install)

# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script.

```shell
git clone https://github.com/safeheron/crypto-tss-rsa-cpp.git
cd crypto-tss-rsa-cpp
mkdir build && cd build
# Run "cmake .. -DOPENSSL_ROOT_DIR=Your-Root-Directory-of-OPENSSL" instead of the command below on Mac OS.
cmake ..
# Add the path to the LD_LIBRARY_PATH environment variable on Mac OS; Ignore it on Linux
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib/
make
make test
sudo make install
```

More platforms such as Windows would be supported soon.


# To start using crypto-tss-rsa-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build crypto-tss-rsa-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
project(XXXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoSuites REQUIRED)
find_package(CryptoTSSRSA REQUIRED)

add_executable(${PROJECT_NAME} XXXX.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoSuites_INCLUDE_DIRS}
        ${CryptoTSSRSA_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        )

target_link_libraries(${PROJECT_NAME} PUBLIC
        CryptoSuites
        CryptoTSSRSA
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        pthread )
```

# Usage

It's an example where the key length is 1024, the number of parties is 3 and threshold is 2.
```c++
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
```

Here is the CMakeList.txt:

```shell
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoSuites REQUIRED)
find_package(CryptoTSSRSA REQUIRED)

add_executable(${PROJECT_NAME} example.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoTSSRSA_INCLUDE_DIRS}
        ${CryptoSuites_INCLUDE_DIRS}
        /usr/local/include
        )

target_link_directories(${PROJECT_NAME} PUBLIC
        /usr/local/lib
        )

target_link_libraries(${PROJECT_NAME} PUBLIC
        CryptoSuites
        CryptoTSSRSA
        pthread )
```

Compile and run:
```shell
key meta data: {
 "k": 2,
 "l": 3,
 "vkv": "0DDBA893E62B4986BCF290ECB388F415D63CC9631EC5AF45A1DBF06DDEF0406179854CF0EBEA0EFC432DBCC4763B47B7EA66970257D9A462F2D9B6830D034CEDD4714A6EB029A9D097F275EB30E14596DBFE41686900264BA650C90E7448E9FC3B58EC4FB65B605B0B34E2E4C909472D88D39E450F599169B1EEC9CFE1070485",
 "vku": "4347039D7302CD8B85556E344ADBB42298ABF450B73CDA29BFC5E5185C051CE6DB051AC410640A014DE77AF30CAE98261810BE850AA8871ADDC7E65159B780A82C2C76B0852E5555898DA7E5EB97CAB0B3BF7BC61DC6AEC3676283B9905DF685602F03D4A990B1544049B5F1D214FD0CDFC03AE08BE8028C284172D8491A15FA",
 "vkiArr": [
  "610C486EA0D217068AF1D7E71A907653E6B459184FA60D5E61239CE26D075E01CAFBD4480156261E11E463C89209E81A8D49BF98CEAA29712EA7A9C68262CF5E5DE05C97D9AFB59880AE69AB9D25DB177F5E93AF075994FF95027FB283DA9CCA776422ED5BED154BBBD2868CBF8F3E7A380838C0B9368D703B1107EC5C9B53E8",
  "721520733794B87FC5F9FE58E498D79F2CAA7AE5534FE5CEA07E48E94DB3B32E9E699AFB20FE4E5AAF1D448CB0FC9164F1674F71D86384FE44AC3B0E60443CE444A9BDADE4921BE9EB26CBB6D9A9904C0D5CF4E3F96DB438D4A07D3629EA281F0578DEF8ADE366EFAE2D6C68D32FEC6004AA5DA57FDA33AB008DCF0455AF5E7B",
  "1B7F52DCD58CC607CA37E833AFEFB0C611BE781DBD4A7F1A5E914E50AB7846D81D440AE93F8967D54B6150D03E30347B173FF2391A0100DD0E61A25A6752F498C736C780C3717FFF4171069771FEB016FC13C734839DAED7AC25049D7B8417F52FD55EFBEC9B1786B9193BCA0077E02A08D8A009C568CFBA6EA1A53A0491FD31"
 ]
}

public key: {
 "n": "C25ACE144A58F41ABF77B42E470DB17DA488564EE92D22B22D3D9BB453AAFB28F602ABDFFF8D68790A16F4FA58CA1DBB78AAFB7944E16C4DFEA703C3327A96D7DDEA5C83311A1BDC872D8296FF31F4E4006FA55C05F0C9BAC2046056D2B901BDEF90AA6F259A6C01F417DD45EC014DA1F20B5D706D61B13D0D1B4841FF946EA5",
 "e": "010001"
}

private key share 1: {
 "i": 1,
 "si": "2D2A961CF06FFBC7C32402DC85900B04CC4173251E4CE91D2C36E35B0EB6F605B1426982B152365E81512BDB5FDD839B53EE9917F1F43F955E7B0E131A4BE18E06CF28380FCE81EC92A4B80262736F9C83408028645DD6745DBF3903B56662DA06EDDFA0447DF0867B03893D89F779C431F9336C59010114F828BBAB29A8AB93"
}

private key share 2: {
 "i": 2,
 "si": "1DF05F1C07CAED6AE6C707ABD5EF8734DC1882806B3B91BEB797E61DD1B48D3DE7A45AF88248E8F3DB5390884C7FF7A5938287201610D9F70E223EC5630A14B305606FEB2271F0178C701EDC2B248B2E9349778C72F01B46CF0FA0EB035036DB3259318779626F9C0337147B933AC24411FC6D4401891A142722C02EABE68A3D"
}

private key share 3: {
 "i": 3,
 "si": "0EB6281B1F25DF0E0A6A0C7B264F0364EBEF91DBB82A3A6042F8E8E094B224761E064C6E533F9B893555F53539226BAFD31675283A2D7458BDC96F77ABC847D803F1B79E35155E42863B85B5F3D5A6C0A3526EF081826019406008D2513A0ADC5DC4836EAE46EEB18B6A9FB99C7E0AC3F1FFA71BAA113313561CC4B22E2468E7"
}

signature share 1: {
 "index": 1,
 "sigShare": "A338BFD2AE9628D2CFD3EFA8CDF354F528EBFBD55706E59049EA7E35EE23E981EEB8AF76E06083AD7BA1855F9DDF2313D365CECC74D990E40B65B0DF5FC1B35512A79E73E2439307E1C86D7406E614C46B76E9836CE88097102A8D8A9A4A0B3274195D80DCAB6BEF2642358DFFEA02A0B2792C5E2AEBBB81AC69A94E8837A2C9",
 "z": "012CE94E66FC4DA5B91F4BEBC41E74C51A1C8BB8577BECB3174F28E714B760AE39549F90C941FC4388EBEF3B0E58DB7F63ED775991F0A6A5B899C76F873992B1467CCDAE8BC42172F036198BF009B3A04FB5A585D913A88A8587933C2193CA59249372D6BD4D0EB07030857A8AEE2171F8ADE364EDB7DE9CD58F2D0391310ABC44E41DACF2DD6FE4EF02A09672CC8DB99A80CC6A3DF55098DD99D46DA3D01AB226EAD8E8BA63A3DE7565A8BD4B5501873D3F8E7C7A9EDF944D1E842E3010277850",
 "c": "7A0B4E6293F6CFAF58EA9E7C623FC6DE44D09A846452B46D7177684B665A1CDF"
}

signature share 2: {
 "index": 2,
 "sigShare": "4CCD1B9CA3E8CC6354E4D41E04C832C6601DFC2AD22778CDADABBA7272B80E7E3DCDE9171C0D14303D8E32A014C543A6AB3EBDBA2E081FA1C42C0C0E59941CF57903EAD5C8993CEB9AF17D44C8406C0C31E3A0144DF06D446F6DAA6D72924DA9357AE7B16CE94CC28860898ACDB15F0705135AEF9CD147FD5D4A5696D4FAEE66",
 "z": "7C6632A5D8946F55D938752C15548E762E1C77242213146E607C8689582E729FAD8FE8690AD9446F7A502092D062570D50498C7E44A2154685861C9713875DF30B840799CB9ABD9696393292EDA74065FFD467D021931299475CACA717E6B9B2BCC20AF7F03EBF10893323CD2531A7C15CF4DD28F197CC78A7F0CE0E8FE5480910AC7CD787042B1FAA8B86D328A99DA4A943750D054EB4E99A73249A8D256C8ED7C52A3742DBA9B662C06826CEAAC887A74DFF8A0164498F40A36B0F08888650",
 "c": "2BDA577C48AA49493A3A8CA31B31049C6AB0C150E001E070481B305543014BA8"
}

signature share 3: {
 "index": 3,
 "sigShare": "0A7E3614C858DCD41C5783C183179028F2E8CD771AE549434CC108DDC5A09837B2D27B617F964F8862EAEE9CC07D223A802BA4BEEF8ADF2AD363BB72CBB56FD256375290D4E7F93E93EC1D953359863033269C8AD9729300B0213613E57B2D95D45FC99A2F1882542A51FB0159A3179E7789A1C47C86998E724382F2BE2EB05A",
 "z": "017CC56F8E91ECA0C8A498B4BCBEDD4332E1741D63C54F63EB1CDBD7DB61A33477B35F97546933366B3DD8F44CEC12916675D4C7CB6F15D7D853D916D87D30927661DE9C2BC826DC5DD753E3D525120E9C5472A0110C419D7DE25343B0B723CAE6624A21EAEB8E8EB82D3C90C91E1659597A13B5E4770E9BEF11B62B2879F8941F35172CBE5B1483BD3ED145E7B9DC5E8F0C088B3467309B0AD303E3E419478BDD1751138D9EDAE22D7C164E3B544134840AB5C51726AAB7D8323896A83056E1E5",
 "c": "D550B1205C099585ABFCD08CC4033195C0D4F85F444FD1167C43CA31515852D3"
}

final signature = 0x50C8E974FC694FE01CE19968E35310614264F9CAC1F2E294A59DA1E7608563DFEE3A62D92C6A2C362955FE916D4D517418DEFAEA14D629D7C687085C68C466148F360874CD3A5B39A1631E1FBB5B0AE4343FF9B67D51DA3D76A46C2054C7A07C99FD7260CEB1D5F695B5AF2B1A16C61D91BFFEF7E214A4B77C961EA82C491106

```

# Reference

##### [1] [Practical Threshold Signatures](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf)
##### [2] [Description of TSS-RSA Signature Algorithm](./doc/Description_of_TSS_RSA_Signature_Algorithm.md)

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail or join Safeheron Telegram for discussions on code and research.
