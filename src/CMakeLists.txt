find_package(PkgConfig REQUIRED)
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoBN REQUIRED)
find_package(CryptoSSS REQUIRED)
find_package(CryptoHash REQUIRED)

add_library(${CMAKE_PROJECT_NAME} SHARED
        crypto-tss-rsa/RSAPrivateKeyShare.cpp
        crypto-tss-rsa/RSAPublicKey.cpp
        crypto-tss-rsa/RSAKeyMeta.cpp
        crypto-tss-rsa/RSASigShare.cpp
        crypto-tss-rsa/KeyGenParam.cpp
        crypto-tss-rsa/RSASigShareProof.cpp
        crypto-tss-rsa/tss_rsa.cpp
        crypto-tss-rsa/tss_rsa.pb.cc
        )

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CryptoBN_INCLUDE_DIRS}
        ${CryptoSSS_INCLUDE_DIRS}
        ${CryptoHash_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        )

TARGET_LINK_LIBRARIES(${CMAKE_PROJECT_NAME}
        CryptoBN
        CryptoSSS
        CryptoHash
        OpenSSL::Crypto
        -ldl
        )
