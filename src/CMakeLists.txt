find_package(PkgConfig REQUIRED)
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoSuites REQUIRED)

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
        ${CryptoSuites_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        /usr/local/include
        )

target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE /usr/local/lib)

TARGET_LINK_LIBRARIES(${CMAKE_PROJECT_NAME}
        CryptoSuites
        OpenSSL::Crypto
        -ldl
        )
