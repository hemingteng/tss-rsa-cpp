cmake_minimum_required(VERSION 3.10)
project(example)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

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