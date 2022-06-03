find_package(GTest REQUIRED)
find_package(CryptoSuites REQUIRED)

include_directories(../src
        ${CryptoSuites_INCLUDE_DIRS}
        ${GTEST_INCLUDE_DIRS})
link_libraries(CryptoTSSRSA
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread)

add_executable(tss-rsa-test tss-rsa-test.cpp)
add_test(NAME tss-rsa-test COMMAND tss-rsa-test)


