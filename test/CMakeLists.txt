find_package(GTest REQUIRED)

add_executable(bn-arithmetic-operation-test tss-rsa-test.cpp)
target_include_directories(bn-arithmetic-operation-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-arithmetic-operation-test
        CryptoTSSRSA
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-arithmetic-operation-test COMMAND tss-rsa-test.cpp)


