find_package(GTest REQUIRED)

add_executable(tss-rsa-test tss-rsa-test.cpp)
target_include_directories(tss-rsa-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(tss-rsa-test
        CryptoTSSRSA
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME tss-rsa-test COMMAND tss-rsa-test)


