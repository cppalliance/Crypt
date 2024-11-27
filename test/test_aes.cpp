// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/aes/aes128.hpp>
#include <boost/core/lightweight_test.hpp>
#include <array>

void basic_aes128_test()
{
    // AES-128 key
    boost::crypt::array<uint8_t, 16> key = {
        0x13, 0x9a, 0x35, 0x42, 0x2f, 0x1d, 0x61, 0xde,
        0x3c, 0x91, 0x78, 0x7f, 0xe0, 0x50, 0x7a, 0xfd
    };

    boost::crypt::array<uint8_t, 16> plaintext = {
        0xb9, 0x14, 0x5a, 0x76, 0x8b, 0x7d, 0xc4, 0x89,
        0xa0, 0x96, 0xb5, 0x46, 0xf4, 0x3b, 0x23, 0x1f
    };


    boost::crypt::aes128 gen;
    BOOST_TEST(gen.init(key, key.size()) == boost::crypt::state::success);
    BOOST_TEST(gen.encrypt<boost::crypt::aes::cipher_mode::ecb>(plaintext.begin(), plaintext.size()) == boost::crypt::state::success);
}

int main()
{
    basic_aes128_test();

    return boost::report_errors();
}
