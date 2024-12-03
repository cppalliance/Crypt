// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/aes/aes128.hpp>
#include <boost/core/lightweight_test.hpp>
#include <array>

void basic_aes128_test()
{
    // AES-128 key from appendix A.1
    boost::crypt::array<uint8_t, 16> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    boost::crypt::array<uint8_t, 16> plaintext = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    const auto original_message {plaintext};

    boost::crypt::aes128 gen;
    BOOST_TEST(gen.init(key, key.size()) == boost::crypt::state::success);
    BOOST_TEST(gen.encrypt<boost::crypt::aes::cipher_mode::ecb>(plaintext.begin(), plaintext.size()) == boost::crypt::state::success);

    const boost::crypt::array<uint8_t, 16> validation_1 = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
    };

    BOOST_TEST(plaintext == validation_1);

    BOOST_TEST(gen.decrypt<boost::crypt::aes::cipher_mode::ecb>(plaintext.begin(), plaintext.size()) == boost::crypt::state::success);

    BOOST_TEST(plaintext == original_message);

    gen.destroy();
}

int main()
{
    basic_aes128_test();

    return boost::report_errors();
}
