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

void cbc_test()
{
    // GFSbox test
    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> key = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> iv {key};

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> plaintext_start = {
            0xf3, 0x44, 0x81, 0xec, 0x3c, 0xc6, 0x27, 0xba,
            0xcd, 0x5d, 0xc3, 0xfb, 0x08, 0xf2, 0x73, 0xe6
    };

    auto plaintext {plaintext_start};

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> ciphertext = {
        0x03, 0x36, 0x76, 0x3e, 0x96, 0x6d, 0x92, 0x59,
        0x5a, 0x56, 0x7c, 0xc9, 0xce, 0x53, 0x7f, 0x5e
    };

    boost::crypt::aes128 gen;
    BOOST_TEST(gen.init(key, key.size()) == boost::crypt::state::success);
    BOOST_TEST(gen.encrypt<boost::crypt::aes::cipher_mode::cbc>(plaintext.begin(), plaintext.size(), iv.begin(), iv.size()) == boost::crypt::state::success);
    BOOST_TEST(plaintext == ciphertext);
    BOOST_TEST(gen.decrypt<boost::crypt::aes::cipher_mode::cbc>(plaintext.begin(), plaintext.size(), iv.begin(), iv.size()) == boost::crypt::state::success);
    BOOST_TEST(plaintext == plaintext_start);
}

void cbc_mmt_test()
{
    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> key = {
        0x07, 0x00, 0xd6, 0x03, 0xa1, 0xc5, 0x14, 0xe4,
        0x6b, 0x61, 0x91, 0xba, 0x43, 0x0a, 0x3a, 0x0c
    };

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> iv = {
        0xaa, 0xd1, 0x58, 0x3c, 0xd9, 0x13, 0x65, 0xe3,
        0xbb, 0x2f, 0x0c, 0x34, 0x30, 0xd0, 0x65, 0xbb
    };

    constexpr boost::crypt::array<boost::crypt::uint8_t, 32> plaintext_original = {
        0x06, 0x8b, 0x25, 0xc7, 0xbf, 0xb1, 0xf8, 0xbd,
        0xd4, 0xcf, 0xc9, 0x08, 0xf6, 0x9d, 0xff, 0xc5,
        0xdd, 0xc7, 0x26, 0xa1, 0x97, 0xf0, 0xe5, 0xf7,
        0x20, 0xf7, 0x30, 0x39, 0x32, 0x79, 0xbe, 0x91
    };

    auto plaintext {plaintext_original};

    constexpr boost::crypt::array<boost::crypt::uint8_t, 32> ciphertext = {
        0xc4, 0xdc, 0x61, 0xd9, 0x72, 0x59, 0x67, 0xa3,
        0x02, 0x01, 0x04, 0xa9, 0x73, 0x8f, 0x23, 0x86,
        0x85, 0x27, 0xce, 0x83, 0x9a, 0xab, 0x17, 0x52,
        0xfd, 0x8b, 0xdb, 0x95, 0xa8, 0x2c, 0x4d, 0x00
    };

    boost::crypt::aes128 gen;
    BOOST_TEST(gen.init(key, key.size()) == boost::crypt::state::success);
    BOOST_TEST(gen.encrypt<boost::crypt::aes::cipher_mode::cbc>(plaintext.begin(), plaintext.size(), iv.begin(), iv.size()) == boost::crypt::state::success);
    BOOST_TEST(plaintext == ciphertext);
    BOOST_TEST(gen.decrypt<boost::crypt::aes::cipher_mode::cbc>(plaintext.begin(), plaintext.size(), iv.begin(), iv.size()) == boost::crypt::state::success);
    BOOST_TEST(plaintext == plaintext_original);
}

void ofb_test()
{
    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> key = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> iv = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> plaintext_original = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    auto plaintext {plaintext_original};

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> ciphertext = {
        0x3a, 0xd7, 0x8e, 0x72, 0x6c, 0x1e, 0xc0, 0x2b,
        0x7e, 0xbf, 0xe9, 0x2b, 0x23, 0xd9, 0xec, 0x34
    };

    boost::crypt::aes128 gen;
    BOOST_TEST(gen.init(key, key.size()) == boost::crypt::state::success);
    BOOST_TEST(gen.encrypt<boost::crypt::aes::cipher_mode::ofb>(plaintext.begin(), plaintext.size(), iv.begin(), iv.size()) == boost::crypt::state::success);
    BOOST_TEST(plaintext == ciphertext);
    BOOST_TEST(gen.decrypt<boost::crypt::aes::cipher_mode::ofb>(plaintext.begin(), plaintext.size(), iv.begin(), iv.size()) == boost::crypt::state::success);
    BOOST_TEST(plaintext == plaintext_original);
}

void ofb_mmt_test()
{
    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> key = {
        0xc9, 0xf4, 0xce, 0x21, 0xb4, 0xc7, 0xda, 0xaa,
        0x4f, 0x93, 0xe2, 0x92, 0xdc, 0x60, 0x5b, 0xc5
    };

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> iv = {
        0x5e, 0x5a, 0x8c, 0xf2, 0x80, 0x8c, 0x72, 0x0e,
        0x01, 0xc1, 0xed, 0x92, 0xd4, 0x70, 0xa4, 0x5d
    };

    constexpr boost::crypt::array<boost::crypt::uint8_t, 32> plaintext_original = {
        0x8e, 0x19, 0xc5, 0xca, 0xcd, 0x01, 0x5a, 0x66,
        0x2e, 0x7f, 0x40, 0xcd, 0xec, 0xad, 0xbf, 0x79,
        0xa6, 0x80, 0x81, 0xc0, 0x6d, 0x95, 0x44, 0xb4,
        0x1c, 0x2d, 0xd2, 0x48, 0xe7, 0x76, 0x33, 0xb4
    };

    auto plaintext {plaintext_original};

    constexpr boost::crypt::array<boost::crypt::uint8_t, 32> ciphertext = {
        0x88, 0x5d, 0xc4, 0x8a, 0xdd, 0x7e, 0xe6, 0xa1,
        0x83, 0x9b, 0xc5, 0xc5, 0xe0, 0x3b, 0xea, 0xe0,
        0x71, 0x30, 0x1e, 0xcf, 0x91, 0xa0, 0x11, 0x15,
        0x20, 0xcd, 0xe0, 0xd3, 0xa1, 0x12, 0xf5, 0xd2
    };

    boost::crypt::aes128 gen;
    BOOST_TEST(gen.init(key, key.size()) == boost::crypt::state::success);
    BOOST_TEST(gen.encrypt<boost::crypt::aes::cipher_mode::ofb>(plaintext.begin(), plaintext.size(), iv.begin(), iv.size()) == boost::crypt::state::success);
    BOOST_TEST(plaintext == ciphertext);
    BOOST_TEST(gen.decrypt<boost::crypt::aes::cipher_mode::ofb>(plaintext.begin(), plaintext.size(), iv.begin(), iv.size()) == boost::crypt::state::success);
    BOOST_TEST(plaintext == plaintext_original);
}

void ctr_test()
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

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> iv = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const auto original_message {plaintext};

    boost::crypt::aes128 gen;

    BOOST_TEST(gen.init(key, key.size()) == boost::crypt::state::success);
    BOOST_TEST(gen.encrypt<boost::crypt::aes::cipher_mode::ctr>(plaintext.begin(), plaintext.size(), iv.begin(), iv.size()) == boost::crypt::state::success);

    BOOST_TEST(plaintext != original_message);

    BOOST_TEST(gen.decrypt<boost::crypt::aes::cipher_mode::ctr>(plaintext.begin(), plaintext.size(), iv.begin(), iv.size()) == boost::crypt::state::success);

    BOOST_TEST(plaintext == original_message);

    gen.destroy();
}

int main()
{
    basic_aes128_test();
    cbc_test();
    cbc_mmt_test();
    ofb_test();
    ofb_mmt_test();
    ctr_test();

    return boost::report_errors();
}
