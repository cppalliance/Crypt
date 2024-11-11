// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#define BOOST_CRYPT_ENABLE_MD5

#include <boost/crypt/hash/hmac.hpp>
#include <boost/crypt/hash/md5.hpp>
#include <boost/crypt/hash/sha1.hpp>
#include <boost/crypt/hash/sha256.hpp>
#include <boost/crypt/hash/sha512.hpp>
#include <boost/core/lightweight_test.hpp>

template <typename HasherType>
void basic_tests()
{
    boost::crypt::hmac<HasherType> hmac_tester;
    const auto state_1 {hmac_tester.init("key", 3)};
    BOOST_TEST(state_1 == boost::crypt::state::success);

    const char* msg {"The quick brown fox jumps over the lazy dog"};
    const auto state_2 {hmac_tester.process_bytes(msg, std::strlen(msg))};
    BOOST_TEST(state_2 == boost::crypt::state::success);

    const auto res {hmac_tester.get_digest()};

    BOOST_CRYPT_IF_CONSTEXPR (boost::crypt::is_same_v<HasherType, boost::crypt::md5_hasher>)
    {
        constexpr boost::crypt::array<boost::crypt::uint8_t, 16U> soln = {
            0x80, 0x07, 0x07, 0x13, 0x46, 0x3e, 0x77, 0x49, 0xb9, 0x0c, 0x2d, 0xc2, 0x49, 0x11, 0xe2, 0x75
        };

        for (boost::crypt::size_t i {}; i < res.size(); ++i)
        {
            BOOST_TEST_EQ(res[i], soln[i]);
        }
    }
    else BOOST_CRYPT_IF_CONSTEXPR (boost::crypt::is_same_v<HasherType, boost::crypt::sha1_hasher>)
    {
        constexpr boost::crypt::array<boost::crypt::uint8_t, 20U> soln = {
            0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a,
            0x7a, 0x36, 0xf7, 0x0a, 0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9
        };

        for (boost::crypt::size_t i {}; i < res.size(); ++i)
        {
            BOOST_TEST_EQ(res[i], soln[i]);
        }
    }
    else BOOST_CRYPT_IF_CONSTEXPR (boost::crypt::is_same_v<HasherType, boost::crypt::sha256_hasher>)
    {
        constexpr boost::crypt::array<boost::crypt::uint8_t, 32U> soln = {
            0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
            0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
            0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
            0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8
        };

        for (boost::crypt::size_t i {}; i < res.size(); ++i)
        {
            BOOST_TEST_EQ(res[i], soln[i]);
        }
    }
    else BOOST_CRYPT_IF_CONSTEXPR (boost::crypt::is_same_v<HasherType, boost::crypt::sha512_hasher>)
    {
        constexpr boost::crypt::array<boost::crypt::uint8_t, 64U> soln = {
            0xb4, 0x2a, 0xf0, 0x90, 0x57, 0xba, 0xc1, 0xe2,
            0xd4, 0x17, 0x08, 0xe4, 0x8a, 0x90, 0x2e, 0x09,
            0xb5, 0xff, 0x7f, 0x12, 0xab, 0x42, 0x8a, 0x4f,
            0xe8, 0x66, 0x53, 0xc7, 0x3d, 0xd2, 0x48, 0xfb,
            0x82, 0xf9, 0x48, 0xa5, 0x49, 0xf7, 0xb7, 0x91,
            0xa5, 0xb4, 0x19, 0x15, 0xee, 0x4d, 0x1e, 0xc3,
            0x93, 0x53, 0x57, 0xe4, 0xe2, 0x31, 0x72, 0x50,
            0xd0, 0x37, 0x2a, 0xfa, 0x2e, 0xbe, 0xeb, 0x3a
        };

        for (boost::crypt::size_t i {}; i < res.size(); ++i)
        {
            BOOST_TEST_EQ(res[i], soln[i]);
        }
    }
}

template <typename HasherType>
void test_edges()
{
    boost::crypt::hmac<HasherType> hmac_tester;
    const char* msg {"The quick brown fox jumps over the lazy dog"};

    // Usage before init
    const auto state1 {hmac_tester.process_bytes(msg, std::strlen(msg))};
    BOOST_TEST(state1 == boost::crypt::state::state_error);

    // Init with nullptr
    const auto state2 {hmac_tester.init("nullptr", 0)};
    BOOST_TEST(state2 == boost::crypt::state::null);

    // Good init
    const auto state3 {hmac_tester.init("key", 3)};
    BOOST_TEST(state3 == boost::crypt::state::success);

    // Pass in nullptr
    const auto state4 {hmac_tester.process_bytes("msg", 0)};
    BOOST_TEST(state4 == boost::crypt::state::null);

    // Good pass
    const auto state5 {hmac_tester.process_bytes(msg, std::strlen(msg))};
    BOOST_TEST(state5 == boost::crypt::state::success);

    // Get digest twice
    hmac_tester.get_digest();
    const auto res {hmac_tester.get_digest()};

    for (const auto byte : res)
    {
        BOOST_TEST_EQ(byte, static_cast<std::uint8_t>(0));
    }

    const char* big_key {"This is a really really really really really really really really really really"
                         " really really really really really really really really really really"
                         " really really really really really really really really really really"
                         " really really really really really really really really really really"
                         " really really really really really really really really really really"
                         " really really really really really really really really really really"
                         " really really really really really really really really really really"
                         " really really really really really really really really really really"
                         " really really really really really really really really really really"
                         " really really really really really really really really really really"
                         " long key"};

    const auto state6 {hmac_tester.init(big_key, std::strlen(big_key))};
    BOOST_TEST(state6 == boost::crypt::state::success);

    // Init from keys
    const auto outer_key {hmac_tester.get_outer_key()};
    const auto inner_key {hmac_tester.get_inner_key()};

    hmac_tester.process_bytes(msg, std::strlen(msg));
    const auto res2 {hmac_tester.get_digest()};

    hmac_tester.init_from_keys(inner_key, outer_key);
    hmac_tester.process_bytes(msg, std::strlen(msg));
    const auto res3 {hmac_tester.get_digest()};

    for (std::size_t i {}; i < res2.size(); ++i)
    {
        BOOST_TEST_EQ(res2[i], res3[i]);
    }
}

int main()
{
    basic_tests<boost::crypt::md5_hasher>();
    basic_tests<boost::crypt::sha1_hasher>();
    basic_tests<boost::crypt::sha256_hasher>();
    basic_tests<boost::crypt::sha512_hasher>();

    test_edges<boost::crypt::md5_hasher>();
    test_edges<boost::crypt::sha1_hasher>();
    test_edges<boost::crypt::sha256_hasher>();
    test_edges<boost::crypt::sha512_hasher>();

    return boost::report_errors();
}
