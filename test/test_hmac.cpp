// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#define BOOST_CRYPT_ENABLE_MD5

#include <boost/crypt/hash/hmac.hpp>
#include <boost/crypt/hash/md5.hpp>
#include <boost/crypt/hash/sha1.hpp>
#include <boost/crypt/hash/sha256.hpp>
#include <boost/core/lightweight_test.hpp>

template <typename HasherType>
void basic_tests()
{
    boost::crypt::hmac<HasherType> hmac_tester;
    const auto state_1 {hmac_tester.init("key", 3)};
    BOOST_TEST(state_1 == boost::crypt::hasher_state::success);

    const char* msg {"The quick brown fox jumps over the lazy dog"};
    const auto state_2 {hmac_tester.process_bytes(msg, std::strlen(msg))};
    BOOST_TEST(state_2 == boost::crypt::hasher_state::success);

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
            0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a, 0x7a, 0x36, 0xf7, 0x0a, 0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9
        };

        for (boost::crypt::size_t i {}; i < res.size(); ++i)
        {
            BOOST_TEST_EQ(res[i], soln[i]);
        }
    }
    else BOOST_CRYPT_IF_CONSTEXPR (boost::crypt::is_same_v<HasherType, boost::crypt::sha256_hasher>)
    {
        constexpr boost::crypt::array<boost::crypt::uint8_t, 32U> soln = {
            0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8
        };

        for (boost::crypt::size_t i {}; i < res.size(); ++i)
        {
            BOOST_TEST_EQ(res[i], soln[i]);
        }
    }
}

int main()
{
    basic_tests<boost::crypt::md5_hasher>();
    basic_tests<boost::crypt::sha1_hasher>();
    basic_tests<boost::crypt::sha256_hasher>();

    return boost::report_errors();
}
