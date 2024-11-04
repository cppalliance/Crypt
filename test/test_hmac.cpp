// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#define BOOST_CRYPT_ENABLE_MD5

#include <boost/crypt/hash/hmac.hpp>
#include <boost/crypt/hash/md5.hpp>
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
}

int main()
{
    basic_tests<boost::crypt::md5_hasher>();

    return boost::report_errors();
}
