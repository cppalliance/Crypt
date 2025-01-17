// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/mac/hmac.hpp>
#include <boost/crypt2/hash/sha1.hpp>
#include <boost/crypt2/hash/sha256.hpp>
#include <boost/crypt2/hash/sha512.hpp>
#include <boost/core/lightweight_test.hpp>

template <typename HasherType>
void basic_tests()
{
    boost::crypt::hmac<HasherType> hmac_tester;
    const auto state_1 {hmac_tester.init(std::string{"key"})};
    BOOST_TEST(state_1 == boost::crypt::state::success);

    std::string msg {"The quick brown fox jumps over the lazy dog"};
    const auto state_2 {hmac_tester.process_bytes(msg)};
    BOOST_TEST(state_2 == boost::crypt::state::success);

    hmac_tester.finalize();
    const auto res {hmac_tester.get_digest().value()};
    
    if constexpr (std::is_same_v<HasherType, boost::crypt::sha1_hasher>)
    {
        constexpr std::array<std::uint8_t, 20U> soln = {
            0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a,
            0x7a, 0x36, 0xf7, 0x0a, 0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9
        };

        for (std::size_t i {}; i < res.size(); ++i)
        {
            BOOST_TEST(res[i] == static_cast<std::byte>(soln[i]));
        }
    }
    else if constexpr (std::is_same_v<HasherType, boost::crypt::sha256_hasher>)
    {
        constexpr std::array<std::uint8_t, 32U> soln = {
            0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
            0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
            0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
            0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8
        };

        for (std::size_t i {}; i < res.size(); ++i)
        {
            BOOST_TEST(res[i] == static_cast<std::byte>(soln[i]));
        }
    }
    else if constexpr (std::is_same_v<HasherType, boost::crypt::sha512_hasher>)
    {
        constexpr std::array<std::uint8_t, 64U> soln = {
            0xb4, 0x2a, 0xf0, 0x90, 0x57, 0xba, 0xc1, 0xe2,
            0xd4, 0x17, 0x08, 0xe4, 0x8a, 0x90, 0x2e, 0x09,
            0xb5, 0xff, 0x7f, 0x12, 0xab, 0x42, 0x8a, 0x4f,
            0xe8, 0x66, 0x53, 0xc7, 0x3d, 0xd2, 0x48, 0xfb,
            0x82, 0xf9, 0x48, 0xa5, 0x49, 0xf7, 0xb7, 0x91,
            0xa5, 0xb4, 0x19, 0x15, 0xee, 0x4d, 0x1e, 0xc3,
            0x93, 0x53, 0x57, 0xe4, 0xe2, 0x31, 0x72, 0x50,
            0xd0, 0x37, 0x2a, 0xfa, 0x2e, 0xbe, 0xeb, 0x3a
        };

        for (std::size_t i {}; i < res.size(); ++i)
        {
            BOOST_TEST(res[i] == static_cast<std::byte>(soln[i]));
        }
    }
}

template <typename HasherType>
void test_edges()
{
    boost::crypt::hmac<HasherType> hmac_tester;
    std::string msg {"The quick brown fox jumps over the lazy dog"};

    // Usage before init
    const auto state1 {hmac_tester.process_bytes(msg)};
    BOOST_TEST(state1 == boost::crypt::state::state_error);

    // Good init
    const auto state3 {hmac_tester.init(std::string{"key"})};
    BOOST_TEST(state3 == boost::crypt::state::success);

    // Good pass
    const auto state5 {hmac_tester.process_bytes(msg)};
    BOOST_TEST(state5 == boost::crypt::state::success);

    // Get digest twice
    hmac_tester.finalize();
    [[maybe_unused]] const auto garbage = hmac_tester.get_digest();
    const auto res {hmac_tester.get_digest()};
    BOOST_TEST(res.has_value());

    std::string big_key {"This is a really really really really really really really really really really"
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

    const auto state6 {hmac_tester.init(big_key)};
    BOOST_TEST(state6 == boost::crypt::state::success);

    // Init from keys
    const auto outer_key {hmac_tester.get_outer_key()};
    const auto inner_key {hmac_tester.get_inner_key()};

    hmac_tester.process_bytes(msg);
    hmac_tester.finalize();
    const auto res2 {hmac_tester.get_digest().value()};

    hmac_tester.init_from_keys(inner_key, outer_key);
    hmac_tester.process_bytes(msg);
    hmac_tester.finalize();
    const auto res3 {hmac_tester.get_digest().value()};

    for (std::size_t i {}; i < res2.size(); ++i)
    {
        BOOST_TEST(res2[i] == res3[i]);
    }

    BOOST_TEST(hmac_tester.finalize() == boost::crypt::state::state_error);
}

template <typename T>
consteval bool immediate_test()
{
    const std::byte vals[] = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
    std::span<const std::byte> byte_span {vals};
    constexpr std::array<std::byte, 64> message {
            std::byte{0xdd}, std::byte{0xaf}, std::byte{0x35}, std::byte{0xa1}, std::byte{0x93}, std::byte{0x61},
            std::byte{0x7a}, std::byte{0xba}, std::byte{0xcc}, std::byte{0x41}, std::byte{0x73}, std::byte{0x49},
            std::byte{0xae}, std::byte{0x20}, std::byte{0x41}, std::byte{0x31}, std::byte{0x12}, std::byte{0xe6},
            std::byte{0xfa}, std::byte{0x4e}, std::byte{0x89}, std::byte{0xa9}, std::byte{0x7e}, std::byte{0xa2},
            std::byte{0x0a}, std::byte{0x9e}, std::byte{0xee}, std::byte{0xe6}, std::byte{0x4b}, std::byte{0x55},
            std::byte{0xd3}, std::byte{0x9a}, std::byte{0x21}, std::byte{0x92}, std::byte{0x99}, std::byte{0x2a},
            std::byte{0x27}, std::byte{0x4f}, std::byte{0xc1}, std::byte{0xa8}, std::byte{0x36}, std::byte{0xba},
            std::byte{0x3c}, std::byte{0x23}, std::byte{0xa3}, std::byte{0xfe}, std::byte{0xeb}, std::byte{0xbd},
            std::byte{0x45}, std::byte{0x4d}, std::byte{0x44}, std::byte{0x23}, std::byte{0x64}, std::byte{0x3c},
            std::byte{0xe8}, std::byte{0x0e}, std::byte{0x2a}, std::byte{0x9a}, std::byte{0xc9}, std::byte{0x4f},
            std::byte{0xa5}, std::byte{0x4c}, std::byte{0xa4}, std::byte{0x9f}
    };
    std::span<const std::byte, 64> message_span {message};

    boost::crypt::hmac<T> hmac_tester;
    hmac_tester.init(byte_span);
    hmac_tester.process_bytes(message_span);
    hmac_tester.finalize();
    const auto res = hmac_tester.get_digest().value();

    std::size_t zero_counter {};
    for (const auto val : res)
    {
        if (val == std::byte{})
        {
            ++zero_counter;
        }
    }

    return zero_counter != res.size();
}

int main()
{
    basic_tests<boost::crypt::sha1_hasher>();
    basic_tests<boost::crypt::sha256_hasher>();
    basic_tests<boost::crypt::sha512_hasher>();

    test_edges<boost::crypt::sha1_hasher>();
    test_edges<boost::crypt::sha256_hasher>();
    test_edges<boost::crypt::sha512_hasher>();

    // GCC-14 has an internal compiler error here
    #if defined(__GNUC__) && __GNUC__ != 14
    static_assert(immediate_test<boost::crypt::sha1_hasher>());
    #endif

    return boost::report_errors();
}
