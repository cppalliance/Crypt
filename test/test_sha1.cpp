// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/hash/sha1.hpp>
#include <boost/core/lightweight_test.hpp>
#include "generate_random_strings.hpp"

#ifdef __clang__
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wconversion"
#  pragma clang diagnostic ignored "-Wold-style-cast"
#elif defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

#include <boost/uuid/detail/sha1.hpp>

#ifdef __clang__
#  pragma clang diagnostic pop
#elif defined(__GNUC__)
#  pragma GCC diagnostic pop
#endif

#include <random>
#include <iostream>
#include <string>
#include <array>
#include <tuple>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <cstring>

auto get_boost_uuid_result(const char* str, size_t length)
{
    unsigned char digest[20];
    boost::uuids::detail::sha1 hasher;
    hasher.process_bytes(str, length);
    hasher.get_digest(digest);

    std::array<unsigned char, 16> return_array {};
    for (std::size_t i {}; i < 16U; ++i)
    {
        return_array[i] = digest[i];
    }

    return return_array;
}

constexpr std::array<std::tuple<const char*, std::array<uint16_t, 20>>, 3> test_values =
{
        // // Start with the sample hashes from wiki
        std::make_tuple("The quick brown fox jumps over the lazy dog",
                        std::array<std::uint16_t, 20>{0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84,
                                                      0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12}),
        std::make_tuple("The quick brown fox jumps over the lazy cog",
                        std::array<std::uint16_t, 20>{0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3,
                                                      0xe8, 0x5a, 0x0b, 0xd1, 0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3}),
        std::make_tuple("",
                        std::array<std::uint16_t, 20>{0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
                                                      0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09}),

};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::sha1(std::get<0>(test_value))};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST_EQ(message_result[i], valid_result[i]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }
    }
}

void string_test()
{
    for (const auto& test_value : test_values)
    {
        const std::string string_message {std::get<0>(test_value)};
        const auto message_result {boost::crypt::sha1(string_message)};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST_EQ(message_result[i], valid_result[i]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }
    }
}

void string_view_test()
{
    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    for (const auto& test_value : test_values)
    {
        const std::string string_message {std::get<0>(test_value)};
        const std::string_view string_view_message {string_message};
        const auto message_result {boost::crypt::sha1(string_view_message)};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST_EQ(message_result[i], valid_result[i]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }
    }
    #endif
}

void bad_input()
{
    const auto null_message {boost::crypt::sha1(static_cast<const char*>(nullptr))};
    BOOST_TEST_EQ(null_message[0], 0x0);
    BOOST_TEST_EQ(null_message[1], 0x0);
    BOOST_TEST_EQ(null_message[2], 0x0);
    BOOST_TEST_EQ(null_message[3], 0x0);

    const auto null_message_len {boost::crypt::sha1(static_cast<const char*>(nullptr), 100)};
    BOOST_TEST_EQ(null_message_len[0], 0x0);
    BOOST_TEST_EQ(null_message_len[1], 0x0);
    BOOST_TEST_EQ(null_message_len[2], 0x0);
    BOOST_TEST_EQ(null_message_len[3], 0x0);

    const auto unsigned_null_message {boost::crypt::sha1(static_cast<const std::uint8_t*>(nullptr))};
    BOOST_TEST_EQ(unsigned_null_message[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[3], 0x0);

    const auto unsigned_null_message_len {boost::crypt::sha1(static_cast<const std::uint8_t*>(nullptr), 100)};
    BOOST_TEST_EQ(unsigned_null_message_len[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[3], 0x0);

    std::string test_str {"Test string"};
    const auto reveresed_input {boost::crypt::detail::sha1(test_str.end(), test_str.begin())};
    BOOST_TEST_EQ(reveresed_input[0], 0x0);
    BOOST_TEST_EQ(reveresed_input[1], 0x0);
    BOOST_TEST_EQ(reveresed_input[2], 0x0);
    BOOST_TEST_EQ(reveresed_input[3], 0x0);
}

void test_class()
{
    boost::crypt::sha1_hasher hasher;

    for (const auto& test_value : test_values)
    {
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg, std::strlen(msg));
        const auto message_result {hasher.get_digest()};

        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST_EQ(message_result[i], valid_result[i]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }

        hasher.init();
    }
}

template <typename T>
void test_random_values()
{
    constexpr std::size_t max_str_len {65535U};
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<std::size_t> str_len(1, max_str_len - 1);

    char* str {new char[max_str_len]};

    for (std::size_t i {}; i < 1024; ++i)
    {
        std::memset(str, '\0', max_str_len);
        const std::size_t current_str_len {str_len(rng)};
        boost::crypt::generate_random_string(str, current_str_len);
        const auto uuid_res {get_boost_uuid_result(str, current_str_len)};

        // boost::crypt::array is implicitly convertible to std::array
        const std::array<std::uint8_t, 20> crypt_res = boost::crypt::sha1(str, current_str_len);

        for (std::size_t j {}; j < crypt_res.size(); ++j)
        {
            if (!BOOST_TEST_EQ(uuid_res[j], crypt_res[j]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with string: " << str << std::endl;
                break;
                // LCOV_EXCL_STOP
            }
        }
    }

    delete[] str;
}

template <typename T>
void test_random_piecewise_values()
{
    constexpr std::size_t max_str_len {65535U};
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<std::size_t> str_len(1, max_str_len - 1);

    char* str {new char[max_str_len]};
    char* str_2 {new char[max_str_len]};

    for (std::size_t i {}; i < 1024; ++i)
    {
        boost::uuids::detail::sha1 boost_hasher;
        boost::crypt::sha1_hasher sha1_hasher;

        std::memset(str, '\0', max_str_len);
        std::memset(str_2, '\0', max_str_len);

        const std::size_t current_str_len {str_len(rng)};
        boost::crypt::generate_random_string(str, current_str_len);
        boost::crypt::generate_random_string(str_2, current_str_len);

        boost_hasher.process_bytes(str, current_str_len);
        boost_hasher.process_bytes(str_2, current_str_len);
        boost_hasher.process_byte(52); // "4"
        unsigned char digest[20];
        boost_hasher.get_digest(digest);

        std::array<unsigned char, 20> uuid_res {};
        for (std::size_t j {}; j < 20U; ++j)
        {
            uuid_res[j] = digest[j];
        }

        sha1_hasher.process_bytes(str, current_str_len);
        sha1_hasher.process_bytes(str_2, current_str_len);
        sha1_hasher.process_byte(52); // "4"
        const auto crypt_res {sha1_hasher.get_digest()};

        for (std::size_t j {}; j < crypt_res.size(); ++j)
        {
            if (!BOOST_TEST_EQ(uuid_res[j], crypt_res[j]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with string: " << str << std::endl;
                break;
                // LCOV_EXCL_STOP
            }
        }
    }

    delete[] str;
    delete[] str_2;
}

int main()
{
    basic_tests();
    string_test();
    string_view_test();
    bad_input();
    test_class();

    test_random_values<char>();
    test_random_piecewise_values<char>();

    test_random_values<char16_t>();
    test_random_piecewise_values<char16_t>();

    test_random_values<char32_t>();
    test_random_piecewise_values<char32_t>();

    test_random_values<wchar_t>();
    test_random_piecewise_values<wchar_t>();

    return boost::report_errors();
}
