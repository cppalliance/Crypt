// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/hash/sha3_256.hpp>
#include <boost/core/lightweight_test.hpp>
#include "generate_random_strings.hpp"
#include <random>
#include <iostream>
#include <string>
#include <array>
#include <tuple>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <cstring>

constexpr std::array<std::tuple<const char*, boost::crypt::sha3_256_hasher::return_type>, 3> test_values =
{
    std::make_tuple("",
                    boost::crypt::sha3_256_hasher::return_type {
                        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
                        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
                        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
                        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    boost::crypt::sha3_256_hasher::return_type {
                        0x69, 0x07, 0x0d, 0xda, 0x01, 0x97, 0x5c, 0x8c,
                        0x12, 0x0c, 0x3a, 0xad, 0xa1, 0xb2, 0x82, 0x39,
                        0x4e, 0x7f, 0x03, 0x2f, 0xa9, 0xcf, 0x32, 0xf4,
                        0xcb, 0x22, 0x59, 0xa0, 0x89, 0x7d, 0xfc, 0x04
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    boost::crypt::sha3_256_hasher::return_type {
                        0xa8, 0x0f, 0x83, 0x9c, 0xd4, 0xf8, 0x3f, 0x6c,
                        0x3d, 0xaf, 0xc8, 0x7f, 0xea, 0xe4, 0x70, 0x04,
                        0x5e, 0x4e, 0xb0, 0xd3, 0x66, 0x39, 0x7d, 0x5c,
                        0x6c, 0xe3, 0x4b, 0xa1, 0x73, 0x9f, 0x73, 0x4d
                    }),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::sha3_256(std::get<0>(test_value))};
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
        const auto message_result {boost::crypt::sha3_256(string_message)};
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
        const auto message_result {boost::crypt::sha3_256(string_view_message)};
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

        boost::crypt::sha3_256_hasher hasher;
        const auto current_state = hasher.process_bytes(string_view_message);
        BOOST_TEST(current_state == boost::crypt::hasher_state::success);
        const auto result2 = hasher.get_digest();
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST_EQ(result2[i], valid_result[i]))
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
    const auto null_message {boost::crypt::sha3_256(static_cast<const char*>(nullptr))};
    BOOST_TEST_EQ(null_message[0], 0x0);
    BOOST_TEST_EQ(null_message[1], 0x0);
    BOOST_TEST_EQ(null_message[2], 0x0);
    BOOST_TEST_EQ(null_message[3], 0x0);

    const auto null_message_len {boost::crypt::sha3_256(static_cast<const char*>(nullptr), 100)};
    BOOST_TEST_EQ(null_message_len[0], 0x0);
    BOOST_TEST_EQ(null_message_len[1], 0x0);
    BOOST_TEST_EQ(null_message_len[2], 0x0);
    BOOST_TEST_EQ(null_message_len[3], 0x0);

    const auto unsigned_null_message {boost::crypt::sha3_256(static_cast<const std::uint8_t*>(nullptr))};
    BOOST_TEST_EQ(unsigned_null_message[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[3], 0x0);

    const auto unsigned_null_message_len {boost::crypt::sha3_256(static_cast<const std::uint8_t*>(nullptr), 100)};
    BOOST_TEST_EQ(unsigned_null_message_len[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[3], 0x0);

    std::string test_str {"Test string"};
    const auto reveresed_input {boost::crypt::detail::sha3_256(test_str.end(), test_str.begin())};
    BOOST_TEST_EQ(reveresed_input[0], 0x0);
    BOOST_TEST_EQ(reveresed_input[1], 0x0);
    BOOST_TEST_EQ(reveresed_input[2], 0x0);
    BOOST_TEST_EQ(reveresed_input[3], 0x0);
}

void test_class()
{
    boost::crypt::sha3_256_hasher hasher;

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
void test_file(T filename, const boost::crypt::sha3_256_hasher::return_type& res)
{
    const auto crypt_res {boost::crypt::sha3_256_file(filename)};

    for (std::size_t j {}; j < crypt_res.size(); ++j)
    {
        if (!BOOST_TEST_EQ(res[j], crypt_res[j]))
        {
            // LCOV_EXCL_START
            std::cerr << "Failure with file: " << filename << std::endl;
            break;
            // LCOV_EXCL_STOP
        }
    }
}

template <typename T>
void test_invalid_file(T filename)
{
    constexpr boost::crypt::sha3_256_hasher::return_type res{};

    const auto crypt_res {boost::crypt::sha3_256_file(filename)};

    for (std::size_t j {}; j < crypt_res.size(); ++j)
    {
        if (!BOOST_TEST_EQ(res[j], crypt_res[j]))
        {
            // LCOV_EXCL_START
            std::cerr << "Failure with file: " << filename << std::endl;
            break;
            // LCOV_EXCL_STOP
        }
    }
}

void files_test()
{
    // Based off where we are testing from (test vs boost_root) we need to adjust our filepath
    const char* filename;
    const char* filename_2;

    // Boost-root
    std::ifstream fd("libs/crypt/test/test_file_1.txt", std::ios::binary | std::ios::in);
    filename = "libs/crypt/test/test_file_1.txt";
    filename_2 = "libs/crypt/test/test_file_2.txt";

    // LCOV_EXCL_START
    if (!fd.is_open())
    {
        // Local test directory or IDE
        std::ifstream fd2("test_file_1.txt", std::ios::binary | std::ios::in);
        filename = "test_file_1.txt";
        filename_2 = "test_file_2.txt";

        if (!fd2.is_open())
        {
            // test/cover
            std::ifstream fd3("../test_file_1.txt", std::ios::binary | std::ios::in);
            filename = "../test_file_1.txt";
            filename_2 = "../test_file_2.txt";

            if (!fd3.is_open())
            {
                std::cerr << "Test not run due to file system issues" << std::endl;
                return;
            }
            else
            {
                fd3.close();
            }
        }
        else
        {
            fd2.close();
        }
    }
    else
    {
        fd.close();
    }
    // LCOV_EXCL_STOP

    // On macOS 15
    // openssl dgst -sha3-256 test_file_1.txt
    // sha3_256 (test_file_1.txt) = a6b14417b96c60706bc7bd3bbbeefc303e18285ad54d8ee0d10c31103ef94fee
    constexpr boost::crypt::sha3_256_hasher::return_type res{0xa6, 0xb1, 0x44, 0x17, 0xb9, 0x6c, 0x60, 0x70, 0x6b, 0xc7, 0xbd, 0x3b, 0xbb, 0xee, 0xfc, 0x30, 0x3e, 0x18, 0x28, 0x5a, 0xd5, 0x4d, 0x8e, 0xe0, 0xd1, 0x0c, 0x31, 0x10, 0x3e, 0xf9, 0x4f, 0xee};

    test_file(filename, res);

    const std::string str_filename {filename};
    test_file(str_filename, res);

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    const std::string_view str_view_filename {str_filename};
    test_file(str_view_filename, res);
    #endif

    const auto invalid_filename = "broken.bin";
    test_invalid_file(invalid_filename);

    const std::string str_invalid_filename {invalid_filename};
    test_invalid_file(str_invalid_filename);

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    const std::string_view str_view_invalid_filename {str_invalid_filename};
    test_invalid_file(str_view_invalid_filename);
    #endif

    // On macOS 15
    // openssl dgst -sha3-256 test_file_2.txt
    // sha3_256 (test_file_2.txt) = 8b0bd446d395a3711f849023baeba17acbfa8c9d2a532baa01c745bf9e129ac2
    constexpr boost::crypt::sha3_256_hasher::return_type res_2{0x8b, 0x0b, 0xd4, 0x46, 0xd3, 0x95, 0xa3, 0x71, 0x1f, 0x84, 0x90, 0x23, 0xba, 0xeb, 0xa1, 0x7a, 0xcb, 0xfa, 0x8c, 0x9d, 0x2a, 0x53, 0x2b, 0xaa, 0x01, 0xc7, 0x45, 0xbf, 0x9e, 0x12, 0x9a, 0xc2};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    test_invalid_file(test_null_file);
}

void test_invalid_state()
{
    boost::crypt::sha3_256_hasher hasher;
    auto current_state = hasher.process_bytes("test", 4);
    BOOST_TEST(current_state == boost::crypt::hasher_state::success);

    hasher.get_digest();

    const auto bad_state = hasher.process_bytes("test", 4);
    BOOST_TEST(bad_state == boost::crypt::hasher_state::state_error);

    const auto digest = hasher.get_digest();

    for (const auto& val : digest)
    {
        BOOST_TEST_EQ(val, static_cast<std::uint8_t>(0));
    }

    hasher.init();

    current_state = hasher.process_bytes("test", 4);
    BOOST_TEST(current_state == boost::crypt::hasher_state::success);
    current_state = hasher.process_byte(0x03);
    BOOST_TEST(current_state == boost::crypt::hasher_state::success);
    const char* ptr = nullptr;
    current_state = hasher.process_bytes(ptr, 4);
    BOOST_TEST(current_state == boost::crypt::hasher_state::null);

    const char16_t* ptr16 = nullptr;
    current_state = hasher.process_bytes(ptr16, 4);
    BOOST_TEST(current_state == boost::crypt::hasher_state::null);

    const char32_t* ptr32 = nullptr;
    current_state = hasher.process_bytes(ptr32, 4);
    BOOST_TEST(current_state == boost::crypt::hasher_state::null);

    const wchar_t* wptr = nullptr;
    current_state = hasher.process_bytes(wptr, 4);
    BOOST_TEST(current_state == boost::crypt::hasher_state::null);
}

// This ends up being completely calculated in a constexpr fashion so Codecov complains
// LCOV_EXCL_START
void test_span()
{
    #ifdef BOOST_CRYPT_HAS_SPAN

    // "abc" in hex
    const std::byte vals[] = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
    std::span<const std::byte> byte_span {vals};
    const auto expected_res = std::array<std::uint8_t, 64>{0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32};
    const auto res = boost::crypt::sha3_256(byte_span);

    for (std::size_t i {}; i < res.size(); ++i)
    {
        BOOST_TEST_EQ(res[i], expected_res[i]);
    }

    boost::crypt::sha3_256_hasher hasher;
    auto current_state = hasher.process_bytes(byte_span);
    BOOST_TEST(current_state == boost::crypt::hasher_state::success);
    const auto res_2 = hasher.get_digest();

    for (std::size_t i {}; i < res.size(); ++i)
    {
        BOOST_TEST_EQ(res_2[i], expected_res[i]);
    }

    #endif // BOOST_CRYPT_HAS_SPAN
}
// LCOV_EXCL_STOP

int main()
{
    basic_tests();
    string_test();
    string_view_test();
    bad_input();
    test_class();

    // The Windows file system returns a different result than on UNIX platforms
    #if defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
    files_test();
    #endif

    test_invalid_state();

    test_span();

    return boost::report_errors();
}
