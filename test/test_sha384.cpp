// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/hash/sha384.hpp>
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

constexpr std::array<std::tuple<const char*, boost::crypt::sha384_hasher::return_type>, 3> test_values =
{
    std::make_tuple("",
                    boost::crypt::sha384_hasher::return_type {
                        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
                        0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
                        0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
                        0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
                        0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
                        0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    boost::crypt::sha384_hasher::return_type {
                        0xca, 0x73, 0x7f, 0x10, 0x14, 0xa4, 0x8f, 0x4c,
                        0x0b, 0x6d, 0xd4, 0x3c, 0xb1, 0x77, 0xb0, 0xaf,
                        0xd9, 0xe5, 0x16, 0x93, 0x67, 0x54, 0x4c, 0x49,
                        0x40, 0x11, 0xe3, 0x31, 0x7d, 0xbf, 0x9a, 0x50,
                        0x9c, 0xb1, 0xe5, 0xdc, 0x1e, 0x85, 0xa9, 0x41,
                        0xbb, 0xee, 0x3d, 0x7f, 0x2a, 0xfb, 0xc9, 0xb1
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    boost::crypt::sha384_hasher::return_type {
                        0xed, 0x89, 0x24, 0x81, 0xd8, 0x27, 0x2c, 0xa6,
                        0xdf, 0x37, 0x0b, 0xf7, 0x06, 0xe4, 0xd7, 0xbc,
                        0x1b, 0x57, 0x39, 0xfa, 0x21, 0x77, 0xaa, 0xe6,
                        0xc5, 0x0e, 0x94, 0x66, 0x78, 0x71, 0x8f, 0xc6,
                        0x7a, 0x7a, 0xf2, 0x81, 0x9a, 0x02, 0x1c, 0x2f,
                        0xc3, 0x4e, 0x91, 0xbd, 0xb6, 0x34, 0x09, 0xd7
                    }),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::sha384(std::get<0>(test_value))};
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
        const auto message_result {boost::crypt::sha384(string_message)};
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
        const auto message_result {boost::crypt::sha384(string_view_message)};
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
    const auto null_message {boost::crypt::sha384(static_cast<const char*>(nullptr))};
    BOOST_TEST_EQ(null_message[0], 0x0);
    BOOST_TEST_EQ(null_message[1], 0x0);
    BOOST_TEST_EQ(null_message[2], 0x0);
    BOOST_TEST_EQ(null_message[3], 0x0);

    const auto null_message_len {boost::crypt::sha384(static_cast<const char*>(nullptr), 100)};
    BOOST_TEST_EQ(null_message_len[0], 0x0);
    BOOST_TEST_EQ(null_message_len[1], 0x0);
    BOOST_TEST_EQ(null_message_len[2], 0x0);
    BOOST_TEST_EQ(null_message_len[3], 0x0);

    const auto unsigned_null_message {boost::crypt::sha384(static_cast<const std::uint8_t*>(nullptr))};
    BOOST_TEST_EQ(unsigned_null_message[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[3], 0x0);

    const auto unsigned_null_message_len {boost::crypt::sha384(static_cast<const std::uint8_t*>(nullptr), 100)};
    BOOST_TEST_EQ(unsigned_null_message_len[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[3], 0x0);

    std::string test_str {"Test string"};
    const auto reveresed_input {boost::crypt::detail::sha384(test_str.end(), test_str.begin())};
    BOOST_TEST_EQ(reveresed_input[0], 0x0);
    BOOST_TEST_EQ(reveresed_input[1], 0x0);
    BOOST_TEST_EQ(reveresed_input[2], 0x0);
    BOOST_TEST_EQ(reveresed_input[3], 0x0);
}

void test_class()
{
    boost::crypt::sha384_hasher hasher;

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
void test_file(T filename, const boost::crypt::sha384_hasher::return_type& res)
{
    const auto crypt_res {boost::crypt::sha384_file(filename)};

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
    constexpr boost::crypt::sha384_hasher::return_type res{};

    const auto crypt_res {boost::crypt::sha384_file(filename)};

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
    // sha384 test_file_1.txt
    // sha384 (test_file_1.txt) = d51d28d0141e56f692952ea14861898e2b417b922831e0f4bcdbc326a7fe1e9d9563182e83d3a8af66f68536e0d42b88
    constexpr boost::crypt::sha384_hasher::return_type res{0xd5, 0x1d, 0x28, 0xd0, 0x14, 0x1e, 0x56, 0xf6, 0x92, 0x95, 0x2e, 0xa1, 0x48, 0x61, 0x89, 0x8e, 0x2b, 0x41, 0x7b, 0x92, 0x28, 0x31, 0xe0, 0xf4, 0xbc, 0xdb, 0xc3, 0x26, 0xa7, 0xfe, 0x1e, 0x9d, 0x95, 0x63, 0x18, 0x2e, 0x83, 0xd3, 0xa8, 0xaf, 0x66, 0xf6, 0x85, 0x36, 0xe0, 0xd4, 0x2b, 0x88};

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
    // sha384 test_file_2.txt
    // sha384 (test_file_2.txt) = 6c7706ecceaac08c152fe321291c86d7572ca37604f7da727eefd33ad3d0d29afcb1c74103efe1e892337c2034e3f127
    constexpr boost::crypt::sha384_hasher::return_type res_2{0x6c, 0x77, 0x06, 0xec, 0xce, 0xaa, 0xc0, 0x8c, 0x15, 0x2f, 0xe3, 0x21, 0x29, 0x1c, 0x86, 0xd7, 0x57, 0x2c, 0xa3, 0x76, 0x04, 0xf7, 0xda, 0x72, 0x7e, 0xef, 0xd3, 0x3a, 0xd3, 0xd0, 0xd2, 0x9a, 0xfc, 0xb1, 0xc7, 0x41, 0x03, 0xef, 0xe1, 0xe8, 0x92, 0x33, 0x7c, 0x20, 0x34, 0xe3, 0xf1, 0x27};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    test_invalid_file(test_null_file);
}

void test_invalid_state()
{
    boost::crypt::sha384_hasher hasher;
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
    const auto expected_res = std::array<std::uint8_t, 64>{0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};
    const auto res = boost::crypt::sha384(byte_span);

    for (std::size_t i {}; i < res.size(); ++i)
    {
        BOOST_TEST_EQ(res[i], expected_res[i]);
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
