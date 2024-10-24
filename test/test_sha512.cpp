// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/hash/sha512.hpp>
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

constexpr std::array<std::tuple<const char*, boost::crypt::sha512_hasher::return_type>, 3> test_values =
{
    std::make_tuple("",
                    boost::crypt::sha512_hasher::return_type {
                            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
                            0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
                            0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
                            0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
                            0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
                            0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
                            0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    boost::crypt::sha512_hasher::return_type {
                            0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73,
                            0xf7, 0x3f, 0xba, 0xc0, 0x43, 0x5e, 0xd7, 0x69,
                            0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88,
                            0xa3, 0x09, 0xd7, 0x85, 0x43, 0x6b, 0xbb, 0x64,
                            0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2, 0x39,
                            0x12, 0x54, 0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6,
                            0xe1, 0xbf, 0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f,
                            0xa0, 0x53, 0x8f, 0x3d, 0xb8, 0x54, 0xfe, 0xe6
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    boost::crypt::sha512_hasher::return_type {
                            0x91, 0xea, 0x12, 0x45, 0xf2, 0x0d, 0x46, 0xae,
                            0x9a, 0x03, 0x7a, 0x98, 0x9f, 0x54, 0xf1, 0xf7,
                            0x90, 0xf0, 0xa4, 0x76, 0x07, 0xee, 0xb8, 0xa1,
                            0x4d, 0x12, 0x89, 0x0c, 0xea, 0x77, 0xa1, 0xbb,
                            0xc6, 0xc7, 0xed, 0x9c, 0xf2, 0x05, 0xe6, 0x7b,
                            0x7f, 0x2b, 0x8f, 0xd4, 0xc7, 0xdf, 0xd3, 0xa7,
                            0xa8, 0x61, 0x7e, 0x45, 0xf3, 0xc4, 0x63, 0xd4,
                            0x81, 0xc7, 0xe5, 0x86, 0xc3, 0x9a, 0xc1, 0xed
                    }),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::sha512(std::get<0>(test_value))};
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
        const auto message_result {boost::crypt::sha512(string_message)};
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
        const auto message_result {boost::crypt::sha512(string_view_message)};
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
    const auto null_message {boost::crypt::sha512(static_cast<const char*>(nullptr))};
    BOOST_TEST_EQ(null_message[0], 0x0);
    BOOST_TEST_EQ(null_message[1], 0x0);
    BOOST_TEST_EQ(null_message[2], 0x0);
    BOOST_TEST_EQ(null_message[3], 0x0);

    const auto null_message_len {boost::crypt::sha512(static_cast<const char*>(nullptr), 100)};
    BOOST_TEST_EQ(null_message_len[0], 0x0);
    BOOST_TEST_EQ(null_message_len[1], 0x0);
    BOOST_TEST_EQ(null_message_len[2], 0x0);
    BOOST_TEST_EQ(null_message_len[3], 0x0);

    const auto unsigned_null_message {boost::crypt::sha512(static_cast<const std::uint8_t*>(nullptr))};
    BOOST_TEST_EQ(unsigned_null_message[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[3], 0x0);

    const auto unsigned_null_message_len {boost::crypt::sha512(static_cast<const std::uint8_t*>(nullptr), 100)};
    BOOST_TEST_EQ(unsigned_null_message_len[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[3], 0x0);

    std::string test_str {"Test string"};
    const auto reveresed_input {boost::crypt::detail::sha512(test_str.end(), test_str.begin())};
    BOOST_TEST_EQ(reveresed_input[0], 0x0);
    BOOST_TEST_EQ(reveresed_input[1], 0x0);
    BOOST_TEST_EQ(reveresed_input[2], 0x0);
    BOOST_TEST_EQ(reveresed_input[3], 0x0);
}

void test_class()
{
    boost::crypt::sha512_hasher hasher;

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
void test_file(T filename, const boost::crypt::sha512_hasher::return_type& res)
{
    const auto crypt_res {boost::crypt::sha512_file(filename)};

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
    constexpr boost::crypt::sha512_hasher::return_type res{};

    const auto crypt_res {boost::crypt::sha512_file(filename)};

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
    // sha512 test_file_1.txt
    // sha512 (test_file_1.txt) = 020da0f4d8a4c8bfbc98274027740061d7df52ee07091ed6595a083e0f45327bbe59424312d86f218b74ed2e25507abaf5c7a5fcf4cafcf9538b705808fd55ec
    constexpr boost::crypt::sha512_hasher::return_type res{0x02, 0x0d, 0xa0, 0xf4, 0xd8, 0xa4, 0xc8, 0xbf, 0xbc, 0x98, 0x27, 0x40, 0x27, 0x74, 0x00, 0x61, 0xd7, 0xdf, 0x52, 0xee, 0x07, 0x09, 0x1e, 0xd6, 0x59, 0x5a, 0x08, 0x3e, 0x0f, 0x45, 0x32, 0x7b, 0xbe, 0x59, 0x42, 0x43, 0x12, 0xd8, 0x6f, 0x21, 0x8b, 0x74, 0xed, 0x2e, 0x25, 0x50, 0x7a, 0xba, 0xf5, 0xc7, 0xa5, 0xfc, 0xf4, 0xca, 0xfc, 0xf9, 0x53, 0x8b, 0x70, 0x58, 0x08, 0xfd, 0x55, 0xec};

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
    // sha512 test_file_2.txt
    // sha512 (test_file_2.txt) = 83e18fae406f58d67f459ef301dc236639c44d4c10928e38363021ba037159e73b00a86820607a1595653129b52b284543714834816dd00a33f49cbf16ee5d77
    constexpr boost::crypt::sha512_hasher::return_type res_2{0x83, 0xe1, 0x8f, 0xae, 0x40, 0x6f, 0x58, 0xd6, 0x7f, 0x45, 0x9e, 0xf3, 0x01, 0xdc, 0x23, 0x66, 0x39, 0xc4, 0x4d, 0x4c, 0x10, 0x92, 0x8e, 0x38, 0x36, 0x30, 0x21, 0xba, 0x03, 0x71, 0x59, 0xe7, 0x3b, 0x00, 0xa8, 0x68, 0x20, 0x60, 0x7a, 0x15, 0x95, 0x65, 0x31, 0x29, 0xb5, 0x2b, 0x28, 0x45, 0x43, 0x71, 0x48, 0x34, 0x81, 0x6d, 0xd0, 0x0a, 0x33, 0xf4, 0x9c, 0xbf, 0x16, 0xee, 0x5d, 0x77};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    test_invalid_file(test_null_file);
}

void test_invalid_state()
{
    boost::crypt::sha512_hasher hasher;
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
    const auto expected_res = std::array<std::uint8_t, 64>{0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};
    const auto res = boost::crypt::sha512(byte_span);

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
