// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/hash/shake256.hpp>
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

constexpr std::array<std::tuple<const char*, boost::crypt::shake256_hasher::return_type>, 3> test_values =
{
    std::make_tuple("",
                    boost::crypt::shake256_hasher::return_type {
                        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
                        0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
                        0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
                        0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    boost::crypt::shake256_hasher::return_type {
                        0x2f, 0x67, 0x13, 0x43, 0xd9, 0xb2, 0xe1, 0x60,
                        0x4d, 0xc9, 0xdc, 0xf0, 0x75, 0x3e, 0x5f, 0xe1,
                        0x5c, 0x7c, 0x64, 0xa0, 0xd2, 0x83, 0xcb, 0xbf,
                        0x72, 0x2d, 0x41, 0x1a, 0x0e, 0x36, 0xf6, 0xca
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    boost::crypt::shake256_hasher::return_type {
                        0xbd, 0x22, 0x5b, 0xfc, 0x8b, 0x25, 0x5f, 0x30,
                        0x36, 0xf0, 0xc8, 0x86, 0x60, 0x10, 0xed, 0x00,
                        0x53, 0xb5, 0x16, 0x3a, 0x3c, 0xae, 0x11, 0x1e,
                        0x72, 0x3c, 0x0c, 0x8e, 0x70, 0x4e, 0xca, 0x4e
                    }),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::shake256(std::get<0>(test_value))};
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
        const auto message_result {boost::crypt::shake256(string_message)};
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
        const auto message_result {boost::crypt::shake256(string_view_message)};
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

        boost::crypt::shake256_hasher hasher;
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
    const auto null_message {boost::crypt::shake256(static_cast<const char*>(nullptr))};
    BOOST_TEST_EQ(null_message[0], 0x0);
    BOOST_TEST_EQ(null_message[1], 0x0);
    BOOST_TEST_EQ(null_message[2], 0x0);
    BOOST_TEST_EQ(null_message[3], 0x0);

    const auto null_message_len {boost::crypt::shake256(static_cast<const char*>(nullptr), 100)};
    BOOST_TEST_EQ(null_message_len[0], 0x0);
    BOOST_TEST_EQ(null_message_len[1], 0x0);
    BOOST_TEST_EQ(null_message_len[2], 0x0);
    BOOST_TEST_EQ(null_message_len[3], 0x0);

    const auto unsigned_null_message {boost::crypt::shake256(static_cast<const std::uint8_t*>(nullptr))};
    BOOST_TEST_EQ(unsigned_null_message[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[3], 0x0);

    const auto unsigned_null_message_len {boost::crypt::shake256(static_cast<const std::uint8_t*>(nullptr), 100)};
    BOOST_TEST_EQ(unsigned_null_message_len[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[3], 0x0);

    std::string test_str {"Test string"};
    const auto reveresed_input {boost::crypt::detail::shake256(test_str.end(), test_str.begin())};
    BOOST_TEST_EQ(reveresed_input[0], 0x0);
    BOOST_TEST_EQ(reveresed_input[1], 0x0);
    BOOST_TEST_EQ(reveresed_input[2], 0x0);
    BOOST_TEST_EQ(reveresed_input[3], 0x0);
}

void test_class()
{
    boost::crypt::shake256_hasher hasher;

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

void test_user_container()
{
    boost::crypt::shake256_hasher hasher;

    for (const auto& test_value : test_values)
    {
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg, std::strlen(msg));
        std::array<std::uint8_t, 16U> message_result {};
        const auto status {hasher.get_digest(message_result)};
        BOOST_TEST_EQ(status, 16U);
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

        std::vector<std::uint8_t> bad;
        const auto bad_container = hasher.get_digest(bad);
        BOOST_TEST_EQ(bad_container, 0U);

        hasher.init();
    }
}

void test_continuous_output()
{
    boost::crypt::shake256_hasher hasher;

    for (const auto& test_value : test_values)
    {
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg, std::strlen(msg));
        std::array<std::uint8_t, 64U> message_result {};
        std::array<std::uint8_t, 64U> message_result_previous {};
        hasher.get_digest(message_result_previous);
        for (std::size_t i {}; i < 100; ++i)
        {
            const auto status {hasher.get_digest(message_result)};
            BOOST_TEST_EQ(status, message_result.size());
            int same_counter = 0;
            for (std::size_t j {}; j < message_result.size(); ++j)
            {
                if (message_result[j] == message_result_previous[j])
                {
                    ++same_counter;
                }
            }
            BOOST_TEST_LE(same_counter, 64);
            message_result_previous = message_result;
        }

        hasher.init();
    }
}

void test_user_pointer()
{
    boost::crypt::shake256_hasher hasher;

    for (const auto& test_value : test_values)
    {
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg, std::strlen(msg));
        std::array<std::uint8_t, 64U> message_result {};
        const auto status {hasher.get_digest(message_result.begin(), 16U)};
        BOOST_TEST_EQ(status, 16U);
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < status; ++i)
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
void test_file(T filename, const boost::crypt::shake256_hasher::return_type& res)
{
    const auto crypt_res {boost::crypt::shake256_file(filename)};

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
    constexpr boost::crypt::shake256_hasher::return_type res{};

    const auto crypt_res {boost::crypt::shake256_file(filename)};

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
    // openssl dgst -shake256 test_file_1.txt
    // shake256 (test_file_1.txt) = 4645896122b04fd3cabcee7bbf5c7944293c9347293ba1254310466dd3265e75
    constexpr boost::crypt::shake256_hasher::return_type res{0x46, 0x45, 0x89, 0x61, 0x22, 0xb0, 0x4f, 0xd3, 0xca, 0xbc, 0xee, 0x7b, 0xbf, 0x5c, 0x79, 0x44, 0x29, 0x3c, 0x93, 0x47, 0x29, 0x3b, 0xa1, 0x25, 0x43, 0x10, 0x46, 0x6d, 0xd3, 0x26, 0x5e, 0x75};

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
    // openssl dgst -shake256 test_file_2.txt
    // shake256 (test_file_2.txt) = 23a1aa31e361495b74dbcb1cffc52a3ac8a2af549ad2cd61b3d5cabf7ed7424a
    constexpr boost::crypt::shake256_hasher::return_type res_2{0x23, 0xa1, 0xaa, 0x31, 0xe3, 0x61, 0x49, 0x5b, 0x74, 0xdb, 0xcb, 0x1c, 0xff, 0xc5, 0x2a, 0x3a, 0xc8, 0xa2, 0xaf, 0x54, 0x9a, 0xd2, 0xcd, 0x61, 0xb3, 0xd5, 0xca, 0xbf, 0x7e, 0xd7, 0x42, 0x4a};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    test_invalid_file(test_null_file);
}

void test_invalid_state()
{
    boost::crypt::shake256_hasher hasher;
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
    const auto expected_res = std::array<std::uint8_t, 64>{0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77, 0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d, 0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee, 0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39};
    const auto res = boost::crypt::shake256(byte_span);

    for (std::size_t i {}; i < res.size(); ++i)
    {
        BOOST_TEST_EQ(res[i], expected_res[i]);
    }

    boost::crypt::shake256_hasher hasher;
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
    test_user_container();
    test_user_pointer();
    test_continuous_output();

    // The Windows file system returns a different result than on UNIX platforms
    #if defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
    files_test();
    #endif

    test_invalid_state();

    test_span();

    return boost::report_errors();
}
