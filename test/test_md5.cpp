// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#define BOOST_CRYPT_ENABLE_MD5

#include <boost/crypt/hash/md5.hpp>
#include <boost/core/lightweight_test.hpp>
#include "generate_random_strings.hpp"

#ifdef __clang__
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wconversion"
#  pragma clang diagnostic ignored "-Wold-style-cast"
#elif defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wsign-conversion"
#  pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

#include <boost/uuid/detail/md5.hpp>

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
    unsigned char digest[16];
    boost::uuids::detail::md5 hasher;
    hasher.process_bytes(str, length);
    hasher.get_digest(digest);

    std::array<unsigned char, 16> return_array {};
    for (std::size_t i {}; i < 16U; ++i)
    {
        return_array[i] = digest[i];
    }

    return return_array;
}

constexpr std::array<std::tuple<const char*, std::array<uint16_t, 16>>, 15> test_values =
{
    // // Start with the sample hashes from wiki
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    std::array<std::uint16_t, 16>{0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6}),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    std::array<std::uint16_t, 16>{0xe4, 0xd9, 0x09, 0xc2, 0x90, 0xd0, 0xfb, 0x1c, 0xa0, 0x68, 0xff, 0xad, 0xdf, 0x22, 0xcb, 0xd0}),
    std::make_tuple("",
                    std::array<std::uint16_t, 16>{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e}),
    std::make_tuple("ddcc8542894a27456bbeb43f51f38764c32f72ae",
                    std::array<std::uint16_t, 16>{0x3b, 0x34, 0x0f, 0x00, 0x97, 0x31, 0x2e, 0xc8, 0x2f, 0xa4, 0xda, 0x0d, 0x7d, 0xa5, 0x30, 0x02}),
    std::make_tuple("webmin1980",
                    std::array<std::uint16_t, 16>{0xb7, 0x8a, 0xae, 0x35, 0x67, 0x09, 0xf8, 0xc3, 0x11, 0x18, 0xea, 0x61, 0x39, 0x80, 0x95, 0x4b}),
    std::make_tuple("$2y$10$EQAmcJw0cg.rt.6..SJ2bulFhDo0eWtuMhkfDMPGsNdap4xrOY61K",
                    std::array<std::uint16_t, 16>{0x40, 0xbb, 0xe6, 0x64, 0x4e, 0xfd, 0x93, 0x54, 0x07, 0x8d, 0x8c, 0x70, 0xfb, 0x6c, 0x9f, 0x42}),
    std::make_tuple("pkirsanov",
                    std::array<std::uint16_t, 16>{0x87, 0x93, 0xce, 0x04, 0xf0, 0xc5, 0xf1, 0xe8, 0xed, 0x1e, 0x0c, 0x78, 0xf2, 0x49, 0xfe, 0x1b}),
    std::make_tuple("Eleanor",
                    std::array<std::uint16_t, 16>{0xd3, 0x7e, 0x43, 0x17, 0x49, 0x05, 0xde, 0x70, 0xfb, 0xb5, 0xb0, 0x38, 0xd7, 0x24, 0x7f, 0x57}),
    std::make_tuple("The Whirlpool Galaxy is about 88% the size of the Milky Way, with a diameter of 76,900 light-years",
                    std::array<std::uint16_t, 16>{0xd5, 0xdf, 0xd7, 0xb4, 0x12, 0x35, 0xab, 0xc7, 0xa9, 0xa3, 0x20, 0x5b, 0x68, 0x96, 0xf3, 0x4d}),

    // From the RFC
    std::make_tuple("a",
                    std::array<std::uint16_t, 16>{0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61}),
    std::make_tuple("abc",
                    std::array<std::uint16_t, 16>{0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72}),
    std::make_tuple("message digest",
                    std::array<std::uint16_t, 16>{0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0}),
    std::make_tuple("abcdefghijklmnopqrstuvwxyz",
                    std::array<std::uint16_t, 16>{0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b}),
    std::make_tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    std::array<std::uint16_t, 16>{0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f}),
    std::make_tuple("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                    std::array<std::uint16_t, 16>{0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a}),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::md5(std::get<0>(test_value))};
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
        const auto message_result {boost::crypt::md5(string_message)};
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
        const auto message_result {boost::crypt::md5(string_view_message)};
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
    const auto null_message {boost::crypt::md5(static_cast<const char*>(nullptr))};
    BOOST_TEST_EQ(null_message[0], 0x0);
    BOOST_TEST_EQ(null_message[1], 0x0);
    BOOST_TEST_EQ(null_message[2], 0x0);
    BOOST_TEST_EQ(null_message[3], 0x0);

    const auto null_message_len {boost::crypt::md5(static_cast<const char*>(nullptr), 100)};
    BOOST_TEST_EQ(null_message_len[0], 0x0);
    BOOST_TEST_EQ(null_message_len[1], 0x0);
    BOOST_TEST_EQ(null_message_len[2], 0x0);
    BOOST_TEST_EQ(null_message_len[3], 0x0);

    const auto unsigned_null_message {boost::crypt::md5(static_cast<const std::uint8_t*>(nullptr))};
    BOOST_TEST_EQ(unsigned_null_message[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[3], 0x0);

    const auto unsigned_null_message_len {boost::crypt::md5(static_cast<const std::uint8_t*>(nullptr), 100)};
    BOOST_TEST_EQ(unsigned_null_message_len[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[3], 0x0);
    
    std::string test_str {"Test string"};
    const auto reveresed_input {boost::crypt::detail::md5(test_str.end(), test_str.begin())};
    BOOST_TEST_EQ(reveresed_input[0], 0x0);
    BOOST_TEST_EQ(reveresed_input[1], 0x0);
    BOOST_TEST_EQ(reveresed_input[2], 0x0);
    BOOST_TEST_EQ(reveresed_input[3], 0x0);
}

void test_class()
{
    boost::crypt::md5_hasher hasher;

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
        const std::array<std::uint8_t, 16> crypt_res = boost::crypt::md5(str, current_str_len);

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
        boost::uuids::detail::md5 boost_hasher;
        boost::crypt::md5_hasher md5_hasher;

        std::memset(str, '\0', max_str_len);
        std::memset(str_2, '\0', max_str_len);

        const std::size_t current_str_len {str_len(rng)};
        boost::crypt::generate_random_string(str, current_str_len);
        boost::crypt::generate_random_string(str_2, current_str_len);

        boost_hasher.process_bytes(str, current_str_len);
        boost_hasher.process_bytes(str_2, current_str_len);
        boost_hasher.process_byte(52); // "4"
        unsigned char digest[16];
        boost_hasher.get_digest(digest);

        std::array<unsigned char, 16> uuid_res {};
        for (std::size_t j {}; j < 16U; ++j)
        {
            uuid_res[j] = digest[j];
        }

        md5_hasher.process_bytes(str, current_str_len);
        md5_hasher.process_bytes(str_2, current_str_len);
        md5_hasher.process_byte(52); // "4"
        const auto crypt_res {md5_hasher.get_digest()};

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

template <typename T>
void test_file(T filename, const std::array<std::uint16_t, 16>& res)
{
    const auto crypt_res {boost::crypt::md5_file(filename)};

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
    constexpr std::array<std::uint16_t, 16> res{};

    const auto crypt_res {boost::crypt::md5_file(filename)};

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
    // md5 test_file_1.txt
    // MD5 (test_file_1.txt) = 0d7006cd055e94cf614587e1d2ae0c8e
    constexpr std::array<std::uint16_t, 16> res{0x0d, 0x70, 0x06, 0xcd, 0x05, 0x5e, 0x94, 0xcf,
                                                0x61, 0x45, 0x87, 0xe1, 0xd2, 0xae, 0x0c, 0x8e};

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
    // md5 test_file_2.txt
    // MD5 (test_file_2.txt) = 530e67fa4b01e3ccaee8eca9916a814c
    constexpr std::array<std::uint16_t, 16> res_2{0x53, 0x0e, 0x67, 0xfa, 0x4b, 0x01, 0xe3, 0xcc,
                                                  0xae, 0xe8, 0xec, 0xa9, 0x91, 0x6a, 0x81, 0x4c};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    test_invalid_file(test_null_file);
}

void test_invalid_state()
{
    boost::crypt::md5_hasher hasher;
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
    const auto expected_res = std::array<std::uint16_t, 16>{0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72};
    const auto res = boost::crypt::md5(byte_span);

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

    // The Windows file system returns a different result than on UNIX platforms
    #if defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
    files_test();
    #endif

    test_invalid_state();

    test_span();

    return boost::report_errors();
}
