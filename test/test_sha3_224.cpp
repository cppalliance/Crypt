// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha3_224.hpp>

#if defined(__clang__) && __clang_major__ >= 19
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#endif

#include <boost/core/lightweight_test.hpp>

#if defined(__clang__) && __clang_major__ >= 19
#pragma clang diagnostic pop
#endif

#include "where_file.hpp"

#include <random>
#include <iostream>
#include <string>
#include <array>
#include <tuple>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <cstring>

const std::array<std::tuple<std::string, std::array<uint16_t, 28U>>, 3> test_values =
{
    std::make_tuple("",
                    std::array<uint16_t, 28U> {
                        0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb,
                        0xb7, 0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e,
                        0xb1, 0xab, 0xd4, 0x59, 0x7f, 0x9a, 0x1b,
                        0x07, 0x8e, 0x3f, 0x5b, 0x5a, 0x6b, 0xc7
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    std::array<uint16_t, 28U> {
                        0xd1, 0x5d, 0xad, 0xce, 0xaa, 0x4d, 0x5d,
                        0x7b, 0xb3, 0xb4, 0x8f, 0x44, 0x64, 0x21,
                        0xd5, 0x42, 0xe0, 0x8a, 0xd8, 0x88, 0x73,
                        0x05, 0xe2, 0x8d, 0x58, 0x33, 0x57, 0x95
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    std::array<uint16_t, 28U> {
                        0x2d, 0x07, 0x08, 0x90, 0x38, 0x33, 0xaf,
                        0xab, 0xdd, 0x23, 0x2a, 0x20, 0x20, 0x11,
                        0x76, 0xe8, 0xb5, 0x8c, 0x5b, 0xe8, 0xa6,
                        0xfe, 0x74, 0x26, 0x5a, 0xc5, 0x4d, 0xb0
                    }),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::sha3_224(std::get<0>(test_value)).value()};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST(message_result[i] == static_cast<std::byte>(valid_result[i])))
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
        const auto message_result {boost::crypt::sha3_224(string_message).value()};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST(message_result[i] == static_cast<std::byte>(valid_result[i])))
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
    for (const auto& test_value : test_values)
    {
        const std::string string_message {std::get<0>(test_value)};
        const std::string_view string_view_message {string_message};
        const auto message_result {boost::crypt::sha3_224(string_view_message).value()};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST(message_result[i] == static_cast<std::byte>(valid_result[i])))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }

        boost::crypt::sha3_224_hasher hasher;
        const auto current_state = hasher.process_bytes(string_view_message);
        BOOST_TEST(current_state == boost::crypt::state::success);
        BOOST_TEST(hasher.finalize() == boost::crypt::state::success);
        const auto result2 = hasher.get_digest().value();
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST(result2[i] == static_cast<std::byte>(valid_result[i])))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }
    }
}

void test_class()
{
    boost::crypt::sha3_224_hasher hasher;

    for (const auto& test_value : test_values)
    {
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg);
        hasher.finalize();
        const auto message_result {hasher.get_digest().value()};

        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST(message_result[i] == static_cast<std::byte>(valid_result[i])))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }

        hasher.init();
    }

    for (const auto& test_value : test_values)
    {
        std::array<std::byte, 48U> message_result {};
        hasher.init();
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg);
        hasher.finalize();
        const auto return_state {hasher.get_digest(message_result)};
        BOOST_TEST(return_state == boost::crypt::state::success);

        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < valid_result.size(); ++i)
        {
            if (!BOOST_TEST(message_result[i] == static_cast<std::byte>(valid_result[i])))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }
    }

    const std::string bad_update_msg {"bad"};
    BOOST_TEST(hasher.process_bytes(bad_update_msg) == boost::crypt::state::state_error);
    BOOST_TEST(hasher.finalize() == boost::crypt::state::state_error);
    BOOST_TEST(hasher.get_digest().error() == boost::crypt::state::state_error);

    // Bad return value size
    std::array<std::byte, 5U> bad_container {};
    hasher.init();
    hasher.process_bytes(bad_update_msg);
    const auto array_return1 {hasher.get_digest(bad_container)};
    BOOST_TEST(array_return1 == boost::crypt::state::state_error);
    hasher.finalize();
    const auto array_return2 {hasher.get_digest(bad_container)};
    BOOST_TEST(array_return2 == boost::crypt::state::insufficient_output_length);

    std::span<std::byte, 5U> bad_container_span {bad_container};
    hasher.init();
    hasher.process_bytes(bad_update_msg);
    const auto array_return3 {hasher.get_digest(bad_container_span)};
    BOOST_TEST(array_return3 == boost::crypt::state::state_error);
    hasher.finalize();
    const auto array_return4 {hasher.get_digest(bad_container_span)};
    BOOST_TEST(array_return4 == boost::crypt::state::insufficient_output_length);
}

template <typename T>
void test_file(T filename, const std::array<uint16_t, 28U>& res)
{
    const auto crypt_res {boost::crypt::sha3_224_file(filename).value()};

    for (std::size_t j {}; j < crypt_res.size(); ++j)
    {
        if (!BOOST_TEST(static_cast<std::byte>(res[j]) == crypt_res[j]))
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
    std::ifstream fd(boost::crypt::where_file("test_file_1.txt"), std::ios::binary | std::ios::in);
    std::string filename = boost::crypt::where_file("test_file_1.txt").c_str();
    std::string filename_2 = boost::crypt::where_file("test_file_2.txt").c_str();

    // On macOS 15
    // openssl dgst -sha3-256 test_file_1.txt
    // sha3_224 (test_file_1.txt) = f0a905f288506d9fbb3621165d30852412013ecbb076cb00b30f407e
    constexpr std::array<uint16_t, 28U> res{0xf0, 0xa9, 0x05, 0xf2, 0x88, 0x50, 0x6d, 0x9f, 0xbb, 0x36, 0x21, 0x16, 0x5d, 0x30, 0x85, 0x24, 0x12, 0x01, 0x3e, 0xcb, 0xb0, 0x76, 0xcb, 0x00, 0xb3, 0x0f, 0x40, 0x7e};

    test_file(filename.c_str(), res);

    const std::string str_filename {filename};
    test_file(str_filename, res);

    const std::string_view str_view_filename {str_filename};
    test_file(str_view_filename, res);

    const auto invalid_filename = "broken.bin";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash1 = boost::crypt::sha3_224_file(invalid_filename), std::runtime_error);

    const std::string str_invalid_filename {invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash2 = boost::crypt::sha3_224_file(str_invalid_filename), std::runtime_error);

    const std::string_view str_view_invalid_filename {str_invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash3 = boost::crypt::sha3_224_file(str_view_invalid_filename), std::runtime_error);

    // On macOS 15
    // openssl dgst -sha3-256 test_file_2.txt
    // sha3_224 (test_file_2.txt) = 41e68d5444d452f2ce93d570fac8e9cf86ee92424d9cdfadf1505c23
    constexpr std::array<uint16_t, 28U> res_2{0x41, 0xe6, 0x8d, 0x54, 0x44, 0xd4, 0x52, 0xf2, 0xce, 0x93, 0xd5, 0x70, 0xfa, 0xc8, 0xe9, 0xcf, 0x86, 0xee, 0x92, 0x42, 0x4d, 0x9c, 0xdf, 0xad, 0xf1, 0x50, 0x5c, 0x23};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash4 = boost::crypt::sha3_224_file(test_null_file), std::runtime_error);

    std::filesystem::path bad_path = "path.txt";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash5 = boost::crypt::sha3_224_file(bad_path), std::runtime_error);
}

consteval bool immediate_test()
{
    // "abc" in hex
    const std::byte vals[] = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
    std::span<const std::byte> byte_span {vals};
    const auto expected_res = std::array<std::uint8_t, 64>{0xe6, 0x42, 0x82, 0x4c, 0x3f, 0x8c, 0xf2, 0x4a, 0xd0, 0x92, 0x34, 0xee, 0x7d, 0x3c, 0x76, 0x6f, 0xc9, 0xa3, 0xa5, 0x16, 0x8d, 0x0c, 0x94, 0xad, 0x73, 0xb4, 0x6f, 0xdf};

    boost::crypt::sha3_224_hasher hasher;
    hasher.init();
    hasher.process_bytes(byte_span);
    hasher.finalize();
    const auto res = hasher.get_digest().value();

    bool correct {true};
    for (std::size_t i {}; i < res.size(); ++i)
    {
        if (res[i] != static_cast<std::byte>(expected_res[i]))
        {
            correct = false;
            break;
        }
    }

    return correct;
}

int main()
{
    basic_tests();
    string_test();
    string_view_test();
    test_class();

    // The Windows file system returns a different result than on UNIX platforms
    #if defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
    files_test();
    #endif

    // GCC-14 has an internal compiler error here
    #if defined(__GNUC__) && __GNUC__ != 14
    static_assert(immediate_test());
    #endif

    return boost::report_errors();
}
