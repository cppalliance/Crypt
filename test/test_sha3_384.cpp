// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha3_384.hpp>

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

const std::array<std::tuple<std::string, std::array<uint16_t, 48U>>, 3> test_values =
{
    std::make_tuple("",
                    std::array<uint16_t, 48U> {
                        0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d,
                        0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24, 0x85,
                        0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61,
                        0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98, 0x3a, 0x2a,
                        0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47,
                        0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    std::array<uint16_t, 48U> {
                        0x70, 0x63, 0x46, 0x5e, 0x08, 0xa9, 0x3b, 0xce,
                        0x31, 0xcd, 0x89, 0xd2, 0xe3, 0xca, 0x8f, 0x60,
                        0x24, 0x98, 0x69, 0x6e, 0x25, 0x35, 0x92, 0xed,
                        0x26, 0xf0, 0x7b, 0xf7, 0xe7, 0x03, 0xcf, 0x32,
                        0x85, 0x81, 0xe1, 0x47, 0x1a, 0x7b, 0xa7, 0xab,
                        0x11, 0x9b, 0x1a, 0x9e, 0xbd, 0xf8, 0xbe, 0x41
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    std::array<uint16_t, 48U> {
                        0x1a, 0x34, 0xd8, 0x16, 0x95, 0xb6, 0x22, 0xdf,
                        0x17, 0x8b, 0xc7, 0x4d, 0xf7, 0x12, 0x4f, 0xe1,
                        0x2f, 0xac, 0x0f, 0x64, 0xba, 0x52, 0x50, 0xb7,
                        0x8b, 0x99, 0xc1, 0x27, 0x3d, 0x4b, 0x08, 0x01,
                        0x68, 0xe1, 0x06, 0x52, 0x89, 0x4e, 0xca, 0xd5,
                        0xf1, 0xf4, 0xd5, 0xb9, 0x65, 0x43, 0x7f, 0xb9
                    }),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::sha3_384(std::get<0>(test_value)).value()};
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
        const auto message_result {boost::crypt::sha3_384(string_message).value()};
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
        const auto message_result {boost::crypt::sha3_384(string_view_message).value()};
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

        boost::crypt::sha3_384_hasher hasher;
        const auto current_state = hasher.process_bytes(string_view_message);
        hasher.finalize();
        BOOST_TEST(current_state == boost::crypt::state::success);
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
    boost::crypt::sha3_384_hasher hasher;

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

    for (const auto& test_value : test_values)
    {
        std::array<std::byte, 48U> message_result {};
        std::span<std::byte, 48U> message_result_span {message_result};
        hasher.init();
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg);
        hasher.finalize();
        const auto return_state {hasher.get_digest(message_result_span)};
        BOOST_TEST(return_state == boost::crypt::state::success);

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
void test_file(T filename, const std::array<uint16_t, 48U>& res)
{
    const auto crypt_res {boost::crypt::sha3_384_file(filename).value()};

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
    // openssl dgst -sha3-512 test_file_1.txt
    // sha3_384 (test_file_1.txt) = 1151116cc1d7dd0cb116c2f20f71a183abb83dd86949fa34521bab3e5472c364c58cb22248a8483d7c84ca94c0aeaf57
    constexpr std::array<uint16_t, 48U> res{0x11, 0x51, 0x11, 0x6c, 0xc1, 0xd7, 0xdd, 0x0c, 0xb1, 0x16, 0xc2, 0xf2, 0x0f, 0x71, 0xa1, 0x83, 0xab, 0xb8, 0x3d, 0xd8, 0x69, 0x49, 0xfa, 0x34, 0x52, 0x1b, 0xab, 0x3e, 0x54, 0x72, 0xc3, 0x64, 0xc5, 0x8c, 0xb2, 0x22, 0x48, 0xa8, 0x48, 0x3d, 0x7c, 0x84, 0xca, 0x94, 0xc0, 0xae, 0xaf, 0x57};

    test_file(filename.c_str(), res);

    const std::string str_filename {filename};
    test_file(str_filename, res);

    const std::string_view str_view_filename {str_filename};
    test_file(str_view_filename, res);

    const auto invalid_filename = "broken.bin";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash1 = boost::crypt::sha3_384_file(invalid_filename), std::runtime_error);

    const std::string str_invalid_filename {invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash2 = boost::crypt::sha3_384_file(str_invalid_filename), std::runtime_error);

    const std::string_view str_view_invalid_filename {str_invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash3 = boost::crypt::sha3_384_file(str_view_invalid_filename), std::runtime_error);


    // On macOS 15
    // openssl dgst -sha3-512 test_file_2.txt
    // sha3_384 (test_file_2.txt) = bc3c74a5209ca5b12bfce99c19e33256246184b16b2506a511b48e7ab3cdf2589f1920b394d104fe2ce8139cc55c7af1
    constexpr std::array<uint16_t, 48U> res_2{0xbc, 0x3c, 0x74, 0xa5, 0x20, 0x9c, 0xa5, 0xb1, 0x2b, 0xfc, 0xe9, 0x9c, 0x19, 0xe3, 0x32, 0x56, 0x24, 0x61, 0x84, 0xb1, 0x6b, 0x25, 0x06, 0xa5, 0x11, 0xb4, 0x8e, 0x7a, 0xb3, 0xcd, 0xf2, 0x58, 0x9f, 0x19, 0x20, 0xb3, 0x94, 0xd1, 0x04, 0xfe, 0x2c, 0xe8, 0x13, 0x9c, 0xc5, 0x5c, 0x7a, 0xf1};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash4 = boost::crypt::sha3_384_file(test_null_file), std::runtime_error);

    std::filesystem::path bad_path = "path.txt";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash5 = boost::crypt::sha3_384_file(bad_path), std::runtime_error);
}

consteval bool immediate_test()
{

    // "abc" in hex
    const std::byte vals[] = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
    std::span<const std::byte> byte_span {vals};
    const auto expected_res = std::array<std::uint8_t, 64>{0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9, 0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d, 0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25, 0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2, 0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5, 0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25};

    boost::crypt::sha3_384_hasher hasher;
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
