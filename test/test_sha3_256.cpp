// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha3_256.hpp>

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

const std::array<std::tuple<std::string, std::array<uint16_t, 32U>>, 3> test_values =
{
    std::make_tuple("",
                    std::array<uint16_t, 32U> {
                        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
                        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
                        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
                        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    std::array<uint16_t, 32U> {
                        0x69, 0x07, 0x0d, 0xda, 0x01, 0x97, 0x5c, 0x8c,
                        0x12, 0x0c, 0x3a, 0xad, 0xa1, 0xb2, 0x82, 0x39,
                        0x4e, 0x7f, 0x03, 0x2f, 0xa9, 0xcf, 0x32, 0xf4,
                        0xcb, 0x22, 0x59, 0xa0, 0x89, 0x7d, 0xfc, 0x04
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    std::array<uint16_t, 32U> {
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
        const auto message_result {boost::crypt::sha3_256(std::get<0>(test_value)).value()};
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
        const auto message_result {boost::crypt::sha3_256(string_message).value()};
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
        const auto message_result {boost::crypt::sha3_256(string_view_message).value()};
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

        boost::crypt::sha3_256_hasher hasher;
        const auto current_state = hasher.process_bytes(string_view_message);
        BOOST_TEST(hasher.finalize() == boost::crypt::state::success);
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
    boost::crypt::sha3_256_hasher hasher;

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
void test_file(T filename, const std::array<uint16_t, 32U>& res)
{
    const auto crypt_res {boost::crypt::sha3_256_file(filename).value()};

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
    // sha3_256 (test_file_1.txt) = a6b14417b96c60706bc7bd3bbbeefc303e18285ad54d8ee0d10c31103ef94fee
    constexpr std::array<uint16_t, 32U> res{0xa6, 0xb1, 0x44, 0x17, 0xb9, 0x6c, 0x60, 0x70, 0x6b, 0xc7, 0xbd, 0x3b, 0xbb, 0xee, 0xfc, 0x30, 0x3e, 0x18, 0x28, 0x5a, 0xd5, 0x4d, 0x8e, 0xe0, 0xd1, 0x0c, 0x31, 0x10, 0x3e, 0xf9, 0x4f, 0xee};

    test_file(filename.c_str(), res);

    const std::string str_filename {filename};
    test_file(str_filename, res);

    const std::string_view str_view_filename {str_filename};
    test_file(str_view_filename, res);

    const auto invalid_filename = "broken.bin";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash1 = boost::crypt::sha3_256_file(invalid_filename), std::runtime_error);

    const std::string str_invalid_filename {invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash2 = boost::crypt::sha3_256_file(str_invalid_filename), std::runtime_error);

    const std::string_view str_view_invalid_filename {str_invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash3 = boost::crypt::sha3_256_file(str_view_invalid_filename), std::runtime_error);

    // On macOS 15
    // openssl dgst -sha3-256 test_file_2.txt
    // sha3_256 (test_file_2.txt) = 8b0bd446d395a3711f849023baeba17acbfa8c9d2a532baa01c745bf9e129ac2
    constexpr std::array<uint16_t, 32U> res_2{0x8b, 0x0b, 0xd4, 0x46, 0xd3, 0x95, 0xa3, 0x71, 0x1f, 0x84, 0x90, 0x23, 0xba, 0xeb, 0xa1, 0x7a, 0xcb, 0xfa, 0x8c, 0x9d, 0x2a, 0x53, 0x2b, 0xaa, 0x01, 0xc7, 0x45, 0xbf, 0x9e, 0x12, 0x9a, 0xc2};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash4 = boost::crypt::sha3_256_file(test_null_file), std::runtime_error);

    std::filesystem::path bad_path = "path.txt";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash5 = boost::crypt::sha3_256_file(bad_path), std::runtime_error);
}

consteval bool immediate_test()
{
    // "abc" in hex
    const std::byte vals[] = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
    std::span<const std::byte> byte_span {vals};
    const auto expected_res = std::array<std::uint8_t, 64>{0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32};

    boost::crypt::sha3_256_hasher hasher;
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
