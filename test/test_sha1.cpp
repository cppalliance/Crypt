// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha1.hpp>

#if defined(__clang__) && __clang_major__ >= 19
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#endif

#include <boost/core/lightweight_test.hpp>

#if defined(__clang__) && __clang_major__ >= 19
#pragma clang diagnostic pop
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
#include <cstdint>
#include <string>
#include <filesystem>

using std::byte;

const std::array<std::tuple<std::string, std::array<uint16_t, 20>>, 7> test_values =
{
    // Start with the sample hashes from wiki
    std::make_tuple(std::string{"The quick brown fox jumps over the lazy dog"},
                    std::array<std::uint16_t, 20>{0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84,
                                                  0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12}),
    std::make_tuple(std::string{"The quick brown fox jumps over the lazy cog"},
                    std::array<std::uint16_t, 20>{0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3,
                                                  0xe8, 0x5a, 0x0b, 0xd1, 0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3}),
    std::make_tuple(std::string{""},
                    std::array<std::uint16_t, 20>{0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
                                                  0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09}),
    // Now the ones from the RFC
    std::make_tuple(std::string{"abc"},
                    std::array<std::uint16_t, 20>{0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
                                                  0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D}),

    std::make_tuple(std::string{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
                    std::array<std::uint16_t, 20>{0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
                                                  0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1}),

    std::make_tuple(std::string{"a"},
                    std::array<std::uint16_t, 20>{0x86, 0xf7, 0xe4, 0x37, 0xfa, 0xa5, 0xa7, 0xfc, 0xe1, 0x5d,
                                                  0x1d, 0xdc, 0xb9, 0xea, 0xea, 0xea, 0x37, 0x76, 0x67, 0xb8}),

    std::make_tuple(std::string{"0123456701234567012345670123456701234567012345670123456701234567"},
                    std::array<std::uint16_t, 20>{0xe0, 0xc0, 0x94, 0xe8, 0x67, 0xef, 0x46, 0xc3, 0x50, 0xef,
                                                  0x54, 0xa7, 0xf5, 0x9d, 0xd6, 0x0b, 0xed, 0x92, 0xae, 0x83}),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result_expected {boost::crypt::sha1(std::get<0>(test_value))};
        const auto message_result {message_result_expected.value()};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST(message_result[i] == static_cast<byte>(valid_result[i])))
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
        const auto message_result_expected {boost::crypt::sha1(string_message)};
        const auto message_result {message_result_expected.value()};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST(message_result[i] == static_cast<byte>(valid_result[i])))
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
        const auto message_result_expected {boost::crypt::sha1(string_view_message)};
        const auto message_result {message_result_expected.value()};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST(message_result[i] == static_cast<byte>(valid_result[i])))
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
    boost::crypt::sha1_hasher hasher;

    for (const auto& test_value : test_values)
    {
        hasher.init();
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg);
        hasher.finalize();
        const auto message_result_expected {hasher.get_digest()};
        const auto message_result {message_result_expected.value()};

        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST(message_result[i] == static_cast<byte>(valid_result[i])))
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
        std::array<std::byte, 64U> message_result {};
        std::span<std::byte, 64U> message_result_span {message_result};
        hasher.init();
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg);
        hasher.finalize();
        const auto return_state {hasher.get_digest(message_result_span)};
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

    for (const auto& test_value : test_values)
    {
        std::array<std::byte, 64U> message_result {};
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
void test_file(const T& filename, const std::array<std::uint16_t, 20>& res)
{
    const auto crypt_res_expected {boost::crypt::sha1_file(filename)};
    const auto crypt_res {crypt_res_expected.value()};

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
    // sha1 test_file_1.txt
    // SHA1 (test_file_1.txt) = 9c04cd6372077e9b11f70ca111c9807dc7137e4b
    constexpr std::array<std::uint16_t, 20> res{0x9c, 0x04, 0xcd, 0x63, 0x72, 0x07, 0x7e, 0x9b, 0x11, 0xf7,
                                                0x0c, 0xa1, 0x11, 0xc9, 0x80, 0x7d, 0xc7, 0x13, 0x7e, 0x4b};

    test_file(filename, res);

    const std::string str_filename {filename};
    test_file(str_filename, res);

    const std::string_view str_view_filename {str_filename};
    test_file(str_view_filename, res);

    const auto invalid_filename = "broken.bin";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash1 = boost::crypt::sha1_file(invalid_filename), std::runtime_error);

    const std::string str_invalid_filename {invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash2 = boost::crypt::sha1_file(str_invalid_filename), std::runtime_error);

    // On macOS 15
    // sha1 test_file_2.txt
    // SHA1 (test_file_2.txt) = 5d987ba69fde8b2500594799b47bd9255ac9cb65
    constexpr std::array<std::uint16_t, 20> res_2{0x5d, 0x98, 0x7b, 0xa6, 0x9f, 0xde, 0x8b, 0x25, 0x00, 0x59,
                                                  0x47, 0x99, 0xb4, 0x7b, 0xd9, 0x25, 0x5a, 0xc9, 0xcb, 0x65};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash3 = boost::crypt::sha1_file(test_null_file), std::runtime_error);

    std::filesystem::path bad_path = "path.txt";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash4 = boost::crypt::sha1_file(bad_path), std::runtime_error);
}

consteval bool immediate_test()
{
    constexpr std::array<std::byte, 3> vals = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
    constexpr std::array<std::byte, 20> expected_res = {
        std::byte{0xA9}, std::byte{0x99}, std::byte{0x3E}, std::byte{0x36}, std::byte{0x47}, std::byte{0x06},
        std::byte{0x81}, std::byte{0x6A}, std::byte{0xBA}, std::byte{0x3E}, std::byte{0x25}, std::byte{0x71},
        std::byte{0x78}, std::byte{0x50}, std::byte{0xC2}, std::byte{0x6C}, std::byte{0x9C}, std::byte{0xD0},
        std::byte{0xD8}, std::byte{0x9D}
    };

    const std::span<const std::byte> byte_span {vals};

    boost::crypt::sha1_hasher hasher;
    hasher.init();
    hasher.process_bytes(byte_span);
    hasher.finalize();
    const auto res_expected = hasher.get_digest();
    const auto res {res_expected.value()};

    bool correct {true};
    for (std::size_t i {}; i < res.size(); ++i)
    {
        if (res[i] != expected_res[i])
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
