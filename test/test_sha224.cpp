// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha224.hpp>

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

using std::byte;

const std::array<std::tuple<std::string, std::array<uint16_t, 28>>, 4> test_values =
{
    std::make_tuple(std::string{"a"},
                    std::array<uint16_t, 28>{0xab, 0xd3, 0x75, 0x34, 0xc7, 0xd9, 0xa2, 0xef, 0xb9, 0x46, 0x5d, 0xe9, 0x31, 0xcd, 0x70, 0x55, 0xff, 0xdb, 0x88, 0x79, 0x56, 0x3a, 0xe9, 0x80, 0x78, 0xd6, 0xd6, 0xd5}),
    std::make_tuple(std::string{"The quick brown fox jumps over the lazy dog"},
                    std::array<uint16_t, 28>{0x73, 0x0e, 0x10, 0x9b, 0xd7, 0xa8, 0xa3, 0x2b, 0x1c, 0xb9, 0xd9, 0xa0, 0x9a, 0xa2, 0x32, 0x5d, 0x24, 0x30, 0x58, 0x7d, 0xdb, 0xc0, 0xc3, 0x8b, 0xad, 0x91, 0x15, 0x25}),
    std::make_tuple(std::string{"The quick brown fox jumps over the lazy dog."},
                    std::array<uint16_t, 28>{0x61, 0x9c, 0xba, 0x8e, 0x8e, 0x05, 0x82, 0x6e, 0x9b, 0x8c, 0x51, 0x9c, 0x0a, 0x5c, 0x68, 0xf4, 0xfb, 0x65, 0x3e, 0x8a, 0x3d, 0x8a, 0xa0, 0x4b, 0xb2, 0xc8, 0xcd, 0x4c}),
    std::make_tuple(std::string{""},
                    std::array<uint16_t, 28>{0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f})
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::sha224(std::get<0>(test_value))};
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
        const auto message_result {boost::crypt::sha224(string_message)};
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
        const auto message_result {boost::crypt::sha224(string_view_message)};
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

        boost::crypt::sha224_hasher hasher;
        const auto current_state = hasher.process_bytes(string_view_message);
        BOOST_TEST(current_state == boost::crypt::state::success);
        const auto result2 = hasher.get_digest();
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST(result2[i] == static_cast<byte>(valid_result[i])))
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
    boost::crypt::sha224_hasher hasher;

    for (const auto& test_value : test_values)
    {
        hasher.init();
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg);
        const auto message_result {hasher.get_digest()};

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

    const std::string bad_update_msg {"bad"};
    BOOST_TEST(hasher.process_bytes(bad_update_msg) == boost::crypt::state::state_error);
    BOOST_TEST(hasher.finalize() == boost::crypt::state::state_error);
    BOOST_TEST(hasher.get_digest() == boost::crypt::sha224_hasher ::return_type{});
}

template <typename T>
void test_file(const T filename, const std::array<uint16_t, 28>& res)
{
    const auto crypt_res {boost::crypt::sha224_file(filename)};

    for (std::size_t j {}; j < crypt_res.size(); ++j)
    {
        if (!BOOST_TEST(static_cast<byte>(res[j]) == static_cast<byte>(crypt_res[j])))
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
    // sha224 test_file_1.txt
    // sha224 (test_file_1.txt) = e88799b0d0d5becc6791837fa95388d4056f1250a511d14829766663
    constexpr std::array<std::uint16_t, 28> res{0xe8, 0x87, 0x99, 0xb0, 0xd0, 0xd5, 0xbe, 0xcc, 0x67, 0x91, 0x83, 0x7f, 0xa9, 0x53, 0x88, 0xd4, 0x05, 0x6f, 0x12, 0x50, 0xa5, 0x11, 0xd1, 0x48, 0x29, 0x76, 0x66, 0x63};

    test_file(filename, res);

    const std::string str_filename {filename};
    test_file(str_filename, res);

    const std::string_view str_view_filename {str_filename};
    test_file(str_view_filename, res);

    const auto invalid_filename = "broken.bin";
    BOOST_TEST_THROWS(boost::crypt::sha224_file(invalid_filename), std::runtime_error);

    const std::string str_invalid_filename {invalid_filename};
    BOOST_TEST_THROWS(boost::crypt::sha224_file(str_invalid_filename), std::runtime_error);

    // On macOS 15
    // sha224 test_file_2.txt
    // sha224 (test_file_2.txt) = c58605901d0923feb172e964ca6722378063574d18ff3efa7881bd91
    constexpr std::array<std::uint16_t, 28> res_2{0xc5, 0x86, 0x05, 0x90, 0x1d, 0x09, 0x23, 0xfe, 0xb1, 0x72, 0xe9, 0x64, 0xca, 0x67, 0x22, 0x37, 0x80, 0x63, 0x57, 0x4d, 0x18, 0xff, 0x3e, 0xfa, 0x78, 0x81, 0xbd, 0x91};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    BOOST_TEST_THROWS(boost::crypt::sha224_file(test_null_file), std::runtime_error);

    std::filesystem::path bad_path = "path.txt";
    BOOST_TEST_THROWS(boost::crypt::sha224_file(bad_path), std::runtime_error);
}

consteval bool immediate_test()
{
    constexpr std::array<std::byte, 3> vals = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
    constexpr std::array<std::byte, 28> expected_res = {
            std::byte{0x23}, std::byte{0x09}, std::byte{0x7d}, std::byte{0x22}, std::byte{0x34}, std::byte{0x05},
            std::byte{0xd8}, std::byte{0x22}, std::byte{0x86}, std::byte{0x42}, std::byte{0xa4}, std::byte{0x77},
            std::byte{0xbd}, std::byte{0xa2}, std::byte{0x55}, std::byte{0xb3}, std::byte{0x2a}, std::byte{0xad},
            std::byte{0xbc}, std::byte{0xe4}, std::byte{0xbd}, std::byte{0xa0}, std::byte{0xb3}, std::byte{0xf7},
            std::byte{0xe3}, std::byte{0x6c}, std::byte{0x9d}, std::byte{0xa7}
    };
    std::span<const std::byte> byte_span {vals};

    boost::crypt::sha224_hasher hasher;
    hasher.init();
    hasher.process_bytes(byte_span);
    const auto res = hasher.get_digest();

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
