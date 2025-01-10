// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha512_224.hpp>

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

const std::array<std::tuple<std::string, std::array<uint16_t, 28U>>, 3> test_values =
{
    std::make_tuple("",
                    std::array<uint16_t, 28U> {
                        0x6e, 0xd0, 0xdd, 0x02, 0x80, 0x6f, 0xa8,
                        0x9e, 0x25, 0xde, 0x06, 0x0c, 0x19, 0xd3,
                        0xac, 0x86, 0xca, 0xbb, 0x87, 0xd6, 0xa0,
                        0xdd, 0xd0, 0x5c, 0x33, 0x3b, 0x84, 0xf4
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    std::array<uint16_t, 28U> {
                        0x94, 0x4c, 0xd2, 0x84, 0x7f, 0xb5, 0x45,
                        0x58, 0xd4, 0x77, 0x5d, 0xb0, 0x48, 0x5a,
                        0x50, 0x00, 0x31, 0x11, 0xc8, 0xe5, 0xda,
                        0xa6, 0x3f, 0xe7, 0x22, 0xc6, 0xaa, 0x37
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    std::array<uint16_t, 28U> {
                        0x6d, 0x6a, 0x92, 0x79, 0x49, 0x5e, 0xc4,
                        0x06, 0x17, 0x69, 0x75, 0x2e, 0x7f, 0xf9,
                        0xc6, 0x8b, 0x6b, 0x0b, 0x3c, 0x5a, 0x28,
                        0x1b, 0x79, 0x17, 0xce, 0x05, 0x72, 0xde
                    }),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::sha512_224(std::get<0>(test_value)).value()};
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
        const auto message_result {boost::crypt::sha512_224(string_message).value()};
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
        const auto message_result {boost::crypt::sha512_224(string_view_message).value()};
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

        boost::crypt::sha512_224_hasher hasher;
        const auto current_state = hasher.process_bytes(string_view_message);
        BOOST_TEST(current_state == boost::crypt::state::success);
        hasher.finalize();
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
    boost::crypt::sha512_224_hasher hasher;

    for (const auto& test_value : test_values)
    {
        hasher.init();
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
    }

    const std::string bad_update_msg {"bad"};
    BOOST_TEST(hasher.process_bytes(bad_update_msg) == boost::crypt::state::state_error);
    BOOST_TEST(hasher.finalize() == boost::crypt::state::state_error);
    BOOST_TEST(hasher.get_digest().error() == boost::crypt::state::state_error);
}

template <typename T>
void test_file(T filename, const std::array<uint16_t, 28U>& res)
{
    const auto crypt_res {boost::crypt::sha512_224_file(filename).value()};

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
    // shasum -a 512224 test_file_1.txt
    // d90ec85475853bc495a3243d13e664a3af0804705cee3e07edf741b
    constexpr std::array<uint16_t, 28> res{0x4d, 0x90, 0xec, 0x85, 0x47, 0x58, 0x53, 0xbc, 0x49, 0x5a, 0x32, 0x43, 0xd1, 0x3e, 0x66, 0x4a, 0x3a, 0xf0, 0x80, 0x47, 0x05, 0xce, 0xe3, 0xe0, 0x7e, 0xdf, 0x74, 0x1b};

    test_file(filename, res);

    const std::string str_filename {filename};
    test_file(str_filename, res);

    const std::string_view str_view_filename {str_filename};
    test_file(str_view_filename, res);

    const auto invalid_filename = "broken.bin";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash1 = boost::crypt::sha512_224_file(invalid_filename), std::runtime_error);

    const std::string str_invalid_filename {invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash2 = boost::crypt::sha512_224_file(str_invalid_filename), std::runtime_error);

    const std::string_view str_view_invalid_filename {str_invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash3 = boost::crypt::sha512_224_file(str_view_invalid_filename), std::runtime_error);

    // On macOS 15
    // shasum -a 512224 test_file_2.txt
    // 6dc95388edc5b8eab4c7f440023bf7450651bdf9a5a72e65a24c3fe6
    constexpr std::array<uint16_t, 28U> res_2{0x6d, 0xc9, 0x53, 0x88, 0xed, 0xc5, 0xb8, 0xea, 0xb4, 0xc7, 0xf4, 0x40, 0x02, 0x3b, 0xf7, 0x45, 0x06, 0x51, 0xbd, 0xf9, 0xa5, 0xa7, 0x2e, 0x65, 0xa2, 0x4c, 0x3f, 0xe6};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash4 =boost::crypt::sha512_224_file(test_null_file), std::runtime_error);

    std::filesystem::path bad_path = "path.txt";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash5 =boost::crypt::sha512_224_file(bad_path), std::runtime_error);
}

consteval bool immediate_test()
{
    constexpr std::array<std::byte, 3> vals = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
    constexpr std::array<uint16_t, 28> expected_res {
        0x46, 0x34, 0x27, 0x0f, 0x70, 0x7b, 0x6a,
        0x54, 0xda, 0xae, 0x75, 0x30, 0x46, 0x08,
        0x42, 0xe2, 0x0e, 0x37, 0xed, 0x26, 0x5c,
        0xee, 0xe9, 0xa4, 0x3e, 0x89, 0x24, 0xaa
    };

    std::span<const std::byte> byte_span {vals};

    boost::crypt::sha512_224_hasher hasher;
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
