// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha512.hpp>

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

const std::array<std::tuple<std::string, std::array<uint16_t, 64U>>, 3> test_values =
{
    std::make_tuple("",
                    std::array<uint16_t, 64U> {
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
                    std::array<uint16_t, 64U> {
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
                    std::array<uint16_t, 64U> {
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
        const auto message_result {boost::crypt::sha512(std::get<0>(test_value)).value()};
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
        const auto message_result {boost::crypt::sha512(string_message).value()};
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
        const auto message_result {boost::crypt::sha512(string_view_message).value()};
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

        boost::crypt::sha512_hasher hasher;
        const auto current_state = hasher.process_bytes(string_view_message);
        BOOST_TEST(current_state == boost::crypt::state::success);
        hasher.finalize();
        const auto result2 = hasher.get_digest().value();
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
    boost::crypt::sha512_hasher hasher;

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
        std::array<std::byte, 128U> message_result {};
        std::span<std::byte, 128U> message_result_span {message_result};
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
void test_file(T filename, const std::array<uint16_t, 64U>& res)
{
    const auto crypt_res {boost::crypt::sha512_file(filename).value()};

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
    // sha512 test_file_1.txt
    // sha512 (test_file_1.txt) = 020da0f4d8a4c8bfbc98274027740061d7df52ee07091ed6595a083e0f45327bbe59424312d86f218b74ed2e25507abaf5c7a5fcf4cafcf9538b705808fd55ec
    constexpr std::array<std::uint16_t, 64U> res{0x02, 0x0d, 0xa0, 0xf4, 0xd8, 0xa4, 0xc8, 0xbf, 0xbc, 0x98, 0x27, 0x40, 0x27, 0x74, 0x00, 0x61, 0xd7, 0xdf, 0x52, 0xee, 0x07, 0x09, 0x1e, 0xd6, 0x59, 0x5a, 0x08, 0x3e, 0x0f, 0x45, 0x32, 0x7b, 0xbe, 0x59, 0x42, 0x43, 0x12, 0xd8, 0x6f, 0x21, 0x8b, 0x74, 0xed, 0x2e, 0x25, 0x50, 0x7a, 0xba, 0xf5, 0xc7, 0xa5, 0xfc, 0xf4, 0xca, 0xfc, 0xf9, 0x53, 0x8b, 0x70, 0x58, 0x08, 0xfd, 0x55, 0xec};

    test_file(filename, res);

    const std::string str_filename {filename};
    test_file(str_filename, res);
    
    const std::string_view str_view_filename {str_filename};
    test_file(str_view_filename, res);

    const auto invalid_filename = "broken.bin";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash1 = boost::crypt::sha512_file(invalid_filename), std::runtime_error);

    const std::string str_invalid_filename {invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash2 =boost::crypt::sha512_file(str_invalid_filename), std::runtime_error);

    const std::string_view str_view_invalid_filename {str_invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash3 =boost::crypt::sha512_file(str_view_invalid_filename), std::runtime_error);
    // On macOS 15
    // sha512 test_file_2.txt
    // sha512 (test_file_2.txt) = 83e18fae406f58d67f459ef301dc236639c44d4c10928e38363021ba037159e73b00a86820607a1595653129b52b284543714834816dd00a33f49cbf16ee5d77
    constexpr std::array<std::uint16_t, 64U> res_2{0x83, 0xe1, 0x8f, 0xae, 0x40, 0x6f, 0x58, 0xd6, 0x7f, 0x45, 0x9e, 0xf3, 0x01, 0xdc, 0x23, 0x66, 0x39, 0xc4, 0x4d, 0x4c, 0x10, 0x92, 0x8e, 0x38, 0x36, 0x30, 0x21, 0xba, 0x03, 0x71, 0x59, 0xe7, 0x3b, 0x00, 0xa8, 0x68, 0x20, 0x60, 0x7a, 0x15, 0x95, 0x65, 0x31, 0x29, 0xb5, 0x2b, 0x28, 0x45, 0x43, 0x71, 0x48, 0x34, 0x81, 0x6d, 0xd0, 0x0a, 0x33, 0xf4, 0x9c, 0xbf, 0x16, 0xee, 0x5d, 0x77};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash4 =boost::crypt::sha512_file(test_null_file), std::runtime_error);

    std::filesystem::path bad_path = "path.txt";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash5 =boost::crypt::sha512_file(bad_path), std::runtime_error);
}

consteval bool immediate_test()
{
    constexpr std::array<std::byte, 3> vals = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
    constexpr std::array<std::byte, 64> expected_res {
        std::byte{0xdd}, std::byte{0xaf}, std::byte{0x35}, std::byte{0xa1}, std::byte{0x93}, std::byte{0x61},
        std::byte{0x7a}, std::byte{0xba}, std::byte{0xcc}, std::byte{0x41}, std::byte{0x73}, std::byte{0x49},
        std::byte{0xae}, std::byte{0x20}, std::byte{0x41}, std::byte{0x31}, std::byte{0x12}, std::byte{0xe6},
        std::byte{0xfa}, std::byte{0x4e}, std::byte{0x89}, std::byte{0xa9}, std::byte{0x7e}, std::byte{0xa2},
        std::byte{0x0a}, std::byte{0x9e}, std::byte{0xee}, std::byte{0xe6}, std::byte{0x4b}, std::byte{0x55},
        std::byte{0xd3}, std::byte{0x9a}, std::byte{0x21}, std::byte{0x92}, std::byte{0x99}, std::byte{0x2a},
        std::byte{0x27}, std::byte{0x4f}, std::byte{0xc1}, std::byte{0xa8}, std::byte{0x36}, std::byte{0xba},
        std::byte{0x3c}, std::byte{0x23}, std::byte{0xa3}, std::byte{0xfe}, std::byte{0xeb}, std::byte{0xbd},
        std::byte{0x45}, std::byte{0x4d}, std::byte{0x44}, std::byte{0x23}, std::byte{0x64}, std::byte{0x3c},
        std::byte{0xe8}, std::byte{0x0e}, std::byte{0x2a}, std::byte{0x9a}, std::byte{0xc9}, std::byte{0x4f},
        std::byte{0xa5}, std::byte{0x4c}, std::byte{0xa4}, std::byte{0x9f}
    };

    std::span<const std::byte> byte_span {vals};

    boost::crypt::sha512_hasher hasher;
    hasher.init();
    hasher.process_bytes(byte_span);
    hasher.finalize();
    const auto res = hasher.get_digest().value();

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
