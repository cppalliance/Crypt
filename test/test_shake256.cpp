// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/shake256.hpp>

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
                        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
                        0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
                        0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
                        0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    std::array<uint16_t, 32U> {
                        0x2f, 0x67, 0x13, 0x43, 0xd9, 0xb2, 0xe1, 0x60,
                        0x4d, 0xc9, 0xdc, 0xf0, 0x75, 0x3e, 0x5f, 0xe1,
                        0x5c, 0x7c, 0x64, 0xa0, 0xd2, 0x83, 0xcb, 0xbf,
                        0x72, 0x2d, 0x41, 0x1a, 0x0e, 0x36, 0xf6, 0xca
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    std::array<uint16_t, 32U> {
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
        const auto message_result {boost::crypt::shake256(std::get<0>(test_value)).value()};
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
        const auto message_result {boost::crypt::shake256(string_message).value()};
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
        const auto message_result {boost::crypt::shake256(string_view_message).value()};
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

        boost::crypt::shake256_hasher hasher;
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
    boost::crypt::shake256_hasher hasher;

    for (const auto& test_value : test_values)
    {
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(std::string_view{msg});
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
    std::array<std::byte, 5U> small_container {};
    hasher.init();
    hasher.process_bytes(bad_update_msg);
    const auto array_return1 {hasher.get_digest(small_container)};
    BOOST_TEST(array_return1 == boost::crypt::state::state_error);
    hasher.finalize();
    const auto array_return2 {hasher.get_digest(small_container)};
    BOOST_TEST(array_return2 == boost::crypt::state::success);

    std::span<std::byte, 5U> small_container_span {small_container};
    hasher.init();
    hasher.process_bytes(bad_update_msg);
    const auto array_return3 {hasher.get_digest(small_container_span)};
    BOOST_TEST(array_return3 == boost::crypt::state::state_error);
    hasher.finalize();
    const auto array_return4 {hasher.get_digest(small_container_span)};
    BOOST_TEST(array_return4 == boost::crypt::state::success);

    // And the range interfaces
    hasher.init();
    hasher.process_bytes(bad_update_msg);
    BOOST_TEST(hasher.get_digest(small_container, 10U) == boost::crypt::state::state_error);
    hasher.finalize();
    BOOST_TEST(hasher.get_digest(small_container, 10U) == boost::crypt::state::insufficient_output_length);
    BOOST_TEST(hasher.get_digest(small_container, 5U) == boost::crypt::state::success);

    hasher.init();
    hasher.process_bytes(bad_update_msg);
    BOOST_TEST(hasher.get_digest(small_container_span, 10U) == boost::crypt::state::state_error);
    hasher.finalize();
    BOOST_TEST(hasher.get_digest(small_container_span, 10U) == boost::crypt::state::insufficient_output_length);
    BOOST_TEST(hasher.get_digest(small_container_span, 5U) == boost::crypt::state::success);
}

void test_user_container()
{
    boost::crypt::shake256_hasher hasher;

    for (const auto& test_value : test_values)
    {
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg);
        std::array<std::byte, 16U> message_result {};
        hasher.finalize();
        const auto status {hasher.get_digest(message_result)};
        BOOST_TEST(status == boost::crypt::state::success);
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
}

void test_continuous_output()
{
    boost::crypt::shake256_hasher hasher;

    for (const auto& test_value : test_values)
    {
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg);
        std::array<std::uint8_t, 64U> message_result {};
        std::array<std::uint8_t, 64U> message_result_previous {};
        hasher.finalize();
        BOOST_TEST(hasher.get_digest(message_result_previous) == boost::crypt::state::success);
        for (std::size_t i {}; i < 100; ++i)
        {
            const auto status {hasher.get_digest(message_result)};
            BOOST_TEST(status == boost::crypt::state::success);
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
        hasher.process_bytes(msg);
        std::array<std::uint8_t, 64U> message_result {};
        hasher.finalize();
        const auto status {hasher.get_digest(message_result)};
        BOOST_TEST(status == boost::crypt::state::success);
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < valid_result.size(); ++i)
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
void test_file(T filename, const std::array<uint16_t, 32U>& res)
{
    const auto crypt_res {boost::crypt::shake256_file(filename).value()};

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
    // openssl dgst -shake256 test_file_1.txt
    // shake256 (test_file_1.txt) = 4645896122b04fd3cabcee7bbf5c7944293c9347293ba1254310466dd3265e75
    constexpr std::array<uint16_t, 32U> res{0x46, 0x45, 0x89, 0x61, 0x22, 0xb0, 0x4f, 0xd3, 0xca, 0xbc, 0xee, 0x7b, 0xbf, 0x5c, 0x79, 0x44, 0x29, 0x3c, 0x93, 0x47, 0x29, 0x3b, 0xa1, 0x25, 0x43, 0x10, 0x46, 0x6d, 0xd3, 0x26, 0x5e, 0x75};

    test_file(filename.c_str(), res);

    const std::string str_filename {filename};
    test_file(str_filename, res);

    const std::string_view str_view_filename {str_filename};
    test_file(str_view_filename, res);

    const auto invalid_filename = "broken.bin";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash1 = boost::crypt::shake256_file(invalid_filename), std::runtime_error);

    const std::string str_invalid_filename {invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash2 = boost::crypt::shake256_file(str_invalid_filename), std::runtime_error);

    const std::string_view str_view_invalid_filename {str_invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash3 = boost::crypt::shake256_file(str_view_invalid_filename), std::runtime_error);

    // On macOS 15
    // openssl dgst -shake256 test_file_2.txt
    // shake256 (test_file_2.txt) = 23a1aa31e361495b74dbcb1cffc52a3ac8a2af549ad2cd61b3d5cabf7ed7424a
    constexpr std::array<uint16_t, 32U> res_2{0x23, 0xa1, 0xaa, 0x31, 0xe3, 0x61, 0x49, 0x5b, 0x74, 0xdb, 0xcb, 0x1c, 0xff, 0xc5, 0x2a, 0x3a, 0xc8, 0xa2, 0xaf, 0x54, 0x9a, 0xd2, 0xcd, 0x61, 0xb3, 0xd5, 0xca, 0xbf, 0x7e, 0xd7, 0x42, 0x4a};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash4 = boost::crypt::shake256_file(test_null_file), std::runtime_error);

    std::filesystem::path bad_path = "path.txt";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash5 = boost::crypt::shake256_file(bad_path), std::runtime_error);

    // Now test XOF file capabilities
    std::array<std::byte, 200> byte_array {};
    std::span<std::byte, 200> byte_span {byte_array};

    BOOST_TEST(boost::crypt::shake256_file(filename, byte_array) == boost::crypt::state::success);

    std::size_t zero_counter {};
    for (const auto val : byte_array)
    {
        if (val == std::byte{})
        {
            ++zero_counter; // LCOV_EXCL_LINE
        }
    }
    BOOST_TEST(zero_counter < byte_array.size());

    byte_array.fill(std::byte{});

    BOOST_TEST(boost::crypt::shake256_file(filename, byte_span, 100U) == boost::crypt::state::success);

    // Does not matter that we know 100 are zeros
    // If the other 100 are zeros there is a deep problem
    for (const auto val : byte_array)
    {
        if (val == std::byte{})
        {
            ++zero_counter;
        }
    }
    BOOST_TEST(zero_counter < byte_array.size());
}

consteval bool immediate_test()
{

    // "abc" in hex
    const std::byte vals[] = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}};
    std::span<const std::byte> byte_span {vals};
    const auto expected_res = std::array<std::uint8_t, 64>{0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77, 0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d, 0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee, 0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39};

    boost::crypt::shake256_hasher hasher;
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
    test_user_container();
    test_user_pointer();
    test_continuous_output();

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
