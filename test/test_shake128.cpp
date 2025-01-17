// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/shake128.hpp>

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

const std::array<std::tuple<std::string, std::array<uint16_t, 16U>>, 3> test_values =
{
    std::make_tuple("",
                    std::array<uint16_t, 16U> {
                        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    std::array<uint16_t, 16U> {
                        0xf4, 0x20, 0x2e, 0x3c, 0x58, 0x52, 0xf9, 0x18, 0x2a, 0x04, 0x30, 0xfd, 0x81, 0x44, 0xf0, 0xa7
                    }),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    std::array<uint16_t, 16U> {
                        0x63, 0x40, 0x69, 0xe6, 0xb1, 0x3c, 0x3a, 0xf6, 0x4c, 0x57, 0xf0, 0x5b, 0xab, 0xf5, 0x91, 0x1b
                    }),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::shake128(std::get<0>(test_value)).value()};
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
        const auto message_result {boost::crypt::shake128(string_message).value()};
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
        const auto message_result {boost::crypt::shake128(string_view_message).value()};
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

        boost::crypt::shake128_hasher hasher;
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
    boost::crypt::shake128_hasher hasher;

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
}

void test_user_container()
{
    boost::crypt::shake128_hasher hasher;

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
    boost::crypt::shake128_hasher hasher;

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
    boost::crypt::shake128_hasher hasher;

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
void test_file(T filename, const std::array<uint16_t, 16U>& res)
{
    const auto crypt_res {boost::crypt::shake128_file(filename).value()};

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
    // openssl dgst -shake128 test_file_1.txt
    // shake128 (test_file_1.txt) = 33486b7698456baa2eee4092d691127e
    constexpr std::array<uint16_t, 16U> res{0x33, 0x48, 0x6b, 0x76, 0x98, 0x45, 0x6b, 0xaa, 0x2e, 0xee, 0x40, 0x92, 0xd6, 0x91, 0x12, 0x7e};

    test_file(filename.c_str(), res);

    const std::string str_filename {filename};
    test_file(str_filename, res);

    const std::string_view str_view_filename {str_filename};
    test_file(str_view_filename, res);

    const auto invalid_filename = "broken.bin";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash1 = boost::crypt::shake128_file(invalid_filename), std::runtime_error);

    const std::string str_invalid_filename {invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash2 = boost::crypt::shake128_file(str_invalid_filename), std::runtime_error);

    const std::string_view str_view_invalid_filename {str_invalid_filename};
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash3 = boost::crypt::shake128_file(str_view_invalid_filename), std::runtime_error);

    // On macOS 15
    // openssl dgst -shake128 test_file_2.txt
    // shake128 (test_file_2.txt) = aaba435383de557c54c387359864154f
    constexpr std::array<uint16_t, 16U> res_2{0xaa, 0xba, 0x43, 0x53, 0x83, 0xde, 0x55, 0x7c, 0x54, 0xc3, 0x87, 0x35, 0x98, 0x64, 0x15, 0x4f};

    test_file(filename_2, res_2);

    const char* test_null_file = nullptr;
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash4 = boost::crypt::shake128_file(test_null_file), std::runtime_error);

    std::filesystem::path bad_path = "path.txt";
    BOOST_TEST_THROWS([[maybe_unused]] const auto trash5 = boost::crypt::shake128_file(bad_path), std::runtime_error);

    // Now test XOF file capabilities
    std::array<std::byte, 200> byte_array {};
    std::span<std::byte, 200> byte_span {byte_array};

    BOOST_TEST(boost::crypt::shake128_file(filename, byte_array) == boost::crypt::state::success);

    std::size_t zero_counter {};
    for (const auto val : byte_array)
    {
        if (val == std::byte{})
        {
            ++zero_counter;
        }
    }
    BOOST_TEST(zero_counter < byte_array.size());

    byte_array.fill(std::byte{});

    BOOST_TEST(boost::crypt::shake128_file(filename, byte_span, 100U) == boost::crypt::state::success);

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
    const auto expected_res = std::array<std::uint8_t, 64>{0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7};

    boost::crypt::shake128_hasher hasher;
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
