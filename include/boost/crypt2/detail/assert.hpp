// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_DETAIL_ASSERT_HPP
#define BOOST_CRYPT2_DETAIL_ASSERT_HPP

#include <boost/crypt2/detail/config.hpp>

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <source_location>
#include <iostream>
#include <stdexcept>
#include <string_view>
#endif

#if !defined(NDEBUG) && !defined(BOOST_CRYPT_HAS_CUDA)

namespace boost::crypt::assert_detail {

struct assertion_error : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

// Version without message
consteval void constexpr_assert_impl(
        bool condition,
        const char* condition_str,
        const std::source_location& location = std::source_location::current())
{
    if (!condition) {
        throw assertion_error(
                std::string("Assertion failed: ") + condition_str +
                "\nFile: " + location.file_name() +
                "\nLine: " + std::to_string(location.line()) +
                "\nFunction: " + location.function_name() +
                "\nColumn: " + std::to_string(location.column())
        );
    }
}

// Version with message
consteval void constexpr_assert_impl(
        bool condition,
        const char* condition_str,
        const char* message,
        const std::source_location& location = std::source_location::current())
{
    if (!condition) {
        throw assertion_error(
                std::string("Assertion failed: ") + condition_str +
                "\nMessage: " + message +
                "\nFile: " + location.file_name() +
                "\nLine: " + std::to_string(location.line()) +
                "\nFunction: " + location.function_name() +
                "\nColumn: " + std::to_string(location.column())
        );
    }
}

} // namespace boost::crypt::assert_detail

// Macro overloading based on argument count
#define BOOST_CRYPT_ASSERT_1(condition) \
    boost::crypt::assert_detail::constexpr_assert_impl((condition), #condition)

#define BOOST_CRYPT_ASSERT_2(condition, message) \
    boost::crypt::assert_detail::constexpr_assert_impl((condition), #condition, message)

// Helper macros for argument counting
#define BOOST_CRYPT_ASSERT_GET_MACRO(_1, _2, NAME, ...) NAME

// Main macro that selects the appropriate version
#define BOOST_CRYPT_ASSERT(...) \
    BOOST_CRYPT_ASSERT_GET_MACRO(__VA_ARGS__, BOOST_CRYPT_ASSERT_2, BOOST_CRYPT_ASSERT_1)(__VA_ARGS__)

#else

#define BOOST_CRYPT_ASSERT(...)

#endif // NDEBUG and CUDA

#endif // BOOST_CRYPT2_DETAIL_ASSERT_HPP
