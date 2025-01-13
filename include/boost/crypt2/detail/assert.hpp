// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_DETAIL_ASSERT_HPP
#define BOOST_CRYPT2_DETAIL_ASSERT_HPP

#include <boost/crypt2/detail/config.hpp>

// Check for C++23 stacktrace support
// TODO(mborland): Not ready for the mainstream as of 01/25. Manually enable for now
#ifdef BOOST_CRYPT_ENABLE_STACKTRACE
#  if __has_include(<stacktrace>)
#    ifndef BOOST_CRYPT_BUILD_MODULE
#      include <stacktrace>
#    endif
#  endif
#  if defined(__cpp_lib_stacktrace) && __cpp_lib_stacktrace >= 202011L
#    define BOOST_CRYPT_HAS_STACKTRACE 1
#  else
#    define BOOST_CRYPT_HAS_STACKTRACE 0
#  endif
#else
#  define BOOST_CRYPT_HAS_STACKTRACE 0
#endif

#ifndef BOOST_CRYPT_BUILD_MODULE

#include <source_location>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <sstream>

#endif

#if !defined(NDEBUG) && !BOOST_CRYPT_HAS_CUDA

namespace boost::crypt::assert_detail {

struct assertion_error : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

template<typename... Args>
[[nodiscard]] std::string format_assertion_message(
        const char* condition_str,
        const std::source_location& location,
        #if BOOST_CRYPT_HAS_STACKTRACE
        const std::stacktrace& trace,
        #endif
        Args&&... args)
{
    std::stringstream ss;
    ss << "Assertion failed: " << condition_str << '\n'
       << "File: " << location.file_name() << '\n'
       << "Line: " << location.line() << '\n'
       << "Function: " << location.function_name() << '\n'
       << "Column: " << location.column() << '\n';

    // Fold expression to handle optional message
    ((ss << "Message: " << args << '\n'), ...);

    #if BOOST_CRYPT_HAS_STACKTRACE
    // Add stacktrace
    ss << "Stacktrace:\n" << trace;
    #endif

    return ss.str();
}

// Version without message
constexpr void constexpr_assert_impl(
        bool condition,
        const char* condition_str,
        const std::source_location& location = std::source_location::current())
{
    if (!condition)
    {
        #if BOOST_CRYPT_HAS_STACKTRACE
        if (!std::is_constant_evaluated())
        {
                throw assertion_error(
                    format_assertion_message(
                        condition_str,
                        location,
                        std::stacktrace::current()
                    )
                );
            }
            else
            {
                throw assertion_error(
                    format_assertion_message(
                        condition_str,
                        location,
                        std::stacktrace{}
                    )
                );
            }
        #else
        throw assertion_error(
                format_assertion_message(
                        condition_str,
                        location
                )
        );
        #endif
    }
}

// Version with message
constexpr void constexpr_assert_impl(
        bool condition,
        const char* condition_str,
        const char* message,
        const std::source_location& location = std::source_location::current())
{
    if (!condition)
    {
        #if BOOST_CRYPT_HAS_STACKTRACE
        if (!std::is_constant_evaluated())
        {
                throw assertion_error(
                    format_assertion_message(
                        condition_str,
                        location,
                        std::stacktrace::current(),
                        message
                    )
                );
            }
            else
            {
                throw assertion_error(
                    format_assertion_message(
                        condition_str,
                        location,
                        std::stacktrace{},
                        message
                    )
                );
            }
        #else
        throw assertion_error(
                format_assertion_message(
                        condition_str,
                        location,
                        message
                )
        );
        #endif
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
