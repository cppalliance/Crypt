// Copyright 2024 - 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DETAIL_UNREACHABLE_HPP
#define BOOST_CRYPT_DETAIL_UNREACHABLE_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>

namespace boost::crypt::detail {

// LCOV_EXCL_START
[[noreturn]] inline void unreachable()
{
    // Uses compiler specific extensions if possible.
    // Even if no extension is used, undefined behavior is still raised by
    // an empty function body and the noreturn attribute.
#if defined(_MSC_VER) && !defined(__clang__) // MSVC
    __assume(false);
#else // GCC, Clang, NVCC
    __builtin_unreachable();
#endif
}
// LCOV_EXCL_STOP

} // namespace boost::crypt::detail

#endif // BOOST_CRYPT_DETAIL_UNREACHABLE_HPP
