// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DETAIL_SECURE_MEMSET_HPP
#define BOOST_CRYPT_DETAIL_SECURE_MEMSET_HPP

#include <boost/crypt2/detail/config.hpp>

#ifdef BOOST_CRYPT_HAS_CUDA

#include <cuda/std/span>
// There is no real secure memset here
namespace boost::crypt::detail {

template <typename T>
void clear_mem(cuda::std::span<T> ptr)
{
    for (auto& byte : ptr)
    {
        byte = static_cast<T>(0);
    }
}

}

#else

#ifndef BOOST_CRYPT_BUILD_MODULE

#include <span>
#include <type_traits>
#include <cstring>
#include <cstddef>

#ifdef _WIN32
#include <WinBase.h>
#endif

#endif

namespace boost::crypt::detail {

using memset_span_t = void(*)(std::span<std::byte>);

inline constexpr memset_span_t default_memset = [](std::span<std::byte> s) constexpr
{
    std::fill(s.begin(), s.end(), std::byte{0x00});
};

// Define the runtime function separately with external linkage
inline void runtime_memset_impl(std::span<std::byte> s)
{
    #ifdef _WIN32
    SecureZeroMemory(s.data(), s.size());
    #elif defined(BOOST_CRYPT_BUILD_MODULE)
    std::memset(s.data(), 0x00, s.size_bytes());
    #else
    memset_s(s.data(), s.size_bytes(), 0x00, s.size_bytes());
    #endif
}

// Now use the named function instead of lambda
inline volatile memset_span_t runtime_memset_func = runtime_memset_impl;

constexpr void clear_mem(std::span<std::byte> data)
{
    if (std::is_constant_evaluated())
    {
        default_memset(data);
    }
    else
    {
        runtime_memset_func(data);
    }
}

} // namespace boost::crypt::detail

#endif

#endif //BOOST_CRYPT_DETAIL_SECURE_MEMSET_HPP
