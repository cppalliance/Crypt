// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DETAIL_SECURE_MEMSET_HPP
#define BOOST_CRYPT_DETAIL_SECURE_MEMSET_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>

#ifdef BOOST_CRYPT_HAS_CUDA

#include <cuda/std/span>
#include <cuda/std/array>
// There is no real secure memset here
namespace boost::crypt::detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED void clear_mem(cuda::std::span<T> ptr)
{
    for (auto& byte : ptr)
    {
        byte = typename T::value_type{};
    }
}

template <typename T>
BOOST_CRYPT_GPU_ENABLED void clear_mem(T& arr)
{
    for (auto& byte : arr)
    {
        byte = typename T::value_type{};
    }
}

} // End namespace

#else

#ifndef BOOST_CRYPT_BUILD_MODULE

#include <span>
#include <bit>
#include <type_traits>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include <algorithm>

#endif

namespace boost::crypt::detail {

using memset_span_t = void(*)(std::span<std::byte>);

inline constexpr memset_span_t default_memset = [](std::span<std::byte> s) constexpr
{
    std::fill(s.begin(), s.end(), std::byte{0x00});
};

// Define the runtime function separately with external linkage
//
// I am unaware of any other way to accomplish this under safe buffer,
// so we ignore the warning
inline void runtime_memset_impl(std::span<std::byte> s)
{
    #if defined(__clang__) && __clang_major__ >= 20
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-libc-call"
    #endif

    std::memset(s.data(), 0x00, s.size_bytes());

    #if defined(__clang__) && __clang_major__ >= 20
    #pragma clang diagnostic pop
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

using generic_meset_t = void(*)(void*, size_t);

inline void generic_runtime_memset_func_impl(void* ptr, size_t size)
{
    #if defined(__clang__) && __clang_major__ >= 20
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-libc-call"
    #endif

    std::memset(ptr, 0, size);

    #if defined(__clang__) && __clang_major__ >= 20
    #pragma clang diagnostic pop
    #endif
}

inline volatile generic_meset_t generic_runtime_memset_func = generic_runtime_memset_func_impl;

template <typename T>
constexpr void clear_mem(T& data)
{
    if (std::is_constant_evaluated())
    {
        std::fill(data.begin(), data.end(), static_cast<typename T::value_type>(0));
    }
    else
    {
        generic_runtime_memset_func_impl(data.data(), data.size());
    }
}

} // namespace boost::crypt::detail

#endif

#endif //BOOST_CRYPT_DETAIL_SECURE_MEMSET_HPP
