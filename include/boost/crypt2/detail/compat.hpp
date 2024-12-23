// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// Here we inject std and cuda std equivalents into our own namespace
// to help resolve ADL issues with CUDA

#ifndef BOOST_CRYPT2_DETAIL_COMPAT_HPP
#define BOOST_CRYPT2_DETAIL_COMPAT_HPP

#include <boost/crypt2/detail/config.hpp>

#if !defined(BOOST_CRYPT_BUILD_MODULE) && !defined(BOOST_CRYPT_HAS_CUDA)

#include <span>
#include <array>
#include <ranges>
#include <algorithm>
#include <type_traits>
#include <cstdint>
#include <cstddef>
#include <utility>
#include <bit>

#elif defined(BOOST_CRYPT_HAS_CUDA)

#include <cuda/std/span>
#include <cuda/std/array>
#include <cuda/std/cstdint>
#include <cuda/std/cstddef>
#include <cuda/std/type_traits>
#include <cuda/std/concepts>
#include <cuda/std/ranges>
#include <cuda/std/utility>
#include <cuda/std/bit>

#endif

namespace boost::crypt::compat {

// Fixed width types
#ifdef BOOST_CRYPT_HAS_CUDA
using size_t = cuda::std::size_t;
using uint32_t = cuda::std::uint32_t;
#else
using size_t = std::size_t;
using uint32_t = std::uint32_t;
#endif

// Arrays and spans
template <typename T, compat::size_t N>
#ifdef BOOST_CRYPT_HAS_CUDA
using array = cuda::std::array<T, N>;
#else
using array = std::array<T, N>;
#endif

#ifdef BOOST_CRYPT_HAS_CUDA
template<typename T, cuda::std::size_t Extent = cuda::std::dynamic_extent>
using span = cuda::std::span<T, Extent>;
#else
template<typename T, std::size_t Extent = std::dynamic_extent>
using span = std::span<T, Extent>;
#endif

// Byte and friends
#ifdef BOOST_CRYPT_HAS_CUDA
using byte = cuda::std::byte;
#else
using byte = std::byte;
#endif

template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto as_bytes(span<T> s) noexcept
{
    #ifdef BOOST_CRYPT_HAS_CUDA
    return cuda::std::as_bytes(s);
    #else
    return std::as_bytes(s);
    #endif
}

template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto as_writable_bytes(span<T> s) noexcept
{
    #ifdef BOOST_CRYPT_HAS_CUDA
    return cuda::std::as_writable_bytes(s);
    #else
    return std::as_writable_bytes(s);
    #endif
}

// Type traits
#ifdef BOOST_CRYPT_HAS_CUDA
using true_type = cuda::std::true_type;
using false_type = cuda::std::false_type;
#else
using true_type = std::true_type;
using false_type = std::false_type;
#endif

template <typename T>
inline constexpr bool is_trivially_copyable_v =
    #ifdef BOOST_CRYPT_HAS_CUDA
    cuda::std::is_trivially_copyable_v<T>;
    #else
    std::is_trivially_copyable_v<T>;
    #endif

template <typename T>
using remove_reference_t =
    #ifdef BOOST_CRYPT_HAS_CUDA
    cuda::std::remove_reference_t<T>;
    #else
    std::remove_reference_t<T>;
    #endif

template <typename T>
using remove_cvref_t =
    #ifdef BOOST_CRYPT_HAS_CUDA
    cuda::std::remove_cv_t<cuda::std::remove_reference_t<T>>;
    #else
    std::remove_cv_t<std::remove_reference_t<T>>;
    #endif

// Ranges concepts and utilities
template <typename R>
concept sized_range =
    #ifdef BOOST_CRYPT_HAS_CUDA
    cuda::std::ranges::sized_range<R>;
    #else
    std::ranges::sized_range<R>;
    #endif

template <typename R, typename T>
concept output_range =
    #ifdef BOOST_CRYPT_HAS_CUDA
    cuda::std::ranges::output_range<R, T>;
    #else
    std::ranges::output_range<R, T>;
    #endif

template <typename R>
using range_value_t =
    #ifdef BOOST_CRYPT_HAS_CUDA
    cuda::std::ranges::range_value_t<R>;
    #else
    std::ranges::range_value_t<R>;
    #endif

// Utilities
template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto forward(remove_reference_t<T>& t) noexcept -> T&&
{
    #ifdef BOOST_CRYPT_HAS_CUDA
    return cuda::std::forward<T>(t);
    #else
    return std::forward<T>(t);
    #endif
}

template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto forward(remove_reference_t<T>&& t) noexcept -> T&&
{
    #ifdef BOOST_CRYPT_HAS_CUDA
    return cuda::std::forward<T>(cuda::std::move(t));
    #else
    return std::forward<T>(std::move(t));
    #endif
}

// Helper functions
template <typename T>
struct is_span : false_type {};

template <typename T, size_t Extent>
struct is_span<span<T, Extent>> : true_type {};

template <typename T, size_t Extent>
struct is_span<const span<T, Extent>> : true_type {};

// Helper variable template
template<typename T>
inline constexpr bool is_span_v = is_span<T>::value;

template <typename R>
BOOST_CRYPT_GPU_ENABLED constexpr auto make_span(R&& r)
{
    if constexpr (is_span_v<remove_cvref_t<R>>)
    {
        #ifdef BOOST_CRYPT_HAS_CUDA
        return cuda::std::forward<R>(r);
        #else
        return std::forward<R>(r);
        #endif
    }
    else
    {
        #ifdef BOOST_CRYPT_HAS_CUDA
        return cuda::std::span(cuda::std::forward<R>(r));
        #else
        return std::span(std::forward<R>(r));
        #endif
    }
}

template <typename R>
BOOST_CRYPT_GPU_ENABLED constexpr auto make_span(R& r)
{
    if constexpr (is_span_v<remove_cvref_t<R>>)
    {
        return r;
    }
    else
    {
        #ifdef BOOST_CRYPT_HAS_CUDA
        return cuda::std::span(r);
        #else
        return std::span(r);
        #endif
    }
}

// bit
template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto rotl(T val, int shift) noexcept
{
    // Some clangs incorrectly warn on shift being an int instead of an unsigned int
    // C++ standard says shift is to be int
    #ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wsign-conversion"
    #endif

    #ifdef BOOST_CRYPT_HAS_CUDA
    return cuda::std::rotl(val, shift);
    #else
    return std::rotl(val, shift);
    #endif

    #ifdef __clang__
    #pragma clang diagnostic pop
    #endif
}

} // namespace boost::crypt::compat

#endif // BOOST_CRYPT2_DETAIL_COMPAT_HPP
