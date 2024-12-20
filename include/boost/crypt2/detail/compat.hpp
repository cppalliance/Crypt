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

namespace boost::crypt::compat {
    namespace detail = std;
}

#elif defined(BOOST_CRYPT_HAS_CUDA)

#include <cuda/std/span>
#include <cuda/std/array>
#include <cuda/std/cstdint>
#include <cuda/std/cstddef>
#include <cuda/std/type_traits>
#include <cuda/std/concepts>
#include <cuda/std/ranges>
#include <cuda/std/utility>

namespace boost::crypt::compat {
    namespace detail = cuda::std;
}

#endif

namespace boost::crypt::compat {

// Fixed width types
using size_t = detail::size_t;
using uint32_t = detail::uint32_t;

// Arrays and spans
template <typename T, compat::size_t N>
using array = detail::array<T, N>;

template<typename T, compat::size_t Extent = detail::dynamic_extent>
using span = detail::span<T, Extent>;

// Byte and friends
using byte = detail::byte;

template <typename T>
constexpr auto as_bytes(span<T> s) noexcept
{
    return detail::as_bytes(s);
}

template <typename T>
constexpr auto as_writable_bytes(span<T> s) noexcept
{
    return detail::as_writable_bytes(s);
}

// Type traits
template <typename T>
inline constexpr bool is_trivially_copyable_v = detail::is_trivially_copyable_v<T>;

// Ranges concepts and utilities
template <typename R>
concept sized_range = detail::ranges::sized_range<R>;

template <typename R, typename T>
concept output_range = detail::ranges::output_range<R, T>;

template <typename R>
using range_value_t = detail::ranges::range_value_t<R>;

// Utilities
template <typename T>
constexpr auto forward(detail::remove_reference_t<T>& t) noexcept -> T&&
{
    return detail::forward<T>(t);
}

template <typename T>
constexpr auto forward(detail::remove_reference_t<T>&& t) noexcept -> T&&
{
    return detail::forward<T>(detail::move(t));
}

} // namespace boost::crypt::compat

#endif // BOOST_CRYPT2_DETAIL_COMPAT_HPP
