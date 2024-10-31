// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt


#ifndef BOOST_CRYPT_HASH_SHAKE128_HPP
#define BOOST_CRYPT_HASH_SHAKE128_HPP

#include <boost/crypt/hash/detail/sha3_base.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT using shake128_hasher = hash_detail::sha3_base<16U, true>;

namespace detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(T begin, T end) noexcept -> shake128_hasher::return_type
{
    if (end < begin)
    {
        return shake128_hasher::return_type {};
    }
    else if (end == begin)
    {
        return shake128_hasher::return_type {
            0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e
        };
    }

    shake128_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    auto result {hasher.get_digest()};

    return result;
}

} // namespace detail

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(const char* str) noexcept -> shake128_hasher::return_type
{
    if (str == nullptr)
    {
        return shake128_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::shake128(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(const char* str, boost::crypt::size_t len) noexcept -> shake128_hasher::return_type
{
    if (str == nullptr)
    {
        return shake128_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::shake128(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(const boost::crypt::uint8_t* str) noexcept -> shake128_hasher::return_type
{
    if (str == nullptr)
    {
        return shake128_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::shake128(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(const boost::crypt::uint8_t* str, boost::crypt::size_t len) noexcept -> shake128_hasher::return_type
{
    if (str == nullptr)
    {
        return shake128_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::shake128(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(const char16_t* str) noexcept -> shake128_hasher::return_type
{
    if (str == nullptr)
    {
        return shake128_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::shake128(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(const char16_t* str, boost::crypt::size_t len) noexcept -> shake128_hasher::return_type
{
    if (str == nullptr)
    {
        return shake128_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::shake128(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(const char32_t* str) noexcept -> shake128_hasher::return_type
{
    if (str == nullptr)
    {
        return shake128_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::shake128(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(const char32_t* str, boost::crypt::size_t len) noexcept -> shake128_hasher::return_type
{
    if (str == nullptr)
    {
        return shake128_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::shake128(str, str + len);
}

// On some platforms wchar_t is 16 bits and others it's 32
// Since we check sizeof() the underlying with SFINAE in the actual implementation this is handled transparently
BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(const wchar_t* str) noexcept -> shake128_hasher::return_type
{
    if (str == nullptr)
    {
        return shake128_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::shake128(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(const wchar_t* str, boost::crypt::size_t len) noexcept -> shake128_hasher::return_type
{
    if (str == nullptr)
    {
        return shake128_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::shake128(str, str + len);
}

// ----- String and String view aren't in the libcu++ STL so they so not have device markers -----

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_EXPORT inline auto shake128(const std::string& str) noexcept -> shake128_hasher::return_type
{
    return detail::shake128(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto shake128(const std::u16string& str) noexcept -> shake128_hasher::return_type
{
    return detail::shake128(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto shake128(const std::u32string& str) noexcept -> shake128_hasher::return_type
{
    return detail::shake128(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto shake128(const std::wstring& str) noexcept -> shake128_hasher::return_type
{
    return detail::shake128(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT constexpr auto shake128(std::string_view str) -> shake128_hasher::return_type
{
    return detail::shake128(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT constexpr auto shake128(std::u16string_view str) -> shake128_hasher::return_type
{
    return detail::shake128(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT constexpr auto shake128(std::u32string_view str) -> shake128_hasher::return_type
{
    return detail::shake128(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT constexpr auto shake128(std::wstring_view str) -> shake128_hasher::return_type
{
    return detail::shake128(str.begin(), str.end());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

// ---- CUDA also does not have the ability to consume files -----

namespace detail {

template <boost::crypt::size_t block_size>
auto shake128_file_impl(utility::file_reader<block_size>& reader) noexcept -> shake128_hasher::return_type
{
    shake128_hasher hasher;
    while (!reader.eof())
    {
        const auto buffer_iter {reader.read_next_block()};
        const auto len {reader.get_bytes_read()};
        hasher.process_bytes(buffer_iter, len);
    }

    return hasher.get_digest();
}

} // namespace detail

#ifndef BOOST_CRYPT_DISABLE_IOSTREAM

BOOST_CRYPT_EXPORT inline auto shake128_file(const std::string& filepath) noexcept -> shake128_hasher::return_type
{
    try
    {
        utility::file_reader<168U> reader(filepath);
        return detail::shake128_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return shake128_hasher::return_type{};
    }
}

BOOST_CRYPT_EXPORT inline auto shake128_file(const char* filepath) noexcept -> shake128_hasher::return_type
{
    try
    {
        if (filepath == nullptr)
        {
            return shake128_hasher::return_type{};
        }

        utility::file_reader<168U> reader(filepath);
        return detail::shake128_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return shake128_hasher::return_type{};
    }
}

#endif // !BOOST_CRYPT_DISABLE_IOSTREAM

#if (defined(BOOST_CRYPT_HAS_STRING_VIEW) && !defined(BOOST_CRYPT_DISABLE_IOSTREAM))

BOOST_CRYPT_EXPORT inline auto shake128_file(std::string_view filepath) noexcept -> shake128_hasher::return_type
{
    try
    {
        utility::file_reader<168U> reader(filepath);
        return detail::shake128_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return shake128_hasher::return_type{};
    }
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW && !BOOST_CRYPT_DISABLE_IOSTREAM

#endif // BOOST_CRYPT_HAS_CUDA

// ---- The CUDA versions that we support all offer <cuda/std/span> ----

#ifdef BOOST_CRYPT_HAS_SPAN

BOOST_CRYPT_EXPORT template <typename T, std::size_t extent>
constexpr auto shake128(std::span<T, extent> data) noexcept -> shake128_hasher::return_type
{
    return detail::shake128(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED constexpr auto shake128(cuda::std::span<T, extent> data) noexcept -> shake128_hasher::return_type
{
    return detail::shake128(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_SHAKE128_HPP
