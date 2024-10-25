// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc4634

#ifndef BOOST_CRYPT_HASH_SHA224_HPP
#define BOOST_CRYPT_HASH_SHA224_HPP

#include <boost/crypt/hash/detail/sha224_256_hasher.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT using sha224_hasher = hash_detail::sha_224_256_hasher<28U>;

namespace detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED inline auto sha224(T begin, T end) noexcept -> sha224_hasher::return_type
{
    if (end < begin)
    {
        return sha224_hasher::return_type {};
    }
    else if (end == begin)
    {
        return boost::crypt::sha224_hasher::return_type {
            0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b,
            0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82,
            0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82,
            0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f
        };
    }

    sha224_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    auto result {hasher.get_digest()};

    return result;
}

} // namespace detail

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha224(const char* str) noexcept -> sha224_hasher::return_type
{
    if (str == nullptr)
    {
        return sha224_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha224(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha224(const char* str, boost::crypt::size_t len) noexcept -> sha224_hasher::return_type
{
    if (str == nullptr)
    {
        return sha224_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha224(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha224(const boost::crypt::uint8_t* str) noexcept -> sha224_hasher::return_type
{
    if (str == nullptr)
    {
        return sha224_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha224(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha224(const boost::crypt::uint8_t* str, boost::crypt::size_t len) noexcept -> sha224_hasher::return_type
{
    if (str == nullptr)
    {
        return sha224_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha224(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha224(const char16_t* str) noexcept -> sha224_hasher::return_type
{
    if (str == nullptr)
    {
        return sha224_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha224(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha224(const char16_t* str, boost::crypt::size_t len) noexcept -> sha224_hasher::return_type
{
    if (str == nullptr)
    {
        return sha224_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha224(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha224(const char32_t* str) noexcept -> sha224_hasher::return_type
{
    if (str == nullptr)
    {
        return sha224_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha224(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha224(const char32_t* str, boost::crypt::size_t len) noexcept -> sha224_hasher::return_type
{
    if (str == nullptr)
    {
        return sha224_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha224(str, str + len);
}

// On some platforms wchar_t is 16 bits and others it's 32
// Since we check sizeof() the underlying with SFINAE in the actual implementation this is handled transparently
BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha224(const wchar_t* str) noexcept -> sha224_hasher::return_type
{
    if (str == nullptr)
    {
        return sha224_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha224(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha224(const wchar_t* str, boost::crypt::size_t len) noexcept -> sha224_hasher::return_type
{
    if (str == nullptr)
    {
        return sha224_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha224(str, str + len);
}

// ----- String and String view aren't in the libcu++ STL so they so not have device markers -----

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_EXPORT inline auto sha224(const std::string& str) noexcept -> sha224_hasher::return_type
{
    return detail::sha224(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha224(const std::u16string& str) noexcept -> sha224_hasher::return_type
{
    return detail::sha224(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha224(const std::u32string& str) noexcept -> sha224_hasher::return_type
{
    return detail::sha224(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha224(const std::wstring& str) noexcept -> sha224_hasher::return_type
{
    return detail::sha224(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto sha224(std::string_view str) -> sha224_hasher::return_type
{
    return detail::sha224(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha224(std::u16string_view str) -> sha224_hasher::return_type
{
    return detail::sha224(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha224(std::u32string_view str) -> sha224_hasher::return_type
{
    return detail::sha224(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha224(std::wstring_view str) -> sha224_hasher::return_type
{
    return detail::sha224(str.begin(), str.end());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

// ---- CUDA also does not have the ability to consume files -----

namespace detail {

template <boost::crypt::size_t block_size = 64U>
auto sha224_file_impl(utility::file_reader<block_size>& reader) noexcept -> sha224_hasher::return_type
{
    sha224_hasher hasher;
    while (!reader.eof())
    {
        const auto buffer_iter {reader.read_next_block()};
        const auto len {reader.get_bytes_read()};
        hasher.process_bytes(buffer_iter, len);
    }

    return hasher.get_digest();
}

} // namespace detail

BOOST_CRYPT_EXPORT inline auto sha224_file(const std::string& filepath) noexcept -> sha224_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha224_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha224_hasher::return_type{};
    }
}

BOOST_CRYPT_EXPORT inline auto sha224_file(const char* filepath) noexcept -> sha224_hasher::return_type
{
    try
    {
        if (filepath == nullptr)
        {
            return sha224_hasher::return_type{};
        }

        utility::file_reader<64U> reader(filepath);
        return detail::sha224_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha224_hasher::return_type{};
    }
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto sha224_file(std::string_view filepath) noexcept -> sha224_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha224_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha224_hasher::return_type{};
    }
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

#endif // BOOST_CRYPT_HAS_CUDA

// ---- The CUDA versions that we support all offer <cuda/std/span> ----

#ifdef BOOST_CRYPT_HAS_SPAN

BOOST_CRYPT_EXPORT template <typename T, std::size_t extent>
inline auto sha224(std::span<T, extent> data) noexcept -> sha224_hasher::return_type
{
    return detail::sha224(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED inline auto sha224(cuda::std::span<T, extent> data) noexcept -> sha224_hasher::return_type
{
    return detail::sha224(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_SHA224_HPP
