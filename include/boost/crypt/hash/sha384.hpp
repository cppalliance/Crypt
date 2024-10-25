// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc6234
// See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=31

#ifndef BOOST_CRYPT_HASH_SHA384_HPP
#define BOOST_CRYPT_HASH_SHA384_HPP

#include <boost/crypt/hash/detail/sha512_base.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT using sha384_hasher = hash_detail::sha512_base<48U>;

namespace detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED inline auto sha384(T begin, T end) noexcept -> sha384_hasher::return_type
{
    if (end < begin)
    {
        return sha384_hasher::return_type {};
    }
    else if (end == begin)
    {
        return sha384_hasher::return_type {
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
            0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
            0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
            0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
            0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
            0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
        };
    }

    sha384_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    auto result {hasher.get_digest()};

    return result;
}

} // namespace detail

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha384(const char* str) noexcept -> sha384_hasher::return_type
{
    if (str == nullptr)
    {
        return sha384_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha384(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha384(const char* str, boost::crypt::size_t len) noexcept -> sha384_hasher::return_type
{
    if (str == nullptr)
    {
        return sha384_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha384(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha384(const boost::crypt::uint8_t* str) noexcept -> sha384_hasher::return_type
{
    if (str == nullptr)
    {
        return sha384_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha384(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha384(const boost::crypt::uint8_t* str, boost::crypt::size_t len) noexcept -> sha384_hasher::return_type
{
    if (str == nullptr)
    {
        return sha384_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha384(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha384(const char16_t* str) noexcept -> sha384_hasher::return_type
{
    if (str == nullptr)
    {
        return sha384_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha384(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha384(const char16_t* str, boost::crypt::size_t len) noexcept -> sha384_hasher::return_type
{
    if (str == nullptr)
    {
        return sha384_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha384(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha384(const char32_t* str) noexcept -> sha384_hasher::return_type
{
    if (str == nullptr)
    {
        return sha384_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha384(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha384(const char32_t* str, boost::crypt::size_t len) noexcept -> sha384_hasher::return_type
{
    if (str == nullptr)
    {
        return sha384_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha384(str, str + len);
}

// On some platforms wchar_t is 16 bits and others it's 32
// Since we check sizeof() the underlying with SFINAE in the actual implementation this is handled transparently
BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha384(const wchar_t* str) noexcept -> sha384_hasher::return_type
{
    if (str == nullptr)
    {
        return sha384_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha384(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha384(const wchar_t* str, boost::crypt::size_t len) noexcept -> sha384_hasher::return_type
{
    if (str == nullptr)
    {
        return sha384_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha384(str, str + len);
}

// ----- String and String view aren't in the libcu++ STL so they so not have device markers -----

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_EXPORT inline auto sha384(const std::string& str) noexcept -> sha384_hasher::return_type
{
    return detail::sha384(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha384(const std::u16string& str) noexcept -> sha384_hasher::return_type
{
    return detail::sha384(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha384(const std::u32string& str) noexcept -> sha384_hasher::return_type
{
    return detail::sha384(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha384(const std::wstring& str) noexcept -> sha384_hasher::return_type
{
    return detail::sha384(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto sha384(std::string_view str) -> sha384_hasher::return_type
{
    return detail::sha384(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha384(std::u16string_view str) -> sha384_hasher::return_type
{
    return detail::sha384(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha384(std::u32string_view str) -> sha384_hasher::return_type
{
    return detail::sha384(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha384(std::wstring_view str) -> sha384_hasher::return_type
{
    return detail::sha384(str.begin(), str.end());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

// ---- CUDA also does not have the ability to consume files -----

namespace detail {

template <boost::crypt::size_t block_size = 64U>
auto sha384_file_impl(utility::file_reader<block_size>& reader) noexcept -> sha384_hasher::return_type
{
    sha384_hasher hasher;
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

BOOST_CRYPT_EXPORT inline auto sha384_file(const std::string& filepath) noexcept -> sha384_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha384_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha384_hasher::return_type{};
    }
}

BOOST_CRYPT_EXPORT inline auto sha384_file(const char* filepath) noexcept -> sha384_hasher::return_type
{
    try
    {
        if (filepath == nullptr)
        {
            return sha384_hasher::return_type{};
        }

        utility::file_reader<64U> reader(filepath);
        return detail::sha384_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha384_hasher::return_type{};
    }
}

#endif // !BOOST_CRYPT_DISABLE_IOSTREAM

#if (defined(BOOST_CRYPT_HAS_STRING_VIEW) && !defined(BOOST_CRYPT_DISABLE_IOSTREAM))

BOOST_CRYPT_EXPORT inline auto sha384_file(std::string_view filepath) noexcept -> sha384_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha384_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha384_hasher::return_type{};
    }
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW && !BOOST_CRYPT_DISABLE_IOSTREAM

#endif // BOOST_CRYPT_HAS_CUDA

// ---- The CUDA versions that we support all offer <cuda/std/span> ----

#ifdef BOOST_CRYPT_HAS_SPAN

BOOST_CRYPT_EXPORT template <typename T, std::size_t extent>
inline auto sha384(std::span<T, extent> data) noexcept -> sha384_hasher::return_type
{
    return detail::sha384(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED inline auto sha384(cuda::std::span<T, extent> data) noexcept -> sha384_hasher::return_type
{
    return detail::sha384(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_SHA384_HPP
