// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc6234
// See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=31

#ifndef BOOST_CRYPT_HASH_SHA512_HPP
#define BOOST_CRYPT_HASH_SHA512_HPP

#include <boost/crypt/hash/detail/sha512_base.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT using sha512_hasher = hash_detail::sha512_base<64U>;

namespace detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED inline auto sha512(T begin, T end) noexcept -> sha512_hasher::return_type
{
    if (end < begin)
    {
        return sha512_hasher::return_type {};
    }
    else if (end == begin)
    {
        return sha512_hasher::return_type {
                0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
                0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
                0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
                0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
                0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
                0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
                0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
        };
    }

    sha512_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    auto result {hasher.get_digest()};

    return result;
}

} // namespace detail

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha512(const char* str) noexcept -> sha512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha512(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha512(const char* str, boost::crypt::size_t len) noexcept -> sha512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha512(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha512(const boost::crypt::uint8_t* str) noexcept -> sha512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha512(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha512(const boost::crypt::uint8_t* str, boost::crypt::size_t len) noexcept -> sha512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha512(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha512(const char16_t* str) noexcept -> sha512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha512(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha512(const char16_t* str, boost::crypt::size_t len) noexcept -> sha512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha512(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha512(const char32_t* str) noexcept -> sha512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha512(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha512(const char32_t* str, boost::crypt::size_t len) noexcept -> sha512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha512(str, str + len);
}

// On some platforms wchar_t is 16 bits and others it's 32
// Since we check sizeof() the underlying with SFINAE in the actual implementation this is handled transparently
BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha512(const wchar_t* str) noexcept -> sha512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha512(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha512(const wchar_t* str, boost::crypt::size_t len) noexcept -> sha512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha512(str, str + len);
}

// ----- String and String view aren't in the libcu++ STL so they so not have device markers -----

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_EXPORT inline auto sha512(const std::string& str) noexcept -> sha512_hasher::return_type
{
    return detail::sha512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha512(const std::u16string& str) noexcept -> sha512_hasher::return_type
{
    return detail::sha512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha512(const std::u32string& str) noexcept -> sha512_hasher::return_type
{
    return detail::sha512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha512(const std::wstring& str) noexcept -> sha512_hasher::return_type
{
    return detail::sha512(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto sha512(std::string_view str) -> sha512_hasher::return_type
{
    return detail::sha512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha512(std::u16string_view str) -> sha512_hasher::return_type
{
    return detail::sha512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha512(std::u32string_view str) -> sha512_hasher::return_type
{
    return detail::sha512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha512(std::wstring_view str) -> sha512_hasher::return_type
{
    return detail::sha512(str.begin(), str.end());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

// ---- CUDA also does not have the ability to consume files -----

namespace detail {

template <boost::crypt::size_t block_size = 64U>
auto sha512_file_impl(utility::file_reader<block_size>& reader) noexcept -> sha512_hasher::return_type
{
    sha512_hasher hasher;
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

BOOST_CRYPT_EXPORT inline auto sha512_file(const std::string& filepath) noexcept -> sha512_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha512_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha512_hasher::return_type{};
    }
}

BOOST_CRYPT_EXPORT inline auto sha512_file(const char* filepath) noexcept -> sha512_hasher::return_type
{
    try
    {
        if (filepath == nullptr)
        {
            return sha512_hasher::return_type{};
        }

        utility::file_reader<64U> reader(filepath);
        return detail::sha512_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha512_hasher::return_type{};
    }
}

#endif // !BOOST_CRYPT_DISABLE_IOSTREAM

#if (defined(BOOST_CRYPT_HAS_STRING_VIEW) && !defined(BOOST_CRYPT_DISABLE_IOSTREAM))

BOOST_CRYPT_EXPORT inline auto sha512_file(std::string_view filepath) noexcept -> sha512_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha512_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha512_hasher::return_type{};
    }
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW && !BOOST_CRYPT_DISABLE_IOSTREAM

#endif // BOOST_CRYPT_HAS_CUDA

// ---- The CUDA versions that we support all offer <cuda/std/span> ----

#ifdef BOOST_CRYPT_HAS_SPAN

BOOST_CRYPT_EXPORT template <typename T, std::size_t extent>
inline auto sha512(std::span<T, extent> data) noexcept -> sha512_hasher::return_type
{
    return detail::sha512(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED inline auto sha512(cuda::std::span<T, extent> data) noexcept -> sha512_hasher::return_type
{
    return detail::sha512(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_SHA512_HPP
