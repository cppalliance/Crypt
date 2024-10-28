// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt


#ifndef BOOST_CRYPT_HASH_SHA3_512_HPP
#define BOOST_CRYPT_HASH_SHA3_512_HPP

#include <boost/crypt/hash/detail/sha3_base.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT using sha3_512_hasher = hash_detail::sha3_base<64U>;

namespace detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(T begin, T end) noexcept -> sha3_512_hasher::return_type
{
    if (end < begin)
    {
        return sha3_512_hasher::return_type {};
    }
    else if (end == begin)
    {
        return sha3_512_hasher::return_type {
            0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8,
            0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e, 0x97,
            0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0,
            0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6, 0x15,
            0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11,
            0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58, 0xf5,
            0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01,
            0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26
        };
    }

    sha3_512_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    auto result {hasher.get_digest()};

    return result;
}

} // namespace detail

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(const char* str) noexcept -> sha3_512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha3_512(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(const char* str, boost::crypt::size_t len) noexcept -> sha3_512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha3_512(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(const boost::crypt::uint8_t* str) noexcept -> sha3_512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha3_512(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(const boost::crypt::uint8_t* str, boost::crypt::size_t len) noexcept -> sha3_512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha3_512(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(const char16_t* str) noexcept -> sha3_512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha3_512(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(const char16_t* str, boost::crypt::size_t len) noexcept -> sha3_512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha3_512(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(const char32_t* str) noexcept -> sha3_512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha3_512(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(const char32_t* str, boost::crypt::size_t len) noexcept -> sha3_512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha3_512(str, str + len);
}

// On some platforms wchar_t is 16 bits and others it's 32
// Since we check sizeof() the underlying with SFINAE in the actual implementation this is handled transparently
BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(const wchar_t* str) noexcept -> sha3_512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha3_512(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(const wchar_t* str, boost::crypt::size_t len) noexcept -> sha3_512_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_512_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha3_512(str, str + len);
}

// ----- String and String view aren't in the libcu++ STL so they so not have device markers -----

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_EXPORT inline auto sha3_512(const std::string& str) noexcept -> sha3_512_hasher::return_type
{
    return detail::sha3_512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha3_512(const std::u16string& str) noexcept -> sha3_512_hasher::return_type
{
    return detail::sha3_512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha3_512(const std::u32string& str) noexcept -> sha3_512_hasher::return_type
{
    return detail::sha3_512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha3_512(const std::wstring& str) noexcept -> sha3_512_hasher::return_type
{
    return detail::sha3_512(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto sha3_512(std::string_view str) -> sha3_512_hasher::return_type
{
    return detail::sha3_512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha3_512(std::u16string_view str) -> sha3_512_hasher::return_type
{
    return detail::sha3_512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha3_512(std::u32string_view str) -> sha3_512_hasher::return_type
{
    return detail::sha3_512(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha3_512(std::wstring_view str) -> sha3_512_hasher::return_type
{
    return detail::sha3_512(str.begin(), str.end());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

// ---- CUDA also does not have the ability to consume files -----

namespace detail {

template <boost::crypt::size_t block_size = 64U>
auto sha3_512_file_impl(utility::file_reader<block_size>& reader) noexcept -> sha3_512_hasher::return_type
{
    sha3_512_hasher hasher;
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

BOOST_CRYPT_EXPORT inline auto sha3_512_file(const std::string& filepath) noexcept -> sha3_512_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha3_512_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha3_512_hasher::return_type{};
    }
}

BOOST_CRYPT_EXPORT inline auto sha3_512_file(const char* filepath) noexcept -> sha3_512_hasher::return_type
{
    try
    {
        if (filepath == nullptr)
        {
            return sha3_512_hasher::return_type{};
        }

        utility::file_reader<64U> reader(filepath);
        return detail::sha3_512_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha3_512_hasher::return_type{};
    }
}

#endif // !BOOST_CRYPT_DISABLE_IOSTREAM

#if (defined(BOOST_CRYPT_HAS_STRING_VIEW) && !defined(BOOST_CRYPT_DISABLE_IOSTREAM))

BOOST_CRYPT_EXPORT inline auto sha3_512_file(std::string_view filepath) noexcept -> sha3_512_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha3_512_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha3_512_hasher::return_type{};
    }
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW && !BOOST_CRYPT_DISABLE_IOSTREAM

#endif // BOOST_CRYPT_HAS_CUDA

// ---- The CUDA versions that we support all offer <cuda/std/span> ----

#ifdef BOOST_CRYPT_HAS_SPAN

BOOST_CRYPT_EXPORT template <typename T, std::size_t extent>
inline auto sha3_512(std::span<T, extent> data) noexcept -> sha3_512_hasher::return_type
{
    return detail::sha3_512(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED inline auto sha3_512(cuda::std::span<T, extent> data) noexcept -> sha3_512_hasher::return_type
{
    return detail::sha3_512(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_SHA3_512_HPP
