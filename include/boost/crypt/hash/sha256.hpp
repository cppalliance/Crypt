// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc4634

#ifndef BOOST_CRYPT_HASH_SHA256_HPP
#define BOOST_CRYPT_HASH_SHA256_HPP

#include <boost/crypt/hash/detail/sha224_256_hasher.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT class sha256_hasher final : public hash_detail::sha_224_256_hasher<32U> {};

namespace detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED inline auto sha256(T begin, T end) noexcept -> sha256_hasher::return_type
{
    if (end < begin)
    {
        return sha256_hasher::return_type {};
    }
    else if (end == begin)
    {
        return sha256_hasher::return_type {
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        };
    }

    sha256_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    auto result {hasher.get_digest()};

    return result;
}

} // namespace detail

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char* str) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char* str, boost::crypt::size_t len) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha256(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const boost::crypt::uint8_t* str) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const boost::crypt::uint8_t* str, boost::crypt::size_t len) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha256(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char16_t* str) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char16_t* str, boost::crypt::size_t len) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha256(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char32_t* str) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char32_t* str, boost::crypt::size_t len) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha256(str, str + len);
}

// On some platforms wchar_t is 16 bits and others it's 32
// Since we check sizeof() the underlying with SFINAE in the actual implementation this is handled transparently
BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const wchar_t* str) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const wchar_t* str, boost::crypt::size_t len) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha256(str, str + len);
}

// ----- String and String view aren't in the libcu++ STL so they so not have device markers -----

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_EXPORT inline auto sha256(const std::string& str) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(const std::u16string& str) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(const std::u32string& str) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(const std::wstring& str) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto sha256(std::string_view str) -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(std::u16string_view str) -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(std::u32string_view str) -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(std::wstring_view str) -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

// ---- CUDA also does not have the ability to consume files -----

namespace detail {

template <boost::crypt::size_t block_size = 64U>
auto sha256_file_impl(utility::file_reader<block_size>& reader) noexcept -> sha256_hasher::return_type
{
    sha256_hasher hasher;
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

BOOST_CRYPT_EXPORT inline auto sha256_file(const std::string& filepath) noexcept -> sha256_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha256_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha256_hasher::return_type{};
    }
}

BOOST_CRYPT_EXPORT inline auto sha256_file(const char* filepath) noexcept -> sha256_hasher::return_type
{
    try
    {
        if (filepath == nullptr)
        {
            return sha256_hasher::return_type{};
        }

        utility::file_reader<64U> reader(filepath);
        return detail::sha256_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha256_hasher::return_type{};
    }
}

#endif // !BOOST_CRYPT_DISABLE_IOSTREAM

#if (defined(BOOST_CRYPT_HAS_STRING_VIEW) && !defined(BOOST_CRYPT_DISABLE_IOSTREAM))

BOOST_CRYPT_EXPORT inline auto sha256_file(std::string_view filepath) noexcept -> sha256_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha256_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha256_hasher::return_type{};
    }
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW && !BOOST_CRYPT_DISABLE_IOSTREAM

#endif // BOOST_CRYPT_HAS_CUDA

// ---- The CUDA versions that we support all offer <cuda/std/span> ----

#ifdef BOOST_CRYPT_HAS_SPAN

BOOST_CRYPT_EXPORT template <typename T, std::size_t extent>
inline auto sha256(std::span<T, extent> data) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED inline auto sha256(cuda::std::span<T, extent> data) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namepsace boost

#endif // BOOST_CRYPT_HASH_SHA256_HPP
