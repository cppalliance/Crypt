// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt


#ifndef BOOST_CRYPT_HASH_SHA3_256_HPP
#define BOOST_CRYPT_HASH_SHA3_256_HPP

#include <boost/crypt/hash/detail/sha3_base.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT using sha3_256_hasher = hash_detail::sha3_base<32U>;

namespace detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(T begin, T end) noexcept -> sha3_256_hasher::return_type
{
    if (end < begin)
    {
        return sha3_256_hasher::return_type {};
    }
    else if (end == begin)
    {
        return sha3_256_hasher::return_type {
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
        };
    }

    sha3_256_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    auto result {hasher.get_digest()};

    return result;
}

} // namespace detail

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(const char* str) noexcept -> sha3_256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha3_256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(const char* str, boost::crypt::size_t len) noexcept -> sha3_256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha3_256(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(const boost::crypt::uint8_t* str) noexcept -> sha3_256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha3_256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(const boost::crypt::uint8_t* str, boost::crypt::size_t len) noexcept -> sha3_256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha3_256(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(const char16_t* str) noexcept -> sha3_256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha3_256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(const char16_t* str, boost::crypt::size_t len) noexcept -> sha3_256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha3_256(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(const char32_t* str) noexcept -> sha3_256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha3_256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(const char32_t* str, boost::crypt::size_t len) noexcept -> sha3_256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha3_256(str, str + len);
}

// On some platforms wchar_t is 16 bits and others it's 32
// Since we check sizeof() the underlying with SFINAE in the actual implementation this is handled transparently
BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(const wchar_t* str) noexcept -> sha3_256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha3_256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(const wchar_t* str, boost::crypt::size_t len) noexcept -> sha3_256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha3_256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha3_256(str, str + len);
}

// ----- String and String view aren't in the libcu++ STL so they so not have device markers -----

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_EXPORT inline auto sha3_256(const std::string& str) noexcept -> sha3_256_hasher::return_type
{
    return detail::sha3_256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha3_256(const std::u16string& str) noexcept -> sha3_256_hasher::return_type
{
    return detail::sha3_256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha3_256(const std::u32string& str) noexcept -> sha3_256_hasher::return_type
{
    return detail::sha3_256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha3_256(const std::wstring& str) noexcept -> sha3_256_hasher::return_type
{
    return detail::sha3_256(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT constexpr auto sha3_256(std::string_view str) -> sha3_256_hasher::return_type
{
    return detail::sha3_256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT constexpr auto sha3_256(std::u16string_view str) -> sha3_256_hasher::return_type
{
    return detail::sha3_256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT constexpr auto sha3_256(std::u32string_view str) -> sha3_256_hasher::return_type
{
    return detail::sha3_256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT constexpr auto sha3_256(std::wstring_view str) -> sha3_256_hasher::return_type
{
    return detail::sha3_256(str.begin(), str.end());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

// ---- CUDA also does not have the ability to consume files -----

namespace detail {

template <boost::crypt::size_t block_size>
auto sha3_256_file_impl(utility::file_reader<block_size>& reader) noexcept -> sha3_256_hasher::return_type
{
    sha3_256_hasher hasher;
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

BOOST_CRYPT_EXPORT inline auto sha3_256_file(const std::string& filepath) noexcept -> sha3_256_hasher::return_type
{
    try
    {
        utility::file_reader<136U> reader(filepath);
        return detail::sha3_256_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha3_256_hasher::return_type{};
    }
}

BOOST_CRYPT_EXPORT inline auto sha3_256_file(const char* filepath) noexcept -> sha3_256_hasher::return_type
{
    try
    {
        if (filepath == nullptr)
        {
            return sha3_256_hasher::return_type{};
        }

        utility::file_reader<136U> reader(filepath);
        return detail::sha3_256_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha3_256_hasher::return_type{};
    }
}

#endif // !BOOST_CRYPT_DISABLE_IOSTREAM

#if (defined(BOOST_CRYPT_HAS_STRING_VIEW) && !defined(BOOST_CRYPT_DISABLE_IOSTREAM))

BOOST_CRYPT_EXPORT inline auto sha3_256_file(std::string_view filepath) noexcept -> sha3_256_hasher::return_type
{
    try
    {
        utility::file_reader<136U> reader(filepath);
        return detail::sha3_256_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha3_256_hasher::return_type{};
    }
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW && !BOOST_CRYPT_DISABLE_IOSTREAM

#endif // BOOST_CRYPT_HAS_CUDA

// ---- The CUDA versions that we support all offer <cuda/std/span> ----

#ifdef BOOST_CRYPT_HAS_SPAN

BOOST_CRYPT_EXPORT template <typename T, std::size_t extent>
constexpr auto sha3_256(std::span<T, extent> data) noexcept -> sha3_256_hasher::return_type
{
    return detail::sha3_256(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED constexpr auto sha3_256(cuda::std::span<T, extent> data) noexcept -> sha3_256_hasher::return_type
{
    return detail::sha3_256(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_SHA3_256_HPP
