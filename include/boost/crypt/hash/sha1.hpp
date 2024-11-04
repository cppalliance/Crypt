// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc3174

#ifndef BOOST_CRYPT_HASH_SHA1_HPP
#define BOOST_CRYPT_HASH_SHA1_HPP

#include <boost/crypt/hash/detail/hasher_base_512.hpp>
#include <boost/crypt/hash/hasher_state.hpp>
#include <boost/crypt/hash/hmac.hpp>
#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/bit.hpp>
#include <boost/crypt/utility/byte.hpp>
#include <boost/crypt/utility/array.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/type_traits.hpp>
#include <boost/crypt/utility/strlen.hpp>
#include <boost/crypt/utility/cstddef.hpp>
#include <boost/crypt/utility/iterator.hpp>
#include <boost/crypt/utility/file.hpp>
#include <boost/crypt/utility/null.hpp>

#if !defined(BOOST_CRYPT_BUILD_MODULE) && !defined(BOOST_CRYPT_HAS_CUDA)
#include <memory>
#include <string>
#include <cstdint>
#include <cstring>
#endif

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT class sha1_hasher final : public hash_detail::hasher_base_512<20U, 5U, sha1_hasher>
{
private:

    friend class hash_detail::hasher_base_512<20U, 5U, sha1_hasher>;

    BOOST_CRYPT_GPU_ENABLED constexpr auto process_message_block() noexcept -> void;

public:

    BOOST_CRYPT_GPU_ENABLED constexpr sha1_hasher() noexcept { this->init(); }

    BOOST_CRYPT_GPU_ENABLED constexpr auto init() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto get_digest() noexcept -> sha1_hasher::return_type { return get_base_digest(); }
};

BOOST_CRYPT_EXPORT using hmac_sha1 = hmac<sha1_hasher>;

BOOST_CRYPT_GPU_ENABLED constexpr auto sha1_hasher::init() noexcept -> void
{
    hash_detail::hasher_base_512<20U, 5U, sha1_hasher>::base_init();

    intermediate_hash_[0] = 0x67452301;
    intermediate_hash_[1] = 0xEFCDAB89;
    intermediate_hash_[2] = 0x98BADCFE;
    intermediate_hash_[3] = 0x10325476;
    intermediate_hash_[4] = 0xC3D2E1F0;
}

namespace sha1_detail {

BOOST_CRYPT_GPU_ENABLED constexpr auto round1(boost::crypt::uint32_t& A,
                                           boost::crypt::uint32_t& B,
                                           boost::crypt::uint32_t& C,
                                           boost::crypt::uint32_t& D,
                                           boost::crypt::uint32_t& E,
                                           boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(A, 5U) + ((B & C) | ((~B) & D)) + E + W + 0x5A827999U};
    E = D;
    D = C;
    C = detail::rotl(B, 30U);
    B = A;
    A = temp;
}

BOOST_CRYPT_GPU_ENABLED constexpr auto round2(boost::crypt::uint32_t& A,
                                           boost::crypt::uint32_t& B,
                                           boost::crypt::uint32_t& C,
                                           boost::crypt::uint32_t& D,
                                           boost::crypt::uint32_t& E,
                                           boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(A, 5U) + (B ^ C ^ D) + E + W + 0x6ED9EBA1U};
    E = D;
    D = C;
    C = detail::rotl(B, 30U);
    B = A;
    A = temp;
}

BOOST_CRYPT_GPU_ENABLED constexpr auto round3(boost::crypt::uint32_t& A,
                                           boost::crypt::uint32_t& B,
                                           boost::crypt::uint32_t& C,
                                           boost::crypt::uint32_t& D,
                                           boost::crypt::uint32_t& E,
                                           boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(A, 5U) + ((B & C) | (B & D) | (C & D)) + E + W + 0x8F1BBCDCU};
    E = D;
    D = C;
    C = detail::rotl(B, 30U);
    B = A;
    A = temp;
}

BOOST_CRYPT_GPU_ENABLED constexpr auto round4(boost::crypt::uint32_t& A,
                                           boost::crypt::uint32_t& B,
                                           boost::crypt::uint32_t& C,
                                           boost::crypt::uint32_t& D,
                                           boost::crypt::uint32_t& E,
                                           boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(A, 5U) + (B ^ C ^ D) + E + W + 0xCA62C1D6U};
    E = D;
    D = C;
    C = detail::rotl(B, 30U);
    B = A;
    A = temp;
}

} // Namespace sha1_detail

// See definitions from the RFC on the rounds
BOOST_CRYPT_GPU_ENABLED constexpr auto sha1_hasher::process_message_block() noexcept -> void
{
    using namespace sha1_detail;

    boost::crypt::array<boost::crypt::uint32_t, 80> W {};

    // Init the first 16 words of W
    for (boost::crypt::size_t i {}; i < 16UL; ++i)
    {
        W[i] = (static_cast<boost::crypt::uint32_t>(buffer_[i * 4U]) << 24U) |
               (static_cast<boost::crypt::uint32_t>(buffer_[i * 4U + 1U]) << 16U) |
               (static_cast<boost::crypt::uint32_t>(buffer_[i * 4U + 2U]) << 8U) |
               (static_cast<boost::crypt::uint32_t>(buffer_[i * 4U + 3U]));

    }

    for (boost::crypt::size_t i {16U}; i < W.size(); ++i)
    {
        W[i] = detail::rotl(W[i - 3U] ^ W[i - 8U] ^ W[i - 14] ^ W[i - 16], 1U);
    }

    auto A {intermediate_hash_[0]};
    auto B {intermediate_hash_[1]};
    auto C {intermediate_hash_[2]};
    auto D {intermediate_hash_[3]};
    auto E {intermediate_hash_[4]};

    // Round 1
    round1(A, B, C, D, E, W[0]);
    round1(A, B, C, D, E, W[1]);
    round1(A, B, C, D, E, W[2]);
    round1(A, B, C, D, E, W[3]);
    round1(A, B, C, D, E, W[4]);
    round1(A, B, C, D, E, W[5]);
    round1(A, B, C, D, E, W[6]);
    round1(A, B, C, D, E, W[7]);
    round1(A, B, C, D, E, W[8]);
    round1(A, B, C, D, E, W[9]);
    round1(A, B, C, D, E, W[10]);
    round1(A, B, C, D, E, W[11]);
    round1(A, B, C, D, E, W[12]);
    round1(A, B, C, D, E, W[13]);
    round1(A, B, C, D, E, W[14]);
    round1(A, B, C, D, E, W[15]);
    round1(A, B, C, D, E, W[16]);
    round1(A, B, C, D, E, W[17]);
    round1(A, B, C, D, E, W[18]);
    round1(A, B, C, D, E, W[19]);

    // Round 2
    round2(A, B, C, D, E, W[20]);
    round2(A, B, C, D, E, W[21]);
    round2(A, B, C, D, E, W[22]);
    round2(A, B, C, D, E, W[23]);
    round2(A, B, C, D, E, W[24]);
    round2(A, B, C, D, E, W[25]);
    round2(A, B, C, D, E, W[26]);
    round2(A, B, C, D, E, W[27]);
    round2(A, B, C, D, E, W[28]);
    round2(A, B, C, D, E, W[29]);
    round2(A, B, C, D, E, W[30]);
    round2(A, B, C, D, E, W[31]);
    round2(A, B, C, D, E, W[32]);
    round2(A, B, C, D, E, W[33]);
    round2(A, B, C, D, E, W[34]);
    round2(A, B, C, D, E, W[35]);
    round2(A, B, C, D, E, W[36]);
    round2(A, B, C, D, E, W[37]);
    round2(A, B, C, D, E, W[38]);
    round2(A, B, C, D, E, W[39]);

    // Round 3
    round3(A, B, C, D, E, W[40]);
    round3(A, B, C, D, E, W[41]);
    round3(A, B, C, D, E, W[42]);
    round3(A, B, C, D, E, W[43]);
    round3(A, B, C, D, E, W[44]);
    round3(A, B, C, D, E, W[45]);
    round3(A, B, C, D, E, W[46]);
    round3(A, B, C, D, E, W[47]);
    round3(A, B, C, D, E, W[48]);
    round3(A, B, C, D, E, W[49]);
    round3(A, B, C, D, E, W[50]);
    round3(A, B, C, D, E, W[51]);
    round3(A, B, C, D, E, W[52]);
    round3(A, B, C, D, E, W[53]);
    round3(A, B, C, D, E, W[54]);
    round3(A, B, C, D, E, W[55]);
    round3(A, B, C, D, E, W[56]);
    round3(A, B, C, D, E, W[57]);
    round3(A, B, C, D, E, W[58]);
    round3(A, B, C, D, E, W[59]);

    // Round 4
    round4(A, B, C, D, E, W[60]);
    round4(A, B, C, D, E, W[61]);
    round4(A, B, C, D, E, W[62]);
    round4(A, B, C, D, E, W[63]);
    round4(A, B, C, D, E, W[64]);
    round4(A, B, C, D, E, W[65]);
    round4(A, B, C, D, E, W[66]);
    round4(A, B, C, D, E, W[67]);
    round4(A, B, C, D, E, W[68]);
    round4(A, B, C, D, E, W[69]);
    round4(A, B, C, D, E, W[70]);
    round4(A, B, C, D, E, W[71]);
    round4(A, B, C, D, E, W[72]);
    round4(A, B, C, D, E, W[73]);
    round4(A, B, C, D, E, W[74]);
    round4(A, B, C, D, E, W[75]);
    round4(A, B, C, D, E, W[76]);
    round4(A, B, C, D, E, W[77]);
    round4(A, B, C, D, E, W[78]);
    round4(A, B, C, D, E, W[79]);

    intermediate_hash_[0] += A;
    intermediate_hash_[1] += B;
    intermediate_hash_[2] += C;
    intermediate_hash_[3] += D;
    intermediate_hash_[4] += E;

    buffer_index_ = 0U;
}

namespace detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(T begin, T end) noexcept -> sha1_hasher::return_type
{
    if (end < begin)
    {
        return sha1_hasher::return_type {};
    }
    else if (end == begin)
    {
        return sha1_hasher::return_type {
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
            0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
        };
    }

    sha1_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    auto result {hasher.get_digest()};

    return result;
}

} // namespace detail

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(const char* str) noexcept -> sha1_hasher::return_type
{
    if (str == nullptr)
    {
        return sha1_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha1(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(const char* str, boost::crypt::size_t len) noexcept -> sha1_hasher::return_type
{
    if (str == nullptr)
    {
        return sha1_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha1(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(const boost::crypt::uint8_t* str) noexcept -> sha1_hasher::return_type
{
    if (str == nullptr)
    {
        return sha1_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha1(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(const boost::crypt::uint8_t* str, boost::crypt::size_t len) noexcept -> sha1_hasher::return_type
{
    if (str == nullptr)
    {
        return sha1_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha1(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(const char16_t* str) noexcept -> sha1_hasher::return_type
{
    if (str == nullptr)
    {
        return sha1_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha1(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(const char16_t* str, boost::crypt::size_t len) noexcept -> sha1_hasher::return_type
{
    if (str == nullptr)
    {
        return sha1_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha1(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(const char32_t* str) noexcept -> sha1_hasher::return_type
{
    if (str == nullptr)
    {
        return sha1_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha1(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(const char32_t* str, boost::crypt::size_t len) noexcept -> sha1_hasher::return_type
{
    if (str == nullptr)
    {
        return sha1_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha1(str, str + len);
}

// On some platforms wchar_t is 16 bits and others it's 32
// Since we check sizeof() the underlying with SFINAE in the actual implementation this is handled transparently
BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(const wchar_t* str) noexcept -> sha1_hasher::return_type
{
    if (str == nullptr)
    {
        return sha1_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha1(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(const wchar_t* str, boost::crypt::size_t len) noexcept -> sha1_hasher::return_type
{
    if (str == nullptr)
    {
        return sha1_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha1(str, str + len);
}

// ----- String and String view aren't in the libcu++ STL so they so not have device markers -----

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_EXPORT inline auto sha1(const std::string& str) noexcept -> sha1_hasher::return_type
{
    return detail::sha1(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha1(const std::u16string& str) noexcept -> sha1_hasher::return_type
{
    return detail::sha1(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha1(const std::u32string& str) noexcept -> sha1_hasher::return_type
{
    return detail::sha1(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha1(const std::wstring& str) noexcept -> sha1_hasher::return_type
{
    return detail::sha1(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT constexpr auto sha1(std::string_view str) -> sha1_hasher::return_type
{
    return detail::sha1(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT constexpr auto sha1(std::u16string_view str) -> sha1_hasher::return_type
{
    return detail::sha1(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT constexpr auto sha1(std::u32string_view str) -> sha1_hasher::return_type
{
    return detail::sha1(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT constexpr auto sha1(std::wstring_view str) -> sha1_hasher::return_type
{
    return detail::sha1(str.begin(), str.end());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

// ---- CUDA also does not have the ability to consume files -----

namespace detail {

template <boost::crypt::size_t block_size = 64U>
auto sha1_file_impl(utility::file_reader<block_size>& reader) noexcept -> sha1_hasher::return_type
{
    sha1_hasher hasher;
    while (!reader.eof())
    {
        const auto buffer_iter {reader.read_next_block()};
        const auto len {reader.get_bytes_read()};
        hasher.process_bytes(buffer_iter, len);
    }

    return hasher.get_digest();
}

} // namespace detail

BOOST_CRYPT_EXPORT inline auto sha1_file(const std::string& filepath) noexcept -> sha1_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha1_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha1_hasher::return_type{};
    }
}

BOOST_CRYPT_EXPORT inline auto sha1_file(const char* filepath) noexcept -> sha1_hasher::return_type
{
    try
    {
        if (filepath == nullptr)
        {
            return sha1_hasher::return_type{};
        }

        utility::file_reader<64U> reader(filepath);
        return detail::sha1_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha1_hasher::return_type{};
    }
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto sha1_file(std::string_view filepath) noexcept -> sha1_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha1_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha1_hasher::return_type{};
    }
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

#endif // BOOST_CRYPT_HAS_CUDA

// ---- The CUDA versions that we support all offer <cuda/std/span> ----

#ifdef BOOST_CRYPT_HAS_SPAN

BOOST_CRYPT_EXPORT template <typename T, std::size_t extent>
constexpr auto sha1(std::span<T, extent> data) noexcept -> sha1_hasher::return_type
{
    return detail::sha1(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED constexpr auto sha1(cuda::std::span<T, extent> data) noexcept -> sha1_hasher::return_type
{
    return detail::sha1(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namepsace boost

#endif // BOOST_CRYPT_HASH_SHA1_HPP
