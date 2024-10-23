// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://www.ietf.org/rfc/rfc1321.txt

#ifndef BOOST_CRYPT_HASH_MD5_HPP
#define BOOST_CRYPT_HASH_MD5_HPP

#include <boost/crypt/hash/detail/hasher_base_512.hpp>
#include <boost/crypt/hash/hasher_state.hpp>
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

BOOST_CRYPT_EXPORT class md5_hasher final : public hash_detail::hasher_base_512<16U, 4U>
{
public:

    BOOST_CRYPT_GPU_ENABLED md5_hasher() noexcept { this->init(); }

    BOOST_CRYPT_GPU_ENABLED inline auto init() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED inline auto get_digest() noexcept -> return_type override;

private:

    BOOST_CRYPT_GPU_ENABLED inline auto process_message_block() noexcept -> void override;
};

BOOST_CRYPT_GPU_ENABLED inline auto md5_hasher::init() noexcept -> void
{
    hash_detail::hasher_base_512<16U, 4U>::base_init();

    intermediate_hash_[0] = 0x67452301;
    intermediate_hash_[1] = 0xefcdab89;
    intermediate_hash_[2] = 0x98badcfe;
    intermediate_hash_[3] = 0x10325476;
}

// See: Applied Cryptography - Bruce Schneier
// Section 18.5
namespace md5_body_detail {

BOOST_CRYPT_GPU_ENABLED inline auto F(boost::crypt::uint32_t x, boost::crypt::uint32_t y, boost::crypt::uint32_t z) noexcept
{
    return (x & y) | ((~x) & z);
}

BOOST_CRYPT_GPU_ENABLED inline auto G(boost::crypt::uint32_t x, boost::crypt::uint32_t y, boost::crypt::uint32_t z) noexcept
{
    return (x & z) | (y & (~z));
}

BOOST_CRYPT_GPU_ENABLED inline auto H(boost::crypt::uint32_t x, boost::crypt::uint32_t y, boost::crypt::uint32_t z) noexcept
{
    return x ^ y ^ z;
}

BOOST_CRYPT_GPU_ENABLED inline auto I(boost::crypt::uint32_t x, boost::crypt::uint32_t y, boost::crypt::uint32_t z) noexcept
{
    return y ^ (x | (~z));
}

BOOST_CRYPT_GPU_ENABLED inline auto FF(boost::crypt::uint32_t& a, boost::crypt::uint32_t b,  boost::crypt::uint32_t c,
                                       boost::crypt::uint32_t d,  boost::crypt::uint32_t Mj, boost::crypt::uint32_t si,
                                       boost::crypt::uint32_t ti) noexcept
{
    a = b + detail::rotl((a + F(b, c, d) + Mj + ti), si);
}

BOOST_CRYPT_GPU_ENABLED inline auto GG(boost::crypt::uint32_t& a, boost::crypt::uint32_t b,  boost::crypt::uint32_t c,
                                       boost::crypt::uint32_t d,  boost::crypt::uint32_t Mj, boost::crypt::uint32_t si,
                                       boost::crypt::uint32_t ti) noexcept
{
    a = b + detail::rotl((a + G(b, c, d) + Mj + ti), si);
}

BOOST_CRYPT_GPU_ENABLED inline auto HH(boost::crypt::uint32_t& a, boost::crypt::uint32_t b,  boost::crypt::uint32_t c,
                                       boost::crypt::uint32_t d,  boost::crypt::uint32_t Mj, boost::crypt::uint32_t si,
                                       boost::crypt::uint32_t ti) noexcept
{
    a = b + detail::rotl((a + H(b, c, d) + Mj + ti), si);
}

BOOST_CRYPT_GPU_ENABLED inline auto II(boost::crypt::uint32_t& a, boost::crypt::uint32_t b,  boost::crypt::uint32_t c,
                                       boost::crypt::uint32_t d,  boost::crypt::uint32_t Mj, boost::crypt::uint32_t si,
                                       boost::crypt::uint32_t ti) noexcept
{
    a = b + detail::rotl((a + I(b, c, d) + Mj + ti), si);
}

} // md5_body_detail

BOOST_CRYPT_GPU_ENABLED inline auto md5_hasher::process_message_block() noexcept -> void
{
    using namespace md5_body_detail;

    boost::crypt::array<boost::crypt::uint32_t, 16> blocks {};

    // Convert the buffer into 32-bit blocks for hashing
    boost::crypt::size_t index {};
    for (auto& block : blocks)
    {
        block = static_cast<boost::crypt::uint32_t>(
                static_cast<boost::crypt::uint32_t>(buffer_[index]) |
                (static_cast<boost::crypt::uint32_t>(buffer_[index + 1U]) << 8U) |
                (static_cast<boost::crypt::uint32_t>(buffer_[index + 2U]) << 16U) |
                (static_cast<boost::crypt::uint32_t>(buffer_[index + 3U]) << 24U)
        );

        index += 4U;
    }

    auto a {intermediate_hash_[0]};
    auto b {intermediate_hash_[1]};
    auto c {intermediate_hash_[2]};
    auto d {intermediate_hash_[3]};

    // Round 1
    FF(a, b, c, d, blocks[0],   7, 0xd76aa478);
    FF(d, a, b, c, blocks[1],  12, 0xe8c7b756);
    FF(c, d, a, b, blocks[2],  17, 0x242070db);
    FF(b, c, d, a, blocks[3],  22, 0xc1bdceee);
    FF(a, b, c, d, blocks[4],   7, 0xf57c0faf);
    FF(d, a, b, c, blocks[5],  12, 0x4787c62a);
    FF(c, d, a, b, blocks[6],  17, 0xa8304613);
    FF(b, c, d, a, blocks[7],  22, 0xfd469501);
    FF(a, b, c, d, blocks[8],   7, 0x698098d8);
    FF(d, a, b, c, blocks[9],  12, 0x8b44f7af);
    FF(c, d, a, b, blocks[10], 17, 0xffff5bb1);
    FF(b, c, d, a, blocks[11], 22, 0x895cd7be);
    FF(a, b, c, d, blocks[12],  7, 0x6b901122);
    FF(d, a, b, c, blocks[13], 12, 0xfd987193);
    FF(c, d, a, b, blocks[14], 17, 0xa679438e);
    FF(b, c, d, a, blocks[15], 22, 0x49b40821);

    // Round 2
    GG(a, b, c, d, blocks[1],   5, 0xf61e2562);
    GG(d, a, b, c, blocks[6],   9, 0xc040b340);
    GG(c, d, a, b, blocks[11], 14, 0x265e5a51);
    GG(b, c, d, a, blocks[0],  20, 0xe9b6c7aa);
    GG(a, b, c, d, blocks[5],   5, 0xd62f105d);
    GG(d, a, b, c, blocks[10],  9, 0x02441453);
    GG(c, d, a, b, blocks[15], 14, 0xd8a1e681);
    GG(b, c, d, a, blocks[4],  20, 0xe7d3fbc8);
    GG(a, b, c, d, blocks[9],   5, 0x21e1cde6);
    GG(d, a, b, c, blocks[14],  9, 0xc33707d6);
    GG(c, d, a, b, blocks[3],  14, 0xf4d50d87);
    GG(b, c, d, a, blocks[8],  20, 0x455a14ed);
    GG(a, b, c, d, blocks[13],  5, 0xa9e3e905);
    GG(d, a, b, c, blocks[2],   9, 0xfcefa3f8);
    GG(c, d, a, b, blocks[7],  14, 0x676f02d9);
    GG(b, c, d, a, blocks[12], 20, 0x8d2a4c8a);

    // Round 3
    HH(a, b, c, d, blocks[5],   4, 0xfffa3942);
    HH(d, a, b, c, blocks[8],  11, 0x8771f681);
    HH(c, d, a, b, blocks[11], 16, 0x6d9d6122);
    HH(b, c, d, a, blocks[14], 23, 0xfde5380c);
    HH(a, b, c, d, blocks[1],   4, 0xa4beea44);
    HH(d, a, b, c, blocks[4],  11, 0x4bdecfa9);
    HH(c, d, a, b, blocks[7],  16, 0xf6bb4b60);
    HH(b, c, d, a, blocks[10], 23, 0xbebfbc70);
    HH(a, b, c, d, blocks[13],  4, 0x289b7ec6);
    HH(d, a, b, c, blocks[0],  11, 0xeaa127fa);
    HH(c, d, a, b, blocks[3],  16, 0xd4ef3085);
    HH(b, c, d, a, blocks[6],  23, 0x04881d05);
    HH(a, b, c, d, blocks[9],   4, 0xd9d4d039);
    HH(d, a, b, c, blocks[12], 11, 0xe6db99e5);
    HH(c, d, a, b, blocks[15], 16, 0x1fa27cf8);
    HH(b, c, d, a, blocks[2],  23, 0xc4ac5665);

    // Round 4
    II(a, b, c, d, blocks[0],   6, 0xf4292244);
    II(d, a, b, c, blocks[7],  10, 0x432aff97);
    II(c, d, a, b, blocks[14], 15, 0xab9423a7);
    II(b, c, d, a, blocks[5],  21, 0xfc93a039);
    II(a, b, c, d, blocks[12],  6, 0x655b59c3);
    II(d, a, b, c, blocks[3],  10, 0x8f0ccc92);
    II(c, d, a, b, blocks[10], 15, 0xffeff47d);
    II(b, c, d, a, blocks[1],  21, 0x85845dd1);
    II(a, b, c, d, blocks[8],   6, 0x6fa87e4f);
    II(d, a, b, c, blocks[15], 10, 0xfe2ce6e0);
    II(c, d, a, b, blocks[6],  15, 0xa3014314);
    II(b, c, d, a, blocks[13], 21, 0x4e0811a1);
    II(a, b, c, d, blocks[4],   6, 0xf7537e82);
    II(d, a, b, c, blocks[11], 10, 0xbd3af235);
    II(c, d, a, b, blocks[2],  15, 0x2ad7d2bb);
    II(b, c, d, a, blocks[9],  21, 0xeb86d391);

    intermediate_hash_[0] += a;
    intermediate_hash_[1] += b;
    intermediate_hash_[2] += c;
    intermediate_hash_[3] += d;

    buffer_index_ = 0U;
}

BOOST_CRYPT_GPU_ENABLED inline auto md5_hasher::get_digest() noexcept -> return_type
{
    return_type digest {};
    if (corrupted)
    {
        return digest;
    }

    auto used {(low_ >> 3U) & 0x3F}; // Number of bytes used in buffer
    buffer_[used++] = 0x80;
    auto available {buffer_.size() - used};

    if (available < 8U)
    {
        fill_array(buffer_.begin() + used, buffer_.end(), static_cast<boost::crypt::uint8_t>(0));
        process_message_block();
        used = 0;
        buffer_.fill(0);
    }
    else
    {
        fill_array(buffer_.begin() + used, buffer_.end() - 8, static_cast<boost::crypt::uint8_t>(0));
    }

    const auto total_bits {(static_cast<uint64_t>(high_) << 32) | low_};

    // Append the length in bits as a 64-bit little-endian integer
    buffer_[56] = static_cast<boost::crypt::uint8_t>(total_bits & 0xFF);
    buffer_[57] = static_cast<boost::crypt::uint8_t>((total_bits >> 8) & 0xFF);
    buffer_[58] = static_cast<boost::crypt::uint8_t>((total_bits >> 16) & 0xFF);
    buffer_[59] = static_cast<boost::crypt::uint8_t>((total_bits >> 24) & 0xFF);
    buffer_[60] = static_cast<boost::crypt::uint8_t>((total_bits >> 32) & 0xFF);
    buffer_[61] = static_cast<boost::crypt::uint8_t>((total_bits >> 40) & 0xFF);
    buffer_[62] = static_cast<boost::crypt::uint8_t>((total_bits >> 48) & 0xFF);
    buffer_[63] = static_cast<boost::crypt::uint8_t>((total_bits >> 56) & 0xFF);

    process_message_block();
    computed = true;

    for (boost::crypt::size_t i {}; i < intermediate_hash_.size(); ++i)
    {
        digest[i*4]     = static_cast<boost::crypt::uint8_t>(intermediate_hash_[i] & 0xFF);
        digest[i*4 + 1] = static_cast<boost::crypt::uint8_t>((intermediate_hash_[i] >> 8U) & 0xFF);
        digest[i*4 + 2] = static_cast<boost::crypt::uint8_t>((intermediate_hash_[i] >> 16U) & 0xFF);
        digest[i*4 + 3] = static_cast<boost::crypt::uint8_t>((intermediate_hash_[i] >> 24U) & 0xFF);
    }

    return digest;
}

namespace detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED inline auto md5(T begin, T end) noexcept -> md5_hasher::return_type
{
    if (end < begin)
    {
        return md5_hasher::return_type {};
    }
    else if (end == begin)
    {
        return md5_hasher::return_type {
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
        };
    }

    boost::crypt::md5_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    auto result {hasher.get_digest()};

    return result;
}

} // Namespace detail

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto md5(const char* str) noexcept -> md5_hasher::return_type
{
    if (str == nullptr)
    {
        return md5_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::md5(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto md5(const char* str, boost::crypt::size_t len) noexcept -> md5_hasher::return_type
{
    if (str == nullptr)
    {
        return md5_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::md5(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto md5(const boost::crypt::uint8_t* str) noexcept -> md5_hasher::return_type
{
    if (str == nullptr)
    {
        return md5_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::md5(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto md5(const boost::crypt::uint8_t* str, boost::crypt::size_t len) noexcept -> md5_hasher::return_type
{
    if (str == nullptr)
    {
        return md5_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::md5(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto md5(const char16_t* str) noexcept -> md5_hasher::return_type
{
    if (str == nullptr)
    {
        return md5_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::md5(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto md5(const char16_t* str, boost::crypt::size_t len) noexcept -> md5_hasher::return_type
{
    if (str == nullptr)
    {
        return md5_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::md5(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto md5(const char32_t* str) noexcept -> md5_hasher::return_type
{
    if (str == nullptr)
    {
        return md5_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::md5(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto md5(const char32_t* str, boost::crypt::size_t len) noexcept -> md5_hasher::return_type
{
    if (str == nullptr)
    {
        return md5_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::md5(str, str + len);
}

// On some platforms wchar_t is 16 bits and others it's 32
// Since we check sizeof() the underlying with SFINAE in the actual implementation this is handled transparently
BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto md5(const wchar_t* str) noexcept -> md5_hasher::return_type
{
    if (str == nullptr)
    {
        return md5_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::md5(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto md5(const wchar_t* str, boost::crypt::size_t len) noexcept -> md5_hasher::return_type
{
    if (str == nullptr)
    {
        return md5_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::md5(str, str + len);
}

// ----- String and String view aren't in the libcu++ STL so they so not have device markers -----

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_EXPORT inline auto md5(const std::string& str) noexcept -> md5_hasher::return_type
{
    return detail::md5(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto md5(const std::u16string& str) noexcept -> md5_hasher::return_type
{
    return detail::md5(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto md5(const std::u32string& str) noexcept -> md5_hasher::return_type
{
    return detail::md5(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto md5(const std::wstring& str) noexcept -> md5_hasher::return_type
{
    return detail::md5(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto md5(std::string_view str) -> md5_hasher::return_type
{
    return detail::md5(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto md5(std::u16string_view str) -> md5_hasher::return_type
{
    return detail::md5(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto md5(std::u32string_view str) -> md5_hasher::return_type
{
    return detail::md5(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto md5(std::wstring_view str) -> md5_hasher::return_type
{
    return detail::md5(str.begin(), str.end());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

// ---- CUDA also does not have the ability to consume files -----

namespace detail {

template <boost::crypt::size_t block_size = 64U>
auto md5_file_impl(utility::file_reader<block_size>& reader) noexcept -> md5_hasher::return_type
{
    md5_hasher hasher;
    while (!reader.eof())
    {
        const auto buffer_iter {reader.read_next_block()};
        const auto len {reader.get_bytes_read()};
        hasher.process_bytes(buffer_iter, len);
    }

    return hasher.get_digest();
}

} // namespace detail

BOOST_CRYPT_EXPORT inline auto md5_file(const std::string& filepath) noexcept -> md5_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::md5_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return md5_hasher::return_type{};
    }
}

BOOST_CRYPT_EXPORT inline auto md5_file(const char* filepath) noexcept -> md5_hasher::return_type
{
    try
    {
        if (filepath == nullptr)
        {
            return md5_hasher::return_type {};
        }

        utility::file_reader<64U> reader(filepath);
        return detail::md5_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return md5_hasher::return_type{};
    }
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto md5_file(std::string_view filepath) noexcept -> md5_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::md5_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return md5_hasher::return_type{};
    }
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

#endif // BOOST_CRYPT_HAS_CUDA

// ---- The CUDA versions that we support all offer <cuda/std/span> ----

#ifdef BOOST_CRYPT_HAS_SPAN

BOOST_CRYPT_EXPORT template <typename T, std::size_t extent>
inline auto md5(std::span<T, extent> data) noexcept -> md5_hasher::return_type
{
    return detail::md5(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED inline auto md5(cuda::std::span<T, extent> data) noexcept -> md5_hasher::return_type
{
    return detail::md5(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_MD5_HPP
