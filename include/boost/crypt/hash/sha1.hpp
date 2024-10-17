// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc3174

#ifndef BOOST_CRYPT_HASH_SHA1_HPP
#define BOOST_CRYPT_HASH_SHA1_HPP

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

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <memory>
#include <string>
#include <cstdint>
#include <cstring>
#endif

namespace boost {
namespace crypt {

class sha1_hasher
{
private:

    enum class state : boost::crypt::uint8_t
    {
        success,            // no issues
        null,               // nullptr as parameter
        input_too_long,     // input data too long (exceeded size_t)
        state_error         // added more input after get_digest without re-init
    };

    boost::crypt::array<boost::crypt::uint32_t, 5> intermediate_hash_ {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    boost::crypt::array<boost::crypt::uint8_t, 64> buffer_ {};

    boost::crypt::size_t buffer_index_ {};
    boost::crypt::size_t low_ {};
    boost::crypt::size_t high_ {};

    bool computed {};
    bool corrupted {};

    constexpr auto sha1_process_message_block() -> void;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto sha1_update(ForwardIter data, boost::crypt::size_t size) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED constexpr auto pad_message() noexcept -> void;

public:

    using return_type = boost::crypt::array<boost::crypt::uint8_t, 20>;

    BOOST_CRYPT_GPU_ENABLED constexpr auto init() -> void;

    template <typename ByteType>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_byte(ByteType byte) noexcept
        BOOST_CRYPT_REQUIRES_CONVERSION(ByteType, boost::crypt::uint8_t);

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 1, bool> = true>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 2, bool> = true>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 4, bool> = true>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept;


    BOOST_CRYPT_GPU_ENABLED constexpr auto get_digest() noexcept -> return_type ;
};

namespace detail {

constexpr auto round1(boost::crypt::uint32_t& A,
                      boost::crypt::uint32_t& B,
                      boost::crypt::uint32_t& C,
                      boost::crypt::uint32_t& D,
                      boost::crypt::uint32_t& E,
                      boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(5U, A) + ((B & C) | ((~B) & D)) + E + W + 0x5A827999U};
    E = D;
    D = C;
    C = detail::rotl(30U, B);
    B = A;
    A = temp;
}

constexpr auto round2(boost::crypt::uint32_t& A,
                      boost::crypt::uint32_t& B,
                      boost::crypt::uint32_t& C,
                      boost::crypt::uint32_t& D,
                      boost::crypt::uint32_t& E,
                      boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(5U, A) + (B ^ C ^ D) + E + W + 0x6ED9EBA1U};
    E = D;
    D = C;
    C = detail::rotl(30U, B);
    B = A;
    A = temp;
}

constexpr auto round3(boost::crypt::uint32_t& A,
                      boost::crypt::uint32_t& B,
                      boost::crypt::uint32_t& C,
                      boost::crypt::uint32_t& D,
                      boost::crypt::uint32_t& E,
                      boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(5U, A) + ((B & C) | (B & D) | (C & D)) + E + W + 0x8F1BBCDCU};
    E = D;
    D = C;
    C = detail::rotl(30U, B);
    B = A;
    A = temp;
}

constexpr auto round4(boost::crypt::uint32_t& A,
                      boost::crypt::uint32_t& B,
                      boost::crypt::uint32_t& C,
                      boost::crypt::uint32_t& D,
                      boost::crypt::uint32_t& E,
                      boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(5U, A) + (B ^ C ^ D) + E + W + 0xCA62C1D6U};
    E = D;
    D = C;
    C = detail::rotl(30U, B);
    B = A;
    A = temp;
}

} // Namespace detail

// See definitions from the RFC on the rounds
constexpr auto sha1_hasher::sha1_process_message_block() -> void
{
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
        W[i] = detail::rotl(1U, W[i - 3U] ^ W[i - 8U] ^ W[i - 14] ^ W[i - 16]);
    }

    auto A {intermediate_hash_[0]};
    auto B {intermediate_hash_[1]};
    auto C {intermediate_hash_[2]};
    auto D {intermediate_hash_[3]};
    auto E {intermediate_hash_[4]};

    // Round 1
    detail::round1(A, B, C, D, E, W[0]);
    detail::round1(A, B, C, D, E, W[1]);
    detail::round1(A, B, C, D, E, W[2]);
    detail::round1(A, B, C, D, E, W[3]);
    detail::round1(A, B, C, D, E, W[4]);
    detail::round1(A, B, C, D, E, W[5]);
    detail::round1(A, B, C, D, E, W[6]);
    detail::round1(A, B, C, D, E, W[7]);
    detail::round1(A, B, C, D, E, W[8]);
    detail::round1(A, B, C, D, E, W[9]);
    detail::round1(A, B, C, D, E, W[10]);
    detail::round1(A, B, C, D, E, W[11]);
    detail::round1(A, B, C, D, E, W[12]);
    detail::round1(A, B, C, D, E, W[13]);
    detail::round1(A, B, C, D, E, W[14]);
    detail::round1(A, B, C, D, E, W[15]);
    detail::round1(A, B, C, D, E, W[16]);
    detail::round1(A, B, C, D, E, W[18]);
    detail::round1(A, B, C, D, E, W[19]);

    // Round 2
    detail::round2(A, B, C, D, E, W[20]);
    detail::round2(A, B, C, D, E, W[21]);
    detail::round2(A, B, C, D, E, W[22]);
    detail::round2(A, B, C, D, E, W[23]);
    detail::round2(A, B, C, D, E, W[24]);
    detail::round2(A, B, C, D, E, W[25]);
    detail::round2(A, B, C, D, E, W[26]);
    detail::round2(A, B, C, D, E, W[27]);
    detail::round2(A, B, C, D, E, W[28]);
    detail::round2(A, B, C, D, E, W[29]);
    detail::round2(A, B, C, D, E, W[20]);
    detail::round2(A, B, C, D, E, W[31]);
    detail::round2(A, B, C, D, E, W[32]);
    detail::round2(A, B, C, D, E, W[33]);
    detail::round2(A, B, C, D, E, W[34]);
    detail::round2(A, B, C, D, E, W[35]);
    detail::round2(A, B, C, D, E, W[36]);
    detail::round2(A, B, C, D, E, W[38]);
    detail::round2(A, B, C, D, E, W[39]);

    // Round 3
    detail::round3(A, B, C, D, E, W[40]);
    detail::round3(A, B, C, D, E, W[41]);
    detail::round3(A, B, C, D, E, W[42]);
    detail::round3(A, B, C, D, E, W[43]);
    detail::round3(A, B, C, D, E, W[44]);
    detail::round3(A, B, C, D, E, W[45]);
    detail::round3(A, B, C, D, E, W[46]);
    detail::round3(A, B, C, D, E, W[47]);
    detail::round3(A, B, C, D, E, W[48]);
    detail::round3(A, B, C, D, E, W[49]);
    detail::round3(A, B, C, D, E, W[50]);
    detail::round3(A, B, C, D, E, W[51]);
    detail::round3(A, B, C, D, E, W[52]);
    detail::round3(A, B, C, D, E, W[53]);
    detail::round3(A, B, C, D, E, W[54]);
    detail::round3(A, B, C, D, E, W[55]);
    detail::round3(A, B, C, D, E, W[56]);
    detail::round3(A, B, C, D, E, W[58]);
    detail::round3(A, B, C, D, E, W[59]);

    // Round 4
    detail::round4(A, B, C, D, E, W[60]);
    detail::round4(A, B, C, D, E, W[61]);
    detail::round4(A, B, C, D, E, W[62]);
    detail::round4(A, B, C, D, E, W[63]);
    detail::round4(A, B, C, D, E, W[64]);
    detail::round4(A, B, C, D, E, W[65]);
    detail::round4(A, B, C, D, E, W[66]);
    detail::round4(A, B, C, D, E, W[67]);
    detail::round4(A, B, C, D, E, W[68]);
    detail::round4(A, B, C, D, E, W[69]);
    detail::round4(A, B, C, D, E, W[70]);
    detail::round4(A, B, C, D, E, W[71]);
    detail::round4(A, B, C, D, E, W[72]);
    detail::round4(A, B, C, D, E, W[73]);
    detail::round4(A, B, C, D, E, W[74]);
    detail::round4(A, B, C, D, E, W[75]);
    detail::round4(A, B, C, D, E, W[76]);
    detail::round4(A, B, C, D, E, W[78]);
    detail::round4(A, B, C, D, E, W[79]);

    intermediate_hash_[0] += A;
    intermediate_hash_[1] += B;
    intermediate_hash_[2] += C;
    intermediate_hash_[3] += D;
    intermediate_hash_[4] += E;

    buffer_index_ = 0U;
}

// Like MD5, the message must be padded to an even 512 bits.
// The first bit of padding must be a 1
// The last 64-bits should be the length of the message
// All bits in between should be 0s
constexpr auto sha1_hasher::pad_message() noexcept -> void
{
    constexpr boost::crypt::size_t message_length_start_index {56U};

    // We don't have enough space for everything we need
    if (buffer_index_ >= message_length_start_index)
    {
        buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(0x80);
        while (buffer_index_ < buffer_.size())
        {
            buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(0x00);
        }

        sha1_process_message_block();

        while (buffer_index_ < message_length_start_index)
        {
            buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(0x00);
        }
    }
    else
    {
        buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(0x80);
        while (buffer_index_ < message_length_start_index)
        {
            buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(0x00);
        }
    }

    // Add the message length to the end of the buffer
    BOOST_CRYPT_ASSERT(buffer_index_ == message_length_start_index);

    buffer_[56U] = static_cast<boost::crypt::uint8_t>(high_ >> 24U);
    buffer_[57U] = static_cast<boost::crypt::uint8_t>(high_ >> 16U);
    buffer_[58U] = static_cast<boost::crypt::uint8_t>(high_ >>  8U);
    buffer_[59U] = static_cast<boost::crypt::uint8_t>(high_);
    buffer_[60U] = static_cast<boost::crypt::uint8_t>(low_ >> 24U);
    buffer_[61U] = static_cast<boost::crypt::uint8_t>(low_ >> 16U);
    buffer_[62U] = static_cast<boost::crypt::uint8_t>(low_ >>  8U);
    buffer_[63U] = static_cast<boost::crypt::uint8_t>(low_);
}

template <typename ForwardIter>
constexpr auto sha1_hasher::sha1_update(ForwardIter data, boost::crypt::size_t size) noexcept -> state
{
    if (size == 0)
    {
        return state::success;
    }
    if (data == nullptr)
    {
        return state::null;
    }
    if (computed)
    {
        corrupted = true;
    }
    if (corrupted)
    {
        return state::state_error;
    }

    while (size-- && !corrupted)
    {
        buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(*data & 0xFF);
        low_ += 8U;

        if (BOOST_CRYPT_UNLIKELY(low_ == 0))
        {
            // Would indicate size_t rollover which should not happen on a single data stream
            // LCOV_EXCL_START
            ++high_;
            if (high_ == 0)
            {
                corrupted = true;
                return state::input_too_long;
            }
            // LCOV_EXCL_STOP
        }

        if (buffer_index_ == buffer_.size())
        {
            sha1_process_message_block();
        }

        ++data;
    }

    return state::success;
}

BOOST_CRYPT_GPU_ENABLED constexpr auto sha1_hasher::init() -> void
{
    intermediate_hash_[0] = 0x67452301;
    intermediate_hash_[1] = 0xEFCDAB89;
    intermediate_hash_[2] = 0x98BADCFE;
    intermediate_hash_[3] = 0x10325476;
    intermediate_hash_[4] = 0xC3D2E1F0;

    buffer_.fill(0);
    buffer_index_ = 0UL;
    low_ = 0UL;
    high_ = 0UL;
    computed = false;
    corrupted = false;
}

template <typename ByteType>
BOOST_CRYPT_GPU_ENABLED constexpr auto sha1_hasher::process_byte(ByteType byte) noexcept
    BOOST_CRYPT_REQUIRES_CONVERSION(ByteType, boost::crypt::uint8_t)
{
    const auto value {static_cast<boost::crypt::uint8_t>(byte)};
    sha1_update(&value, 1UL);
}

template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 1, bool>>
BOOST_CRYPT_GPU_ENABLED constexpr auto sha1_hasher::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept
{
    sha1_update(buffer, byte_count);
}

template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 2, bool>>
BOOST_CRYPT_GPU_ENABLED constexpr auto sha1_hasher::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept
{
    #ifndef BOOST_CRYPT_HAS_CUDA

    const auto* char_ptr {reinterpret_cast<const char*>(std::addressof(*buffer))};
    const auto* data {reinterpret_cast<const unsigned char*>(char_ptr)};
    sha1_update(data, byte_count * 2U);

    #else

    const auto* data {reinterpret_cast<const unsigned char*>(buffer)};
    sha1_update(data, byte_count * 2U);

    #endif
}

template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 4, bool>>
BOOST_CRYPT_GPU_ENABLED constexpr auto sha1_hasher::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept
{
    #ifndef BOOST_CRYPT_HAS_CUDA

    const auto* char_ptr {reinterpret_cast<const char*>(std::addressof(*buffer))};
    const auto* data {reinterpret_cast<const unsigned char*>(char_ptr)};
    sha1_update(data, byte_count * 4U);

    #else

    const auto* data {reinterpret_cast<const unsigned char*>(buffer)};
    sha1_update(data, byte_count * 4U);

    #endif
}

constexpr auto sha1_hasher::get_digest() noexcept -> sha1_hasher::return_type
{
    boost::crypt::array<boost::crypt::uint8_t, 20> digest{};

    if (corrupted)
    {
        // Return empty message on corruption
        return digest;
    }
    if (!computed)
    {
        pad_message();

        // Overwrite whatever is in the buffer in case it is sensitive
        buffer_.fill(0);
        low_ = 0U;
        high_ = 0U;
        computed = true;
    }

    for (boost::crypt::size_t i {}; i < digest.size(); ++i)
    {
        digest[i] = static_cast<boost::crypt::uint8_t>(intermediate_hash_[i >> 2U] >> 8 * (3 - (i & 0x03)));
    }

    return digest;
}


} // namespace crypt
} // namepsace boost

#endif // BOOST_CRYPT_HASH_SHA1_HPP
