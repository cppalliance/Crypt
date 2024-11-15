// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc6234
// See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=31

#ifndef BOOST_CRYPT_HASH_DETAIL_SHA512_BASE_HPP
#define BOOST_CRYPT_HASH_DETAIL_SHA512_BASE_HPP

#include <boost/crypt/utility/state.hpp>
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
namespace hash_detail {

template <boost::crypt::size_t digest_size>
class sha512_base final
{
public:

    static constexpr boost::crypt::size_t block_size {128U};

private:

    static_assert(digest_size == 28U || digest_size == 32U || digest_size == 48U || digest_size == 64U,
                  "Digest size must be 28 (SHA512/224), 32 (SHA512/256), 48 (SHA384), or 64 (SHA512)");

    using sha_type = boost::crypt::integral_constant<boost::crypt::size_t, digest_size>;

    boost::crypt::array<boost::crypt::uint64_t, 8U> intermediate_hash_ {};
    boost::crypt::array<boost::crypt::uint8_t, 128U> buffer_ {};
    boost::crypt::size_t buffer_index_ {};
    boost::crypt::uint64_t low_ {};
    boost::crypt::uint64_t high_ {};
    bool computed_ {};
    bool corrupted_ {};

    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const boost::crypt::integral_constant<boost::crypt::size_t, 28U>&) noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const boost::crypt::integral_constant<boost::crypt::size_t, 32U>&) noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const boost::crypt::integral_constant<boost::crypt::size_t, 48U>&) noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const boost::crypt::integral_constant<boost::crypt::size_t, 64U>&) noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto process_message_block() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto pad_message() noexcept -> void;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto update(ForwardIter data, boost::crypt::size_t size) noexcept -> state;

public:

    using return_type = boost::crypt::array<boost::crypt::uint8_t, digest_size>;

    BOOST_CRYPT_GPU_ENABLED constexpr sha512_base() noexcept { init(); }

    BOOST_CRYPT_GPU_ENABLED constexpr auto init() noexcept -> void;

    template <typename ByteType>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_byte(ByteType byte) noexcept -> state;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 1, bool> = true>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> state;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 2, bool> = true>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> state;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 4, bool> = true>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> state;

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW

    constexpr auto process_bytes(std::string_view str) noexcept -> state;

    constexpr auto process_bytes(std::u16string_view str) noexcept -> state;

    constexpr auto process_bytes(std::u32string_view str) noexcept -> state;

    constexpr auto process_bytes(std::wstring_view str) noexcept -> state;

    #endif // BOOST_CRYPT_HAS_STRING_VIEW

    #ifdef BOOST_CRYPT_HAS_SPAN

    template <typename T, boost::crypt::size_t extent>
    constexpr auto process_bytes(std::span<T, extent> data) noexcept -> state;

    #endif // BOOST_CRYPT_HAS_SPAN

    #ifdef BOOST_CRYPT_HAS_CUDA

    template <typename T, boost::crypt::size_t extent>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_bytes(cuda::std::span<T, extent> data) noexcept -> state;

    #endif // BOOST_CRYPT_HAS_CUDA

    BOOST_CRYPT_GPU_ENABLED constexpr auto get_digest() noexcept -> return_type;
};

template <boost::crypt::size_t digest_size>
template <typename ByteType>
constexpr auto sha512_base<digest_size>::process_byte(ByteType byte) noexcept -> state
{
    static_assert(boost::crypt::is_convertible_v<ByteType, boost::crypt::uint8_t>, "Byte must be convertible to uint8_t");
    const auto value {static_cast<boost::crypt::uint8_t>(byte)};
    return update(&value, 1UL);
}

template <boost::crypt::size_t digest_size>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 1, bool>>
constexpr auto sha512_base<digest_size>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> state
{
    if (!utility::is_null(buffer))
    {
        return update(buffer, byte_count);
    }
    else
    {
        return state::null;
    }
}

template <boost::crypt::size_t digest_size>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 2, bool>>
constexpr auto sha512_base<digest_size>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> state
{
    #ifndef BOOST_CRYPT_HAS_CUDA

    if (!utility::is_null(buffer))
    {
        const auto* char_ptr {reinterpret_cast<const char *>(std::addressof(*buffer))};
        const auto* data {reinterpret_cast<const unsigned char *>(char_ptr)};
        return update(data, byte_count * 2U);
    }
    else
    {
        return state::null;
    }

    #else

    if (!utility::is_null(buffer))
    {
        const auto* data {reinterpret_cast<const unsigned char*>(buffer)};
        return update(data, byte_count * 2U);
    }
    else
    {
        return state::null;
    }

    #endif
}

template <boost::crypt::size_t digest_size>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 4, bool>>
constexpr auto sha512_base<digest_size>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> state
{
    #ifndef BOOST_CRYPT_HAS_CUDA

    if (!utility::is_null(buffer))
    {
        const auto* char_ptr {reinterpret_cast<const char *>(std::addressof(*buffer))};
        const auto* data {reinterpret_cast<const unsigned char *>(char_ptr)};
        return update(data, byte_count * 4U);
    }
    else
    {
        return state::null;
    }

    #else

    if (!utility::is_null(buffer))
    {
        const auto* data {reinterpret_cast<const unsigned char*>(buffer)};
        return update(data, byte_count * 4U);
    }
    else
    {
        return state::null;
    }

    #endif
}

template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::get_digest() noexcept -> sha512_base::return_type
{
    return_type digest {};

    if (corrupted_)
    {
        return digest;
    }
    if (!computed_)
    {
        pad_message();

        buffer_.fill(0U);
        low_ = 0UL;
        high_ = 0UL;
        computed_ = true;
    }

    for (boost::crypt::size_t i {}; i < digest_size; ++i)
    {
        digest[i] = static_cast<boost::crypt::uint8_t>(intermediate_hash_[i >> 3U] >> 8U * (7 - (i % 8U)));
    }

    return digest;
}

template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::pad_message() noexcept -> void
{
    constexpr boost::crypt::size_t message_length_start_index {112U};

    // We don't have enough space for everything we need
    if (buffer_index_ >= message_length_start_index)
    {
        buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(0x80);
        while (buffer_index_ < buffer_.size())
        {
            buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(0x00);
        }

        process_message_block();

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

    buffer_[112U] = static_cast<boost::crypt::uint8_t>(high_ >> 56U);
    buffer_[113U] = static_cast<boost::crypt::uint8_t>(high_ >> 48U);
    buffer_[114U] = static_cast<boost::crypt::uint8_t>(high_ >> 40U);
    buffer_[115U] = static_cast<boost::crypt::uint8_t>(high_ >> 32U);
    buffer_[116U] = static_cast<boost::crypt::uint8_t>(high_ >> 24U);
    buffer_[117U] = static_cast<boost::crypt::uint8_t>(high_ >> 16U);
    buffer_[118U] = static_cast<boost::crypt::uint8_t>(high_ >>  8U);
    buffer_[119U] = static_cast<boost::crypt::uint8_t>(high_);

    buffer_[120U] = static_cast<boost::crypt::uint8_t>(low_ >> 56U);
    buffer_[121U] = static_cast<boost::crypt::uint8_t>(low_ >> 48U);
    buffer_[122U] = static_cast<boost::crypt::uint8_t>(low_ >> 40U);
    buffer_[123U] = static_cast<boost::crypt::uint8_t>(low_ >> 32U);
    buffer_[124U] = static_cast<boost::crypt::uint8_t>(low_ >> 24U);
    buffer_[125U] = static_cast<boost::crypt::uint8_t>(low_ >> 16U);
    buffer_[126U] = static_cast<boost::crypt::uint8_t>(low_ >>  8U);
    buffer_[127U] = static_cast<boost::crypt::uint8_t>(low_);

    process_message_block();
}

namespace sha512_detail {

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_INLINE_CONSTEXPR boost::crypt::array<boost::crypt::uint64_t, 80U> sha512_k = {
        0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL,
        0xE9B5DBA58189DBBCULL, 0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,
        0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL, 0xD807AA98A3030242ULL,
        0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
        0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,
        0xC19BF174CF692694ULL, 0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,
        0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL, 0x2DE92C6F592B0275ULL,
        0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
        0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL,
        0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,
        0x06CA6351E003826FULL, 0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL,
        0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
        0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL,
        0x92722C851482353BULL, 0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,
        0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL,
        0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
        0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL,
        0x34B0BCB5E19B48A8ULL, 0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,
        0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL,
        0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
        0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL,
        0xC67178F2E372532BULL, 0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,
        0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL, 0x06F067AA72176FBAULL,
        0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
        0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,
        0x431D67C49C100D4CULL, 0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,
        0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
};

#endif

// See section 4.1.3
BOOST_CRYPT_GPU_ENABLED constexpr auto big_sigma0(const boost::crypt::uint64_t x) noexcept -> boost::crypt::uint64_t
{
    return detail::rotr(x, 28UL) ^ detail::rotr(x, 34UL) ^ detail::rotr(x, 39UL);
}

BOOST_CRYPT_GPU_ENABLED constexpr auto big_sigma1(const boost::crypt::uint64_t x) noexcept -> boost::crypt::uint64_t
{
    return detail::rotr(x, 14UL) ^ detail::rotr(x, 18UL) ^ detail::rotr(x, 41UL);
}

BOOST_CRYPT_GPU_ENABLED constexpr auto little_sigma0(const boost::crypt::uint64_t x) noexcept -> boost::crypt::uint64_t
{
    return detail::rotr(x, 1UL) ^ detail::rotr(x, 8UL) ^ (x >> 7UL);
}

BOOST_CRYPT_GPU_ENABLED constexpr auto little_sigma1(const boost::crypt::uint64_t x) noexcept -> boost::crypt::uint64_t
{
    return detail::rotr(x, 19UL) ^ detail::rotr(x, 61UL) ^ (x >> 6UL);
}

BOOST_CRYPT_GPU_ENABLED constexpr auto sha_ch(const boost::crypt::uint64_t x,
                                           const boost::crypt::uint64_t y,
                                           const boost::crypt::uint64_t z) -> boost::crypt::uint64_t
{
    return (x & y) ^ ((~x) & z);
}

BOOST_CRYPT_GPU_ENABLED constexpr auto sha_maj(const boost::crypt::uint64_t x,
                                            const boost::crypt::uint64_t y,
                                            const boost::crypt::uint64_t z) -> boost::crypt::uint64_t
{
    return (x & y) ^ (x & z) ^ (y & z);
}

} // namespace sha512_detail

template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::process_message_block() noexcept -> void
{
    #ifdef BOOST_CRYPT_HAS_CUDA

    constexpr boost::crypt::array<boost::crypt::uint64_t, 80U> sha512_k = {
            0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL,
            0xE9B5DBA58189DBBCULL, 0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,
            0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL, 0xD807AA98A3030242ULL,
            0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
            0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,
            0xC19BF174CF692694ULL, 0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,
            0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL, 0x2DE92C6F592B0275ULL,
            0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
            0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL,
            0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,
            0x06CA6351E003826FULL, 0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL,
            0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
            0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL,
            0x92722C851482353BULL, 0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,
            0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL,
            0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
            0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL,
            0x34B0BCB5E19B48A8ULL, 0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,
            0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL,
            0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
            0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL,
            0xC67178F2E372532BULL, 0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,
            0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL, 0x06F067AA72176FBAULL,
            0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
            0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,
            0x431D67C49C100D4CULL, 0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,
            0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
    };

    #endif

    using namespace sha512_detail;
    boost::crypt::array<boost::crypt::uint64_t, 80U> W {};

    // Init the first 16 words of W
    for (boost::crypt::size_t i {}; i < 16UL; ++i)
    {
        W[i] = (static_cast<boost::crypt::uint64_t>(buffer_[i * 8U]) << 56U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i * 8U + 1U]) << 48U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i * 8U + 2U]) << 40U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i * 8U + 3U]) << 32U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i * 8U + 4U]) << 24U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i * 8U + 5U]) << 16U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i * 8U + 6U]) << 8U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i * 8U + 7U]));
    }

    // Init the last 64
    for (boost::crypt::size_t i {16U}; i < W.size(); ++i)
    {
        W[i] = little_sigma1(W[i - 2U])  + W[i - 7U] +
               little_sigma0(W[i - 15U]) + W[i - 16U];
    }

    auto A {intermediate_hash_[0]};
    auto B {intermediate_hash_[1]};
    auto C {intermediate_hash_[2]};
    auto D {intermediate_hash_[3]};
    auto E {intermediate_hash_[4]};
    auto F {intermediate_hash_[5]};
    auto G {intermediate_hash_[6]};
    auto H {intermediate_hash_[7]};

    for (boost::crypt::size_t i {}; i < W.size(); ++i)
    {
        const auto temp1 {H + big_sigma1(E) + sha_ch(E, F, G) + sha512_k[i] + W[i]};
        const auto temp2 {big_sigma0(A) + sha_maj(A, B, C)};
        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
    }

    intermediate_hash_[0] += A;
    intermediate_hash_[1] += B;
    intermediate_hash_[2] += C;
    intermediate_hash_[3] += D;
    intermediate_hash_[4] += E;
    intermediate_hash_[5] += F;
    intermediate_hash_[6] += G;
    intermediate_hash_[7] += H;

    buffer_index_ = 0U;
}

template <boost::crypt::size_t digest_size>
template <typename ForwardIter>
constexpr auto sha512_base<digest_size>::update(ForwardIter data, boost::crypt::size_t size) noexcept -> state
{
    if (size == 0U)
    {
        return state::success;
    }
    if (computed_)
    {
        corrupted_ = true;
    }
    if (corrupted_)
    {
        return state::state_error;
    }

    #ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wsign-conversion"
    #elif defined(__GNUC__) && __GNUC__ >= 5
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Warray-bounds="
    #pragma GCC diagnostic ignored "-Wrestrict"
    #pragma GCC diagnostic ignored "-Wsign-conversion"
    #endif

    for (boost::crypt::size_t i {}; i < size; ++i)
    {
        buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(static_cast<boost::crypt::uint8_t>(data[i]) &
                                                                      static_cast<boost::crypt::uint8_t>(0xFF));
        low_ += 8U;

        if (BOOST_CRYPT_UNLIKELY(low_ == 0))
        {
            // Would indicate size_t rollover which should not happen on a single data stream
            // LCOV_EXCL_START
            ++high_;
            if (BOOST_CRYPT_UNLIKELY(high_ == 0))
            {
                corrupted_ = true;
                return state::input_too_long;
            }
            // LCOV_EXCL_STOP
        }

        if (buffer_index_ == buffer_.size())
        {
            process_message_block();
        }
    }

    #ifdef __clang__
    #pragma clang diagnostic pop
    #elif defined(__GNUC__) && __GNUC__ >= 5
    #pragma GCC diagnostic pop
    #endif

    return state::success;
}

// SHA512/224
template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::init(const integral_constant<boost::crypt::size_t, 28U> &) noexcept -> void
{
    intermediate_hash_[0] = 0x8C3D37C819544DA2UL;
    intermediate_hash_[1] = 0x73E1996689DCD4D6UL;
    intermediate_hash_[2] = 0x1DFAB7AE32FF9C82UL;
    intermediate_hash_[3] = 0x679DD514582F9FCFUL;
    intermediate_hash_[4] = 0x0F6D2B697BD44DA8UL;
    intermediate_hash_[5] = 0x77E36F7304C48942UL;
    intermediate_hash_[6] = 0x3F9D85A86A1D36C8UL;
    intermediate_hash_[7] = 0x1112E6AD91D692A1UL;
}

// SHA512/256
template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::init(const integral_constant<boost::crypt::size_t, 32U> &) noexcept -> void
{
    intermediate_hash_[0] = 0x22312194FC2BF72CUL;
    intermediate_hash_[1] = 0x9F555FA3C84C64C2UL;
    intermediate_hash_[2] = 0x2393B86B6F53B151UL;
    intermediate_hash_[3] = 0x963877195940EABDUL;
    intermediate_hash_[4] = 0x96283EE2A88EFFE3UL;
    intermediate_hash_[5] = 0xBE5E1E2553863992UL;
    intermediate_hash_[6] = 0x2B0199FC2C85B8AAUL;
    intermediate_hash_[7] = 0x0EB72DDC81C52CA2UL;
}

// SHA384
template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::init(const integral_constant<boost::crypt::size_t, 48U> &) noexcept -> void
{
    intermediate_hash_[0] = 0xcbbb9d5dc1059ed8UL;
    intermediate_hash_[1] = 0x629a292a367cd507UL;
    intermediate_hash_[2] = 0x9159015a3070dd17UL;
    intermediate_hash_[3] = 0x152fecd8f70e5939UL;
    intermediate_hash_[4] = 0x67332667ffc00b31UL;
    intermediate_hash_[5] = 0x8eb44a8768581511UL;
    intermediate_hash_[6] = 0xdb0c2e0d64f98fa7UL;
    intermediate_hash_[7] = 0x47b5481dbefa4fa4UL;
}

// SHA512
template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::init(const integral_constant<boost::crypt::size_t, 64U> &) noexcept -> void
{
    intermediate_hash_[0] = 0x6a09e667f3bcc908UL;
    intermediate_hash_[1] = 0xbb67ae8584caa73bUL;
    intermediate_hash_[2] = 0x3c6ef372fe94f82bUL;
    intermediate_hash_[3] = 0xa54ff53a5f1d36f1UL;
    intermediate_hash_[4] = 0x510e527fade682d1UL;
    intermediate_hash_[5] = 0x9b05688c2b3e6c1fUL;
    intermediate_hash_[6] = 0x1f83d9abfb41bd6bUL;
    intermediate_hash_[7] = 0x5be0cd19137e2179UL;
}

template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::init() noexcept -> void
{
    buffer_.fill(0);
    buffer_index_ = 0U;
    low_ = 0U;
    high_ = 0U;
    computed_ = false;
    corrupted_ = false;

    init(sha_type());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::process_bytes(std::string_view str) noexcept -> state
{
    return process_bytes(str.begin(), str.size());
}

template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::process_bytes(std::u16string_view str) noexcept -> state
{
    return process_bytes(str.begin(), str.size());
}

template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::process_bytes(std::u32string_view str) noexcept -> state
{
    return process_bytes(str.begin(), str.size());
}

template <boost::crypt::size_t digest_size>
constexpr auto sha512_base<digest_size>::process_bytes(std::wstring_view str) noexcept -> state
{
    return process_bytes(str.begin(), str.size());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

#ifdef BOOST_CRYPT_HAS_SPAN

template <boost::crypt::size_t digest_size>
template <typename T, boost::crypt::size_t extent>
constexpr auto sha512_base<digest_size>::process_bytes(std::span<T, extent> data) noexcept -> state
{
    return process_bytes(data.begin(), data.size());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <boost::crypt::size_t digest_size>
template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED constexpr auto sha512_base<digest_size>::process_bytes(cuda::std::span<T, extent> data) noexcept -> state
{
    return process_bytes(data.begin(), data.size());
}

#endif // BOOST_CRYPT_HAS_SPAN

} // namespace hash_detail
} // namespace crypt
} // namespace boost

#endif //BOOST_CRYPT_HASH_DETAIL_SHA512_BASE_HPP
