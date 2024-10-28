// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

#ifndef BOOST_CRYPT_HASH_DETAIL_SHA3_BASE_HPP
#define BOOST_CRYPT_HASH_DETAIL_SHA3_BASE_HPP

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
namespace hash_detail {

// The capacity is only related to the digest size for the SHA3-XXX
// For SHAKE it is decoupled
template <boost::crypt::size_t digest_size, bool is_xof = false, boost::crypt::size_t capacity = digest_size * 2U>
class sha3_base
{
private:

    static_assert((!is_xof && (digest_size == 28U || digest_size == 32U || digest_size == 48U || digest_size == 64U)) || is_xof,
                  "Digest size must be 28 (SHA3-224), 32 (SHA3-256), 48 (SHA3-384), or 64(SHA3-512) or this must be an xof");

    boost::crypt::array<boost::crypt::uint64_t, 25U> state_array_ {};
    boost::crypt::array<boost::crypt::uint8_t, capacity> buffer_ {};
    boost::crypt::size_t buffer_index_ {};
    boost::crypt::uint64_t low_ {};
    boost::crypt::uint64_t high_ {};
    bool computed_ {};
    bool corrupted_ {};

    template <typename ForwardIterator>
    BOOST_CRYPT_GPU_ENABLED inline auto update(ForwardIterator data, boost::crypt::size_t size) noexcept -> hasher_state;

    BOOST_CRYPT_GPU_ENABLED inline auto process_message_block() noexcept -> void;


public:

    using return_type = boost::crypt::array<boost::crypt::uint8_t, digest_size>;

    BOOST_CRYPT_GPU_ENABLED sha3_base() noexcept { init(); };

    BOOST_CRYPT_GPU_ENABLED inline auto init() noexcept -> void;

    template <typename ByteType>
    BOOST_CRYPT_GPU_ENABLED inline auto process_byte(ByteType byte) noexcept -> hasher_state;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 1, bool> = true>
    BOOST_CRYPT_GPU_ENABLED inline auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 2, bool> = true>
    BOOST_CRYPT_GPU_ENABLED inline auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 4, bool> = true>
    BOOST_CRYPT_GPU_ENABLED inline auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state;

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW

    inline auto process_bytes(std::string_view str) noexcept -> hasher_state;

    inline auto process_bytes(std::u16string_view str) noexcept -> hasher_state;

    inline auto process_bytes(std::u32string_view str) noexcept -> hasher_state;

    inline auto process_bytes(std::wstring_view str) noexcept -> hasher_state;

    #endif // BOOST_CRYPT_HAS_STRING_VIEW

    #ifdef BOOST_CRYPT_HAS_SPAN

    template <typename T, boost::crypt::size_t extent>
    inline auto process_bytes(std::span<T, extent> data) noexcept -> hasher_state;

    #endif // BOOST_CRYPT_HAS_SPAN

    #ifdef BOOST_CRYPT_HAS_CUDA

    template <typename T, boost::crypt::size_t extent>
    BOOST_CRYPT_GPU_ENABLED inline auto process_bytes(cuda::std::span<T, extent> data) noexcept -> hasher_state;

    #endif // BOOST_CRYPT_HAS_CUDA

    BOOST_CRYPT_GPU_ENABLED inline auto get_digest() noexcept -> return_type;

};

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
BOOST_CRYPT_GPU_ENABLED inline auto sha3_base<digest_size, is_xof, capacity>::init() noexcept -> void
{
    state_array_.fill(0);
    buffer_.fill(0);
    buffer_index_ = 0U;
    low_ = 0UL;
    high_ = 0UL;
    computed_ = false;
    corrupted_ = false;
}

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
template <typename ForwardIterator>
BOOST_CRYPT_GPU_ENABLED inline auto sha3_base<digest_size, is_xof, capacity>::update(ForwardIterator data, boost::crypt::size_t size) noexcept -> hasher_state
{
    if (size == 0U)
    {
        return hasher_state::success;
    }
    if (computed_)
    {
        computed_ = true;
    }
    if (corrupted_)
    {
        return hasher_state::state_error;
    }

    while (size--)
    {
        buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(static_cast<boost::crypt::uint8_t>(*data) &
                                                                      static_cast<boost::crypt::uint8_t>(0xFF));
        low_ += 8U;

        if (BOOST_CRYPT_UNLIKELY(low_ == 0))
        {
            // LCOV_EXCL_START
            ++high_;
            if (BOOST_CRYPT_UNLIKELY(high_ == 0))
            {
                corrupted_ = true;
                return hasher_state::input_too_long;
            }
            // LCOV_EXCL_STOP
        }

        if (buffer_index_ == buffer_.size())
        {
            process_message_block();
        }

        ++data;
    }

    return hasher_state::success;
}

namespace sha3_detail {

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_INLINE_CONSTEXPR boost::crypt::size_t num_rounds {24U};

BOOST_CRYPT_INLINE_CONSTEXPR boost::crypt::array<boost::crypt::uint32_t, num_rounds> rho_rotation {
    1U,  3U,  6U,  10U, 15U, 21U, 28U, 36U, 45U, 55U, 2U,  14U,
    27U, 41U, 56U, 8U,  25U, 43U, 62U, 18U, 39U, 61U, 20U, 44U
};

BOOST_CRYPT_INLINE_CONSTEXPR boost::crypt::array<boost::crypt::uint32_t, num_rounds> pi_lane_number {
    10U, 7U,  11U, 17U, 18U, 3U, 5U,  16U, 8U,  21U, 24U, 4U,
    15U, 23U, 19U, 13U, 12U, 2U, 20U, 14U, 22U, 9U,  6U,  1U
};

BOOST_CRYPT_INLINE_CONSTEXPR boost::crypt::array<boost::crypt::uint64_t, num_rounds> iota {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace sha3_detail

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
BOOST_CRYPT_GPU_ENABLED inline auto sha3_base<digest_size, is_xof, capacity>::process_message_block() noexcept -> void
{
    #ifdef BOOST_CRYPT_HAS_CUDA

    constexpr boost::crypt::size_t num_rounds {24U};

    constexpr boost::crypt::array<boost::crypt::uint32_t, num_rounds> rho_rotation {
        1U,  3U,  6U,  10U, 15U, 21U, 28U, 36U, 45U, 55U, 2U,  14U,
        27U, 41U, 56U, 8U,  25U, 43U, 62U, 18U, 39U, 61U, 20U, 44U
    };

    constexpr boost::crypt::array<boost::crypt::uint32_t, num_rounds> pi_lane_number {
        10U, 7U,  11U, 17U, 18U, 3U, 5U,  16U, 8U,  21U, 24U, 4U,
        15U, 23U, 19U, 13U, 12U, 2U, 20U, 14U, 22U, 9U,  6U,  1U
    };

    constexpr boost::crypt::array<boost::crypt::uint64_t, num_rounds> iota {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
    };

    #endif // BOOST_CRYPT_HAS_CUDA

    using namespace sha3_detail;

    // Prepare the state array cube
    for (boost::crypt::size_t i = 0U, state_i = 0U; i < capacity; i += 8U, ++state_i)
    {
        state_array_[state_i] =
               (static_cast<boost::crypt::uint64_t>(buffer_[i]) << 56U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i + 1U]) << 48U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i + 2U]) << 40U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i + 3U]) << 32U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i + 4U]) << 24U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i + 5U]) << 16U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i + 6U]) << 8U) |
               (static_cast<boost::crypt::uint64_t>(buffer_[i + 7U]));
    }

    // Apply Kecckaf
    // TODO(mborland): All of these substep loops can be aggressively unrolled
    boost::crypt::array<boost::crypt::uint64_t, 5U> cd {};
    for (boost::crypt::size_t round {}; round < num_rounds; ++round)
    {
        // Theta
        for (boost::crypt::size_t i {}; i < cd.size(); ++i)
        {
            cd[i] = state_array_[i] ^ state_array_[i + 5U] ^ state_array_[i + 10U] ^ state_array_[i + 15U] ^ state_array_[i + 20U];
        }

        for (boost::crypt::size_t i {}; i < cd.size(); ++i)
        {
            const auto temp {cd[(i + 4U) % 5U] ^ detail::rotl(cd[(i + 1U) % 5U], 1U)};
            for (boost::crypt::size_t j {}; j < state_array_.size(); j += 5U)
            {
                state_array_[j + i] ^= temp;
            }
        }

        // Rho and Pi
        auto temp {state_array_[1U]};
        for (boost::crypt::size_t i {}; i < state_array_.size() - 1U; ++i)
        {
            const auto j {pi_lane_number[i]};
            cd[0] = state_array_[j];
            state_array_[j] = detail::rotl(temp, rho_rotation[i]);
            temp = cd[0];
        }

        // Chi
        for (boost::crypt::size_t j {}; j < state_array_.size(); j += 5U)
        {
            for (boost::crypt::size_t i {}; i < cd.size(); ++i)
            {
                cd[i] = state_array_[j + i];
            }
            for (boost::crypt::size_t i {}; i < cd.size(); ++i)
            {
                state_array_[j + i] ^= (~cd[(i + 1U) % 5U]) & cd[(i + 2U) % 5U];
            }
        }

        // Iota
        state_array_[0] ^= iota[round];
    }

    buffer_index_ = 0U;
}

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
BOOST_CRYPT_GPU_ENABLED inline auto sha3_base<digest_size, is_xof, capacity>::get_digest() noexcept -> sha3_base<digest_size, is_xof, capacity>::return_type
{
    return_type digest{};

    if (corrupted_)
    {
        return digest;
    }
    if (!computed_)
    {
        if (buffer_index_ == capacity)
        {
            process_message_block();
        }

        // SHA-3 uses the pad pattern 10 ... 01

        buffer_[++buffer_index_] = static_cast<boost::crypt::uint8_t>(0x10);

        if (buffer_index_ == capacity)
        {
            process_message_block();
        }

        while (buffer_index_ < capacity - 1U)
        {
            buffer_[buffer_index_++] = static_cast<boost::crypt::uint8_t>(0x00);
        }

        buffer_[buffer_index_] = static_cast<boost::crypt::uint8_t>(0x01);

        low_ = 0UL;
        high_ = 0UL;
        computed_ = true;
    }

    for (boost::crypt::size_t i {}; i < digest.size(); ++i)
    {
        digest[i] = buffer_[i];
    }

    return digest;
}

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
template <typename ByteType>
auto sha3_base<digest_size, is_xof, capacity>::process_byte(ByteType byte) noexcept -> hasher_state
{
    static_assert(boost::crypt::is_convertible_v<ByteType, boost::crypt::uint8_t>, "Byte must be convertible to uint8_t");
    const auto value {static_cast<boost::crypt::uint8_t>(byte)};
    return update(&value, 1UL);
}

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 1, bool>>
auto sha3_base<digest_size, is_xof, capacity>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state
{
    if (!utility::is_null(buffer))
    {
        return update(buffer, byte_count);
    }
    else
    {
        return hasher_state::null;
    }
}

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 2, bool>>
auto sha3_base<digest_size, is_xof, capacity>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state
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
        return hasher_state::null;
    }

    #else

    if (!utility::is_null(buffer))
    {
        const auto* data {reinterpret_cast<const unsigned char*>(buffer)};
        return update(data, byte_count * 2U);
    }
    else
    {
        return hasher_state::null;
    }

    #endif
}

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 4, bool>>
auto sha3_base<digest_size, is_xof, capacity>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state
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
        return hasher_state::null;
    }

    #else

    if (!utility::is_null(buffer))
    {
        const auto* data {reinterpret_cast<const unsigned char*>(buffer)};
        return update(data, byte_count * 4U);
    }
    else
    {
        return hasher_state::null;
    }

    #endif
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
inline auto sha3_base<digest_size, is_xof, capacity>::process_bytes(std::string_view str) noexcept -> hasher_state
{
    return process_bytes(str.begin(), str.size());
}

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
inline auto sha3_base<digest_size, is_xof, capacity>::process_bytes(std::u16string_view str) noexcept -> hasher_state
{
    return process_bytes(str.begin(), str.size());
}

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
inline auto sha3_base<digest_size, is_xof, capacity>::process_bytes(std::u32string_view str) noexcept -> hasher_state
{
    return process_bytes(str.begin(), str.size());
}

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
inline auto sha3_base<digest_size, is_xof, capacity>::process_bytes(std::wstring_view str) noexcept -> hasher_state
{
    return process_bytes(str.begin(), str.size());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

#ifdef BOOST_CRYPT_HAS_SPAN

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
template <typename T, boost::crypt::size_t extent>
inline auto sha3_base<digest_size, is_xof, capacity>::process_bytes(std::span<T, extent> data) noexcept -> hasher_state
{
    return process_bytes(data.begin(), data.size());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <boost::crypt::size_t digest_size, bool is_xof, boost::crypt::size_t capacity>
template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED inline auto sha3_base<digest_size, is_xof, capacity>::process_bytes(cuda::std::span<T, extent> data) noexcept -> hasher_state
{
    return process_bytes(data.begin(), data.size());
}

#endif // BOOST_CRYPT_HAS_SPAN

} // namespace hash_detail
} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_DETAIL_SHA3_BASE_HPP
