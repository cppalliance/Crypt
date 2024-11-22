// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_DETAIL_HASHER_BASE_512_HPP
#define BOOST_CRYPT_HASH_DETAIL_HASHER_BASE_512_HPP

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

// This hasher base is for use processing 512-bit blocks at a time
template <boost::crypt::size_t digest_size,
          boost::crypt::size_t intermediate_hash_size,
          typename Derived>
class hasher_base_512
{
public:
    static constexpr boost::crypt::size_t block_size {64U};

protected:

    // Use CRTP to make this constexpr with C++14
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_message_block() noexcept -> void { static_cast<Derived*>(this)->process_message_block(); };

    BOOST_CRYPT_GPU_ENABLED constexpr auto pad_message() noexcept -> void;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto update(ForwardIter data, boost::crypt::size_t size) noexcept -> state;

    boost::crypt::array<boost::crypt::uint32_t, intermediate_hash_size> intermediate_hash_ {};
    boost::crypt::array<boost::crypt::uint8_t , block_size> buffer_ {};
    boost::crypt::size_t buffer_index_ {};
    boost::crypt::size_t low_ {};
    boost::crypt::size_t high_ {};
    bool computed {};
    bool corrupted {};

public:

    using return_type = boost::crypt::array<boost::crypt::uint8_t, digest_size>;

    BOOST_CRYPT_GPU_ENABLED constexpr auto base_init() noexcept -> void;

    #ifdef BOOST_CRYPT_HAS_CXX20_CONSTEXPR
    BOOST_CRYPT_GPU_ENABLED constexpr ~hasher_base_512() noexcept { destroy(); }
    #endif

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

    BOOST_CRYPT_GPU_ENABLED constexpr auto get_base_digest() noexcept -> return_type;

    BOOST_CRYPT_GPU_ENABLED constexpr auto destroy() noexcept -> void { base_init(); };
};

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
BOOST_CRYPT_GPU_ENABLED constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::base_init() noexcept -> void
{
    intermediate_hash_.fill(0);
    buffer_.fill(0);
    buffer_index_ = 0U;
    low_ = 0U;
    high_ = 0U;
    computed = false;
    corrupted = false;
}

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
template <typename ByteType>
BOOST_CRYPT_GPU_ENABLED constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::process_byte(ByteType byte) noexcept -> state
{
    static_assert(boost::crypt::is_convertible_v<ByteType, boost::crypt::uint8_t>, "Byte must be convertible to uint8_t");
    const auto value {static_cast<boost::crypt::uint8_t>(byte)};
    return update(&value, 1UL);
}

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 1, bool>>
BOOST_CRYPT_GPU_ENABLED constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> state
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

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 2, bool>>
BOOST_CRYPT_GPU_ENABLED constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> state
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

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 4, bool>>
BOOST_CRYPT_GPU_ENABLED constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> state
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

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
BOOST_CRYPT_GPU_ENABLED constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::get_base_digest() noexcept -> hasher_base_512<digest_size, intermediate_hash_size, Derived>::return_type
{
    hasher_base_512<digest_size, intermediate_hash_size, Derived>::return_type digest{};

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
        digest[i] = static_cast<boost::crypt::uint8_t>(intermediate_hash_[i >> 2U] >> 8U * (3U - (i & 0x03U)));
    }

    return digest;
}

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
BOOST_CRYPT_GPU_ENABLED constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::pad_message() noexcept -> void
{
    // 448 bits out of 512
    constexpr boost::crypt::size_t message_length_start_index {56U};

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

    buffer_[56U] = static_cast<boost::crypt::uint8_t>(high_ >> 24U);
    buffer_[57U] = static_cast<boost::crypt::uint8_t>(high_ >> 16U);
    buffer_[58U] = static_cast<boost::crypt::uint8_t>(high_ >>  8U);
    buffer_[59U] = static_cast<boost::crypt::uint8_t>(high_);
    buffer_[60U] = static_cast<boost::crypt::uint8_t>(low_ >> 24U);
    buffer_[61U] = static_cast<boost::crypt::uint8_t>(low_ >> 16U);
    buffer_[62U] = static_cast<boost::crypt::uint8_t>(low_ >>  8U);
    buffer_[63U] = static_cast<boost::crypt::uint8_t>(low_);

    process_message_block();
}

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
template <typename ForwardIter>
BOOST_CRYPT_GPU_ENABLED constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::update(ForwardIter data, boost::crypt::size_t size) noexcept -> state
{
    if (size == 0U)
    {
        return state::success;
    }
    if (computed)
    {
        corrupted = true;
    }
    if (corrupted)
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
                corrupted = true;
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

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::process_bytes(std::string_view str) noexcept -> state
{
    return process_bytes(str.begin(), str.size());
}

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::process_bytes(std::u16string_view str) noexcept -> state
{
    return process_bytes(str.begin(), str.size());
}

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::process_bytes(std::u32string_view str) noexcept -> state
{
    return process_bytes(str.begin(), str.size());
}

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::process_bytes(std::wstring_view str) noexcept -> state
{
    return process_bytes(str.begin(), str.size());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

#ifdef BOOST_CRYPT_HAS_SPAN

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
template <typename T, boost::crypt::size_t extent>
constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::process_bytes(std::span<T, extent> data) noexcept -> state
{
    return process_bytes(data.begin(), data.size());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size, typename Derived>
template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED constexpr auto hasher_base_512<digest_size, intermediate_hash_size, Derived>::process_bytes(cuda::std::span<T, extent> data) noexcept -> state
{
    return process_bytes(data.begin(), data.size());
}

#endif // BOOST_CRYPT_HAS_SPAN

} // namespace hash_detail
} // namespace crypt
} // namespace boost

#endif //BOOST_CRYPT_HASH_DETAIL_HASHER_BASE_512_HPP
