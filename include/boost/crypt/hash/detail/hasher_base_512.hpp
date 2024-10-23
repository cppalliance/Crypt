// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_DETAIL_HASHER_BASE_512_HPP
#define BOOST_CRYPT_HASH_DETAIL_HASHER_BASE_512_HPP

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

// This hasher base is for use processing 512-bit blocks at a time
template <boost::crypt::size_t digest_size,
          boost::crypt::size_t intermediate_hash_size>
class hasher_base_512
{
public:

    using return_type = boost::crypt::array<boost::crypt::uint8_t, digest_size>;

    BOOST_CRYPT_GPU_ENABLED auto base_init() noexcept -> void;

    template <typename ByteType>
    BOOST_CRYPT_GPU_ENABLED auto process_byte(ByteType byte) noexcept -> hasher_state;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 1, bool> = true>
    BOOST_CRYPT_GPU_ENABLED auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 2, bool> = true>
    BOOST_CRYPT_GPU_ENABLED auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state;

    template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 4, bool> = true>
    BOOST_CRYPT_GPU_ENABLED auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state;

    BOOST_CRYPT_GPU_ENABLED auto get_digest() noexcept -> return_type;

protected:

    virtual BOOST_CRYPT_GPU_ENABLED auto process_message_block() noexcept -> void = 0;

    BOOST_CRYPT_GPU_ENABLED auto pad_message() noexcept -> void;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED auto update(ForwardIter data, boost::crypt::size_t size) noexcept -> hasher_state;

    boost::crypt::array<boost::crypt::uint32_t, intermediate_hash_size> intermediate_hash_ {};
    boost::crypt::array<boost::crypt::uint8_t , 64U> buffer_ {};
    boost::crypt::size_t buffer_index_ {};

private:

    boost::crypt::size_t low_ {};
    boost::crypt::size_t high_ {};
    bool computed {};
    bool corrupted {};
};

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED auto hasher_base_512<digest_size, intermediate_hash_size>::base_init() noexcept -> void
{
    buffer_.fill(0);
    buffer_index_ = 0U;
    low_ = 0U;
    high_ = 0U;
    computed = false;
    corrupted = false;
}

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size>
template <typename ByteType>
BOOST_CRYPT_GPU_ENABLED auto hasher_base_512<digest_size, intermediate_hash_size>::process_byte(ByteType byte) noexcept -> hasher_state
{
    static_assert(boost::crypt::is_convertible_v<ByteType, boost::crypt::uint8_t>, "Byte must be convertible to uint8_t");
    const auto value {static_cast<boost::crypt::uint8_t>(byte)};
    return update(&value, 1UL);
}

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 1, bool>>
BOOST_CRYPT_GPU_ENABLED auto hasher_base_512<digest_size, intermediate_hash_size>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state
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

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 2, bool>>
BOOST_CRYPT_GPU_ENABLED auto hasher_base_512<digest_size, intermediate_hash_size>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state
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

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size>
template <typename ForwardIter, boost::crypt::enable_if_t<sizeof(typename utility::iterator_traits<ForwardIter>::value_type) == 4, bool>>
BOOST_CRYPT_GPU_ENABLED auto hasher_base_512<digest_size, intermediate_hash_size>::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept -> hasher_state
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

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED auto hasher_base_512<digest_size, intermediate_hash_size>::get_digest() noexcept -> hasher_base_512<digest_size, intermediate_hash_size>::return_type
{
    hasher_base_512<digest_size, intermediate_hash_size>::return_type digest{};

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

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED auto hasher_base_512<digest_size, intermediate_hash_size>::pad_message() noexcept -> void
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

template <boost::crypt::size_t digest_size, boost::crypt::size_t intermediate_hash_size>
template <typename ForwardIter>
BOOST_CRYPT_GPU_ENABLED auto hasher_base_512<digest_size, intermediate_hash_size>::update(ForwardIter data, boost::crypt::size_t size) noexcept -> hasher_state
{
    if (size == 0U)
    {
        return hasher_state::success;
    }
    if (computed)
    {
        corrupted = true;
    }
    if (corrupted)
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
            // Would indicate size_t rollover which should not happen on a single data stream
            // LCOV_EXCL_START
            ++high_;
            if (BOOST_CRYPT_UNLIKELY(high_ == 0))
            {
                corrupted = true;
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

} // namespace hash_detail
} // namespace crypt
} // namespace boost

#endif //BOOST_CRYPT_HASH_DETAIL_HASHER_BASE_512_HPP
