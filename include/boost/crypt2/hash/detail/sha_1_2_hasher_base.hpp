// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_DETAIL_SHA_1_2_HASHER_BASE_HPP
#define BOOST_CRYPT_HASH_DETAIL_SHA_1_2_HASHER_BASE_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/state.hpp>

#ifndef BOOST_CRYPT_BUILD_MODULE

#include <span>
#include <array>
#include <ranges>
#include <algorithm>
#include <cstdint>
#include <cstddef>

#elif defined(BOOST_CRYPT_HAS_CUDA)

#include <cuda/std/span>
#include <cuda/std/array>
#include <cuda/std/cstdint>
#include <cuda/std/cstddef>
#include <cuda/std/concepts>
#include <cuda/std/ranges>
#include <thrust/fill.h>

#endif

namespace boost::crypt::hash_detail {

// We need to inject these for ADL,
// and make it trivial to switch between CUDA and regular modes
#ifndef BOOST_CRYPT_HAS_CUDA

using std::size_t;
using std::uint32_t;
using std::array;
using std::byte;
using std::fill;
using std::span;
using std::ranges::sized_range;
using std::ranges::output_range;
using std::ranges::range_value_t;
using std::is_trivially_copyable_v;
using std::as_bytes;
using std::as_writable_bytes;
using std::forward;

#else

using size_t = unsigned long;
using cuda::std::uint32_t;
using cuda::std::array;
using cuda::std::byte;
using cuda::std::span;
using cuda::std::ranges::sized_range;
using cuda::std::ranges::output_range;
using cuda::std::ranges::range_value_t;
using cuda::std::is_trivially_copyable_v;
using cuda::std::as_bytes;
using cuda::std::as_writable_bytes;
using cuda::std::forward;
using thrust::fill;

#endif

template <size_t digest_size, size_t intermediate_hash_size>
class sha_1_2_hasher_base
{
public:
    static constexpr size_t block_size {64U};

protected:

    // Each hasher needs to process their own message block in their own way
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR virtual auto process_message_block() noexcept -> void = 0;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto pad_message() noexcept -> void;

    array<uint32_t, intermediate_hash_size> intermediate_hash_ {};
    array<byte, block_size> buffer_ {};
    size_t buffer_index_ {};
    size_t low_ {};
    size_t high_ {};
    bool computed_ {};
    bool corrupted_ {};

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto update(span<const byte> data) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_digest_impl(span<byte, digest_size> data);

public:

    using return_type = array<byte, digest_size>;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha_1_2_hasher_base() noexcept { base_init(); }
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~sha_1_2_hasher_base() noexcept { destroy(); }

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_bytes(span<const byte> data) noexcept -> state;

    template <sized_range Range>
    BOOST_CRYPT_GPU_ENABLED auto process_bytes(Range&& data) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto finalize() noexcept -> state;

    [[nodiscard("Digest is the function return value")]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_digest() noexcept -> return_type;
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_digest(span<byte, digest_size> data) noexcept -> void;

    template <typename Range>
    BOOST_CRYPT_GPU_ENABLED auto get_digest(Range&& data) noexcept -> void
        requires output_range<Range, range_value_t<Range>> &&
                 sized_range<Range> &&
                 is_trivially_copyable_v<range_value_t<Range>>;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto base_init() noexcept -> void;
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto destroy() noexcept -> void;
};

template <size_t digest_size, size_t intermediate_hash_size>
template <typename Range>
auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::get_digest(Range&& data) noexcept -> void
    requires output_range<Range, range_value_t<Range>> &&
             sized_range<Range> &&
             is_trivially_copyable_v<range_value_t<Range>>
{
    using value_type = range_value_t<Range>;

    auto data_span {span<value_type>(forward<Range>(data))};

    if (data_span.size() * sizeof(value_type) < digest_size) {
        return;
    }

    get_digest_impl(span<byte, digest_size>(
            as_writable_bytes(data_span).data(),
            digest_size
    ));
}

template <size_t digest_size, size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::get_digest_impl(span<byte, digest_size> data)
{
    if (corrupted_)
    {
        return data;
    }
    if (!computed_)
    {
        finalize();
    }

    for (size_t i {}; i < data.size(); ++i)
    {
        data[i] = static_cast<byte>(intermediate_hash_[i >> 2U] >> 8U * (3U - (i & 0x03U)));
    }

    return data;
}

template <size_t digest_size, size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
sha_1_2_hasher_base<digest_size, intermediate_hash_size>::get_digest(span<byte, digest_size> data) noexcept -> void
{
    get_digest_impl(data);
}

template <size_t digest_size, size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
sha_1_2_hasher_base<digest_size, intermediate_hash_size>::get_digest() noexcept -> sha_1_2_hasher_base::return_type
{
    return_type digest {};
    get_digest_impl(digest);
    return digest;
}

template <size_t digest_size, size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::finalize() noexcept -> state
{
    if (corrupted_)
    {
        // Return empty message on corruption
        return state::state_error;
    }
    if (!computed_)
    {
        pad_message();

        // Overwrite whatever is in the buffer in case it is sensitive
        detail::clear_mem(buffer_);
        low_ = 0U;
        high_ = 0U;
        computed_ = true;
    }

    return state::success;
}

template <size_t digest_size, size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::pad_message() noexcept -> void
{
    // 448 bits out of 512
    constexpr size_t message_length_start_index {56U};

    // We don't have enough space for everything we need
    if (buffer_index_ >= message_length_start_index)
    {
        buffer_[buffer_index_++] = static_cast<byte>(0x80);
        while (buffer_index_ < buffer_.size())
        {
            buffer_[buffer_index_++] = static_cast<byte>(0x00);
        }

        process_message_block();

        while (buffer_index_ < message_length_start_index)
        {
            buffer_[buffer_index_++] = static_cast<byte>(0x00);
        }
    }
    else
    {
        buffer_[buffer_index_++] = static_cast<byte>(0x80);
        while (buffer_index_ < message_length_start_index)
        {
            buffer_[buffer_index_++] = static_cast<byte>(0x00);
        }
    }

    // Add the message length to the end of the buffer
    // BOOST_CRYPT_ASSERT(buffer_index_ == message_length_start_index);

    buffer_[56U] = static_cast<byte>(high_ >> 24U);
    buffer_[57U] = static_cast<byte>(high_ >> 16U);
    buffer_[58U] = static_cast<byte>(high_ >>  8U);
    buffer_[59U] = static_cast<byte>(high_);
    buffer_[60U] = static_cast<byte>(low_ >> 24U);
    buffer_[61U] = static_cast<byte>(low_ >> 16U);
    buffer_[62U] = static_cast<byte>(low_ >>  8U);
    buffer_[63U] = static_cast<byte>(low_);

    process_message_block();
}

template <size_t digest_size, size_t intermediate_hash_size>
template <sized_range SizedRange>
auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::process_bytes(SizedRange&& data) noexcept -> state
{
    // Clang warns -Wunqualified-std-cast-call with just the using statement
    // so we must change context this way
    #ifndef BOOST_CRYPT_HAS_CUDA
    auto data_span {span(std::forward<SizedRange>(data))};
    #else
    auto data_span {span(cuda::std::forward<SizedRange>(data))};
    #endif

    return update(as_bytes(data_span));
}

template <size_t digest_size, size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::process_bytes(span<const byte> data) noexcept -> state
{
    return update(data);
}

template <size_t digest_size, size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::update(span<const byte> data) noexcept -> state
{
    if (data.empty())
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

    for (const auto val : data)
    {
        buffer_[buffer_index_++] = val;
        low_ += 8U;

        if (low_ == 0U) [[unlikely]]
        {
            // Would indicate size_t rollover which should not happen on a single data stream
            // LCOV_EXCL_START
            ++high_;
            if (high_ == 0U) [[unlikely]]
            {
                corrupted_ = true;
                return state::input_too_long;
            }
            // LCOV_EXCL_STOP
        }

        if (buffer_index_ == buffer_.size())
        {
            process_message_block();
            buffer_index_ = 0U;
        }
    }

    return state::success;
}

template <size_t digest_size, size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::destroy() noexcept -> void
{
    using boost::crypt::detail::clear_mem;

    intermediate_hash_.fill(0U);
    clear_mem(buffer_);
    buffer_index_ = 0U;
    low_ = 0U;
    high_ = 0U;
    computed_ = false;
    corrupted_ = false;
}

template <size_t digest_size, size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::base_init() noexcept -> void
{
    intermediate_hash_.fill(0U);
    buffer_.fill(static_cast<byte>(0));
    buffer_index_ = 0U;
    low_ = 0U;
    high_ = 0U;
    computed_ = false;
    corrupted_ = false;
}

} // namespace boost::crypt::hash_detail

#endif //BOOST_CRYPT_HASH_DETAIL_SHA_1_2_HASHER_BASE_HPP
