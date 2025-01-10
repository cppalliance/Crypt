// Copyright 2024 - 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

#ifndef BOOST_CRYPT2_HASH_DETAIL_SHA3_BASE_HPP
#define BOOST_CRYPT2_HASH_DETAIL_SHA3_BASE_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/assert.hpp>
#include <boost/crypt2/detail/expected.hpp>
#include <boost/crypt2/state.hpp>

namespace boost::crypt::hash_detail {

template <compat::size_t digest_size, bool is_xof = false>
class sha3_base final
{
public:

    static constexpr compat::size_t block_size {200U - 2U * digest_size};

private:

    static_assert((!is_xof && (digest_size == 28U || digest_size == 32U || digest_size == 48U || digest_size == 64U)) || is_xof,
                  "Digest size must be 28 (SHA3-224), 32 (SHA3-256), 48 (SHA3-384), or 64(SHA3-512) or this must be an xof");

    compat::array<compat::uint64_t, 25U> state_array_ {};
    compat::array<compat::byte, block_size> buffer_ {};
    compat::size_t buffer_index_ {};
    bool computed_ {};
    bool corrupted_ {};

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_message_block() noexcept -> void;

    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto update(compat::span<const compat::byte> data) noexcept -> state;

public:

    using return_type = compat::array<compat::byte, digest_size>;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha3_base() noexcept { init(); }

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~sha3_base() noexcept;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init() noexcept -> void;
};

template <compat::size_t digest_size, bool is_xof>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha3_base<digest_size, is_xof>::process_message_block() noexcept -> void
{

}

template <compat::size_t digest_size, bool is_xof>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha3_base<digest_size, is_xof>::update(compat::span<const compat::byte> data) noexcept -> state
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

        if (buffer_index_ == buffer_.size())
        {
            process_message_block();
        }
    }

    return state::success;
}

template <compat::size_t digest_size, bool is_xof>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha3_base<digest_size, is_xof>::~sha3_base() noexcept
{
    detail::clear_mem(state_array_);
    detail::clear_mem(buffer_);
    buffer_index_ = 0U;
    computed_ = false;
    corrupted_ = false;
}

template <compat::size_t digest_size, bool is_xof>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha3_base<digest_size, is_xof>::init() noexcept -> void
{
    state_array_.fill(0ULL);
    buffer_.fill(compat::byte{0x00});
    buffer_index_ = 0U;
    computed_ = false;
    corrupted_ = false;
}

} // namespace boost::crypt::hash_detail

#endif //BOOST_CRYPT2_HASH_DETAIL_SHA3_BASE_HPP
