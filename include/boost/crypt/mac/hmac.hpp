// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_HMAC_HPP
#define BOOST_CRYPT_HASH_HMAC_HPP

#include <boost/crypt/utility/state.hpp>
#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/cstddef.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/null.hpp>
#include <boost/crypt/utility/array.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT template <typename HasherType>
class hmac
{
public:

    static constexpr boost::crypt::size_t block_size_ {HasherType::block_size};
    using return_type = typename HasherType::return_type;
    using key_type = boost::crypt::array<boost::crypt::uint8_t, block_size_>;

private:

    key_type inner_key_ {};
    key_type outer_key_ {};
    HasherType inner_hash_;
    HasherType outer_hash_;
    bool initialized_ {false};
    bool computed_ {false};
    bool corrupted_ {false};

public:

    BOOST_CRYPT_GPU_ENABLED constexpr hmac() noexcept = default;

    #ifdef BOOST_CRYPT_HAS_CXX20_CONSTEXPR
    BOOST_CRYPT_GPU_ENABLED constexpr ~hmac() noexcept { destroy(); }
    #endif

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr hmac(ForwardIter key, boost::crypt::size_t size) noexcept { init(key, size); }

    template <typename Container>
    BOOST_CRYPT_GPU_ENABLED constexpr hmac(const Container& c) noexcept { init(c.begin(), c.size()); }

    BOOST_CRYPT_GPU_ENABLED constexpr hmac(const key_type& inner_key, const key_type& outer_key) noexcept { init_from_keys(inner_key, outer_key); }

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(ForwardIter key, boost::crypt::size_t size) noexcept -> state;

    template <typename Container>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const Container& c) noexcept -> state { return init(c.begin(), c.size()); }

    template <typename Container>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init_from_keys(const Container& inner_key,
                                                          const Container& outer_key) noexcept -> state;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_bytes(ForwardIter data, boost::crypt::size_t size) noexcept -> state;

    template <typename Container>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_bytes(const Container& c) noexcept -> state { return process_bytes(c.begin(), c.size()); }

    BOOST_CRYPT_GPU_ENABLED constexpr auto get_digest() noexcept -> return_type;

    BOOST_CRYPT_GPU_ENABLED constexpr auto get_outer_key() noexcept -> key_type;

    BOOST_CRYPT_GPU_ENABLED constexpr auto get_inner_key() noexcept -> key_type;

    BOOST_CRYPT_GPU_ENABLED constexpr auto destroy() noexcept -> void;
};

template <typename HasherType>
constexpr auto hmac<HasherType>::destroy() noexcept -> void
{
    inner_key_.fill(0x00);
    outer_key_.fill(0x00);
    inner_hash_.destroy();
    outer_hash_.destroy();
    initialized_ = false;
    computed_ = false;
    corrupted_ = false;
}

template <typename HasherType>
constexpr auto hmac<HasherType>::get_inner_key() noexcept -> key_type
{
    return inner_key_;
}

template <typename HasherType>
constexpr auto hmac<HasherType>::get_outer_key() noexcept -> key_type
{
    return outer_key_;
}

template <typename HasherType>
template <typename Container>
constexpr auto hmac<HasherType>::init_from_keys(const Container &inner_key,
                                                const Container &outer_key) noexcept -> state
{
    computed_ = false;
    corrupted_ = false;
    inner_hash_.init();
    outer_hash_.init();

    inner_key_ = inner_key;
    outer_key_ = outer_key;

    const auto inner_result {inner_hash_.process_bytes(inner_key_.begin(), inner_key_.size())};
    const auto outer_result {outer_hash_.process_bytes(outer_key_.begin(), outer_key_.size())};

    if (BOOST_CRYPT_LIKELY(inner_result == state::success && outer_result == state::success))
    {
        initialized_ = true;
        return state::success;
    }
    else
    {
        // If we have some weird OOM result
        // LCOV_EXCL_START
        if (inner_result != state::success)
        {
            return inner_result;
        }
        else
        {
            return outer_result;
        }
        // LCOV_EXCL_STOP
    }
}

template <typename HasherType>
constexpr auto hmac<HasherType>::get_digest() noexcept -> return_type
{
    if (computed_)
    {
        corrupted_ = true;
    }
    if (corrupted_)
    {
        return return_type {};
    }

    computed_ = true;
    const auto r_inner {inner_hash_.get_digest()};
    outer_hash_.process_bytes(r_inner.begin(), r_inner.size());
    return outer_hash_.get_digest();
}

template <typename HasherType>
template <typename ForwardIter>
constexpr auto hmac<HasherType>::process_bytes(ForwardIter data, boost::crypt::size_t size) noexcept -> state
{
    if (utility::is_null(data) || size == 0U)
    {
        return state::null;
    }
    else if (!initialized_ || corrupted_)
    {
        return state::state_error;
    }

    const auto status_code {inner_hash_.process_bytes(data, size)};
    if (BOOST_CRYPT_LIKELY(status_code == state::success))
    {
        return state::success;
    }
    else
    {
        // Cannot test 64 and 128 bit OOM
        // LCOV_EXCL_START
        switch (status_code)
        {
            case state::state_error:
                corrupted_ = true;
                return state::state_error;
            case state::input_too_long:
                corrupted_ = true;
                return state::input_too_long;
            default:
                BOOST_CRYPT_UNREACHABLE;
        }
        // LCOV_EXCL_STOP
    }
}

template <typename HasherType>
template <typename ForwardIter>
constexpr auto hmac<HasherType>::init(ForwardIter key, boost::crypt::size_t size) noexcept -> state
{
    computed_ = false;
    corrupted_ = false;
    inner_hash_.init();
    outer_hash_.init();

    boost::crypt::array<boost::crypt::uint8_t, block_size_> k0 {};

    if (utility::is_null(key) || size == 0U)
    {
        return state::null;
    }

    // Step 1: If the length of K = B set K0 = K. Go to step 4
    // OR
    // Step 3: If the length of K < B: append zeros to the end of K.
    if (size <= block_size_)
    {
        auto key_iter {key};
        for (boost::crypt::size_t i {}; i < size; ++i)
        {
            k0[i] = static_cast<boost::crypt::uint8_t>(*key_iter++);
        }
    }
    // Step 2: If the length of K > B: hash K to obtain an L byte string
    else if (size > block_size_)
    {
        HasherType hasher;
        hasher.process_bytes(key, size);
        const auto res {hasher.get_digest()};
        
        BOOST_CRYPT_ASSERT(res.size() <= k0.size());

        for (boost::crypt::size_t i {}; i < res.size(); ++i)
        {
            k0[i] = res[i];
        }
    }

    // Step 4: XOR k0 with ipad to produce a B-byte string K0 ^ ipad
    // Step 7: XOR k0 with opad to produce a B-byte string K0 ^ opad
    for (boost::crypt::size_t i {}; i < k0.size(); ++i)
    {
        inner_key_[i] = static_cast<boost::crypt::uint8_t>(k0[i] ^ static_cast<boost::crypt::size_t>(0x36));
        outer_key_[i] = static_cast<boost::crypt::uint8_t>(k0[i] ^ static_cast<boost::crypt::size_t>(0x5c));
    }

    const auto inner_result {inner_hash_.process_bytes(inner_key_.begin(), inner_key_.size())};
    const auto outer_result {outer_hash_.process_bytes(outer_key_.begin(), outer_key_.size())};

    if (BOOST_CRYPT_LIKELY(inner_result == state::success && outer_result == state::success))
    {
        initialized_ = true;
        return state::success;
    }
    else
    {
        // If we have some weird OOM result
        // LCOV_EXCL_START
        if (inner_result != state::success)
        {
            return inner_result;
        }
        else
        {
            return outer_result;
        }
        // LCOV_EXCL_STOP
    }
}

} // namespace crypt
} // namespace boost

#endif //BOOST_CRYPT_HASH_HMAC_HPP
