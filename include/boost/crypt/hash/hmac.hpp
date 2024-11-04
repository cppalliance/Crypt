// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_HMAC_HPP
#define BOOST_CRYPT_HASH_HMAC_HPP

#include <boost/crypt/hash/hasher_state.hpp>
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

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr hmac(ForwardIter key, boost::crypt::size_t size) noexcept { init(key, size); }

    BOOST_CRYPT_GPU_ENABLED constexpr hmac(const key_type& inner_key, const key_type& outer_key) noexcept { init_from_keys(inner_key, outer_key); }

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(ForwardIter key, boost::crypt::size_t size) noexcept -> hasher_state;

    BOOST_CRYPT_GPU_ENABLED constexpr auto init_from_keys(const key_type& inner_key,
                                                          const key_type& outer_key) noexcept -> hasher_state;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto process_bytes(ForwardIter data, boost::crypt::size_t size) noexcept -> hasher_state;

    BOOST_CRYPT_GPU_ENABLED constexpr auto get_digest() noexcept -> return_type;

    BOOST_CRYPT_GPU_ENABLED constexpr auto get_outer_key() noexcept -> key_type;

    BOOST_CRYPT_GPU_ENABLED constexpr auto get_inner_key() noexcept -> key_type;
};

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
constexpr auto
hmac<HasherType>::init_from_keys(const boost::crypt::array<boost::crypt::uint8_t, block_size_> &inner_key,
                                 const boost::crypt::array<boost::crypt::uint8_t, block_size_> &outer_key) noexcept -> hasher_state
{
    inner_key_ = inner_key;
    outer_key_ = outer_key;

    const auto inner_result {inner_hash_.process_bytes(inner_key_.begin(), inner_key_.size())};
    const auto outer_result {outer_hash_.process_bytes(outer_hash_.begin(), outer_key_.size())};

    if (BOOST_CRYPT_LIKELY(inner_result == hasher_state::success && outer_result == hasher_state::success))
    {
        initialized_ = true;
        return hasher_state::success;
    }
    else
    {
        // If we have some weird OOM result
        // LCOV_EXCL_START
        if (inner_result != hasher_state::success)
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
constexpr auto hmac<HasherType>::process_bytes(ForwardIter data, boost::crypt::size_t size) noexcept -> hasher_state
{
    if (utility::is_null(data) || size == 0U)
    {
        return hasher_state::null;
    }
    else if (!initialized_ || corrupted_)
    {
        return hasher_state::state_error;
    }

    const auto status_code {inner_hash_.process_bytes(data, size)};
    if (BOOST_CRYPT_LIKELY(status_code == hasher_state::success))
    {
        return hasher_state::success;
    }
    else
    {
        // Cannot test 64 and 128 bit OOM
        // LCOV_EXCL_START
        switch (status_code)
        {
            case hasher_state::state_error:
                corrupted_ = true;
                return hasher_state::state_error;
            case hasher_state::input_too_long:
                corrupted_ = true;
                return hasher_state::input_too_long;
            default:
                BOOST_CRYPT_UNREACHABLE;
                return status_code;
        }
        // LCOV_EXCL_STOP
    }
}

template <typename HasherType>
template <typename ForwardIter>
constexpr auto hmac<HasherType>::init(ForwardIter key, boost::crypt::size_t size) noexcept -> hasher_state
{
    boost::crypt::array<boost::crypt::uint8_t, block_size_> k0 {};

    if (utility::is_null(key) || size == 0U)
    {
        return hasher_state::null;
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

        auto key_iter {res.begin()};
        for (auto& byte : k0)
        {
            byte = *key_iter++;
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

    if (BOOST_CRYPT_LIKELY(inner_result == hasher_state::success && outer_result == hasher_state::success))
    {
        initialized_ = true;
        return hasher_state::success;
    }
    else
    {
        // If we have some weird OOM result
        // LCOV_EXCL_START
        if (inner_result != hasher_state::success)
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
