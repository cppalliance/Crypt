// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DRBG_HMAC_DRBG_HPP
#define BOOST_CRYPT_DRBG_HMAC_DRBG_HPP

#include <boost/crypt/fwd.hpp>
#include <boost/crypt/hash/hmac.hpp>
#include <boost/crypt/drbg/drbg_state.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/cstddef.hpp>
#include <boost/crypt/utility/type_traits.hpp>
#include <boost/crypt/utility/array.hpp>
#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/null.hpp>

#if !defined(BOOST_CRYPT_BUILD_MODULE) && !defined(BOOST_CRYPT_HAS_CUDA)
#include <memory>
#include <string>
#include <cstdint>
#include <cstring>
#endif

namespace boost {
namespace crypt {
namespace drbg {

// Max hasher security is defined in NIST SP 800-57 Table 3:
// See: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
//
// 112: None
// 128: SHA-1
// 192: SHA-224, SHA-512/224, SHA3-224
// 256: SHA-256, SHA-512/256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512
//
// Outlen is defined in NIST SP 800-90A Rev 1 Section 10.1 table 2
// 160: SHA-1
// 224: SHA-224, SHA-512/224
// 256: SHA-256, SHA-512/256
// 384: SHA-384
// 512: SHA-512
template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
class hmac_drbg
{
private:
    static constexpr boost::crypt::size_t outlen_bytes {outlen / 8U};
    static constexpr boost::crypt::size_t max_bytes_per_request {65536U};
    static constexpr boost::crypt::size_t min_length {max_hasher_security / 8U};
    static constexpr boost::crypt::size_t min_entropy {min_length * 3U / 2U};

    static constexpr boost::crypt::uint64_t max_length {4294967296ULL}; // 2^35 / 8
    static constexpr boost::crypt::uint64_t reseed_interval {281474976710656ULL}; // 2^48

    typename HMACType::return_type key_ {};
    typename HMACType::return_type value_ {};
    boost::crypt::size_t reseed_counter_ {};
    bool initialized_ {};

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED inline auto update_impl(ForwardIter1 provided_data, boost::crypt::size_t provided_data_size,
                                                    ForwardIter2 storage, boost::crypt::size_t storage_size) noexcept -> drbg_state;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED inline auto update(ForwardIter provided_data, boost::crypt::size_t size) noexcept -> drbg_state;

public:

    BOOST_CRYPT_GPU_ENABLED constexpr hmac_drbg() = default;

    template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3 = const boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED inline auto init(ForwardIter1 entropy, boost::crypt::size_t entropy_size,
                                             ForwardIter2 nonce = nullptr, boost::crypt::size_t nonce_size = 0,
                                             ForwardIter3 personalization = nullptr, boost::crypt::size_t personalization_size = 0) noexcept -> drbg_state;

    template <typename ForwardIter1, typename ForwardIter2 = const boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED inline auto reseed(ForwardIter1 entropy, boost::crypt::size_t entropy_size,
                                               ForwardIter2 additional_input = nullptr, boost::crypt::size_t additional_input_size = 0) noexcept -> drbg_state;

    template <typename ForwardIter1, typename ForwardIter2 = const boost::crypt::uint8_t*, boost::crypt::enable_if_t<!prediction_resistance, bool> = true>
    BOOST_CRYPT_GPU_ENABLED inline auto generate(ForwardIter1 data, boost::crypt::size_t requested_bits,
                                                 ForwardIter2 additional_data = nullptr, boost::crypt::size_t additional_data_size = 0) noexcept -> drbg_state;
};

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2>
auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::update_impl(
        ForwardIter1 provided_data, boost::crypt::size_t provided_data_size,
        ForwardIter2 storage, boost::crypt::size_t storage_size) noexcept -> drbg_state
{
    BOOST_CRYPT_ASSERT(value_.size() + 1U + provided_data_size <= storage_size);
    static_cast<void>(storage_size);

    // Step 1: V || 0x00 || provided data
    boost::crypt::size_t offset {};
    for (boost::crypt::size_t i {}; i < value_.size(); ++i)
    {
        storage[offset++] = static_cast<boost::crypt::uint8_t>(value_[i]);
    }
    storage[offset++] = static_cast<boost::crypt::uint8_t>(0x00);
    for (boost::crypt::size_t i {}; i < provided_data_size; ++i)
    {
        storage[offset++] = static_cast<boost::crypt::uint8_t>(provided_data[i]);
    }

    HMACType hmac(key_);
    hmac.process_bytes(storage, offset);
    key_ = hmac.get_digest();
    hmac.init(key_);
    hmac.process_bytes(value_);
    value_ = hmac.get_digest();

    if (provided_data_size != 0U)
    {
        // Need to overwrite the value of V
        // The provided data remains the same
        for (boost::crypt::size_t i {}; i < value_.size(); ++i)
        {
            storage[i] = static_cast<boost::crypt::uint8_t>(value_[i]);
        }
        storage[value_.size()] = static_cast<boost::crypt::uint8_t>(0x01);

        hmac.init(key_);
        hmac.process_bytes(storage, offset);
        key_ = hmac.get_digest();
        hmac.init(key_);
        hmac.process_bytes(value_);
        value_ = hmac.get_digest();
    }

    return drbg_state::success;
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter>
inline auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::update(
        ForwardIter provided_data, boost::crypt::size_t size) noexcept -> drbg_state
{
    // Still need to process even with null pointer
    if (utility::is_null(provided_data))
    {
        size = 0U;
    }

    if (BOOST_CRYPT_LIKELY(size < 3 * outlen_bytes))
    {
        boost::crypt::array<boost::crypt::uint8_t, outlen_bytes * 4 + 1U> data_plus_value {};
        return update_impl(provided_data, size, data_plus_value.begin(), data_plus_value.size());
    }
    else
    {
        // We need to do dynamic memory allocation because the upper bound on memory usage is huge
        // V || 0x00 or 0x01 || additional data
        const auto total_size {value_.size() + 1U + size};
        #ifndef BOOST_CRYPT_HAS_CUDA
        auto data_plus_value {std::make_unique<boost::crypt::uint8_t[]>(total_size)};
        #else
        boost::crypt::uint8_t* data_plus_value;
        cudaMallocManaged(&data_plus_value, total_size * sizeof(boost::crypt_uint8_t));
        #endif

        if (data_plus_value == nullptr)
        {
            return drbg_state::out_of_memory; // LCOV_EXCL_LINE
        }

        #ifndef BOOST_CRYPT_HAS_CUDA
        return update_impl(provided_data, size, data_plus_value.get(), total_size);
        #else
        const auto return_val {update_impl(provided_data, size, data_plus_value, total_size)};
        cudaFree(data_plus_value);
        return return_val;
        #endif
    }
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
inline auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::init(
        ForwardIter1 entropy, boost::crypt::size_t entropy_size,
        ForwardIter2 nonce, boost::crypt::size_t nonce_size,
        ForwardIter3 personalization, boost::crypt::size_t personalization_size) noexcept -> drbg_state
{
    // Nonce is to be at least >= 0.5 * max_hasher_security
    // Unless entropy + nonce >= 1.5 * max_hasher_security
    if (utility::is_null(entropy) || entropy_size == 0U)
    {
        return drbg_state::null;
    }

    if (utility::is_null(nonce) || nonce_size == 0U)
    {
        nonce_size = 0U;
    }
    else if (entropy_size + nonce_size < min_entropy)
    {
        return drbg_state::insufficient_entropy;
    }

    if (utility::is_null(personalization) || personalization_size == 0U)
    {
        personalization_size = 0U;
    }

    // Key needs to be set to all 0x00
    for (auto& byte : key_)
    {
        byte = static_cast<boost::crypt::uint8_t>(0x00);
    }
    // Value needs to be set to all 0x01
    for (auto& byte : value_)
    {
        byte = static_cast<boost::crypt::uint8_t>(0x01);
    }

    const boost::crypt::size_t total_input_size {entropy_size + nonce_size + personalization_size};

    if (BOOST_CRYPT_LIKELY(total_input_size < 3 * outlen_bytes))
    {
        boost::crypt::array<boost::crypt::uint8_t, 3 * outlen_bytes> seed_material {};
        boost::crypt::size_t offset {};

        // Seed material is: entropy_input || nonce || personalization_string
        for (boost::crypt::size_t i {}; i < entropy_size; ++i)
        {
            seed_material[offset++] = static_cast<boost::crypt::uint8_t>(entropy[i]);
        }
        for (boost::crypt::size_t i {}; i < nonce_size; ++i)
        {
            seed_material[offset++] = static_cast<boost::crypt::uint8_t>(nonce[i]);
        }
        for (boost::crypt::size_t i {}; i < personalization_size; ++i)
        {
            seed_material[offset++] = static_cast<boost::crypt::uint8_t>(personalization[i]);
        }

        BOOST_CRYPT_ASSERT(offset == total_input_size);

        const auto update_return {update(seed_material.begin(), offset)};
        if (update_return != drbg_state::success)
        {
            return update_return;
        }
    }
    else if (entropy_size > max_length)
    {
        return drbg_state::entropy_too_long; // LCOV_EXCL_LINE
    }
    else if (nonce_size > max_length)
    {
        return drbg_state::nonce_too_long; // LCOV_EXCL_LINE
    }
    else if (personalization_size > max_length)
    {
        return drbg_state::personalization_too_long; // LCOV_EXCL_LINE
    }
    else
    {
        // We need to do dynamic memory allocation because the upper bound on memory usage is huge
        #ifndef BOOST_CRYPT_HAS_CUDA
        auto seed_material {std::make_unique<boost::crypt::uint8_t[]>(total_input_size)};
        #else
        boost::crypt::uint8_t* seed_material;
        cudaMallocManaged(&seed_material, total_input_size * sizeof(boost::crypt_uint8_t));
        #endif

        if (seed_material == nullptr)
        {
            return drbg_state::out_of_memory; // LCOV_EXCL_LINE
        }

        boost::crypt::size_t offset {};
        for (boost::crypt::size_t i {}; i < entropy_size; ++i)
        {
            seed_material[offset++] = static_cast<boost::crypt::uint8_t>(entropy[i]);
        }
        for (boost::crypt::size_t i {}; i < nonce_size; ++i)
        {
            seed_material[offset++] = static_cast<boost::crypt::uint8_t>(nonce[i]);
        }
        for (boost::crypt::size_t i {}; i < personalization_size; ++i)
        {
            seed_material[offset++] = static_cast<boost::crypt::uint8_t>(personalization[i]);
        }

        #ifndef BOOST_CRYPT_HAS_CUDA
        const auto update_return {update(seed_material.get(), offset)};
        #else
        const auto update_return {update(seed_material, offset)};
        cudaFree(seed_material);
        #endif

        if (update_return != drbg_state::success)
        {
            return update_return;
        }
    }

    reseed_counter_ = 1U;
    initialized_ = true;
    return drbg_state::success;
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2>
auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::reseed(
        ForwardIter1 entropy, boost::crypt::size_t entropy_size,
        ForwardIter2 additional_input, boost::crypt::size_t additional_input_size) noexcept -> drbg_state
{
    constexpr auto min_reseed_entropy {max_hasher_security / 8U};
    if (utility::is_null(entropy) || entropy_size == 0U)
    {
        return drbg_state::null;
    }
    if (entropy_size < min_reseed_entropy)
    {
        return drbg_state::insufficient_entropy;
    }
    if (utility::is_null(additional_input))
    {
        additional_input_size = 0U;
    }

    const auto seed_material_size {entropy_size + additional_input_size};

    if (seed_material_size < 3U * min_reseed_entropy)
    {
        // Happy path of static memory init
        boost::crypt::array<boost::crypt::uint8_t, 3U * min_reseed_entropy> seed_material {};
        boost::crypt::size_t offset {};
        for (boost::crypt::size_t i {}; i < entropy_size; ++i)
        {
            seed_material[offset++] = static_cast<boost::crypt::uint8_t>(*entropy++);
        }
        for (boost::crypt::size_t i {}; i < additional_input_size; ++i)
        {
            seed_material[offset++] = static_cast<boost::crypt::uint8_t>(*additional_input++);
        }

        BOOST_CRYPT_ASSERT(offset == seed_material_size);

        const auto update_result {update(seed_material, seed_material_size)};
        if (update_result != drbg_state::success)
        {
            return update_result;
        }
    }
    else if (entropy_size > max_length)
    {
        return drbg_state::entropy_too_long;
    }
    else if (additional_input_size > max_length)
    {
        return drbg_state::personalization_too_long;
    }
    else
    {
        // We need to do dynamic memory allocation because the upper bound on memory usage is huge
        #ifndef BOOST_CRYPT_HAS_CUDA
        auto seed_material {std::make_unique<boost::crypt::uint8_t[]>(seed_material_size)};
        #else
        boost::crypt::uint8_t* seed_material;
        cudaMallocManaged(&seed_material, seed_material_size * sizeof(boost::crypt_uint8_t));
        #endif

        if (seed_material == nullptr)
        {
            return drbg_state::out_of_memory; // LCOV_EXCL_LINE
        }

        boost::crypt::size_t offset {};
        for (boost::crypt::size_t i {}; i < entropy_size; ++i)
        {
            seed_material[offset++] = static_cast<boost::crypt::uint8_t>(*entropy++);
        }
        for (boost::crypt::size_t i {}; i < additional_input_size; ++i)
        {
            seed_material[offset++] = static_cast<boost::crypt::uint8_t>(*additional_input++);
        }

        #ifndef BOOST_CRYPT_HAS_CUDA
        const auto update_return {update(seed_material.get(), seed_material_size)};
        #else
        const auto update_return {update(seed_material, seed_material_size)};
        cudaFree(seed_material);
        #endif

        if (update_return != drbg_state::success)
        {
            return update_return;
        }
    }

    reseed_counter_ = 1U;
    return drbg_state::success;
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, boost::crypt::enable_if_t<!prediction_resistance, bool>>
auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::generate(
        ForwardIter1 data, boost::crypt::size_t requested_bits,
        ForwardIter2 additional_data, boost::crypt::size_t additional_data_size) noexcept -> drbg_state
{
    if (reseed_counter_ > reseed_interval)
    {
        return drbg_state::requires_reseed;
    }
    if (utility::is_null(data))
    {
        return drbg_state::null;
    }
    if (!initialized_)
    {
        return drbg_state::uninitialized;
    }

    const boost::crypt::size_t requested_bytes {requested_bits / 8U};
    if (requested_bytes > max_bytes_per_request)
    {
        return drbg_state::requested_too_many_bits;
    }

    if (utility::is_null(additional_data))
    {
        additional_data_size = 0U;
    }
    if (additional_data_size != 0U)
    {
        if (additional_data_size > max_length)
        {
            return drbg_state::personalization_too_long;
        }
        update(additional_data, additional_data_size);
    }

    boost::crypt::size_t bytes {};
    while (bytes < requested_bytes)
    {
        HMACType hmac(key_);
        hmac.process_bytes(value_);
        value_ = hmac.get_digest();

        if (bytes + value_.size() < requested_bytes)
        {
            for (boost::crypt::size_t i {}; i < value_.size(); ++i)
            {
                *data++ = value_[i];
            }

            bytes += value_.size();
        }
        else
        {
            boost::crypt::size_t i {};
            while (bytes < requested_bytes)
            {
                *data++ = value_[i++];
                ++bytes;
            }
        }
    }

    update(additional_data, additional_data_size);

    ++reseed_counter_;
    return drbg_state::success;
}

template <bool prediction_resistance>
BOOST_CRYPT_EXPORT using sha1_hmac_drbg_t = drbg::hmac_drbg<hmac<sha1_hasher>, 128U, 160U, prediction_resistance>;

} // namespace drbg

BOOST_CRYPT_EXPORT using sha1_hmac_drbg = drbg::sha1_hmac_drbg_t<false>;
BOOST_CRYPT_EXPORT using sha1_hmac_drbg_pr = drbg::sha1_hmac_drbg_t<true>;

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_DRBG_HMAC_DRBG_HPP
