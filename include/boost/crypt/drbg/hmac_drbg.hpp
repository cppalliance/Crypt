// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DRBG_HMAC_DRBG_HPP
#define BOOST_CRYPT_DRBG_HMAC_DRBG_HPP

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
template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen>
class hmac_drbg
{
private:
    static constexpr boost::crypt::size_t outlen_bytes {outlen / 8U};
    static constexpr boost::crypt::size_t max_bytes_per_request {65536U};
    static constexpr boost::crypt::size_t min_length {max_hasher_security / 8U};
    static constexpr boost::crypt::size_t max_length {4294967296UL}; // 2^35 / 8
    static constexpr boost::crypt::size_t min_entropy {min_length * 3U / 2U};

    typename HMACType::return_type key_ {};
    typename HMACType::return_type value_ {};
    boost::crypt::size_t reseed_counter_ {};
    bool initialized_ {};
    bool corrupted_ {};

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED inline auto update_impl(ForwardIter data_plus_value, boost::crypt::size_t size) noexcept -> void;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED inline auto update(ForwardIter provided_data, boost::crypt::size_t size) noexcept -> drbg_state;

public:

    BOOST_CRYPT_GPU_ENABLED constexpr hmac_drbg() = default;

    template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3 = void>
    BOOST_CRYPT_GPU_ENABLED inline auto init(ForwardIter1 entropy, boost::crypt::size_t entropy_size,
                                             ForwardIter2 nonce = nullptr, boost::crypt::size_t nonce_size = 0,
                                             ForwardIter3 personalization = nullptr, boost::crypt::size_t personalization_size = 0) noexcept -> drbg_state;
};

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen>
template <typename ForwardIter>
auto hmac_drbg<HMACType, max_hasher_security, outlen>::update_impl(ForwardIter data_plus_value,
                                                                   boost::crypt::size_t size) noexcept -> void
{
    HMACType hmac_(key_);
    hmac_.process_bytes(data_plus_value, size);
    key_ = hmac_.get_digest();
    hmac_.init(key_);
    hmac_.process_bytes(value_);
    value_ = hmac_.get_digest();
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen>
template <typename ForwardIter>
inline auto hmac_drbg<HMACType, max_hasher_security, outlen>::update(ForwardIter provided_data,
                                                                     boost::crypt::size_t size) noexcept -> drbg_state
{
    if (BOOST_CRYPT_LIKELY(size < 3 * outlen_bytes))
    {
        boost::crypt::array<boost::crypt::uint8_t, outlen_bytes * 4 + 1U> data_plus_value {};
        
        boost::crypt::size_t offset {};
        for (boost::crypt::size_t i {}; i < value_.size(); ++i)
        {
            data_plus_value[offset++] = value_[i];
        }
        data_plus_value[offset++] = static_cast<boost::crypt::uint8_t>(0x00);
        for (boost::crypt::size_t i {}; i < size; ++i)
        {
            data_plus_value[offset++] = *provided_data++;
        }

        update_impl(data_plus_value.begin(), offset);

        boost::crypt::size_t offset_second_pass {};
        for (boost::crypt::size_t i {}; i < value_.size(); ++i)
        {
            data_plus_value[offset_second_pass++] = value_[i];
        }
        data_plus_value[offset_second_pass] = static_cast<boost::crypt::uint8_t>(0x01);

        update_impl(data_plus_value.begin(), offset);

        return drbg_state::success;
    }
    else
    {
        // We need to do dynamic memory allocation because the upper bound on memory usage is huge
        #ifndef BOOST_CRYPT_HAS_CUDA
        auto data_plus_value {std::make_unique<boost::crypt::uint8_t[]>(size)};
        #else
        boost::crypt::uint8_t* data_plus_value;
        cudaMallocManaged(&data_plus_value, size * sizeof(boost::crypt_uint8_t));
        #endif

        if (data_plus_value == nullptr)
        {
            return drbg_state::out_of_memory; // LCOV_EXCL_LINE
        }

        boost::crypt::size_t offset {};
        for (boost::crypt::size_t i {}; i < value_.size(); ++i)
        {
            data_plus_value[offset++] = value_[i];
        }
        data_plus_value[offset++] = static_cast<boost::crypt::uint8_t>(0x00);
        for (boost::crypt::size_t i {}; i < size; ++i)
        {
            data_plus_value[offset++] = *provided_data++;
        }

        #ifndef BOOST_CRYPT_HAS_CUDA
        update_impl(data_plus_value.get(), offset);
        #else
        update_impl(data_plus_value, offset);
        #endif

        boost::crypt::size_t offset_second_pass {};
        for (boost::crypt::size_t i {}; i < value_.size(); ++i)
        {
            data_plus_value[offset_second_pass++] = value_[i];
        }
        data_plus_value[offset_second_pass] = static_cast<boost::crypt::uint8_t>(0x01);

        #ifndef BOOST_CRYPT_HAS_CUDA
        update_impl(data_plus_value.get(), offset);
        #else
        update_impl(data_plus_value, offset);
        #endif

        #ifdef BOOST_CRYPT_HAS_CUDA
        cudaFree(data_plus_value);
        #endif

        return drbg_state::success;
    }
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
inline auto
hmac_drbg<HMACType, max_hasher_security, outlen>::init(ForwardIter1 entropy, boost::crypt::size_t entropy_size,
                                                         ForwardIter2 nonce, boost::crypt::size_t nonce_size,
                                                         ForwardIter3 personalization,
                                                         boost::crypt::size_t personalization_size) noexcept -> drbg_state
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
            seed_material[offset++] = *entropy++;
        }
        for (boost::crypt::size_t i {}; i < nonce_size; ++i)
        {
            seed_material[offset++] = *nonce++;
        }
        for (boost::crypt::size_t i {}; i < personalization_size; ++i)
        {
            seed_material[offset++] = *personalization++;
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
            seed_material[offset++] = *entropy++;
        }
        for (boost::crypt::size_t i {}; i < nonce_size; ++i)
        {
            seed_material[offset++] = *nonce++;
        }
        for (boost::crypt::size_t i {}; i < personalization_size; ++i)
        {
            seed_material[offset++] = *personalization++;
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

} // namespace drbg
} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_DRBG_HMAC_DRBG_HPP
