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
template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen>
class hmac_drbg
{
private:
    static constexpr boost::crypt::size_t outlen_bytes {outlen / 8U};
    static constexpr boost::crypt::size_t max_bytes_per_request {65536U};
    static constexpr boost::crypt::size_t min_length {max_hasher_security / 8U};
    static constexpr boost::crypt::size_t max_length {4294967296UL}; // 2^35 / 8
    static constexpr boost::crypt::size_t min_entropy {min_length * 3U / 2U};

    boost::crypt::array<boost::crypt::uint8_t, outlen_bytes> key_ {};
    boost::crypt::array<boost::crypt::uint8_t, outlen_bytes> value_ {};
    boost::crypt::size_t reseed_counter_ {};
    bool initialized_ {};
    bool corrupted_ {};

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto update(ForwardIter provided_data, boost::crypt::size_t size) noexcept -> void;

public:

    BOOST_CRYPT_GPU_ENABLED constexpr hmac_drbg() = default;

    // TODO(mborland): constexpr_init: Does not allow arbitrary length inputs. Just 3 * outlen_bytes

    template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3 = void>
    BOOST_CRYPT_GPU_ENABLED inline auto init(ForwardIter1 entropy, boost::crypt::size_t entropy_size,
                                             ForwardIter2 nonce = nullptr, boost::crypt::size_t nonce_size = 0,
                                             ForwardIter3 personalization = nullptr, boost::crypt::size_t personalization_size = 0) noexcept -> drbg_state;
};

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
inline auto
hmac_drbg<HasherType, max_hasher_security, outlen>::init(ForwardIter1 entropy, boost::crypt::size_t entropy_size,
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
        update(seed_material.get(), offset);
        #else
        update(seed_material, offset);
        cudaFree(seed_material);
        #endif
    }

    reseed_counter_ = 1U;
    initialized_ = true;
    return drbg_state::success;
}

} // namespace drbg
} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_DRBG_HMAC_DRBG_HPP
