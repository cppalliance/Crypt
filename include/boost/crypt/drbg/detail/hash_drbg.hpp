// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DRBG_HASH_DRBG_HPP
#define BOOST_CRYPT_DRBG_HASH_DRBG_HPP

#include <boost/crypt/utility/state.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/cstddef.hpp>
#include <boost/crypt/utility/type_traits.hpp>
#include <boost/crypt/utility/array.hpp>
#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/null.hpp>

#if !defined(BOOST_CRYPT_BUILD_MODULE) && !defined(BOOST_CRYPT_HAS_CUDA)
#include <memory>
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
template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
class hash_drbg
{
private:

    static constexpr boost::crypt::size_t outlen_bytes {outlen / 8U};
    static constexpr boost::crypt::size_t max_bytes_per_request {65536U};
    static constexpr boost::crypt::size_t min_length {max_hasher_security / 8U};
    static constexpr boost::crypt::size_t min_entropy {min_length * 3U / 2U};
    static constexpr boost::crypt::size_t seedlen {outlen >= 384 ? 888U : 444U};
    static constexpr boost::crypt::size_t seedlen_bytes {seedlen / 8U};

    static constexpr boost::crypt::uint64_t max_length {4294967296ULL}; // 2^35 / 8
    static constexpr boost::crypt::uint64_t reseed_interval {281474976710656ULL}; // 2^48

    boost::crypt::array<boost::crypt::size_t, seedlen_bytes> constant_ {};
    boost::crypt::array<boost::crypt::size_t, seedlen_bytes> value_ {};

    boost::crypt::size_t reseed_counter_ {};
    bool initialized_ {};

    template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3 = boost::crypt::uint8_t*, typename ForwardIter4 = boost::crypt::uint8_t*, typename ForwardIter5 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto hash_df(boost::crypt::uint32_t no_of_bits_to_return,
                                                   ForwardIter1 return_container, boost::crypt::size_t return_container_size,
                                                   ForwardIter2 provided_data_1, boost::crypt::size_t provided_data_size_1,
                                                   ForwardIter3 provided_data_2 = nullptr, boost::crypt::size_t provided_data_size_2 = 0U,
                                                   ForwardIter4 provided_data_3 = nullptr, boost::crypt::size_t provided_data_size_3 = 0U,
                                                   ForwardIter5 provided_data_4 = nullptr, boost::crypt::size_t provided_data_size_4 = 0U) noexcept -> state;

public:

    BOOST_CRYPT_GPU_ENABLED constexpr hash_drbg() = default;

    template <typename ForwardIter1, typename ForwardIter2 = boost::crypt::uint8_t*, typename ForwardIter3 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(ForwardIter1 entropy, boost::crypt::size_t entropy_size,
                                                ForwardIter2 nonce = nullptr, boost::crypt::size_t nonce_size = 0U,
                                                ForwardIter3 personalization = nullptr, boost::crypt::size_t personalization_size = 0U) noexcept -> state;

    template <typename Container1>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const Container1& entropy) noexcept -> state;

    template <typename Container1, typename Container2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const Container1& entropy,
                                                const Container2& nonce) noexcept -> state;

    template <typename Container1, typename Container2, typename Container3>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const Container1& entropy,
                                                const Container2& nonce,
                                                const Container3& personalization) noexcept -> state;

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    constexpr auto init(std::string_view entropy) noexcept -> state
    { return init(entropy.begin(), entropy.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U, static_cast<boost::crypt::uint8_t*>(nullptr), 0U); }

    constexpr auto init(std::string_view entropy, std::string_view nonce) noexcept -> state
    { return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U); }

    constexpr auto init(std::string_view entropy, std::string_view nonce, std::string_view personalization) noexcept -> state
    { return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), personalization.begin(), personalization.size()); }
    #endif

    #ifdef BOOST_CRYPT_HAS_SPAN
    template <typename T, std::size_t extent>
    constexpr auto init(std::span<T, extent> entropy) noexcept -> state
    { return init(entropy.begin(), entropy.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U, static_cast<boost::crypt::uint8_t*>(nullptr), 0U); }

    template <typename T, std::size_t extent>
    constexpr auto init(std::span<T, extent> entropy, std::span<T, extent> nonce) noexcept -> state
    { return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U); }

    template <typename T, std::size_t extent>
    constexpr auto init(std::span<T, extent> entropy, std::span<T, extent> nonce, std::span<T, extent> personalization) noexcept -> state
    { return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), personalization.begin(), personalization.size()); }
    #endif

};

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1, typename Container2, typename Container3>
constexpr auto
hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::init(const Container1 &entropy,
                                                                                const Container2 &nonce,
                                                                                const Container3 &personalization) noexcept -> state
{
    return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), personalization.begin(), personalization.size());
}

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1, typename Container2>
constexpr auto
hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::init(const Container1 &entropy,
                                                                                const Container2 &nonce) noexcept -> state
{
    return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U);
}

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1>
constexpr auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::init(
        const Container1 &entropy) noexcept -> state
{
    return init(entropy.begin(), entropy.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U, static_cast<boost::crypt::uint8_t*>(nullptr), 0U);
}

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
constexpr auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::init(
        ForwardIter1 entropy, boost::crypt::size_t entropy_size,
        ForwardIter2 nonce, boost::crypt::size_t nonce_size,
        ForwardIter3 personalization, boost::crypt::size_t personalization_size) noexcept -> state
{
    // Nonce is to be at least >= 0.5 * max_hasher_security
    // Unless entropy + nonce >= 1.5 * max_hasher_security
    if (utility::is_null(entropy) || entropy_size == 0U)
    {
        return state::null;
    }

    if (entropy_size + nonce_size < min_entropy)
    {
        return state::insufficient_entropy;
    }

    auto seed_status {hash_df(seedlen, value_.begin(), value_.size(), entropy, entropy_size, nonce, nonce_size, personalization, personalization_size)};

    if (BOOST_CRYPT_UNLIKELY(seed_status != state::success))
    {
        return seed_status;
    }

    constexpr boost::crypt::array<boost::crypt::uint8_t, 1U> offset_array = { 0x00 };
    seed_status = hash_df(seedlen, constant_.begin(), constant_.size(), offset_array.begin(), offset_array.size(), value_.begin(), value_.size());

    if (BOOST_CRYPT_UNLIKELY(seed_status != state::success))
    {
        return seed_status;
    }

    initialized_ = true;
    reseed_counter_ = 1U;

    return state::success;
}

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3, typename ForwardIter4, typename ForwardIter5>
constexpr auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::hash_df(
        boost::crypt::uint32_t no_of_bits_to_return,
        ForwardIter1 return_container, boost::crypt::size_t return_container_size,
        ForwardIter2 provided_data_1,  boost::crypt::size_t provided_data_size_1,
        ForwardIter3 provided_data_2,  boost::crypt::size_t provided_data_size_2,
        ForwardIter4 provided_data_3,  boost::crypt::size_t provided_data_size_3,
        ForwardIter5 provided_data_4,  boost::crypt::size_t provided_data_size_4) noexcept -> state
{
    boost::crypt::array<boost::crypt::uint8_t, seedlen_bytes / outlen_bytes + 1> temp {};
    const auto no_of_bytes_to_return {no_of_bits_to_return / 8U};
    const auto len {(no_of_bytes_to_return + 7U) / outlen_bytes};
    BOOST_CRYPT_ASSERT(len <= temp.size());

    if (BOOST_CRYPT_UNLIKELY(len > 255))
    {
        return state::requested_too_many_bits;
    }

    // The hash string concatenates the value of no_of_bits_to_return
    boost::crypt::array<boost::crypt::uint8_t, 4U> bits_to_return_array = {
        static_cast<boost::crypt::uint8_t>(no_of_bits_to_return & 0xFF),
        static_cast<boost::crypt::uint8_t>((no_of_bits_to_return >> 8) & 0xFF),
        static_cast<boost::crypt::uint8_t>((no_of_bits_to_return >> 16) & 0xFF),
        static_cast<boost::crypt::uint8_t>((no_of_bits_to_return >> 24) & 0xFF)
    };

    // See 10.3.1
    // temp = temp || HASH(counter, no_of_bits_to_return || input_string)
    boost::crypt::size_t offset {};
    for (boost::crypt::uint8_t counter {0x01}; counter < static_cast<boost::crypt::uint8_t>(len); ++counter)
    {
        HasherType hasher;
        hasher.process_byte(counter);
        hasher.process_bytes(bits_to_return_array.begin(), bits_to_return_array.size());
        hasher.process_bytes(provided_data_1, provided_data_size_1);
        hasher.process_bytes(provided_data_2, provided_data_size_2);
        hasher.process_bytes(provided_data_3, provided_data_size_3);
        hasher.process_bytes(provided_data_4, provided_data_size_4);
        const auto return_val {hasher.get_digest()};

        if (BOOST_CRYPT_UNLIKELY(offset + return_val.size() <= temp.size()))
        {
            return state::out_of_memory;
        }
        for (const auto val : return_val)
        {
            temp[offset++] = val;
        }
    }

    if (BOOST_CRYPT_UNLIKELY(return_container_size > no_of_bytes_to_return))
    {
        return state::out_of_memory;
    }

    for (boost::crypt::size_t i {}; i < no_of_bytes_to_return; ++i)
    {
        return_container[i] = temp[i];
    }

    return state::success;
}

} // Namespace drbg
} // Namespace crypt
} // Namespace boost

#endif //BOOST_CRYPT_DRBG_HASH_DRBG_HPP
