// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DRBG_HMAC_DRBG_HPP
#define BOOST_CRYPT_DRBG_HMAC_DRBG_HPP

#include <boost/crypt/mac/hmac.hpp>
#include <boost/crypt/utility/state.hpp>
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

    template <typename ForwardIter1, typename ForwardIter2 = boost::crypt::uint8_t*, typename ForwardIter3 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto update(ForwardIter1 provided_data_1, boost::crypt::size_t provided_data_size_1,
                                                  ForwardIter2 provided_data_2 = nullptr, boost::crypt::size_t provided_data_size_2 = 0U,
                                                  ForwardIter3 provided_data_3 = nullptr, boost::crypt::size_t provided_data_size_3 = 0U) noexcept -> state;

    template <typename ForwardIter1, typename ForwardIter2 = const boost::crypt::uint8_t*, typename ForwardIter3 = const boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generate_impl(const boost::crypt::false_type&,
                                                      ForwardIter1 data, boost::crypt::size_t requested_bits,
                                                      ForwardIter2 additional_data = nullptr, boost::crypt::size_t additional_data_size = 0,
                                                      ForwardIter3 additional_data_2 = nullptr, boost::crypt::size_t additional_data_2_size = 0) noexcept -> state;

    // Provides prediction resistance
    template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3 = const boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generate_impl(const boost::crypt::true_type&,
                                                      ForwardIter1 data, boost::crypt::size_t requested_bits,
                                                      ForwardIter2 entropy, boost::crypt::size_t entropy_size,
                                                      ForwardIter3 additional_data = nullptr, boost::crypt::size_t additional_data_size = 0) noexcept -> state;

public:

    BOOST_CRYPT_GPU_ENABLED constexpr hmac_drbg() = default;

    template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3 = const boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(ForwardIter1 entropy, boost::crypt::size_t entropy_size,
                                                ForwardIter2 nonce = nullptr, boost::crypt::size_t nonce_size = 0,
                                                ForwardIter3 personalization = nullptr, boost::crypt::size_t personalization_size = 0) noexcept -> state;

    template <typename Container1, typename Container2, typename Container3>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const Container1& entropy,
                                                const Container2& nonce,
                                                const Container3& personalization) noexcept -> state;

    template <typename Container1, typename Container2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const Container1& entropy,
                                                const Container2& nonce) noexcept -> state;

    template <typename Container1>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(const Container1& entropy) noexcept -> state;

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    constexpr auto init(std::string_view entropy) noexcept -> state { return init(entropy.begin(), entropy.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U, static_cast<boost::crypt::uint8_t*>(nullptr), 0U); }
    constexpr auto init(std::string_view entropy, std::string_view nonce) noexcept -> state { return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U); }
    constexpr auto init(std::string_view entropy, std::string_view nonce, std::string_view personalization) noexcept -> state { return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), personalization.begin(), personalization.size()); }
    #endif

    #ifdef BOOST_CRYPT_HAS_SPAN
    template <typename T, std::size_t extent>
    constexpr auto init(std::span<T, extent> entropy) noexcept -> state { return init(entropy.begin(), entropy.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U, static_cast<boost::crypt::uint8_t*>(nullptr), 0U); }

    template <typename T, std::size_t extent>
    constexpr auto init(std::span<T, extent> entropy, std::span<T, extent> nonce) noexcept -> state { return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U); }

    template <typename T, std::size_t extent>
    constexpr auto init(std::span<T, extent> entropy, std::span<T, extent> nonce, std::span<T, extent> personalization) noexcept -> state { return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), personalization.begin(), personalization.size()); }
    #endif

    template <typename ForwardIter1, typename ForwardIter2 = const boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto reseed(ForwardIter1 entropy, boost::crypt::size_t entropy_size,
                                                  ForwardIter2 additional_input = nullptr, boost::crypt::size_t additional_input_size = 0) noexcept -> state;

    template <typename Container1>
    BOOST_CRYPT_GPU_ENABLED constexpr auto reseed(const Container1& entropy) noexcept -> state;

    template <typename Container1, typename Container2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto reseed(const Container1& entropy,
                                                  const Container2& additional_input) noexcept -> state;

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    constexpr auto reseed(std::string_view entropy) noexcept -> state { return reseed(entropy.begin(), entropy.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U); }
    constexpr auto reseed(std::string_view entropy, std::string_view additional_input) noexcept -> state { return reseed(entropy.begin(), entropy.size(), additional_input.begin(), additional_input.size()); }
    #endif

    #ifdef BOOST_CRYPT_HAS_SPAN
    template <typename T, std::size_t extent>
    constexpr auto reseed(std::span<T, extent> entropy) noexcept -> state { return reseed(entropy.begin(), entropy.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U); }

    template <typename T, std::size_t extent>
    constexpr auto reseed(std::span<T, extent> entropy, std::span<T, extent> additional_input) noexcept -> state { return reseed(entropy.begin(), entropy.size(), additional_input.begin(), additional_input.size()); }
    #endif

    template <typename ForwardIter1, typename ForwardIter2 = const boost::crypt::uint8_t*, typename ForwardIter3 = const boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generate(ForwardIter1 data, boost::crypt::size_t requested_bits,
                                                    ForwardIter2 additional_data_1 = nullptr, boost::crypt::size_t additional_data_1_size = 0,
                                                    ForwardIter3 additional_data_2 = nullptr, boost::crypt::size_t additional_data_2_size = 0) noexcept -> state;

    template <typename Container1>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generate(Container1& data) noexcept -> state;

    template <typename Container1, typename Container2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generate(Container1& data, const Container2& additional_data_1) noexcept -> state;

    template <typename Container1, typename Container2, typename Container3>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generate(Container1& data, const Container2& additional_data_1, const Container3& additional_data_2) noexcept -> state;

};

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::generate(
        ForwardIter1 data, boost::crypt::size_t requested_bits,
        ForwardIter2 additional_data_1, boost::crypt::size_t additional_data_1_size,
        ForwardIter3 additional_data_2, boost::crypt::size_t additional_data_2_size) noexcept -> state
{
    using impl_type = boost::crypt::integral_constant<bool, prediction_resistance>;
    return generate_impl(impl_type(), data, requested_bits, additional_data_1, additional_data_1_size, additional_data_2, additional_data_2_size);
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::update(
        ForwardIter1 provided_data_1, boost::crypt::size_t provided_data_size_1,
        ForwardIter2 provided_data_2, boost::crypt::size_t provided_data_size_2,
        ForwardIter3 provided_data_3, boost::crypt::size_t provided_data_size_3) noexcept -> state
{
    const auto provided_data_size {provided_data_size_1 + provided_data_size_2 + provided_data_size_3};

    // Step 1: V || 0x00 || provided data
    boost::crypt::array<boost::crypt::uint8_t, 1> storage_gap {0x00};
    HMACType hmac(key_);
    hmac.process_bytes(value_.begin(), value_.size());
    hmac.process_bytes(storage_gap.begin(), storage_gap.size());
    hmac.process_bytes(provided_data_1, provided_data_size_1);
    hmac.process_bytes(provided_data_2, provided_data_size_2);
    hmac.process_bytes(provided_data_3, provided_data_size_3);
    key_ = hmac.get_digest();
    hmac.init(key_);
    hmac.process_bytes(value_);
    value_ = hmac.get_digest();

    if (provided_data_size != 0U)
    {
        // Step 2: V || 0x01 || provided data
        storage_gap[0] = static_cast<boost::crypt::uint8_t>(0x01);
        hmac.init(key_);
        hmac.process_bytes(value_.begin(), value_.size());
        hmac.process_bytes(storage_gap.begin(), storage_gap.size());
        hmac.process_bytes(provided_data_1, provided_data_size_1);
        hmac.process_bytes(provided_data_2, provided_data_size_2);
        hmac.process_bytes(provided_data_3, provided_data_size_3);
        key_ = hmac.get_digest();
        hmac.init(key_);
        hmac.process_bytes(value_);
        value_ = hmac.get_digest();
    }

    return state::success;
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::init(
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

    if (utility::is_null(nonce) || nonce_size == 0U)
    {
        nonce_size = 0U;
    }
    else if (entropy_size + nonce_size < min_entropy)
    {
        return state::insufficient_entropy;
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

    update(entropy, entropy_size, nonce, nonce_size, personalization, personalization_size);

    reseed_counter_ = 1U;
    initialized_ = true;
    return state::success;
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1, typename Container2, typename Container3>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::init(
        const Container1& entropy,
        const Container2& nonce,
        const Container3& personalization) noexcept -> state
{
    return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), personalization.begin(), personalization.size());
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1, typename Container2>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::init(
        const Container1& entropy,
        const Container2& nonce) noexcept -> state
{
    return init(entropy.begin(), entropy.size(), nonce.begin(), nonce.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U);
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::init(const Container1& entropy) noexcept -> state
{
    return init(entropy.begin(), static_cast<boost::crypt::size_t>(entropy.size()), static_cast<boost::crypt::uint8_t*>(nullptr), 0U, static_cast<boost::crypt::uint8_t*>(nullptr), 0U);
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::reseed(
        ForwardIter1 entropy, boost::crypt::size_t entropy_size,
        ForwardIter2 additional_input, boost::crypt::size_t additional_input_size) noexcept -> state
{
    constexpr auto min_reseed_entropy {max_hasher_security / 8U};
    if (utility::is_null(entropy) || entropy_size == 0U)
    {
        return state::null;
    }
    if (entropy_size < min_reseed_entropy)
    {
        return state::insufficient_entropy;
    }
    if (utility::is_null(additional_input))
    {
        additional_input_size = 0U;
    }

    update(entropy, entropy_size, additional_input, additional_input_size);

    reseed_counter_ = 1U;
    return state::success;
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::reseed(const Container1& entropy) noexcept -> state
{
    return reseed(entropy.begin(), entropy.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U);
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1, typename Container2>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::reseed(
        const Container1& entropy, const Container2& additional_input) noexcept -> state
{
    return reseed(entropy.begin(), entropy.size(), additional_input.begin(), additional_input.size());
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::generate_impl(
        const boost::crypt::false_type&,
        ForwardIter1 data, boost::crypt::size_t requested_bits,
        ForwardIter2 additional_data, boost::crypt::size_t additional_data_size,
        ForwardIter3, boost::crypt::size_t) noexcept -> state
{
    if (reseed_counter_ > reseed_interval)
    {
        return state::requires_reseed;
    }
    if (utility::is_null(data))
    {
        return state::null;
    }
    if (!initialized_)
    {
        return state::uninitialized;
    }

    const boost::crypt::size_t requested_bytes {requested_bits / 8U};
    if (requested_bytes > max_bytes_per_request)
    {
        return state::requested_too_many_bits;
    }

    if (utility::is_null(additional_data))
    {
        additional_data_size = 0U;
    }
    if (additional_data_size != 0U)
    {
        if (additional_data_size > max_length)
        {
            return state::input_too_long;
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
    return state::success;
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::generate_impl(
        const boost::crypt::true_type&,
        ForwardIter1 data, boost::crypt::size_t requested_bits,
        ForwardIter2 entropy, boost::crypt::size_t entropy_size,
        ForwardIter3 additional_data, boost::crypt::size_t additional_data_size) noexcept -> state
{
    if (reseed_counter_ > reseed_interval)
    {
        return state::requires_reseed;
    }
    if (utility::is_null(data) || utility::is_null(entropy))
    {
        return state::null;
    }
    if (!initialized_)
    {
        return state::uninitialized;
    }

    // 9.3.3 Reseed using the entropy and the additional data, then set additional data to NULL
    const auto reseed_return {reseed(entropy, entropy_size, additional_data, additional_data_size)};
    if (reseed_return != state::success)
    {
        return reseed_return;
    }

    return generate_impl(boost::crypt::false_type(), data, requested_bits);
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::generate(Container1& data) noexcept -> state
{
    return generate(data.begin(), data.size() * 8U, static_cast<boost::crypt::uint8_t*>(nullptr), 0U, static_cast<boost::crypt::uint8_t*>(nullptr), 0U);
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1, typename Container2>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::generate(
        Container1& data,
        const Container2& additional_data_1) noexcept -> state
{
    return generate(data.begin(), data.size() * 8U, additional_data_1.begin(), additional_data_1.size(), static_cast<boost::crypt::uint8_t*>(nullptr), 0U);
}

template <typename HMACType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1, typename Container2, typename Container3>
constexpr auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::generate(
        Container1& data,
        const Container2& additional_data_1,
        const Container3& additional_data_2) noexcept -> state
{
    return generate(data.begin(), data.size() * 8U, additional_data_1.begin(), additional_data_1.size(), additional_data_2.begin(), additional_data_2.size());
}

} // namespace drbg
} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_DRBG_HMAC_DRBG_HPP
