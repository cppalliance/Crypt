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
    static constexpr boost::crypt::size_t seedlen {outlen >= 384 ? 888U : 440U};
    static constexpr boost::crypt::size_t seedlen_bytes {seedlen / 8U};

    static constexpr boost::crypt::uint64_t max_length {4294967296ULL}; // 2^35 / 8
    static constexpr boost::crypt::uint64_t reseed_interval {281474976710656ULL}; // 2^48

    boost::crypt::array<boost::crypt::uint8_t, seedlen_bytes> constant_ {};
    boost::crypt::array<boost::crypt::uint8_t, seedlen_bytes> value_ {};

    boost::crypt::uint64_t reseed_counter_ {};
    bool initialized_ {};

    template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3 = boost::crypt::uint8_t*, typename ForwardIter4 = boost::crypt::uint8_t*, typename ForwardIter5 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto hash_df(boost::crypt::uint32_t no_of_bits_to_return,
                                                   ForwardIter1 return_container, boost::crypt::size_t return_container_size,
                                                   ForwardIter2 provided_data_1, boost::crypt::size_t provided_data_size_1,
                                                   ForwardIter3 provided_data_2 = nullptr, boost::crypt::size_t provided_data_size_2 = 0U,
                                                   ForwardIter4 provided_data_3 = nullptr, boost::crypt::size_t provided_data_size_3 = 0U,
                                                   ForwardIter5 provided_data_4 = nullptr, boost::crypt::size_t provided_data_size_4 = 0U) noexcept -> state;

    template <typename ForwardIter1>
    BOOST_CRYPT_GPU_ENABLED constexpr auto hashgen(ForwardIter1 returned_bits, boost::crypt::size_t requested_number_of_bytes) noexcept -> state;

    template <typename ForwardIter1, typename ForwardIter2 = boost::crypt::uint8_t*, typename ForwardIter3 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generate_impl(const boost::crypt::false_type&,
                                                         ForwardIter1 data, boost::crypt::size_t requested_bits,
                                                         ForwardIter2 additional_data, boost::crypt::size_t additional_data_size,
                                                         ForwardIter3, boost::crypt::size_t) noexcept -> state;

    template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generate_impl(const boost::crypt::true_type&,
                                                         ForwardIter1 data, boost::crypt::size_t requested_bits,
                                                         ForwardIter2 entropy, boost::crypt::size_t entropy_size,
                                                         ForwardIter3 additional_data, boost::crypt::size_t additional_data_size) noexcept -> state;

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

    template <typename ForwardIter1, typename ForwardIter2 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto reseed(ForwardIter1 entropy, boost::crypt::size_t entropy_size,
                                                  ForwardIter2 additional_input = nullptr, boost::crypt::size_t additional_input_size = 0U) noexcept -> state;

    template <typename Container1>
    BOOST_CRYPT_GPU_ENABLED constexpr auto reseed(const Container1& entropy) noexcept -> state;

    template <typename Container1, typename Container2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto reseed(const Container1& entropy,
                                                  const Container2& additional_input) noexcept -> state;

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    constexpr auto reseed(const std::string_view entropy) noexcept -> state
    { return reseed(entropy.begin(), entropy.size()); }

    constexpr auto reseed(const std::string_view entropy, const std::string_view additional_input) noexcept -> state
    { return reseed(entropy.begin(), entropy.size(), additional_input.begin(), additional_input.size()); }
    #endif  // BOOST_CRYPT_HAS_STRING_VIEW

    #ifdef BOOST_CRYPT_HAS_SPAN
    template <typename T, std::size_t extent>
    constexpr auto reseed(std::span<T, extent> entropy) noexcept -> state
    { return reseed(entropy.begin(), entropy.size()); }

    template <typename T, std::size_t extent>
    constexpr auto reseed(std::span<T, extent> entropy, std::span<T, extent> additional_input) noexcept -> state
    { return reseed(entropy.begin(), entropy.size(), additional_input.begin(), additional_input.size()); }
    #endif // BOOST_CRYPT_HAS_SPAN

    template <typename ForwardIter1, typename ForwardIter2 = boost::crypt::uint8_t*, typename ForwardIter3 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generate(ForwardIter1 data, boost::crypt::size_t requested_bits,
                                                    ForwardIter2 additional_data_1 = nullptr, boost::crypt::size_t additional_data_1_size = 0U,
                                                    ForwardIter3 additional_data_2 = nullptr, boost::crypt::size_t additional_data_2_size = 0U) noexcept -> state;
};

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1>
BOOST_CRYPT_GPU_ENABLED constexpr auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::hashgen(
    ForwardIter1 returned_bits, boost::crypt::size_t requested_number_of_bytes) noexcept -> state
{
    auto data {value_};
    boost::crypt::size_t offset {};
    while (offset < requested_number_of_bytes)
    {
        HasherType hasher {};
        const auto hasher_return {hasher.process_bytes(data.begin(), data.size())};
        if (BOOST_CRYPT_UNLIKELY(hasher_return != state::success))
        {
            return hasher_return;
        }

        #ifdef __clang__
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wsign-conversion"
        #endif

        const auto w {hasher.get_digest()};
        if (offset + w.size() < requested_number_of_bytes)
        {
            for (const auto byte : w)
            {
                returned_bits[offset++] = byte;
            }
        }
        else
        {
            for (boost::crypt::size_t i {}; offset < requested_number_of_bytes; ++i)
            {
                returned_bits[offset++] = w[i];
            }
        }

        #ifdef __clang__
        #pragma clang diagnostic pop
        #pragma clang diagnostic ignored "-Wsign-conversion"
        #endif

        // data = data + 1 mod 2^seedlen
        // We really skip the modulo here because once we hit the bounds check it's effectively the mod
        if (BOOST_CRYPT_LIKELY(data[0] < static_cast<boost::crypt::uint8_t>(0xFFU)))
        {
            data[0] = data[0] + static_cast<boost::crypt::uint8_t>(1U);
        }
        else
        {
            bool continue_rounding {};
            boost::crypt::size_t i {};
            while (i + 1U < data.size() && continue_rounding)
            {
                if (data[i] == static_cast<boost::crypt::uint8_t>(0xFFU))
                {
                    data[i] = static_cast<boost::crypt::uint8_t>(0U);
                    continue_rounding = true;
                }
                else if (continue_rounding)
                {
                    data[i] = data[i] + static_cast<boost::crypt::uint8_t>(1U);
                    continue_rounding = false;
                }

                ++i;
            }
        }
    }

    return state::success;
}

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
BOOST_CRYPT_GPU_ENABLED constexpr auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::generate_impl(
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

    const boost::crypt::size_t requested_bytes {(requested_bits + 7U) / 8U};
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
        // Step 2.1 and 2.2
        if (BOOST_CRYPT_UNLIKELY(additional_data_size > max_length))
        {
            return state::input_too_long; // LCOV_EXCL_LINE
        }
        HasherType hasher {};
        hasher.process_byte(static_cast<boost::crypt::uint8_t>(0x02));
        hasher.process_bytes(value_.begin(), value_.size());
        hasher.process_bytes(additional_data, additional_data_size);
        const auto w {hasher.get_digest()};

        // V = (v + w) mod 2^seedlen
        auto w_iter {w.cbegin()};
        auto v_iter {value_.begin()};

        // Since the size of V depends on the size of w we will never have an overflow situation
        for (; w_iter != w.cend(); ++w_iter, ++v_iter)
        {
            const auto sum_val {static_cast<boost::crypt::uint16_t>(static_cast<boost::crypt::uint16_t>(*w_iter) + static_cast<boost::crypt::uint16_t>(*v_iter))};
            const auto new_val {static_cast<boost::crypt::uint8_t>(sum_val & 0xFFU)};
            *v_iter = new_val;

            // Handle the carry
            if (sum_val > 0xFFU)
            {
                *(v_iter + 1) = *(v_iter + 1) + static_cast<boost::crypt::uint8_t>(1U);
            }
        }
    }

    // Step 3: Fill the buffer with the bytes to return to the user
    const auto hashgen_return {hashgen(data, requested_bytes)};
    if (BOOST_CRYPT_UNLIKELY(hashgen_return != state::success))
    {
        return hashgen_return;
    }

    // Step 4: H = Hash(0x03 || V)
    HasherType hasher {};
    hasher.process_byte(static_cast<boost::crypt::uint8_t>(0x03));
    hasher.process_bytes(value_.begin(), value_.size());
    const auto h {hasher.get_digest()};

    // Step 5: v = (v + h + c + reseed counter) mod 2^seedlen
    // Rather than converting V, H, C and reseed to bignums and applying big num modular arithmetic
    // we add all bytes of the same offset at once and have an integer rather than boolean carry
    // we also terminate the calculation at mod 2^seedlen since anything past that is irrelevant
    // It just so happens that value_ is 2^seedlen long
    const boost::crypt::array<boost::crypt::uint8_t, 64U / 8U> reseed_counter_bytes = {
        static_cast<boost::crypt::uint8_t>((reseed_counter_ >> 56U) & 0xFFU),
        static_cast<boost::crypt::uint8_t>((reseed_counter_ >> 48U) & 0xFFU),
        static_cast<boost::crypt::uint8_t>((reseed_counter_ >> 40U) & 0xFFU),
        static_cast<boost::crypt::uint8_t>((reseed_counter_ >> 32U) & 0xFFU),
        static_cast<boost::crypt::uint8_t>((reseed_counter_ >> 24U) & 0xFFU),
        static_cast<boost::crypt::uint8_t>((reseed_counter_ >> 16U) & 0xFFU),
        static_cast<boost::crypt::uint8_t>((reseed_counter_ >> 8U) & 0xFFU),
        static_cast<boost::crypt::uint8_t>(reseed_counter_ & 0xFFU),
    };

    boost::crypt::size_t offset {};
    boost::crypt::uint16_t carry {};
    while (offset < reseed_counter_bytes.size())
    {
         boost::crypt::uint16_t result {
            static_cast<boost::crypt::uint16_t>(
                static_cast<boost::crypt::uint16_t>(value_[offset]) +
                static_cast<boost::crypt::uint16_t>(h[offset]) +
                static_cast<boost::crypt::uint16_t>(constant_[offset]) +
                static_cast<boost::crypt::uint16_t>(reseed_counter_bytes[offset]) +
                carry
            )};

        carry = result >> 8U;
        result &= 0xFF;

        value_[offset] = static_cast<boost::crypt::uint8_t>(result);

        ++offset;
    }
    if (value_.size() < h.size())
    {
        while (offset < value_.size())
        {
            boost::crypt::uint16_t result {
                static_cast<boost::crypt::uint16_t>(
                    static_cast<boost::crypt::uint16_t>(value_[offset]) +
                    static_cast<boost::crypt::uint16_t>(h[offset]) +
                    static_cast<boost::crypt::uint16_t>(constant_[offset]) +
                    carry
                )};

            carry = result >> 8U;
            result &= 0xFF;

            value_[offset] = static_cast<boost::crypt::uint8_t>(result);

            ++offset;
        }
    }
    else
    {
        while (offset < h.size())
        {
            boost::crypt::uint16_t result {
                static_cast<boost::crypt::uint16_t>(
                    static_cast<boost::crypt::uint16_t>(value_[offset]) +
                    static_cast<boost::crypt::uint16_t>(h[offset]) +
                    static_cast<boost::crypt::uint16_t>(constant_[offset]) +
                    carry
                )};
            carry = result >> 8U;
            result &= 0xFF;

            value_[offset] = static_cast<boost::crypt::uint8_t>(result);

            ++offset;
        }
        while (offset < value_.size())
        {
            boost::crypt::uint16_t result {
                static_cast<boost::crypt::uint16_t>(
                        static_cast<boost::crypt::uint16_t>(value_[offset]) +
                        static_cast<boost::crypt::uint16_t>(constant_[offset]) +
                        carry
                )};
            carry = result >> 8U;
            result &= 0xFF;

            value_[offset] = static_cast<boost::crypt::uint8_t>(result);

            ++offset;
        }
    }

    ++reseed_counter_;
    return state::success;
}

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
BOOST_CRYPT_GPU_ENABLED constexpr auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::generate_impl(
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

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2, typename ForwardIter3>
BOOST_CRYPT_GPU_ENABLED constexpr auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::generate(ForwardIter1 data, boost::crypt::size_t requested_bits,
                                                ForwardIter2 additional_data_1, boost::crypt::size_t additional_data_1_size,
                                                ForwardIter3 additional_data_2, boost::crypt::size_t additional_data_2_size) noexcept -> state
{
    using impl_type = integral_constant<bool, prediction_resistance>;
    return generate_impl(impl_type(), data, requested_bits, additional_data_1, additional_data_1_size, additional_data_2, additional_data_2_size);
}

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1, typename Container2>
constexpr auto
hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::reseed(const Container1& entropy,
                                                                                  const Container2& additional_input) noexcept -> state
{
    return reseed(entropy.begin(), entropy.size(), additional_input.begin(), additional_input.size());
}

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename Container1>
constexpr auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::reseed(
        const Container1& entropy) noexcept -> state
{
    return reseed(entropy.begin(), entropy.size());
}

template <typename HasherType, boost::crypt::size_t max_hasher_security, boost::crypt::size_t outlen, bool prediction_resistance>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::reseed(
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

    constexpr boost::crypt::array<boost::crypt::uint8_t, 1U> offset_array = { 0x01 };
    auto seed_status = hash_df(seedlen, value_.begin(), value_.size(), offset_array.begin(), offset_array.size(), value_.begin(), value_.end(), entropy, entropy_size, additional_input, additional_input_size);

    if (BOOST_CRYPT_UNLIKELY(seed_status != state::success))
    {
        return seed_status;
    }

    constexpr boost::crypt::array<boost::crypt::uint8_t, 1U> c_offset_array = { 0x00 };
    seed_status = hash_df(seedlen, constant_.begin(), constant_.size(), c_offset_array.begin(), c_offset_array.size(), value_.begin(), value_.size());

    if (BOOST_CRYPT_UNLIKELY(seed_status != state::success))
    {
        return seed_status;
    }

    reseed_counter_ = 1U;
    return state::success;
}

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
    const auto no_of_bytes_to_return {(no_of_bits_to_return + 7U) / 8U};
    const auto len {(no_of_bytes_to_return + outlen_bytes - 1U) / outlen_bytes};

    if (BOOST_CRYPT_UNLIKELY(len > 255))
    {
        return state::requested_too_many_bits;
    }
    else if (BOOST_CRYPT_UNLIKELY(return_container_size < no_of_bytes_to_return))
    {
        return state::out_of_memory;
    }

    // The hash string concatenates the value of no_of_bits_to_return
    const boost::crypt::array<boost::crypt::uint8_t, 4U> bits_to_return_array = {
        static_cast<boost::crypt::uint8_t>((no_of_bits_to_return >> 24) & 0xFF),
        static_cast<boost::crypt::uint8_t>((no_of_bits_to_return >> 16) & 0xFF),
        static_cast<boost::crypt::uint8_t>((no_of_bits_to_return >> 8) & 0xFF),
        static_cast<boost::crypt::uint8_t>(no_of_bits_to_return & 0xFF)
    };

    // See 10.3.1
    // temp = temp || HASH(counter, no_of_bits_to_return || input_string)
    boost::crypt::size_t offset {};
    for (boost::crypt::uint8_t counter {0x01}; counter <= static_cast<boost::crypt::uint8_t>(len); ++counter)
    {
        HasherType hasher;
        hasher.process_byte(counter);
        hasher.process_bytes(bits_to_return_array.begin(), bits_to_return_array.size());
        hasher.process_bytes(provided_data_1, provided_data_size_1);
        hasher.process_bytes(provided_data_2, provided_data_size_2);
        hasher.process_bytes(provided_data_3, provided_data_size_3);
        hasher.process_bytes(provided_data_4, provided_data_size_4);
        const auto return_val {hasher.get_digest()};

        for (boost::crypt::size_t i {}; i < return_val.size() && offset < no_of_bytes_to_return; ++i)
        {
            return_container[offset++] = return_val[i];
        }
    }

    return state::success;
}

} // Namespace drbg
} // Namespace crypt
} // Namespace boost

#endif //BOOST_CRYPT_DRBG_HASH_DRBG_HPP
