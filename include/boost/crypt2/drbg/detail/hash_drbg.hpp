// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_DRBG_HASH_DRBG_HPP
#define BOOST_CRYPT2_DRBG_HASH_DRBG_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/state.hpp>

namespace boost::crypt::drbg_detail {

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
template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
class hash_drbg
{
private:

    static constexpr compat::size_t outlen_bytes {outlen / 8U};
    static constexpr compat::size_t max_bytes_per_request {65536U};
    static constexpr compat::size_t min_length {max_hasher_security / 8U};
    static constexpr compat::size_t min_entropy {min_length * 3U / 2U};
    static constexpr compat::size_t seedlen {outlen >= 384 ? 888U : 440U};
    static constexpr compat::size_t seedlen_bytes {seedlen / 8U};

    static constexpr compat::uint64_t max_length {4294967296ULL}; // 2^35 / 8
    static constexpr compat::uint64_t reseed_interval {281474976710656ULL}; // 2^48

    compat::array<compat::byte, seedlen_bytes> constant_ {};
    compat::array<compat::byte, seedlen_bytes> value_ {};

    compat::uint64_t reseed_counter_ {};
    bool initialized_ {};

    template <compat::size_t ExtentReturn = compat::dynamic_extent,
              compat::size_t Extent1 = compat::dynamic_extent,
              compat::size_t Extent2 = compat::dynamic_extent,
              compat::size_t Extent3 = compat::dynamic_extent,
              compat::size_t Extent4 = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hash_df(compat::uint32_t no_of_bits_to_return,
                                                   compat::span<compat::byte, ExtentReturn> return_container,
                                                   compat::span<const compat::byte, Extent1> provided_data_1,
                                                   compat::span<const compat::byte, Extent2> provided_data_2,
                                                   compat::span<const compat::byte, Extent3> provided_data_3,
                                                   compat::span<const compat::byte, Extent4> provided_data_4) noexcept -> state;

    template <compat::size_t Extent = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hashgen(compat::span<compat::byte, Extent> returned_bits, compat::size_t requested_number_of_bytes) noexcept -> state

public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hash_drbg() noexcept = default;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~hash_drbg() noexcept;
};

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t ExtentReturn,
          compat::size_t Extent1,
          compat::size_t Extent2,
          compat::size_t Extent3,
          compat::size_t Extent4>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::hash_df(
        compat::uint32_t no_of_bits_to_return,
        compat::span<compat::byte, ExtentReturn> return_container,
        compat::span<const compat::byte, Extent1> provided_data_1,
        compat::span<const compat::byte, Extent2> provided_data_2,
        compat::span<const compat::byte, Extent3> provided_data_3,
        compat::span<const compat::byte, Extent4> provided_data_4) noexcept -> state
{
    const auto no_of_bytes_to_return {(no_of_bits_to_return + 7U) / 8U};
    const auto len {(no_of_bytes_to_return + outlen_bytes - 1U) / outlen_bytes};

    if (len > 255U) [[unlikely]]
    {
        return state::requested_too_many_bits;
    }
    else if (return_container.size() < no_of_bytes_to_return) [[unlikely]]
    {
        return state::out_of_memory;
    }

    // The hash string concatenates the value of no_of_bits_to_return
    const compat::array<compat::byte, 4U> bits_to_return_array {
        static_cast<compat::byte>((no_of_bits_to_return >> 24) & 0xFF),
        static_cast<compat::byte>((no_of_bits_to_return >> 16) & 0xFF),
        static_cast<compat::byte>((no_of_bits_to_return >> 8) & 0xFF),
        static_cast<compat::byte>(no_of_bits_to_return & 0xFF)
    };
    const compat::span<const compat::byte, 4U> bits_to_return_span {bits_to_return_array};

    // See 10.3.1
    // temp = temp || HASH(counter, no_of_bits_to_return || input_string)
    compat::size_t offset {};
    for (compat::size_t counter {1}; counter <= len; ++counter)
    {
        HasherType hasher;
        hasher.process_byte(static_cast<compat::byte>(counter));
        hasher.process_bytes(bits_to_return_span);

        if constexpr (Extent1 != 0U)
        {
            hasher.process_bytes(provided_data_1);
        }

        if constexpr (Extent2 != 0U)
        {
            hasher.process_bytes(provided_data_2);
        }

        if constexpr (Extent3 != 0U)
        {
            hasher.process_bytes(provided_data_3);
        }

        if constexpr (Extent4 != 0U)
        {
            hasher.process_bytes(provided_data_4);
        }

        hasher.finalize();
        const auto return_val {hasher.get_digest()};

        BOOST_CRYPT_ASSERT(return_val.has_value());

        const auto return_val_array {return_val.value()};

        for (compat::size_t i {}; i < return_val_array.size() && offset < no_of_bytes_to_return; ++i)
        {
            return_container[offset++] = return_val[i];
        }
    }
}

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::~hash_drbg() noexcept
{
    detail::clear_mem(constant_);
    detail::clear_mem(value_);
    reseed_counter_ = 0U;
    initialized_ = false;
}

} // namespace boost::crypt::drbg_detail

#endif //BOOST_CRYPT2_DRBG_HASH_DRBG_HPP
