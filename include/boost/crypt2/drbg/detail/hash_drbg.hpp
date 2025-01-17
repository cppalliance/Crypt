// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_DRBG_HASH_DRBG_HPP
#define BOOST_CRYPT2_DRBG_HASH_DRBG_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>

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

public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hash_drbg() noexcept = default;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~hash_drbg() noexcept;
};

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
