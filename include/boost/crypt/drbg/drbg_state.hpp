// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_DRBG_DRBG_STATE_HPP
#define BOOST_DRBG_DRBG_STATE_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/cstdint.hpp>

namespace boost {
namespace crypt {
namespace drbg {

BOOST_CRYPT_EXPORT enum class drbg_state : boost::crypt::uint8_t
{
    success,                    // No issues
    null,                       // nullptr as parameter
    entropy_too_long,           // input data exceeded the length specified in a FIPS standard
    nonce_too_long,
    personalization_too_long,
    insufficient_entropy,       // Entropy + Nonce length was not at least 3/2 security strength
    out_of_memory,              // Memory exhaustion reported by a function
    requires_reeseeed,          // The number of cycles has exceeded the specified amount
    uninitialized,              // Random bits can not be provided since the generator is uninitialized
    state_error                 // An error has occurred
};

} // namespace drbg
} // namespace crypt
} // namespace boost

#endif // BOOST_DRBG_DRBG_STATE_HPP
