// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_HASHER_STATE_HPP
#define BOOST_CRYPT_HASH_HASHER_STATE_HPP

#include <boost/crypt/utility/cstdint.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT enum class state : boost::crypt::uint8_t
{
    success,                    // no issues
    null,                       // nullptr as parameter
    input_too_long,             // input data too long (exceeded size_t)
    insufficient_entropy,       // Entropy + Nonce length was not at least 3/2 security strength
    out_of_memory,              // Memory exhaustion reported by a function
    requires_reseed,            // The number of cycles has exceeded the specified amount
    uninitialized,              // Random bits can not be provided since the generator is uninitialized
    requested_too_many_bits,    // 2^19 bits is all that's allowed per request
    state_error                 // added more input after get_digest without re-init
};

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_HASHER_STATE_HPP
