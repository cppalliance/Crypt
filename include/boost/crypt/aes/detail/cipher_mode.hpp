// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_AES_DETIAL_MODE_HPP
#define BOOST_CRYPT_AES_DETIAL_MODE_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/cstdint.hpp>

namespace boost {
namespace crypt {
namespace aes {

enum class cipher_mode : boost::crypt::uint8_t
{
    ecb,    // Electronic Codebook
    cbc,    // Cipher Block Chaining
    ofb,    // Output Feedback Mode
    ctr,    // Counter Mode
    cfb8,   // 8-bit cipher feedback mode
    cfb64,  // 64-bit cipher feedback mode
    cfb128  // 128-bit cipher feedback mode
};

} // namespace aes
} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_AES_DETIAL_MODE_HPP
