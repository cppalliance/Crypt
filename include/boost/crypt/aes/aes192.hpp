// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_AES_AES192_HPP
#define BOOST_CRYPT_AES_AES192_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/aes/detail/cipher.hpp>
#include <boost/crypt/aes/detail/cipher_mode.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT using aes192 = aes::cipher<12>;

}
}

#endif // BOOST_CRYPT_AES_AES192_HPP
