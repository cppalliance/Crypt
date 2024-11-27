// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_AES128_HPP
#define BOOST_AES128_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/aes/detail/cipher.hpp>
#include <boost/crypt/aes/detail/cipher_mode.hpp>

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT using aes128 = aes::cipher<10>;

}
}

#endif //BOOST_AES128_HPP
