// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DRBG_SHA3_224_DRBG_HPP
#define BOOST_CRYPT_DRBG_SHA3_224_DRBG_HPP

#include <boost/crypt/drbg/detail/hmac_drbg.hpp>
#include <boost/crypt/hash/sha3_224.hpp>

namespace boost {
namespace crypt {

namespace drbg {

template <bool prediction_resistance>
using sha3_224_hmac_drbg_t = drbg::hmac_drbg<hmac<sha3_224_hasher>, 192U, 224U, prediction_resistance>;

} // namespace drbg

BOOST_CRYPT_EXPORT using sha3_224_hmac_drbg = drbg::sha3_224_hmac_drbg_t<false>;
BOOST_CRYPT_EXPORT using sha3_224_hmac_drbg_pr = drbg::sha3_224_hmac_drbg_t<true>;

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_DRBG_SHA3_224_DRBG_HPP
