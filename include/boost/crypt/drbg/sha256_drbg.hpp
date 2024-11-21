// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DRBG_SHA256_DRBG_HPP
#define BOOST_CRYPT_DRBG_SHA256_DRBG_HPP

#include <boost/crypt/drbg/detail/hmac_drbg.hpp>
#include <boost/crypt/drbg/detail/hash_drbg.hpp>
#include <boost/crypt/hash/sha256.hpp>

namespace boost {
namespace crypt {

namespace drbg {

template <bool prediction_resistance>
using sha256_hash_drbg_t = drbg::hash_drbg<sha256_hasher, 256U, 256U, prediction_resistance>;

template <bool prediction_resistance>
using sha256_hmac_drbg_t = drbg::hmac_drbg<hmac<sha256_hasher>, 256U, 256U, prediction_resistance>;

} // namespace drbg

BOOST_CRYPT_EXPORT using sha256_hash_drbg = drbg::sha256_hash_drbg_t<false>;
BOOST_CRYPT_EXPORT using sha256_hash_drbg_pr = drbg::sha256_hash_drbg_t<true>;

BOOST_CRYPT_EXPORT using sha256_hmac_drbg = drbg::sha256_hmac_drbg_t<false>;
BOOST_CRYPT_EXPORT using sha256_hmac_drbg_pr = drbg::sha256_hmac_drbg_t<true>;

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_DRBG_SHA256_DRBG_HPP
