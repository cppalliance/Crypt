// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DRBG_SHA384_DRBG_HPP
#define BOOST_CRYPT_DRBG_SHA384_DRBG_HPP

#include <boost/crypt/drbg/detail/hmac_drbg.hpp>
#include <boost/crypt/drbg/detail/hash_drbg.hpp>
#include <boost/crypt/hash/sha384.hpp>

namespace boost {
namespace crypt {

namespace drbg {

template <bool prediction_resistance>
using sha384_hash_drbg_t = drbg::hash_drbg<sha384_hasher , 256U, 384U, prediction_resistance>;

template <bool prediction_resistance>
using sha384_hmac_drbg_t = drbg::hmac_drbg<hmac<sha384_hasher>, 256U, 384U, prediction_resistance>;

} // namespace drbg

BOOST_CRYPT_EXPORT using sha384_hash_drbg = drbg::sha384_hash_drbg_t<false>;
BOOST_CRYPT_EXPORT using sha384_hash_drbg_pr = drbg::sha384_hash_drbg_t<true>;

BOOST_CRYPT_EXPORT using sha384_hmac_drbg = drbg::sha384_hmac_drbg_t<false>;
BOOST_CRYPT_EXPORT using sha384_hmac_drbg_pr = drbg::sha384_hmac_drbg_t<true>;

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_DRBG_SHA384_DRBG_HPP
