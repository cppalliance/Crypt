// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DRBG_SHA1_DRBG_HPP
#define BOOST_CRYPT_DRBG_SHA1_DRBG_HPP

#include <boost/crypt/drbg/detail/hmac_drbg.hpp>
#include <boost/crypt/hash/sha1.hpp>

namespace boost {
namespace crypt {

namespace drbg {

template <bool prediction_resistance>
using sha1_hmac_drbg_t = drbg::hmac_drbg<hmac<sha1_hasher>, 128U, 160U, prediction_resistance>;

} // namespace drbg

BOOST_CRYPT_EXPORT using sha1_hmac_drbg = drbg::sha1_hmac_drbg_t<false>;
BOOST_CRYPT_EXPORT using sha1_hmac_drbg_pr = drbg::sha1_hmac_drbg_t<true>;

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_DRBG_SHA1_DRBG_HPP
