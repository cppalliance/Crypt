// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/hash/sha1.hpp>

#include "test_nist_cavs_detail.hpp"

auto main() -> int
{
  bool result_is_ok { true };

  {
    nist::cavs::test_vector_container_type test_vectors_short { };

    static_cast<void>(nist::cavs::detail::parse_file_vectors("SHA1ShortMsg.rsp", test_vectors_short));

    result_is_ok = (nist::cavs::test_vectors_oneshot<boost::crypt::sha1_hasher>(test_vectors_short) && result_is_ok);

    BOOST_TEST(result_is_ok);
  }


  {
    nist::cavs::test_vector_container_type test_vectors_long { };

    static_cast<void>(nist::cavs::detail::parse_file_vectors("SHA1LongMsg.rsp", test_vectors_long));

    result_is_ok = (nist::cavs::test_vectors_oneshot<boost::crypt::sha1_hasher>(test_vectors_long) && result_is_ok);

    BOOST_TEST(result_is_ok);
  }

  return boost::report_errors();
}
