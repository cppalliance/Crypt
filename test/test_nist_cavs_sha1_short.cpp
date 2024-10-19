// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include "test_nist_cavs_detail.hpp"

#include <boost/crypt/hash/sha1.hpp>

auto main() -> int
{
  nist::cavs::test_vector_container_type test_vectors { };

  static_cast<void>(nist::cavs::detail::parse_file_vectors("SHA1ShortMsg.rsp", test_vectors));

  const bool result_is_ok { nist::cavs::test_vectors_oneshot<boost::crypt::sha1_hasher>(test_vectors) };

  static_cast<void>(result_is_ok);

  return boost::report_errors();
}
