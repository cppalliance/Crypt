// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/hash/sha256.hpp>

#include "test_nist_cavs_detail.hpp"

auto main() -> int
{
  bool result_is_ok { true };

  {
    nist::cavs::test_vector_container_type my_test_vectors_monte { };

    std::vector<std::uint8_t>
      seed_init
      (
        {
            0x6d, 0x1e, 0x72, 0xad, 0x03, 0xdd, 0xeb, 0x5d, 0xe8, 0x91, 0xe5, 0x72, 0xe2, 0x39, 0x6f, 0x8d, 0xa0, 0x15, 0xd8, 0x99, 0xef, 0x0e, 0x79, 0x50, 0x31, 0x52, 0xd6, 0x01, 0x0a, 0x3f, 0xe6, 0x91
        }
      );

    static_cast<void>(nist::cavs::parse_file_monte("SHA256Monte.rsp", my_test_vectors_monte));

    result_is_ok = (nist::cavs::test_vectors_monte<boost::crypt::sha256_hasher>(my_test_vectors_monte, seed_init) && result_is_ok);

    BOOST_TEST(result_is_ok);
  }

  return boost::report_errors();
}
