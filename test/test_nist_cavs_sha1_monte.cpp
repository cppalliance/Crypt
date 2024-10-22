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
    nist::cavs::test_vector_container_type my_test_vectors_monte { };

    std::vector<std::uint8_t>
      seed_init
      (
        {
          0xDDU, 0x4DU, 0xF6U, 0x44U, 0xEAU, 0xF3U, 0xD8U, 0x5BU,
          0xACU, 0xE2U, 0xB2U, 0x1AU, 0xCCU, 0xAAU, 0x22U, 0xB2U,
          0x88U, 0x21U, 0xF5U, 0xCDU
        }
      );

    static_cast<void>(nist::cavs::parse_file_monte("SHA1Monte.rsp", my_test_vectors_monte));

    result_is_ok = (nist::cavs::test_vectors_monte<boost::crypt::sha1_hasher>(my_test_vectors_monte, seed_init) && result_is_ok);

    BOOST_TEST(result_is_ok);
  }

  return boost::report_errors();
}
