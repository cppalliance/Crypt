// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/hash/sha384.hpp>

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
                0xdc, 0xab, 0x0e, 0xa1, 0x21, 0xa6, 0xfc, 0x7c, 0xe7, 0x94, 0xb1, 0x1d, 0x01, 0x8a, 0x40, 0x5c, 0xbb, 0x36, 0xee, 0x7c, 0x1b, 0x15, 0x95, 0x01, 0x67, 0xe5, 0x46, 0xc1, 0xe7, 0x5e, 0x32, 0x3e, 0xec, 0x1d, 0xcb, 0x33, 0x12, 0xe1, 0x26, 0x6d, 0xc1, 0xf9, 0xa4, 0xdc, 0xfa, 0xfd, 0xd1, 0xea
            }
        );

        static_cast<void>(nist::cavs::parse_file_monte("SHA384Monte.rsp", my_test_vectors_monte));

        result_is_ok = (nist::cavs::test_vectors_monte<boost::crypt::sha384_hasher>(my_test_vectors_monte, seed_init) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

  return boost::report_errors();
}
