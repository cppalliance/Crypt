// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha512_256.hpp>

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
                0x76, 0x2c, 0x3e, 0x17, 0x4e, 0x96, 0x66, 0xb1, 0x90, 0xe0, 0x96, 0x35, 0x03, 0xc5, 0x6e, 0x57, 0xdf, 0xac, 0x88, 0xd8, 0x31, 0x7d, 0xfe, 0xf9, 0x80, 0xb4, 0x2d, 0x35, 0xb1, 0xb4, 0xb9, 0x2f
            }
        );

        static_cast<void>(nist::cavs::parse_file_monte("SHA512_256Monte.rsp", my_test_vectors_monte));

        result_is_ok = (nist::cavs::test_vectors_monte<boost::crypt::sha512_256_hasher>(my_test_vectors_monte, seed_init) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

  return boost::report_errors();
}
