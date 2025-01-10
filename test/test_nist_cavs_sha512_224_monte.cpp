// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha512_224.hpp>

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
                0x31, 0xd9, 0x67, 0x9a, 0x1b, 0x36, 0x3e, 0x8f, 0x0f, 0x29, 0x3e, 0x43, 0x18, 0xda, 0x00, 0xb8, 0xc4, 0xf6, 0x90, 0x9f, 0x8f, 0x53, 0x7b, 0x1b, 0xa0, 0xd3, 0x29, 0xc8
            }
        );

        static_cast<void>(nist::cavs::parse_file_monte("SHA512_224Monte.rsp", my_test_vectors_monte));

        result_is_ok = (nist::cavs::test_vectors_monte<boost::crypt::sha512_224_hasher>(my_test_vectors_monte, seed_init) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

  return boost::report_errors();
}
