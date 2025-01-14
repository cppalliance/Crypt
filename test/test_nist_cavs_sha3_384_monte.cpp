// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha3_384.hpp>

#include "test_nist_cavs_detail.hpp"

auto main() -> int
{
    bool result_is_ok { true };

    {
        nist::cavs::test_vector_container_type my_test_vectors_monte { };

        std::vector<std::uint8_t>
        seed_init
        {
            0x7a, 0x00, 0x79, 0x1f, 0x6f, 0x65, 0xc2, 0x1f, 0x1c, 0x97, 0xc5, 0x8f, 0xa3, 0xc0, 0x52, 0x0c, 0xfc, 0x85, 0xcd, 0x7e, 0x3d, 0x39, 0x8c, 0xf0, 0x19, 0x50, 0x81, 0x9f, 0xa7, 0x17, 0x19, 0x50, 0x65, 0xa3, 0x63, 0xe7, 0x7d, 0x07, 0x75, 0x36, 0x47, 0xcb, 0x0c, 0x13, 0x0e, 0x99, 0x72, 0xad
        };

        static_cast<void>(nist::cavs::parse_file_monte("SHA3_384Monte.rsp", my_test_vectors_monte));

        result_is_ok = (nist::cavs::test_vectors_monte_sha3<boost::crypt::sha3_384_hasher>(my_test_vectors_monte, seed_init) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

    return boost::report_errors();
}
