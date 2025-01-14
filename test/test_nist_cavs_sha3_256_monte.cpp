// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha3_256.hpp>

#include "test_nist_cavs_detail.hpp"

auto main() -> int
{
    bool result_is_ok { true };

    {
        nist::cavs::test_vector_container_type my_test_vectors_monte { };

        std::vector<std::uint8_t>
        seed_init
        {
            0xaa, 0x64, 0xf7, 0x24, 0x5e, 0x21, 0x77, 0xc6, 0x54, 0xeb, 0x4d, 0xe3, 0x60, 0xda, 0x87, 0x61, 0xa5, 0x16, 0xfd, 0xc7, 0x57, 0x8c, 0x34, 0x98, 0xc5, 0xe5, 0x82, 0xe0, 0x96, 0xb8, 0x73, 0x0c
        };

        static_cast<void>(nist::cavs::parse_file_monte("SHA3_256Monte.rsp", my_test_vectors_monte));

        result_is_ok = (nist::cavs::test_vectors_monte_sha3<boost::crypt::sha3_256_hasher>(my_test_vectors_monte, seed_init) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

    return boost::report_errors();
}
