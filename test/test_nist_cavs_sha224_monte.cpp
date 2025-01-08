// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha224.hpp>

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
                0x99, 0xf9, 0x57, 0xf2, 0x72, 0xb0, 0xac,
                0xc5, 0xbf, 0xaf, 0x38, 0xc0, 0x30, 0x78,
                0xc8, 0x8c, 0x97, 0x22, 0x67, 0x1a, 0xf0,
                0x4f, 0x7e, 0x39, 0x9f, 0x5e, 0x40, 0x68
            }
        );

        static_cast<void>(nist::cavs::parse_file_monte("SHA224Monte.rsp", my_test_vectors_monte));

        result_is_ok = (nist::cavs::test_vectors_monte<boost::crypt::sha224_hasher>(my_test_vectors_monte, seed_init) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

    return boost::report_errors();
}
