// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha3_224.hpp>

#include "test_nist_cavs_detail.hpp"

auto main() -> int
{
    bool result_is_ok { true };

    {
        nist::cavs::test_vector_container_type my_test_vectors_monte { };

        std::vector<std::uint8_t>
        seed_init
        {
            0x3a, 0x94, 0x15, 0xd4, 0x01, 0xae, 0xb8, 0x56, 0x7e, 0x6f, 0x0e, 0xce, 0xe3, 0x11, 0xf4, 0xf7, 0x16, 0xb3, 0x9e, 0x86, 0x04, 0x5c, 0x8a, 0x51, 0x38, 0x3d, 0xb2, 0xb6
        };

        static_cast<void>(nist::cavs::parse_file_monte("SHA3_224Monte.rsp", my_test_vectors_monte));

        result_is_ok = (nist::cavs::test_vectors_monte_sha3<boost::crypt::sha3_224_hasher>(my_test_vectors_monte, seed_init) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

    return boost::report_errors();
}
