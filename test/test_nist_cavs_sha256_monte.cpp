// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha256.hpp>

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

    {
        nist::cavs::test_vector_container_type my_test_vectors_monte { };

        std::vector<std::uint8_t>
        seed_init
        (
            {
                0x2b, 0x2b, 0x23, 0x03, 0xfc, 0x76, 0x4d, 0xa5, 0xf3, 0x38, 0x49, 0x26, 0x4d, 0xd0, 0xcd, 0xf7, 0x0a, 0x4d, 0x7c, 0xb9, 0x94, 0x81, 0xaf, 0xf5, 0xa1, 0x56, 0x75, 0x0d, 0x5a, 0x66, 0xd9, 0x72
            }
        );

        static_cast<void>(nist::cavs::parse_file_monte("SHA256Monte21.rsp", my_test_vectors_monte));

        result_is_ok = (nist::cavs::test_vectors_monte<boost::crypt::sha256_hasher>(my_test_vectors_monte, seed_init) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

    return boost::report_errors();
}
