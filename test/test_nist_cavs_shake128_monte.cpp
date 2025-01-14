// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/shake128.hpp>

#include "test_nist_cavs_detail.hpp"

auto main() -> int
{
    bool result_is_ok { true };

    {
        nist::cavs::test_vector_container_type my_test_vectors_monte { };

        std::vector<std::uint8_t>
        seed_init
        {
            0xc8, 0xb3, 0x10, 0xcb, 0x97, 0xef, 0xa3, 0x85, 0x54, 0x34, 0x99, 0x8f, 0xa8, 0x1c, 0x76, 0x74
        };

        std::vector<std::size_t> lengths {};
        lengths.reserve(200U);
        static_cast<void>(nist::cavs::detail::parse_file_monte_xof("SHAKE128Monte.rsp", my_test_vectors_monte, lengths));

        result_is_ok = (nist::cavs::test_vectors_monte_xof<boost::crypt::shake128_hasher>(my_test_vectors_monte, lengths, seed_init) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

    return boost::report_errors();
}
