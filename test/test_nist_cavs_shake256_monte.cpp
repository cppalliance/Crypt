// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/hash/shake256.hpp>

#include "test_nist_cavs_detail.hpp"

auto main() -> int
{
  bool result_is_ok { true };

    {
        nist::cavs::test_vector_container_type my_test_vectors_monte { };

        std::vector<std::uint8_t>
        seed_init
        {
            0x48, 0xa0, 0x32, 0x1b, 0x36, 0x53, 0xe4, 0xe8, 0x64, 0x46, 0xd0, 0x0f, 0x6a, 0x03, 0x6e, 0xfd
        };

        std::vector<std::size_t> lengths {};
        lengths.resize(100U);
        static_cast<void>(nist::cavs::detail::parse_file_monte_xof("SHAKE256Monte.rsp", my_test_vectors_monte, lengths));

        result_is_ok = (nist::cavs::test_vectors_monte_xof<boost::crypt::shake256_hasher>(my_test_vectors_monte, lengths, seed_init) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

  return boost::report_errors();
}
