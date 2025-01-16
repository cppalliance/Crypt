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
        nist::cavs::test_vector_container_type test_vectors {};

        static_cast<void>(nist::cavs::detail::parse_file_vectors_hmac("sha3_256.fax", test_vectors));

        result_is_ok = (nist::cavs::test_vectors_hmac<boost::crypt::sha3_256_hasher>(test_vectors) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

    return boost::report_errors();
}
