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
        nist::cavs::test_vector_container_type my_test_vectors_variable { };
        
        std::vector<std::size_t> lengths {};
        static_cast<void>(nist::cavs::detail::parse_file_vectors_variable_xof("SHAKE128VariableOut.rsp", my_test_vectors_variable, lengths));

        result_is_ok = (nist::cavs::test_vectors_variable<boost::crypt::shake128_hasher>(my_test_vectors_variable, lengths) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

    return boost::report_errors();
}
