// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/aes/aes192.hpp>
#include "test_nist_cavs_detail.hpp"
#include <string>
#include <vector>
#include <iostream>

auto main() -> int
{
    bool result_is_ok { true };

    const std::vector<std::string> files_to_test = {
        "CFB128MMT192.rsp",
        "CFB128MMT192_20.rsp"
    };

    for (const auto& file : files_to_test)
    {
        nist::cavs::test_vector_container_aes test_vectors {};

        if (!BOOST_TEST(nist::cavs::detail::parse_file_aes(file, test_vectors)))
        {
            // LCOV_EXCL_START
            std::cerr << "Failed to open file: " << file << std::endl;
            continue;
            // LCOV_EXCL_STOP
        }

        result_is_ok = (nist::cavs::test_vectors_aes_mmt<boost::crypt::aes::cipher_mode::cfb128, boost::crypt::aes192>(test_vectors) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

    return boost::report_errors();
}
