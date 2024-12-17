// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/aes/aes128.hpp>
#include "test_nist_cavs_detail.hpp"
#include <string>
#include <vector>
#include <iostream>

auto main() -> int
{
    const std::vector<std::string> files_to_test = {
        "CFB8GFSbox128.rsp",
        "CFB8KeySbox128.rsp",
        "CFB8VarKey128.rsp",
        "CFB8VarTxt128.rsp",
        "CFB8GFSbox128_20.rsp",
        "CFB8KeySbox128_20.rsp",
        "CFB8VarKey128_20.rsp",
        "CFB8VarTxt128_20.rsp"
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

        const bool result_is_ok = (nist::cavs::test_vectors_aes_kat<boost::crypt::aes::cipher_mode::cfb8, boost::crypt::aes128>(test_vectors));

        if (!BOOST_TEST(result_is_ok))
        {
            std::cerr << "Error found in file: " << file << std::endl; // LCOV_EXCL_LINE
        }
    }

    return boost::report_errors();
}
