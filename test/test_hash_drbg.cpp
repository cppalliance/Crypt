// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/drbg/sha1_drbg.hpp>
#include <boost/core/lightweight_test.hpp>
#include <iostream>
#include <string>
#include <cstring>

void sha_1_basic_correctness()
{
    boost::crypt::sha1_hash_drbg rng;

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> entropy = {
        0x13, 0x6c, 0xf1, 0xc1, 0x74, 0xe5, 0xa0, 0x9f, 0x66, 0xb9, 0x62, 0xd9, 0x94, 0x39, 0x65, 0x25
    };

    constexpr boost::crypt::array<boost::crypt::uint8_t, 8> nonce = {
        0xff, 0xf1, 0xc6, 0x64, 0x5f, 0x19, 0x23, 0x1f
    };

    boost::crypt::array<boost::crypt::uint8_t, 80> return_bits {};

    // Test process is:
    // 1) Instantiate drbg
    // 2) Generate bits, do not compare
    // 3) Generate bits, compare
    // 4) Destroy drbg
    BOOST_TEST(rng.init(entropy, entropy.size(), nonce, nonce.size()) == boost::crypt::state::success);
    // ** INSTANTIATE:
    // V = a884a83fa40bcf730e7395dd5800ea7101b4877aaa29da9b7bc0bd2bd052b9b4022f83bae38064134a233835845fdd1442bf3a0221bdc8
    // C = 4977fb1268c1f6286b5b3969d416fb8ca7e4eaab7fd2edefc239202baa033f8b44e9145148ad24ce83d597176a0bacc84c99246f15e088

    BOOST_TEST(rng.generate(return_bits.begin(), 640U) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    // V = f1fca3520ccdc59b79cecf472c17e5fda999722629fcc88b3df9dd577a55f93f47189892b18e1c5f39dfc077ae256588eecec7bbd0323c
    // C = 4977fb1268c1f6286b5b3969d416fb8ca7e4eaab7fd2edefc239202baa033f8b44e9145148ad24ce83d597176a0bacc84c99246f15e088

    BOOST_TEST(rng.generate(return_bits.begin(), 640U) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    // V = 3b749e64758fbbc3e52a08b1002ee18a517e5cd1a9cfb67b0032fd83245938ca8c01add77068515bde248c75adea10bbaaf0bc18e66a2c
    // C = 4977fb1268c1f6286b5b3969d416fb8ca7e4eaab7fd2edefc239202baa033f8b44e9145148ad24ce83d597176a0bacc84c99246f15e088

    constexpr boost::crypt::array<boost::crypt::uint8_t, 80> nist_return = {
        0x0e, 0x28, 0x13, 0x0f, 0xa5, 0xca, 0x11, 0xed, 0xd3, 0x29,
        0x3c, 0xa2, 0x6f, 0xdb, 0x8a, 0xe1, 0x81, 0x06, 0x11, 0xf7,
        0x87, 0x15, 0x08, 0x2e, 0xd3, 0x84, 0x1e, 0x74, 0x86, 0xf1,
        0x66, 0x77, 0xb2, 0x8e, 0x33, 0xff, 0xe0, 0xb9, 0x3d, 0x98,
        0xba, 0x57, 0xba, 0x35, 0x8c, 0x13, 0x43, 0xab, 0x2a, 0x26,
        0xb4, 0xeb, 0x79, 0x40, 0xf5, 0xbc, 0x63, 0x93, 0x84, 0x64,
        0x1e, 0xe8, 0x0a, 0x25, 0x14, 0x03, 0x31, 0x07, 0x62, 0x68,
        0xbd, 0x1c, 0xe7, 0x02, 0xad, 0x53, 0x4d, 0xda, 0x0e, 0xd8
    };

    for (boost::crypt::size_t i {}; i < return_bits.size(); ++i)
    {
        if (!BOOST_TEST_EQ(return_bits[i], nist_return[i]))
        {
            // LCOV_EXCL_START
            std::cerr << std::hex
                      << "Got: " << static_cast<boost::crypt::uint32_t>(return_bits[i])
                      << "\nExpected: " << static_cast<boost::crypt::uint32_t>(nist_return[i]) << std::endl;
            // LCOV_EXCL_STOP
        }
    }
}

int main()
{
    sha_1_basic_correctness();

    return boost::report_errors();
}
