// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/drbg/hmac_drbg.hpp>
#include <boost/crypt/hash/sha1.hpp>
#include <boost/core/lightweight_test.hpp>
#include <iostream>
#include <cstring>

void sha1_basic_correctness()
{
    boost::crypt::sha1_hmac_drbg rng;
    const char* entropy = "e91b63309e93d1d08e30e8d556906875";
    const char* nonce = "f59747c468b0d0da";
    boost::crypt::array<boost::crypt::uint8_t, 80> return_bits {};

    // Test process is:
    // 1) Instantiate drbg
    // 2) Generate bits, do not compare
    // 3) Generate bits, compare
    // 4) Destroy drbg
    BOOST_TEST(rng.init(entropy, std::strlen(entropy), nonce, std::strlen(nonce)) == boost::crypt::drbg::drbg_state::success);
    // ** INSTANTIATE:
    // V   = 7ea45af5f8fcba082fa40bcbea2748dfe7e09f6a
    // Key = be3976a33f77e0155b7ca84a5732d44f319e5f3a

    BOOST_TEST(rng.generate(return_bits.begin(), 640U) == boost::crypt::drbg::drbg_state::success);
    // ** GENERATE (FIRST CALL):
    // V   = 0e28fe04dd16482f8e4b048675318adcd5e6e6cf
    // Key = 764d4f1fb7b04624bcb14642acb24d70eff3c0c8

    BOOST_TEST(rng.generate(return_bits.begin(), 640U) == boost::crypt::drbg::drbg_state::success);
    // ** GENERATE (SECOND CALL):
    //	V   = 749a95f0882e0179d66d8ae2697802f8f568ce2f
    //	Key = bfcd86fcb4c2efce22f6e9b69742751a17b0056c

    constexpr boost::crypt::array<boost::crypt::uint8_t, 80> nist_return = {
        0xb7, 0x92, 0x8f, 0x95, 0x03, 0xa4, 0x17, 0x11, 0x07, 0x88,
        0xf9, 0xd0, 0xc2, 0x58, 0x5f, 0x8a, 0xee, 0x6f, 0xb7, 0x3b,
        0x22, 0x0a, 0x62, 0x6b, 0x3a, 0xb9, 0x82, 0x5b, 0x7a, 0x9f,
        0xac, 0xc7, 0x97, 0x23, 0xd7, 0xe1, 0xba, 0x92, 0x55, 0xe4,
        0x0e, 0x65, 0xc2, 0x49, 0xb6, 0x08, 0x2a, 0x7b, 0xc5, 0xe3,
        0xf1, 0x29, 0xd3, 0xd8, 0xf6, 0x9b, 0x04, 0xed, 0x11, 0x83,
        0x41, 0x9d, 0x6c, 0x4f, 0x2a, 0x13, 0xb3, 0x04, 0xd2, 0xc5,
        0x74, 0x3f, 0x41, 0xc8, 0xb0, 0xee, 0x73, 0x22, 0x53, 0x47
    };

    for (boost::crypt::size_t i {}; i < return_bits.size(); ++i)
    {
        if (!BOOST_TEST_EQ(return_bits[i], nist_return[i]))
        {
            std::cerr << std::hex
                      << "Got: " << static_cast<boost::crypt::uint32_t>(return_bits[i])
                      << "\nExpected: " << static_cast<boost::crypt::uint32_t>(nist_return[i]) << std::endl;
        }
    }
}

int main()
{
    sha1_basic_correctness();

    return boost::report_errors();
}
