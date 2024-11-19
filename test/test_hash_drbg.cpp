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
    // V = a8 84 a8 3f a4 0b cf 73 0e 73 95 dd 58 00 ea 71 01 b4 87 7a aa 29 da 9b 7b c0 bd 2b d0 52 b9 b4 02 2f 83 ba e3 80 64 13 4a 23 38 35 84 5f dd 14 42 bf 3a 02 21 bd c8
    // C = 49 77 fb 12 68 c1 f6 28 6b 5b 39 69 d4 16 fb 8c a7 e4 ea ab 7f d2 ed ef c2 39 20 2b aa 03 3f 8b 44 e9 14 51 48 ad 24 ce 83 d5 97 17 6a 0b ac c8 4c 99 24 6f 15 e0 88

    BOOST_TEST(rng.generate(return_bits.begin(), 640U) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    // V = f1 fc a3 52 0c cd c5 9b 79 ce cf 47 2c 17 e5 fd a9 99 72 26 29 fc c8 8b 3d f9 dd 57 7a 55 f9 3f 47 18 98 92 b1 8e 1c 5f 39 df c0 77 ae 25 65 88 ee ce c7 bb d0 32 3c
    // C = 49 77 fb 12 68 c1 f6 28 6b 5b 39 69 d4 16 fb 8c a7 e4 ea ab 7f d2 ed ef c2 39 20 2b aa 03 3f 8b 44 e9 14 51 48 ad 24 ce 83 d5 97 17 6a 0b ac c8 4c 99 24 6f 15 e0 88

    BOOST_TEST(rng.generate(return_bits.begin(), 640U) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    // V = 3b 74 9e 64 75 8f bb c3 e5 2a 08 b1 00 2e e1 8a 51 7e 5c d1 a9 cf b6 7b 00 32 fd 83 24 59 38 ca 8c 01 ad d7 70 68 51 5b de 24 8c 75 ad ea 10 bb aa f0 bc 18 e6 6a 2c
    // C = 49 77 fb 12 68 c1 f6 28 6b 5b 39 69 d4 16 fb 8c a7 e4 ea ab 7f d2 ed ef c2 39 20 2b aa 03 3f 8b 44 e9 14 51 48 ad 24 ce 83 d5 97 17 6a 0b ac c8 4c 99 24 6f 15 e0 88

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
