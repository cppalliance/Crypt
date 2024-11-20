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

void sha1_pr_false()
{
    boost::crypt::sha1_hash_drbg rng;

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> entropy = {
            0x16, 0x10, 0xb8, 0x28, 0xcc, 0xd2, 0x7d, 0xe0, 0x8c, 0xee, 0xa0, 0x32, 0xa2, 0x0e, 0x92, 0x08
    };

    constexpr boost::crypt::array<boost::crypt::uint8_t, 8> nonce = {
            0x49, 0x2c, 0xf1, 0x70, 0x92, 0x42, 0xf6, 0xb5
    };

    constexpr boost::crypt::array<boost::crypt::uint8_t, 16> entropy_reseed = {
            0x72, 0xd2, 0x8c, 0x90, 0x8e, 0xda, 0xf9, 0xa4, 0xd1, 0xe5, 0x26, 0xd8, 0xf2, 0xde, 0xd5, 0x44
    };

    boost::crypt::array<boost::crypt::uint8_t, 80> return_bits {};

    // Test process is:
    // 1) Instantiate drbg
    // 2) reseed
    // 3) Generate no-compare
    // 4) Generate compare
    BOOST_TEST(rng.init(entropy, entropy.size(), nonce, nonce.size()) == boost::crypt::state::success);
    // ** INSTANTIATE:
    // 	V = 9e8301725d5f133b4ab7d329fd2f87ae5f89d96a9dd7e2b98beee1c707b8c3fe412d1125b58bae5dc08a11dac3be4a3147347160fef218
    //	C = e5e12450450efe5fdc777c95b8c23c938fcd592e2d788f12461936e4a16131b1f2d11ce7f0159ee1e635e62f3df8bda4fea077ad5f9d06

    BOOST_TEST(rng.reseed(entropy_reseed) == boost::crypt::state::success);
    // ** RESEED:
    //	V = 745c659f2944829ca6e209c8ca2dddecf9f1861383e34e94007a3a51b8444fd5ae738e7d9c0d5e69aa97ee16c49cfd2432eb32ba5738fa
    //	C = a1fc40009357a024d878818cf6f979a88d4cc5d760b308ae1a5b9f067972e6f7cf92ddb129a8d3c1bb0005bcf3f8871fd65e794f1990b7

    BOOST_TEST(rng.generate(return_bits.begin(), 640U) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    // 	V = 1658a59fbc9c22c17f5a8b55c1275795873e4beae49657421ad5d95831b736cd7e066c738bcbb343933c411c7c17917593c03a77bed56b
    //	C = a1fc40009357a024d878818cf6f979a88d4cc5d760b308ae1a5b9f067972e6f7cf92ddb129a8d3c1bb0005bcf3f8871fd65e794f1990b7

    BOOST_TEST(rng.generate(return_bits.begin(), 640U) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    //	V = b854e5a04ff3c2e657d30ce2b820d13e148b11c245495ff03531785eab2a1dc54d994a5597b15c5b10001f49606c88b4ff0d61acb61820
    //	C = a1fc40009357a024d878818cf6f979a88d4cc5d760b308ae1a5b9f067972e6f7cf92ddb129a8d3c1bb0005bcf3f8871fd65e794f1990b7
    constexpr boost::crypt::array<boost::crypt::uint8_t, 80> nist_return = {
            0x56, 0xf3, 0x3d, 0x4f, 0xdb, 0xb9, 0xa5, 0xb6, 0x4d, 0x26,
            0x23, 0x44, 0x97, 0xe9, 0xdc, 0xb8, 0x77, 0x98, 0xc6, 0x8d,
            0x08, 0xf7, 0xc4, 0x11, 0x99, 0xd4, 0xbd, 0xdf, 0x97, 0xeb,
            0xbf, 0x6c, 0xb5, 0x55, 0x0e, 0x5d, 0x14, 0x9f, 0xf4, 0xd5,
            0xbd, 0x0f, 0x05, 0xf2, 0x5a, 0x69, 0x88, 0xc1, 0x74, 0x36,
            0x39, 0x62, 0x27, 0x18, 0x4a, 0xf8, 0x4a, 0x56, 0x43, 0x35,
            0x65, 0x8e, 0x2f, 0x85, 0x72, 0xbe, 0xa3, 0x33, 0xee, 0xe2,
            0xab, 0xff, 0x22, 0xff, 0xa6, 0xde, 0x3e, 0x22, 0xac, 0xa2
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
    sha1_pr_false();

    return boost::report_errors();
}
