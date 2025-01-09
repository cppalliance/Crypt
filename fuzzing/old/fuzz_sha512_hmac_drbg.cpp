// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include "boost/crypt/drbg/sha512_drbg.hpp"
#include <iostream>
#include <exception>
#include <string>
#include <random>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    try
    {
        // Non-PR
        boost::crypt::sha512_hmac_drbg rng;
        rng.init(data, size, data, size, data, size);
        rng.reseed(data, size, data, size);

        std::uint8_t return_bits[4096];
        std::random_device random;
        std::mt19937_64 dist_rng(random());
        std::uniform_int_distribution<std::size_t> dist(0, 4096*CHAR_BIT);
        rng.generate(return_bits, dist(dist_rng));

        // PR
        boost::crypt::sha512_hmac_drbg_pr rng_pr;
        rng_pr.init(data, size, data, size);
        rng_pr.reseed(data, size, data, size);
        rng_pr.generate(return_bits, dist(dist_rng), data, size, data, size);
    }
    catch(...)
    {
        std::cerr << "Error with: " << data << std::endl;
        std::terminate();
    }

    return 0;
}
