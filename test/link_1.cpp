// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#define BOOST_CRYPT_ENABLE_MD5

#include <boost/crypt/hash/md5.hpp>
#include <boost/crypt/hash/sha1.hpp>
#include <boost/crypt/hash/sha224.hpp>
#include <boost/crypt/hash/sha256.hpp>
#include <boost/crypt/hash/sha512.hpp>
#include <boost/crypt/hash/sha512_224.hpp>
#include <boost/crypt/hash/sha512_256.hpp>
#include <boost/crypt/hash/sha3_512.hpp>
#include <boost/crypt/hash/shake128.hpp>

void test_odr_use();

// LCOV_EXCL_START
template <typename T>
void test()
{
    T hasher;
    static_cast<void>(hasher);
    test_odr_use();
}

void f1()
{
    test<boost::crypt::md5_hasher>();
    test<boost::crypt::sha1_hasher>();
    test<boost::crypt::sha224_hasher>();
    test<boost::crypt::sha256_hasher>();
    test<boost::crypt::sha512_hasher>();
    test<boost::crypt::sha512_224_hasher>();
    test<boost::crypt::sha512_256_hasher>();
    test<boost::crypt::sha3_512_hasher>();
    test<boost::crypt::shake128_hasher>();
}
// LCOV_EXCL_STOP
