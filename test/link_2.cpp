// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt/hash/md5.hpp>
#include <boost/crypt/hash/sha1.hpp>
#include <boost/crypt/hash/sha224.hpp>
#include <boost/crypt/hash/sha256.hpp>
#include <boost/crypt/hash/sha512.hpp>
#include <boost/crypt/hash/sha512_224.hpp>
#include <boost/crypt/hash/sha512_256.hpp>

void test_odr_use();

// LCOV_EXCL_START
template <typename T>
void test()
{
    T hasher;
    static_cast<void>(hasher);
    test_odr_use();
}

void f2()
{
    test<boost::crypt::md5_hasher>();
    test<boost::crypt::sha256_hasher>();
    test<boost::crypt::sha1_hasher>();
}
// LCOV_EXCL_STOP
