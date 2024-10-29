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

// LCOV_EXCL_START
void f1();
void f2();

int main()
{
    f1();
    f2();
}

void test_odr_use()
{
}
// LCOV_EXCL_STOP
