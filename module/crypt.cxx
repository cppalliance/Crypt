// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

// Global module fragment required for non-module preprocessing
module;

#include <span>
#include <type_traits>
#include <cstring>
#include <cstddef>

#ifdef _WIN32
#include <WinBase.h>
#endif

#define BOOST_CRYPT_BUILD_MODULE

export module boost2.crypt;

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winclude-angled-in-module-purview"
#endif

#include <boost/crypt2/hash/sha1.hpp>
