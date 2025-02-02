// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#define BOOST_CRYPT_ENABLE_MD5

#include "boost/crypt/hash/md5.hpp"
#include <iostream>
#include <exception>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    try
    {
        auto c_data = reinterpret_cast<const char*>(data);
        std::string c_data_str {c_data, size}; // Guarantee null termination since we can't pass the size argument

        boost::crypt::md5(c_data_str);
        boost::crypt::md5(c_data, size);
        boost::crypt::md5(data, size);

        #ifdef BOOST_CRYPT_HAS_STRING_VIEW
        std::string_view view {c_data_str};
        boost::crypt::md5(view);
        #endif

        #ifdef BOOST_CRYPT_HAS_SPAN
        std::span data_span {c_data, size};
        boost::crypt::md5(data_span);
        #endif

        // Fuzz the hasher object
        boost::crypt::md5_hasher hasher;
        hasher.process_bytes(data, size);
        hasher.process_bytes(data, size);
        hasher.process_bytes(data, size);
        hasher.get_digest();
        hasher.process_bytes(data, size); // State is invalid but should not crash
    }
    catch(...)
    {
        std::cerr << "Error with: " << data << std::endl;
        std::terminate();
    }

    return 0;
}
