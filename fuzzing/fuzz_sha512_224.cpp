// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha512_224.hpp>
#include <iostream>
#include <exception>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    try
    {
        auto c_data = reinterpret_cast<const char*>(data);
        std::string c_data_str {c_data, size}; // Guarantee null termination since we can't pass the size argument

        boost::crypt::sha512_224(c_data_str);

        std::string_view view {c_data_str};
        boost::crypt::sha512_224(view);

        std::span data_span {c_data, size};
        boost::crypt::sha512_224(data_span);

        // Fuzz the hasher object
        boost::crypt::sha512_224_hasher hasher;
        hasher.process_bytes(data_span);
        hasher.process_bytes(data_span);
        hasher.process_bytes(data_span);
        hasher.finalize();
        [[maybe_unused]] const auto res = hasher.get_digest();
        hasher.process_bytes(data_span); // State is invalid but should not crash
    }
    catch(...)
    {
        std::cerr << "Error with: " << data << std::endl;
        std::terminate();
    }

    return 0;
}
