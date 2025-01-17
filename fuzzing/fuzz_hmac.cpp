// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/hash/sha1.hpp>
#include <boost/crypt2/hash/sha512.hpp>
#include <boost/crypt2/hash/sha3_256.hpp>
#include <boost/crypt2/mac/hmac.hpp>
#include <iostream>
#include <exception>
#include <string>
#include <vector>
#include <cstdint>
#include <string>
#include <span>
#include <string_view>
#include <vector>
#include <type_traits>

using namespace boost::crypt;

// Type list to store hasher types
template<typename... Ts>
struct type_list {};

// Helper to iterate over types
template<typename TypeList, template<typename> class F>
struct for_each_type;

template<template<typename> class F, typename... Ts>
struct for_each_type<type_list<Ts...>, F> {
    static void apply(const std::uint8_t* data, std::size_t size) {
        (F<Ts>::apply(data, size), ...);
    }
};

// Functor to process each hash type
template<typename Hasher>
struct process_hash {
    static void apply(const std::uint8_t* data, std::size_t size) {
        auto c_data = reinterpret_cast<const char*>(data);
        std::string c_data_str{c_data, size};
        std::span<const std::uint8_t> c_data_span{data, size};
        std::string_view c_data_str_view{c_data_str};

        hmac<Hasher> hmac_tester;
        hmac_tester.init(c_data_str);
        hmac_tester.process_bytes(c_data_span);
        hmac_tester.process_bytes(c_data_str_view);
        hmac_tester.finalize();
        std::vector<std::byte> return_vector(size);
        [[maybe_unused]] const auto code = hmac_tester.get_digest(return_vector);
    }
};

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr || size == 0) {
        return 0;
    }

    try {
        using hasher_types = type_list<
                sha1_hasher,
                sha512_hasher,
                sha3_256_hasher
        >;

        for_each_type<hasher_types, process_hash>::apply(data, size);
    }
    catch (...) {
        return 0; // Silent failure for fuzzing
    }

    return 0;
}
