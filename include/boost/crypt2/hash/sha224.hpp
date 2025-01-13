// Copyright 2024 - 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc4634
// See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

#ifndef BOOST_CRYPT2_SHA224_HPP
#define BOOST_CRYPT2_SHA224_HPP

#include <boost/crypt2/hash/detail/sha224_256_hasher.hpp>
#include <boost/crypt2/hash/detail/hash_file.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>

namespace boost::crypt {

BOOST_CRYPT_EXPORT using sha224_hasher = hash_detail::sha_224_256_hasher<28U>;

// One shot functions
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha224(compat::span<const compat::byte> data) noexcept -> compat::expected<sha224_hasher::return_type, state>
{
    sha224_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

template <compat::sized_range SizedRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha224(SizedRange&& data) noexcept -> compat::expected<sha224_hasher::return_type, state>
{
    sha224_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

#if !BOOST_CRYPT_HAS_CUDA

template <concepts::file_system_path T>
[[nodiscard]] BOOST_CRYPT_EXPORT inline auto sha224_file(const T& filepath) -> compat::expected<sha224_hasher::return_type, state>
{
    return hash_detail::hash_file_impl<sha224_hasher>(filepath);
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace boost::crypt

#endif //BOOST_CRYPT2_SHA224_HPP
