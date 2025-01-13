// Copyright 2024 - 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_HASH_SHA384_HPP
#define BOOST_CRYPT2_HASH_SHA384_HPP

#include <boost/crypt2/hash/detail/sha3_base.hpp>
#include <boost/crypt2/hash/detail/hash_file.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>

namespace boost::crypt {

BOOST_CRYPT_EXPORT using sha3_512_hasher = hash_detail::sha3_base<64U>;

// One shot functions
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha3_512(compat::span<const compat::byte> data) noexcept -> compat::expected<sha3_512_hasher::return_type, state>
{
    sha3_512_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

template <compat::sized_range SizedRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto sha3_512(SizedRange&& data) noexcept -> compat::expected<sha3_512_hasher::return_type, state>
{
    sha3_512_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

#ifndef BOOST_CRYPT_HAS_CUDA


template <concepts::file_system_path T>
[[nodiscard]] BOOST_CRYPT_EXPORT
auto sha3_512_file(const T& filepath) -> compat::expected<sha3_512_hasher::return_type, state>
{
    return hash_detail::hash_file_impl<sha3_512_hasher>(filepath);
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace boost::crypt

#endif //BOOST_CRYPT2_HASH_SHA384_HPP
