// Copyright 2024 - 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_HASH_SHAKE128_HPP
#define BOOST_CRYPT2_HASH_SHAKE128_HPP

#include <boost/crypt2/hash/detail/sha3_base.hpp>
#include <boost/crypt2/hash/detail/hash_file.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>

namespace boost::crypt {

BOOST_CRYPT_EXPORT using shake128_hasher = hash_detail::sha3_base<16U, true>;

// One shot functions
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto shake128(compat::span<const compat::byte> data) noexcept -> compat::expected<shake128_hasher::return_type, state>
{
    shake128_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

template <compat::sized_range SizedRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto shake128(SizedRange&& data) noexcept -> compat::expected<shake128_hasher::return_type, state>
{
    shake128_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

// One shot functions that add the xof capability
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto shake128(compat::span<const compat::byte> data, compat::span<compat::byte> out) noexcept -> state
{
    shake128_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out);
}

template <concepts::writable_output_range OutputRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto shake128(compat::span<const compat::byte> data, OutputRange&& out) noexcept -> state
{
    shake128_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out);
}

template <compat::sized_range SizedRange, concepts::writable_output_range OutputRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto shake128(SizedRange&& data, OutputRange&& out) noexcept -> state
{
    shake128_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out);
}

[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto shake128(compat::span<const compat::byte> data, compat::span<compat::byte> out, compat::size_t amount) noexcept -> state
{
    shake128_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out, amount);
}

template <concepts::writable_output_range OutputRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto shake128(compat::span<const compat::byte> data, OutputRange&& out, compat::size_t amount) noexcept -> state
{
    shake128_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out, amount);
}

template <compat::sized_range SizedRange, concepts::writable_output_range OutputRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto shake128(SizedRange&& data, OutputRange&& out, compat::size_t amount) noexcept -> state
{
    shake128_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out, amount);
}

#if !BOOST_CRYPT_HAS_CUDA

template <concepts::file_system_path T>
[[nodiscard]] BOOST_CRYPT_EXPORT
auto shake128_file(const T& filepath) -> compat::expected<shake128_hasher::return_type, state>
{
    return hash_detail::hash_file_impl<shake128_hasher>(filepath);
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace boost::crypt

#endif //BOOST_CRYPT2_HASH_SHAKE128_HPP
