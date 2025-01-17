// Copyright 2024 - 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_HASH_SHAKE256_HPP
#define BOOST_CRYPT2_HASH_SHAKE256_HPP

#include <boost/crypt2/hash/detail/sha3_base.hpp>
#include <boost/crypt2/hash/detail/hash_file.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>

namespace boost::crypt {

BOOST_CRYPT_EXPORT using shake256_hasher = hash_detail::sha3_base<32U, true>;

// One shot functions
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto shake256(compat::span<const compat::byte> data) noexcept -> compat::expected<shake256_hasher::return_type, state>
{
    shake256_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

template <concepts::sized_range SizedRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto shake256(SizedRange&& data) noexcept -> compat::expected<shake256_hasher::return_type, state>
{
    shake256_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

// One shot functions that add the xof capability
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto shake256(compat::span<const compat::byte> data, compat::span<compat::byte> out) noexcept -> state
{
    shake256_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out);
}

template <concepts::writable_output_range OutputRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto shake256(compat::span<const compat::byte> data, OutputRange&& out) noexcept -> state
{
    shake256_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out);
}

template <concepts::sized_range SizedRange, concepts::writable_output_range OutputRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto shake256(SizedRange&& data, OutputRange&& out) noexcept -> state
{
    shake256_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out);
}

[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto shake256(compat::span<const compat::byte> data, compat::span<compat::byte> out, std::size_t amount) noexcept -> state
{
    shake256_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out, amount);
}

template <concepts::writable_output_range OutputRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto shake256(compat::span<const compat::byte> data, OutputRange&& out, std::size_t amount) noexcept -> state
{
    shake256_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out, amount);
}

template <concepts::sized_range SizedRange, concepts::writable_output_range OutputRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto shake256(SizedRange&& data, OutputRange&& out, std::size_t amount) noexcept -> state
{
    shake256_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest(out, amount);
}

#if !BOOST_CRYPT_HAS_CUDA

template <concepts::file_system_path T>
[[nodiscard]] BOOST_CRYPT_EXPORT
auto shake256_file(const T& filepath) -> compat::expected<shake256_hasher::return_type, state>
{
    return hash_detail::hash_file_impl<shake256_hasher>(filepath);
}

template <concepts::file_system_path T>
[[nodiscard]] BOOST_CRYPT_EXPORT
auto shake256_file(const T& filepath, compat::span<compat::byte> out) -> compat::expected<shake256_hasher::return_type, state>
{
    return hash_detail::hash_file_impl<shake256_hasher>(filepath, out);
}

template <concepts::file_system_path T>
[[nodiscard]] BOOST_CRYPT_EXPORT
auto shake256_file(const T& filepath, compat::span<compat::byte> out, compat::size_t amount) -> compat::expected<shake256_hasher::return_type, state>
{
    return hash_detail::hash_file_impl<shake256_hasher>(filepath, out, amount);
}

template <concepts::file_system_path T, concepts::writable_output_range OutputRange>
[[nodiscard]] BOOST_CRYPT_EXPORT
auto shake256_file(const T& filepath, OutputRange&& out) -> compat::expected<shake256_hasher::return_type, state>
{
    using value_type = compat::range_value_t<OutputRange>;
    auto data_span {compat::span<value_type>(compat::forward<OutputRange>(out))};

    return hash_detail::hash_file_impl<shake256_hasher>(filepath, compat::span<compat::byte>(compat::as_writable_bytes(data_span).data(), data_span.size_bytes()), data_span.size_bytes());
}

template <concepts::file_system_path T, concepts::writable_output_range OutputRange>
[[nodiscard]] BOOST_CRYPT_EXPORT
auto shake256_file(const T& filepath, OutputRange&& out, compat::size_t amount) -> compat::expected<shake256_hasher::return_type, state>
{
    using value_type = compat::range_value_t<OutputRange>;
    auto data_span {compat::span<value_type>(compat::forward<OutputRange>(out))};

    return hash_detail::hash_file_impl<shake256_hasher>(filepath, compat::span<compat::byte>(compat::as_writable_bytes(data_span).data(), data_span.size_bytes()), amount);
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace boost::crypt

#endif //BOOST_CRYPT2_HASH_SHAKE256_HPP
