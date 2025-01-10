// Copyright 2024 - 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc4634
// See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

#ifndef BOOST_CRYPT2_SHA256_HPP
#define BOOST_CRYPT2_SHA256_HPP

#include <boost/crypt2/hash/detail/sha224_256_hasher.hpp>
#include <boost/crypt2/detail/file_reader.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>

namespace boost::crypt {

BOOST_CRYPT_EXPORT using sha256_hasher = hash_detail::sha_224_256_hasher<32U>;

// One shot functions
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha256(compat::span<const compat::byte> data) noexcept -> compat::expected<sha256_hasher::return_type, state>
{
    sha256_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

template <compat::sized_range SizedRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha256(SizedRange&& data) noexcept -> compat::expected<sha256_hasher::return_type, state>
{
    sha256_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

#ifndef BOOST_CRYPT_HAS_CUDA

// Error: the two-parameter std::span construction is unsafe as it can introduce mismatch between buffer size and the bound information [-Werror,-Wunsafe-buffer-usage-in-container]
// Since this is the way the file streams report sizing information we must use it
// If a bad read occurs an exception is thrown so there's little risk of a bad region
#if defined(__clang__) && __clang_major__ >= 19
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
#endif

namespace detail {

[[nodiscard]] inline auto sha256_file_impl(detail::file_reader<64U>& reader) -> compat::expected<sha256_hasher::return_type, state>
{
    sha256_hasher hasher;
    while (!reader.eof())
    {
        const auto buffer_iter {reader.read_next_block()};
        const auto len {reader.get_bytes_read()};
        const auto buffer_span {std::span(buffer_iter, len)};
        hasher.process_bytes(buffer_span);
    }

    hasher.finalize();
    return hasher.get_digest();
}

} // namespace detail

template <concepts::file_system_path T>
[[nodiscard]] BOOST_CRYPT_EXPORT inline auto sha256_file(const T& filepath) -> compat::expected<sha256_hasher::return_type, state>
{
    if constexpr (std::is_pointer_v<std::remove_cvref_t<T>>)
    {
        if (filepath == nullptr)
        {
            throw std::runtime_error("Invalid file path");
        }
    }

    detail::file_reader<64U> reader(filepath);
    return detail::sha256_file_impl(reader);
}

#if defined(__clang__) && __clang_major__ >= 19
#pragma clang diagnostic pop
#endif

#endif

} // namespace boost::crypt

#endif //BOOST_CRYPT2_SHA256_HPP
