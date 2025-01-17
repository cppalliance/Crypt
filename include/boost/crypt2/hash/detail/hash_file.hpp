// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_HASH_DETAIL_HASH_FILE_HPP
#define BOOST_CRYPT2_HASH_DETAIL_HASH_FILE_HPP

#include <boost/crypt2/detail/config.hpp>

#if !BOOST_CRYPT_HAS_CUDA

#include <boost/crypt2/detail/file_reader.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/compat.hpp>

#if !defined(BOOST_CRYPT_BUILD_MODULE)
#include <limits>
#endif

namespace boost::crypt::hash_detail {

// Error: the two-parameter std::span construction is unsafe as it can introduce mismatch between buffer size and the bound information [-Werror,-Wunsafe-buffer-usage-in-container]
// Since this is the way the file streams report sizing information we must use it
// If a bad read occurs an exception is thrown so there's little risk of a bad region
#if defined(__clang__) && __clang_major__ >= 19
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
#endif

template <typename HasherType, concepts::file_system_path T>
[[nodiscard]] auto hash_file_impl(const T& filepath) -> compat::expected<typename HasherType::return_type, state>
{
    if constexpr (std::is_pointer_v<std::remove_cvref_t<T>>)
    {
        if (filepath == nullptr)
        {
            throw std::runtime_error("Invalid file path");
        }
    }

    detail::file_reader<HasherType::block_size> reader(filepath);
    HasherType hasher;

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

template <typename HasherType, concepts::file_system_path T>
[[nodiscard]] auto hash_file_impl(const T& filepath, std::span<std::byte> out, std::size_t amount = std::numeric_limits<std::size_t>::max()) -> state
{
    if constexpr (std::is_pointer_v<std::remove_cvref_t<T>>)
    {
        if (filepath == nullptr)
        {
            throw std::runtime_error("Invalid file path");
        }
    }

    detail::file_reader<HasherType::block_size> reader(filepath);
    HasherType hasher;

    while (!reader.eof())
    {
        const auto buffer_iter {reader.read_next_block()};
        const auto len {reader.get_bytes_read()};
        const auto buffer_span {std::span(buffer_iter, len)};
        hasher.process_bytes(buffer_span);
    }

    hasher.finalize();

    if (amount == std::numeric_limits<std::size_t>::max())
    {
        return hasher.get_digest(out);
    }
    else
    {
        return hasher.get_digest(out, amount);
    }
}

#if defined(__clang__) && __clang_major__ >= 19
#pragma clang diagnostic pop
#endif

} // namespace boost::crypt::detail

#endif // BOOST_CRYPT_HAS_CUDA

#endif //BOOST_CRYPT2_HASH_DETAIL_HASH_FILE_HPP
