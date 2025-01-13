// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DETAIL_CONCEPTS_HPP
#define BOOST_CRYPT_DETAIL_CONCEPTS_HPP

#include <boost/crypt2/detail/compat.hpp>

#if !defined(BOOST_CRYPT_BUILD_MODULE) && !BOOST_CRYPT_HAS_CUDA
#include <filesystem>
#include <type_traits>
#endif

namespace boost::crypt::concepts {

#if !BOOST_CRYPT_HAS_CUDA

template <typename T>
concept file_system_path =
    std::is_convertible_v<T, std::string> ||
    std::is_convertible_v<T, std::string_view> ||
    std::is_convertible_v<T, const char*> ||
    std::is_same_v<std::remove_cvref_t<T>, std::filesystem::path> ||
    std::is_same_v<std::remove_cvref_t<T>, char*>;

#endif

template <typename Range>
concept writable_output_range =  compat::output_range<Range, compat::range_value_t<Range>> &&
                                 compat::sized_range<Range> &&
                                 compat::is_trivially_copyable_v<compat::range_value_t<Range>>;

} // namespace boost::crypt::concepts

#endif // BOOST_CRYPT_DETAIL_CONCEPTS_HPP
