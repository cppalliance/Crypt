// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DETAIL_CONCEPTS_HPP
#define BOOST_CRYPT_DETAIL_CONCEPTS_HPP

#include <boost/crypt2/detail/compat.hpp>

#if !defined(BOOST_CRYPT_BUILD_MODULE) && !defined(BOOST_CRYPT_HAS_CUDA)
#include <filesystem>
#include <type_traits>
#endif

namespace boost::crypt::concepts {

#ifndef BOOST_CRYPT_HAS_CUDA

template <typename T>
concept file_system_path = std::is_convertible_v<T, std::string> ||
                           std::is_convertible_v<T, std::string_view> ||
                           std::is_same_v<std::remove_cvref<T>, std::filesystem::path>;

#endif

} // namespace boost::crypt::concepts

#endif // BOOST_CRYPT_DETAIL_CONCEPTS_HPP
