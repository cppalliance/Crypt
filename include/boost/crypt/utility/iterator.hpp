// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_UTILITES_ITERATOR_HPP
#define BOOST_CRYPT_UTILITES_ITERATOR_HPP

#include <boost/crypt/utility/config.hpp>

#ifdef BOOST_CRYPT_HAS_CUDA

#include <cuda/std/iterator>

namespace boost {
namespace crypt {
namespace utility {

template <typename Iter>
struct iterator_traits : public cuda::std::iterator_traits<Iter> {};

template <typename T>
struct iterator_traits<T*> : public cuda::std::iterator_traits<T*> {};

} // namespace utility
} // namespace crypt
} // namespace boost

#else

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <iterator>
#endif

namespace boost {
namespace crypt {
namespace utility {

template <typename Iter>
struct iterator_traits : public std::iterator_traits<Iter> {};

template <typename T>
struct iterator_traits<T*> : public std::iterator_traits<T*> {};

} // namespace utility
} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HAS_CUDA

#endif //BOOST_CRYPT_UTILITES_ITERATOR_HPP
