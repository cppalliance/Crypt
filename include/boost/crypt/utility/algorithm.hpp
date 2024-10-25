// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_UTILITIES_ALGORITHM_HPP
#define BOOST_CRYPT_UTILITIES_ALGORITHM_HPP

#include <boost/crypt/utility/config.hpp>

namespace boost { namespace crypt {

template<class InputIt1, class InputIt2>
BOOST_CRYPT_GPU_ENABLED constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2) -> bool
{
    while(first1 != last1)
    {
        if(!(*first1 == *first2))
        {
            return false;
        }

        ++first1;
        ++first2;
    }

    return true;
}

template<class InputIt1, class InputIt2>
BOOST_CRYPT_GPU_ENABLED constexpr auto lexicographical_compare(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) -> bool
{
    while((first1 != last1) && (first2 != last2))
    {
        if(*first1 < *first2)
        {
            return true;
        }

        if(*first2 < *first1)
        {
            return false;
        }

        ++first1;
        ++first2;
    }

    return ((first1 == last1) && (first2 != last2));
}

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_UTILITIES_ALGORITHM_HPP
