// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/detail/assert.hpp>

int main()
{
    try
    {
        BOOST_CRYPT_ASSERT(false);
    }
    catch (...)
    {
        std::cerr << "Caught exception as expected" << std::endl;
    }

    return 0;
}
