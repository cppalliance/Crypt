# Copyright 2018, 2019 Peter Dimov
# Copyright 2023 Matt Borland
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt

include(BoostTestJamfile OPTIONAL RESULT_VARIABLE HAVE_BOOST_TEST)

if(HAVE_BOOST_TEST)
    if(BOOST_CRYPT_ENABLE_CUDA)
        message(STATUS "Building boost.crypt tests with CUDA")

        boost_test_jamfile(
                FILE nvcc_jamfile
                LINK_LIBRARIES Boost::crypt Boost::core CUDA::cudart
                INCLUDE_DIRECTORIES ${CUDAToolkit_INCLUDE_DIRS}
                COMPILE_OPTIONS
                --expt-relaxed-constexpr
        )
    else()
        message(STATUS "Building boost.crypt tests without CUDA")

        boost_test_jamfile(
                FILE jamfile
                LINK_LIBRARIES Boost::crypt Boost::core
        )
    endif()
endif()
