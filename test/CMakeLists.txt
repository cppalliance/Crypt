# Copyright 2018, 2019 Peter Dimov
# Copyright 2023 Matt Borland
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt

include(BoostTestJamfile OPTIONAL RESULT_VARIABLE HAVE_BOOST_TEST)

if(HAVE_BOOST_TEST)

    if (BOOST_CRYPT_ENABLE_CUDA)

        message(STATUS "Building boost.crypt with CUDA")
        find_package(CUDAToolkit REQUIRED)
        enable_language(CUDA)
        set(CMAKE_CUDA_EXTENSIONS OFF)
        set(CMAKE_CXX_STANDARD 20)
        set(CMAKE_CXX_STANDARD_REQUIRED ON)
        set(CMAKE_CXX_EXTENSIONS OFF)

        set(CMAKE_CUDA_STANDARD 20)
        set(CMAKE_CUDA_STANDARD_REQUIRED ON)
        set(CMAKE_CUDA_EXTENSIONS OFF)

        set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --expt-relaxed-constexpr")

        boost_test_jamfile(
                FILE nvcc_jamfile
                LINK_LIBRARIES Boost::crypt CUDA::cudart
                INCLUDE_DIRECTORIES ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
                COMPILE_OPTIONS
                --expt-relaxed-constexpr  # Device code relaxed constexpr
        )

    elseif (BOOST_CRYPT_ENABLE_NVRTC)

        message(STATUS "Building boost.crypt with NVRTC")
        find_package(CUDA REQUIRED)
        set(CUDA_nvrtc_LIBRARY /usr/local/cuda/lib64/libnvrtc.so)

        if (BOOST_CRYPT_NVRTC_CI_RUN)

            boost_test_jamfile(FILE nvrtc_jamfile LINK_LIBRARIES Boost::crypt ${CUDA_nvrtc_LIBRARY} ${CUDA_LIBRARIES} ${CUDA_CUDA_LIBRARY} COMPILE_DEFINITIONS BOOST_CRYPT_NVRTC_CI_RUN=1 INCLUDE_DIRECTORIES ${CUDA_INCLUDE_DIRS})

        else ()

            boost_test_jamfile(FILE nvrtc_jamfile LINK_LIBRARIES Boost::crypt ${CUDA_nvrtc_LIBRARY} ${CUDA_LIBRARIES} ${CUDA_CUDA_LIBRARY} INCLUDE_DIRECTORIES ${CUDA_INCLUDE_DIRS} )

        endif ()

    else ()

        boost_test_jamfile(FILE Jamfile LINK_LIBRARIES Boost::crypt Boost::core Boost::uuid)

    endif ()

endif()
