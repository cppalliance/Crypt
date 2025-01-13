// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DETAIL_CONFIG_HPP
#define BOOST_CRYPT_DETAIL_CONFIG_HPP

#ifdef __CUDACC__
#  ifndef BOOST_CRYPT_HAS_CUDA
#    define BOOST_CRYPT_HAS_CUDA
#  endif
#  define BOOST_CRYPT_GPU_ENABLED __host__ __device__
#  define BOOST_CRYPT_GPU_HOST_ENABLED __host__
#  define BOOST_CRYPT_GPU_DEVICE_ENABLED __device__
#  define BOOST_CRYPT_GPU_ENABLED_CONSTEXPR __host__ __device__
#endif

#ifdef __CUDACC_RTC__
#  ifndef BOOST_CRYPT_HAS_CUDA
#    define BOOST_CRYPT_HAS_CUDA
#  endif
#  define BOOST_CRYPT_HAS_NVRTC
#  define BOOST_CRYPT_GPU_ENABLED __host__ __device__
#  define BOOST_CRYPT_GPU_HOST_ENABLED __host__
#  define BOOST_CRYPT_GPU_DEVICE_ENABLED __device__
#endif

#ifndef BOOST_CRYPT_GPU_ENABLED
#  define BOOST_CRYPT_GPU_ENABLED
#endif

#ifndef BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
#  define BOOST_CRYPT_GPU_ENABLED_CONSTEXPR constexpr
#endif

#ifndef BOOST_CRYPT_GPU_HOST_ENABLED
#  define BOOST_CRYPT_GPU_HOST_ENABLED
#endif

#ifndef BOOST_CRYPT_GPU_DEVICE_ENABLED
#  define BOOST_CRYPT_GPU_DEVICE_ENABLED
#endif

#ifdef BOOST_CRYPT_BUILD_MODULE
#  define BOOST_CRYPT_EXPORT export
#else
#  define BOOST_CRYPT_EXPORT
#endif

#endif // BOOST_CRYPT_DETAIL_CONFIG_HPP
