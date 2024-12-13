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

#ifndef BOOST_CRYPT_GPU_HOST_ENABLED
#  define BOOST_CRYPT_GPU_HOST_ENABLED
#endif

#ifndef BOOST_CRYPT_GPU_DEVICE_ENABLED
#  define BOOST_CRYPT_GPU_DEVICE_ENABLED
#endif

// See: https://docs.nvidia.com/cuda/cuda-c-programming-guide/index.html#hardware-implementation
#if defined(_WIN32) || defined(BOOST_CRYPT_HAS_CUDA)

#define BOOST_CRYPT_ENDIAN_BIG_BYTE 0
#define BOOST_CRYPT_ENDIAN_LITTLE_BYTE 1

#elif defined(__BYTE_ORDER__)

#define BOOST_CRYPT_ENDIAN_BIG_BYTE (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define BOOST_CRYPT_ENDIAN_LITTLE_BYTE (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

#else

#error Could not determine endian type. Please file an issue at https://github.com/cppalliance/crypt with your architecture

#endif // Determine endianness

#endif // BOOST_CRYPT_DETAIL_CONFIG_HPP
