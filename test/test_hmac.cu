//  Copyright Matt Borland 2024
//  Use, modification and distribution are subject to the
//  Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <cuda_runtime.h>
#include <boost/crypt2/mac/hmac.hpp>
#include <boost/crypt2/hash/sha3_512.hpp>
#include "cuda_managed_ptr.hpp"
#include "stopwatch.hpp"
#include "generate_random_strings.hpp"
#include <iostream>
#include <iomanip>
#include <exception>
#include <memory>
#include <span>

using digest_type = typename boost::crypt::sha3_512_hasher::return_type;

// The kernel function
__global__ void cuda_test(char** in, digest_type* out, int numElements)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;

    if (i < numElements)
    {
        boost::crypt::hmac<boost::crypt::sha3_512_hasher> hmac_class;
        cuda::std::span<char> in_span {in[i], static_cast<cuda::std::size_t>(64)};
        hmac_class.init(in_span);
        hmac_class.process_bytes(in_span);
        hmac_class.finalize();
        out[i] = hmac_class.get_digest().value();
    }
}

int main()
{
    try
    {
        // Error code to check return values for CUDA calls
        cudaError_t err = cudaSuccess;

        // Print the vector length to be used, and compute its size
        constexpr int numElements = 50000;
        constexpr std::size_t elementSize = 64;

        std::cout << "[Vector operation on " << numElements << " elements]" << std::endl;

        // Allocate the managed input vector A
        char** input_vector1;
        cudaMallocManaged(&input_vector1, numElements * sizeof(char*));

        // Allocate the managed output vector C
        cuda_managed_ptr<digest_type> output_vector(numElements);

        for (int i = 0; i < numElements; ++i)
        {
            cudaMallocManaged(&input_vector1[i], elementSize * sizeof(char));
            if (input_vector1[i] == nullptr)
            {
                throw std::runtime_error("Failed to allocate memory for input_vector1");
            }
            boost::crypt::generate_random_string(input_vector1[i], elementSize);
        }

        // Launch the Vector Add CUDA Kernel
        int threadsPerBlock = 256;
        int blocksPerGrid = (numElements + threadsPerBlock - 1) / threadsPerBlock;
        std::cout << "CUDA kernel launch with " << blocksPerGrid << " blocks of " << threadsPerBlock << " threads" << std::endl;

        watch w;
        cuda_test<<<blocksPerGrid, threadsPerBlock>>>(input_vector1, output_vector.get(), numElements);
        cudaDeviceSynchronize();
        std::cout << "CUDA kernal done in " << w.elapsed() << "s" << std::endl;

        err = cudaGetLastError();
        if (err != cudaSuccess)
        {
            std::cerr << "Failed to launch vectorAdd kernel (error code " << cudaGetErrorString(err) << ")!" << std::endl;
            return EXIT_FAILURE;
        }

        // Verify that the result vector is correct
        std::vector<digest_type> results;
        results.reserve(numElements);
        w.reset();
        for(int i = 0; i < numElements; ++i)
        {
            std::span<char> in(input_vector1[i], elementSize);
            boost::crypt::hmac<boost::crypt::sha3_512_hasher> hmac_class;
            auto in_span {cuda::std::span(in, 64)};
            hmac_class.init(in_span);
            hmac_class.process_bytes(in_span);
            hmac_class.finalize();
            results.emplace_back(hmac_class.get_digest().value());
        }
        double t = w.elapsed();

        // check the results
        for(int i = 0; i < numElements; ++i)
        {
            if (output_vector[i][0] != results[i][0])
            {
                std::cerr << "Result verification failed at element " << i << "!" << std::endl;
                return EXIT_FAILURE;
            }
        }

        std::cout << "Test PASSED with calculation time: " << t << "s" << std::endl;
        std::cout << "Done\n";

        // Cleanup all the memory we allocated
        for (int i = 0; i < numElements; ++i)
        {
            cudaFree(input_vector1[i]);
        }
        cudaFree(input_vector1);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Terminated with exception: " << e.what() << std::endl;
    }
}
