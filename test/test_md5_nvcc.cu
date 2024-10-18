//  Copyright Matt Borland 2024
//  Use, modification and distribution are subject to the
//  Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <boost/crypt/hash/md5.hpp>
#include "cuda_managed_ptr.hpp"
#include "stopwatch.hpp"
#include "generate_random_strings.hpp"
#include <iostream>
#include <iomanip>
#include <exception>
#include <memory>

#include <cuda_runtime.h>

using digest_type = boost::crypt::array<boost::crypt::uint8_t, 16>;

// The kernel function
__global__ void cuda_test(char** in, digest_type* out, int numElements)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;

    if (i < numElements)
    {
        out[i] = boost::crypt::md5(in[i]);
    }
}

int main()
{
    try
    {
        // Error code to check return values for CUDA calls
        cudaError_t err = cudaSuccess;

        // Print the vector length to be used, and compute its size
        int numElements = 50000;
        std::cout << "[Vector operation on " << numElements << " elements]" << std::endl;

        // Allocate the managed input vector A
        char** input_vector1 = new char*[numElements];

        // Allocate the managed output vector C
        cuda_managed_ptr<digest_type> output_vector(numElements);

        for (int i = 0; i < numElements; ++i)
        {
            input_vector1[i] = new char[1024];
            boost::crypt::generate_random_string(input_vector1[i], 1024);
        }

        // Launch the Vector Add CUDA Kernel
        int threadsPerBlock = 256;
        int blocksPerGrid =(numElements + threadsPerBlock - 1) / threadsPerBlock;
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
           results.emplace_back(boost::crypt::md5(input_vector1[i]));
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
            delete[] input_vector1[i];
        }
        delete[] input_vector1;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Terminated with exception: " << e.what() << std::endl;
    }
}
