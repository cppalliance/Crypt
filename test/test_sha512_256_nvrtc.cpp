//  Copyright Matt Borland 2024.
//  Use, modification and distribution are subject to the
//  Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

// Must be included first

#include <nvrtc.h>
#include <cuda.h>
#include <cuda_runtime.h>

#include <iostream>
#include <iomanip>
#include <random>
#include <exception>

#include <boost/crypt/hash/sha512_256.hpp>
#include "generate_random_strings.hpp"
#include "cuda_managed_ptr.hpp"
#include "stopwatch.hpp"

using digest_type = boost::crypt::sha512_256_hasher::return_type;

const char* cuda_kernel = R"(

#include <boost/crypt/hash/sha512_256.hpp>
using digest_type = boost::crypt::sha512_256_hasher::return_type;
extern "C" __global__
void test_sha512_256_kernel(char** in, digest_type* out, int numElements)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;

    if (i < numElements)
    {
        out[i] = boost::crypt::sha512_256(in[i]);
    }
}

)";

void checkCUDAError(cudaError_t result, const char* msg)
{
    if (result != cudaSuccess)
    {
        std::cerr << msg << ": " << cudaGetErrorString(result) << std::endl;
        exit(EXIT_FAILURE);
    }
}

void checkCUError(CUresult result, const char* msg)
{
    if (result != CUDA_SUCCESS)
    {
        const char* errorStr;
        cuGetErrorString(result, &errorStr);
        std::cerr << msg << ": " << errorStr << std::endl;
        exit(EXIT_FAILURE);
    }
}

void checkNVRTCError(nvrtcResult result, const char* msg)
{
    if (result != NVRTC_SUCCESS)
    {
        std::cerr << msg << ": " << nvrtcGetErrorString(result) << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main()
{
    try
    {
        // Initialize CUDA driver API
        checkCUError(cuInit(0), "Failed to initialize CUDA");

        // Create CUDA context
        CUcontext context;
        CUdevice device;
        checkCUError(cuDeviceGet(&device, 0), "Failed to get CUDA device");
        checkCUError(cuCtxCreate(&context, 0, device), "Failed to create CUDA context");

        nvrtcProgram prog;
        nvrtcResult res;

        res = nvrtcCreateProgram(&prog, cuda_kernel, "test_sha512_256_kernel.cu", 0, nullptr, nullptr);
        checkNVRTCError(res, "Failed to create NVRTC program");

        nvrtcAddNameExpression(prog, "test_sha512_256_kernel");

        #ifdef BOOST_CRYPT_NVRTC_CI_RUN
        const char* opts[] = {"--std=c++14", "--gpu-architecture=compute_75", "--include-path=/home/runner/work/crypt/boost-root/libs/crypt/include/", "-I/usr/local/cuda/include"};
        #else
        const char* opts[] = {"--std=c++14", "--include-path=/home/mborland/Documents/boost/libs/crypt/include/", "-I/usr/local/cuda/include"};
        #endif

        // Compile the program
        res = nvrtcCompileProgram(prog, sizeof(opts) / sizeof(const char*), opts);
        if (res != NVRTC_SUCCESS)
        {
            size_t log_size;
            nvrtcGetProgramLogSize(prog, &log_size);
            char* log = new char[log_size];
            nvrtcGetProgramLog(prog, log);
            std::cerr << "Compilation failed:\n" << log << std::endl;
            delete[] log;
            exit(EXIT_FAILURE);
        }

        // Get PTX from the program
        size_t ptx_size;
        nvrtcGetPTXSize(prog, &ptx_size);
        char* ptx = new char[ptx_size];
        nvrtcGetPTX(prog, ptx);

        // Load PTX into CUDA module
        CUmodule module;
        CUfunction kernel;
        checkCUError(cuModuleLoadDataEx(&module, ptx, 0, 0, 0), "Failed to load module");
        checkCUError(cuModuleGetFunction(&kernel, module, "test_sha512_256_kernel"), "Failed to get kernel function");

        // Allocate memory
        int numElements = 50000;
        int elementSize = 64;

        char** input_vector1;
        cudaMallocManaged(&input_vector1, numElements * sizeof(char*));

        for (int i = 0; i < numElements; ++i)
        {
            cudaMallocManaged(&input_vector1[i], elementSize * sizeof(char));
            if (input_vector1[i] == nullptr)
            {
                throw std::runtime_error("Failed to allocate memory for input_vector1");
            }
            boost::crypt::generate_random_string(input_vector1[i], elementSize);
        }

        digest_type* output_vector;
        cudaMallocManaged(&output_vector, numElements * sizeof(digest_type));

        int blockSize = 256;
        int numBlocks = (numElements + blockSize - 1) / blockSize;
        void* args[] = { &input_vector1, &output_vector, &numElements };

        watch w;
        checkCUError(cuLaunchKernel(kernel, numBlocks, 1, 1, blockSize, 1, 1, 0, 0, args, 0), "Kernel launch failed");
        checkCUDAError(cudaDeviceSynchronize(), "Kernel execution failed");

        double t = w.elapsed();
        // Verify the result
        int fail_counter = 0;
        for (int i = 0; i < numElements; ++i)
        {
            auto res = boost::crypt::sha512_256(input_vector1[i]);

            for (int j = 0; j < res.size(); ++j)
            {
                if (res[j] != output_vector[i][j])
                {
                    std::cerr << std::hex << "Result verification failed at element " << i << "!\n"
                              << "Got: " << static_cast<std::uint32_t>(output_vector[i][j]) << "\n"
                              << "Expected: " << static_cast<std::uint32_t>(res[j]) << std::endl;
                    ++fail_counter;
                    if (fail_counter == 100)
                    {
                        break;
                    }
                }
            }
        }

        if (fail_counter == 100)
        {
            return EXIT_FAILURE;
        }

        std::cout << "Test PASSED with calculation time: " << t << "s" << std::endl;
        std::cout << "Done\n";

        // Cleanup all the memory we allocated
        for (int i = 0; i < numElements; ++i)
        {
            cudaFree(input_vector1[i]);
        }
        cudaFree(input_vector1);
        cudaFree(output_vector);

        nvrtcDestroyProgram(&prog);
        delete[] ptx;

        cuCtxDestroy(context);

        std::cout << "Kernel executed successfully." << std::endl;
        return 0;
    }
    catch(const std::exception& e)
    {
        std::cerr << "Stopped with exception: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
