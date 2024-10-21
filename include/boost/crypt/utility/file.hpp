// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_UTILITY_FILE_HPP
#define BOOST_CRYPT_UTILITY_FILE_HPP

#include <boost/crypt/utility/config.hpp>

// Can't use file streaming on a CUDA device anyway
#ifndef BOOST_CRYPT_HAS_CUDA

#include <boost/crypt/utility/cstdint.hpp>

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <fstream>
#include <string>
#include <ios>
#include <exception>
#include <array>
#endif

namespace boost {
namespace crypt {
namespace utility {

template <std::size_t block_size = 64U>
class file_reader
{
private:
    std::ifstream fd;
    std::array<std::uint8_t, block_size> buffer_ {};

public:
    explicit file_reader(const std::string& filename) : fd(filename, std::ios::binary | std::ios::in)
    {
        if (!fd.is_open())
        {
            throw std::runtime_error("Error opening file: " + filename);
        }
    }

    explicit file_reader(const char* filename) : fd(filename, std::ios::binary | std::ios::in)
    {
        if (!fd.is_open())
        {
            throw std::runtime_error("Error opening file");
        }
    }

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    explicit file_reader(std::string_view filename) : fd(filename.data(), std::ios::binary | std::ios::in)
    {
        if (!fd.is_open())
        {
            throw std::runtime_error("Error opening file");
        }
    }
    #endif

    auto read_next_block()
    {
        fd.read(reinterpret_cast<char*>(buffer_.data()), block_size);
        return buffer_.begin();
    }

    auto get_bytes_read() const -> std::size_t
    {
        return static_cast<std::size_t>(fd.gcount());
    }

    auto eof() const -> bool
    {
        return fd.eof();
    }

    ~file_reader()
    {
        if (fd.is_open())
        {
            fd.close();
        }
    }
};

} // namespace utility
} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HAS_CUDA

#endif //BOOST_CRYPT_UTILITY_FILE_HPP
