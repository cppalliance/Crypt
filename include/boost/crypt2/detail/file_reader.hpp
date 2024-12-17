// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_UTILITY_FILE_HPP
#define BOOST_CRYPT_UTILITY_FILE_HPP

#include <boost/crypt2/detail/config.hpp>

#ifndef BOOST_CRYPT_HAS_CUDA

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <fstream>
#include <string>
#include <ios>
#include <exception>
#include <array>
#include <cstdint>
#include <string_view>
#include <string>
#include <filesystem>
#endif

namespace boost::crypt::detail {

template <std::size_t block_size = 64U>
class file_reader
{
public:
    using buffer_type = std::array<std::byte, block_size>;
    using iterator = typename buffer_type::iterator;

private:
    std::ifstream fd_;
    buffer_type buffer_{};

public:
    template <typename T>
    explicit file_reader(const T& filename)
        requires std::is_convertible_v<T, std::string>
            : fd_(std::string{filename}, std::ios::binary | std::ios::in)
        {
            const std::string filename_str {filename};
            validate_file(filename_str);
        }

    // Rule of 5
    file_reader(const file_reader&) = delete;
    file_reader& operator=(const file_reader&) = delete;
    file_reader(file_reader&&) noexcept = default;
    file_reader& operator=(file_reader&&) noexcept = default;
    ~file_reader() = default; // RAII handles file closing

    [[nodiscard]] iterator read_next_block()
    {
        if (!fd_.good())
        {
            throw std::runtime_error("Attempt to read from invalid file stream");
        }

        fd_.read(reinterpret_cast<char*>(buffer_.data()), block_size);

        if (fd_.bad())
        {
            throw std::runtime_error("Error occurred while reading file");
        }

        return buffer_.begin();
    }

    [[nodiscard]] std::size_t get_bytes_read() const noexcept
    {
        return static_cast<std::size_t>(fd_.gcount());
    }

    [[nodiscard]] bool eof() const noexcept
    {
        return fd_.eof();
    }

    [[nodiscard]] const buffer_type& buffer() const noexcept
    {
        return buffer_;
    }

private:
    void validate_file(const std::string_view filename) const
    {
        if (!fd_.is_open())
        {
            throw std::runtime_error(std::string{"Error opening file: "} + std::string{filename});
        }
        if (!fd_.good())
        {
            throw std::runtime_error(std::string{"File stream not valid after opening: "} + std::string{filename});
        }
    }
};

} // Namespace boost::crypt::detail

#else

#error "CUDA does not support reading from file"

#endif // BOOST_CRYPT_HAS_CUDA

#endif //BOOST_CRYPT_UTILITY_FILE_HPP
