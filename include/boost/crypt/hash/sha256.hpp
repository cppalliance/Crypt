// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc4634

#ifndef BOOST_CRYPT_HASH_SHA256_HPP
#define BOOST_CRYPT_HASH_SHA256_HPP

#include <boost/crypt/hash/detail/hasher_base_512.hpp>
#include <boost/crypt/hash/hasher_state.hpp>
#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/bit.hpp>
#include <boost/crypt/utility/byte.hpp>
#include <boost/crypt/utility/array.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/type_traits.hpp>
#include <boost/crypt/utility/strlen.hpp>
#include <boost/crypt/utility/cstddef.hpp>
#include <boost/crypt/utility/iterator.hpp>
#include <boost/crypt/utility/file.hpp>
#include <boost/crypt/utility/null.hpp>

#if !defined(BOOST_CRYPT_BUILD_MODULE) && !defined(BOOST_CRYPT_HAS_CUDA)
#include <memory>
#include <string>
#include <cstdint>
#include <cstring>
#endif

namespace boost {
namespace crypt {

BOOST_CRYPT_EXPORT class sha256_hasher final : public hash_detail::hasher_base_512<32U, 8U>
{
public:

    BOOST_CRYPT_GPU_ENABLED sha256_hasher() noexcept { this->init(); }

    BOOST_CRYPT_GPU_ENABLED inline auto init() noexcept -> void;

private:

    BOOST_CRYPT_GPU_ENABLED auto process_message_block() noexcept -> void override;
};

BOOST_CRYPT_GPU_ENABLED inline auto sha256_hasher::init() noexcept -> void
{
    hash_detail::hasher_base_512<32U, 8U>::base_init();

    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    intermediate_hash_[0] = 0x6A09E667;
    intermediate_hash_[1] = 0xBB67AE85;
    intermediate_hash_[2] = 0x3C6EF372;
    intermediate_hash_[3] = 0xA54FF53A;
    intermediate_hash_[4] = 0x510E527F;
    intermediate_hash_[5] = 0x9B05688C;
    intermediate_hash_[6] = 0x1F83D9AB;
    intermediate_hash_[7] = 0x5BE0CD19;
}

namespace sha256_detail {

#ifndef BOOST_CRYPT_HAS_CUDA
BOOST_CRYPT_INLINE_CONSTEXPR boost::crypt::array<boost::crypt::uint32_t, 64> sha256_k = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
#endif

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
// See section 4.1.2
BOOST_CRYPT_GPU_ENABLED inline auto big_sigma0(const boost::crypt::uint32_t value) noexcept -> boost::crypt::uint32_t
{
    return detail::rotr(value, 2U) ^ detail::rotr(value, 13U) ^ detail::rotr(value, 22U);
}

BOOST_CRYPT_GPU_ENABLED inline auto big_sigma1(const boost::crypt::uint32_t value) noexcept -> boost::crypt::uint32_t
{
    return detail::rotr(value, 6U) ^ detail::rotr(value, 11U) ^ detail::rotr(value, 25U);
}

BOOST_CRYPT_GPU_ENABLED inline auto little_sigma0(const boost::crypt::uint32_t value) noexcept -> boost::crypt::uint32_t
{
    return detail::rotr(value, 7U) ^ detail::rotr(value, 18U) ^ (value >> 3U);
}

BOOST_CRYPT_GPU_ENABLED inline auto little_sigma1(const boost::crypt::uint32_t value) noexcept -> boost::crypt::uint32_t
{
    return detail::rotr(value, 17U) ^ detail::rotr(value, 19U) ^ (value >> 10U);
}

BOOST_CRYPT_GPU_ENABLED inline auto sha_ch(const boost::crypt::uint32_t x, const boost::crypt::uint32_t y, const boost::crypt::uint32_t z) noexcept -> boost::crypt::uint32_t
{
    return (x & y) ^ ((~x) & z);
}

BOOST_CRYPT_GPU_ENABLED inline auto sha_maj(const boost::crypt::uint32_t x, const boost::crypt::uint32_t y, const boost::crypt::uint32_t z) noexcept -> boost::crypt::uint32_t
{
    return (x & y) ^ (x & z) ^ (y & z);
}

} // Namespace sha256_detail

// See definitions from the RFC on the rounds
BOOST_CRYPT_GPU_ENABLED inline auto sha256_hasher::process_message_block() noexcept -> void
{
    // On the host we prefer this array to be static but,
    // in a CUDA environment it solves linking problems to move into the function

    #ifdef BOOST_CRYPT_HAS_CUDA
    constexpr boost::crypt::uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    #endif

    using namespace sha256_detail;
    boost::crypt::array<boost::crypt::uint32_t, 64> W {};

    // Init the first 16 words of W
    for (boost::crypt::size_t i {}; i < 16UL; ++i)
    {
        W[i] = (static_cast<boost::crypt::uint32_t>(buffer_[i * 4U]) << 24U) |
               (static_cast<boost::crypt::uint32_t>(buffer_[i * 4U + 1U]) << 16U) |
               (static_cast<boost::crypt::uint32_t>(buffer_[i * 4U + 2U]) << 8U) |
               (static_cast<boost::crypt::uint32_t>(buffer_[i * 4U + 3U]));

    }

    for (boost::crypt::size_t i {16U}; i < W.size(); ++i)
    {
        W[i] = sha256_detail::little_sigma1(W[i - 2U])  + W[i - 7U] +
               sha256_detail::little_sigma0(W[i - 15U]) + W[i - 16U];
    }

    auto A {intermediate_hash_[0]};
    auto B {intermediate_hash_[1]};
    auto C {intermediate_hash_[2]};
    auto D {intermediate_hash_[3]};
    auto E {intermediate_hash_[4]};
    auto F {intermediate_hash_[5]};
    auto G {intermediate_hash_[6]};
    auto H {intermediate_hash_[7]};

    for (boost::crypt::size_t i {}; i < W.size(); ++i)
    {
        const auto temp1 {H + big_sigma1(E) + sha_ch(E, F, G) + sha256_k[i] + W[i]};
        const auto temp2 {big_sigma0(A) + sha_maj(A, B, C)};

        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
    }

    intermediate_hash_[0] += A;
    intermediate_hash_[1] += B;
    intermediate_hash_[2] += C;
    intermediate_hash_[3] += D;
    intermediate_hash_[4] += E;
    intermediate_hash_[5] += F;
    intermediate_hash_[6] += G;
    intermediate_hash_[7] += H;

    buffer_index_ = 0U;
}

namespace detail {

template <typename T>
BOOST_CRYPT_GPU_ENABLED inline auto sha256(T begin, T end) noexcept -> sha256_hasher::return_type
{
    if (end < begin)
    {
        return sha256_hasher::return_type {};
    }
    else if (end == begin)
    {
        return sha256_hasher::return_type {
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        };
    }

    sha256_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    auto result {hasher.get_digest()};

    return result;
}

} // namespace detail

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char* str) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char* str, boost::crypt::size_t len) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha256(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const boost::crypt::uint8_t* str) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const boost::crypt::uint8_t* str, boost::crypt::size_t len) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha256(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char16_t* str) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char16_t* str, boost::crypt::size_t len) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha256(str, str + len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char32_t* str) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const char32_t* str, boost::crypt::size_t len) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha256(str, str + len);
}

// On some platforms wchar_t is 16 bits and others it's 32
// Since we check sizeof() the underlying with SFINAE in the actual implementation this is handled transparently
BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const wchar_t* str) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    const auto message_len {utility::strlen(str)};
    return detail::sha256(str, str + message_len);
}

BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED inline auto sha256(const wchar_t* str, boost::crypt::size_t len) noexcept -> sha256_hasher::return_type
{
    if (str == nullptr)
    {
        return sha256_hasher::return_type{}; // LCOV_EXCL_LINE
    }

    return detail::sha256(str, str + len);
}

// ----- String and String view aren't in the libcu++ STL so they so not have device markers -----

#ifndef BOOST_CRYPT_HAS_CUDA

BOOST_CRYPT_EXPORT inline auto sha256(const std::string& str) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(const std::u16string& str) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(const std::u32string& str) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(const std::wstring& str) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto sha256(std::string_view str) -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(std::u16string_view str) -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(std::u32string_view str) -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

BOOST_CRYPT_EXPORT inline auto sha256(std::wstring_view str) -> sha256_hasher::return_type
{
    return detail::sha256(str.begin(), str.end());
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

// ---- CUDA also does not have the ability to consume files -----

namespace detail {

template <boost::crypt::size_t block_size = 64U>
auto sha256_file_impl(utility::file_reader<block_size>& reader) noexcept -> sha256_hasher::return_type
{
    sha256_hasher hasher;
    while (!reader.eof())
    {
        const auto buffer_iter {reader.read_next_block()};
        const auto len {reader.get_bytes_read()};
        hasher.process_bytes(buffer_iter, len);
    }

    return hasher.get_digest();
}

} // namespace detail

BOOST_CRYPT_EXPORT inline auto sha256_file(const std::string& filepath) noexcept -> sha256_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha256_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha256_hasher::return_type{};
    }
}

BOOST_CRYPT_EXPORT inline auto sha256_file(const char* filepath) noexcept -> sha256_hasher::return_type
{
    try
    {
        if (filepath == nullptr)
        {
            return sha256_hasher::return_type{};
        }

        utility::file_reader<64U> reader(filepath);
        return detail::sha256_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha256_hasher::return_type{};
    }
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW

BOOST_CRYPT_EXPORT inline auto sha256_file(std::string_view filepath) noexcept -> sha256_hasher::return_type
{
    try
    {
        utility::file_reader<64U> reader(filepath);
        return detail::sha256_file_impl(reader);
    }
    catch (const std::runtime_error&)
    {
        return sha256_hasher::return_type{};
    }
}

#endif // BOOST_CRYPT_HAS_STRING_VIEW

#endif // BOOST_CRYPT_HAS_CUDA

// ---- The CUDA versions that we support all offer <cuda/std/span> ----

#ifdef BOOST_CRYPT_HAS_SPAN

BOOST_CRYPT_EXPORT template <typename T, std::size_t extent>
inline auto sha256(std::span<T, extent> data) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_SPAN

#ifdef BOOST_CRYPT_HAS_CUDA

template <typename T, boost::crypt::size_t extent>
BOOST_CRYPT_GPU_ENABLED inline auto sha256(cuda::std::span<T, extent> data) noexcept -> sha256_hasher::return_type
{
    return detail::sha256(data.begin(), data.end());
}

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namepsace boost

#endif // BOOST_CRYPT_HASH_SHA256_HPP
