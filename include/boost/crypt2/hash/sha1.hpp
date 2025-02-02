// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc3174

#ifndef BOOST_CRYPT2_HASH_SHA1_HPP
#define BOOST_CRYPT2_HASH_SHA1_HPP

#include <boost/crypt2/hash/detail/sha_1_2_hasher_base.hpp>
#include <boost/crypt2/hash/detail/hash_file.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>

namespace boost::crypt {

BOOST_CRYPT_EXPORT class sha1_hasher final : public hash_detail::sha_1_2_hasher_base<20U, 5U>
{
private:

    friend class hash_detail::sha_1_2_hasher_base<20U, 5U>;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_message_block() noexcept -> void override;

public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha1_hasher() noexcept { init(); }

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init() noexcept -> void;
};

BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha1_hasher::init() noexcept -> void
{
    hash_detail::sha_1_2_hasher_base<20U, 5U>::base_init();

    intermediate_hash_[0] = 0x67452301;
    intermediate_hash_[1] = 0xEFCDAB89;
    intermediate_hash_[2] = 0x98BADCFE;
    intermediate_hash_[3] = 0x10325476;
    intermediate_hash_[4] = 0xC3D2E1F0;
}

namespace sha1_detail {

BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto round1(compat::uint32_t& A,
                                              compat::uint32_t& B,
                                              compat::uint32_t& C,
                                              compat::uint32_t& D,
                                              compat::uint32_t& E,
                                              compat::uint32_t  W)
{
    const auto temp {compat::rotl(A, 5) + ((B & C) | ((~B) & D)) + E + W + 0x5A827999U};
    E = D;
    D = C;
    C = compat::rotl(B, 30);
    B = A;
    A = temp;
}

BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto round2(compat::uint32_t& A,
                                              compat::uint32_t& B,
                                              compat::uint32_t& C,
                                              compat::uint32_t& D,
                                              compat::uint32_t& E,
                                              compat::uint32_t  W)
{
    const auto temp {compat::rotl(A, 5) + (B ^ C ^ D) + E + W + 0x6ED9EBA1U};
    E = D;
    D = C;
    C = compat::rotl(B, 30);
    B = A;
    A = temp;
}

BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto round3(compat::uint32_t& A,
                                              compat::uint32_t& B,
                                              compat::uint32_t& C,
                                              compat::uint32_t& D,
                                              compat::uint32_t& E,
                                              compat::uint32_t  W)
{
    const auto temp {compat::rotl(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W + 0x8F1BBCDCU};
    E = D;
    D = C;
    C = compat::rotl(B, 30);
    B = A;
    A = temp;
}

BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto round4(compat::uint32_t& A,
                                              compat::uint32_t& B,
                                              compat::uint32_t& C,
                                              compat::uint32_t& D,
                                              compat::uint32_t& E,
                                              compat::uint32_t  W)
{
    const auto temp {compat::rotl(A, 5) + (B ^ C ^ D) + E + W + 0xCA62C1D6U};
    E = D;
    D = C;
    C = compat::rotl(B, 30);
    B = A;
    A = temp;
}

} // Namespace sha1_detail

// See definitions from the RFC on the rounds
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha1_hasher::process_message_block() noexcept -> void
{
    using namespace sha1_detail;

    compat::array<compat::uint32_t, 80> W {};

    // Init the first 16 words of W
    for (compat::size_t i {}; i < 16UL; ++i)
    {
        W[i] = (static_cast<compat::uint32_t>(buffer_[i * 4U]) << 24U) |
               (static_cast<compat::uint32_t>(buffer_[i * 4U + 1U]) << 16U) |
               (static_cast<compat::uint32_t>(buffer_[i * 4U + 2U]) << 8U) |
               (static_cast<compat::uint32_t>(buffer_[i * 4U + 3U]));

    }

    for (compat::size_t i {16U}; i < W.size(); ++i)
    {
        W[i] = compat::rotl(W[i - 3U] ^ W[i - 8U] ^ W[i - 14] ^ W[i - 16], 1);
    }

    auto A {intermediate_hash_[0]};
    auto B {intermediate_hash_[1]};
    auto C {intermediate_hash_[2]};
    auto D {intermediate_hash_[3]};
    auto E {intermediate_hash_[4]};

    // Round 1
    round1(A, B, C, D, E, W[0]);
    round1(A, B, C, D, E, W[1]);
    round1(A, B, C, D, E, W[2]);
    round1(A, B, C, D, E, W[3]);
    round1(A, B, C, D, E, W[4]);
    round1(A, B, C, D, E, W[5]);
    round1(A, B, C, D, E, W[6]);
    round1(A, B, C, D, E, W[7]);
    round1(A, B, C, D, E, W[8]);
    round1(A, B, C, D, E, W[9]);
    round1(A, B, C, D, E, W[10]);
    round1(A, B, C, D, E, W[11]);
    round1(A, B, C, D, E, W[12]);
    round1(A, B, C, D, E, W[13]);
    round1(A, B, C, D, E, W[14]);
    round1(A, B, C, D, E, W[15]);
    round1(A, B, C, D, E, W[16]);
    round1(A, B, C, D, E, W[17]);
    round1(A, B, C, D, E, W[18]);
    round1(A, B, C, D, E, W[19]);

    // Round 2
    round2(A, B, C, D, E, W[20]);
    round2(A, B, C, D, E, W[21]);
    round2(A, B, C, D, E, W[22]);
    round2(A, B, C, D, E, W[23]);
    round2(A, B, C, D, E, W[24]);
    round2(A, B, C, D, E, W[25]);
    round2(A, B, C, D, E, W[26]);
    round2(A, B, C, D, E, W[27]);
    round2(A, B, C, D, E, W[28]);
    round2(A, B, C, D, E, W[29]);
    round2(A, B, C, D, E, W[30]);
    round2(A, B, C, D, E, W[31]);
    round2(A, B, C, D, E, W[32]);
    round2(A, B, C, D, E, W[33]);
    round2(A, B, C, D, E, W[34]);
    round2(A, B, C, D, E, W[35]);
    round2(A, B, C, D, E, W[36]);
    round2(A, B, C, D, E, W[37]);
    round2(A, B, C, D, E, W[38]);
    round2(A, B, C, D, E, W[39]);

    // Round 3
    round3(A, B, C, D, E, W[40]);
    round3(A, B, C, D, E, W[41]);
    round3(A, B, C, D, E, W[42]);
    round3(A, B, C, D, E, W[43]);
    round3(A, B, C, D, E, W[44]);
    round3(A, B, C, D, E, W[45]);
    round3(A, B, C, D, E, W[46]);
    round3(A, B, C, D, E, W[47]);
    round3(A, B, C, D, E, W[48]);
    round3(A, B, C, D, E, W[49]);
    round3(A, B, C, D, E, W[50]);
    round3(A, B, C, D, E, W[51]);
    round3(A, B, C, D, E, W[52]);
    round3(A, B, C, D, E, W[53]);
    round3(A, B, C, D, E, W[54]);
    round3(A, B, C, D, E, W[55]);
    round3(A, B, C, D, E, W[56]);
    round3(A, B, C, D, E, W[57]);
    round3(A, B, C, D, E, W[58]);
    round3(A, B, C, D, E, W[59]);

    // Round 4
    round4(A, B, C, D, E, W[60]);
    round4(A, B, C, D, E, W[61]);
    round4(A, B, C, D, E, W[62]);
    round4(A, B, C, D, E, W[63]);
    round4(A, B, C, D, E, W[64]);
    round4(A, B, C, D, E, W[65]);
    round4(A, B, C, D, E, W[66]);
    round4(A, B, C, D, E, W[67]);
    round4(A, B, C, D, E, W[68]);
    round4(A, B, C, D, E, W[69]);
    round4(A, B, C, D, E, W[70]);
    round4(A, B, C, D, E, W[71]);
    round4(A, B, C, D, E, W[72]);
    round4(A, B, C, D, E, W[73]);
    round4(A, B, C, D, E, W[74]);
    round4(A, B, C, D, E, W[75]);
    round4(A, B, C, D, E, W[76]);
    round4(A, B, C, D, E, W[77]);
    round4(A, B, C, D, E, W[78]);
    round4(A, B, C, D, E, W[79]);

    intermediate_hash_[0] += A;
    intermediate_hash_[1] += B;
    intermediate_hash_[2] += C;
    intermediate_hash_[3] += D;
    intermediate_hash_[4] += E;

    buffer_index_ = 0U;
}

// One shot functions
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha1(compat::span<const compat::byte> data) noexcept -> compat::expected<sha1_hasher::return_type, state>
{
    sha1_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

template <concepts::sized_range SizedRange>
[[nodiscard]] BOOST_CRYPT_EXPORT BOOST_CRYPT_GPU_ENABLED
auto sha1(SizedRange&& data) noexcept -> compat::expected<sha1_hasher::return_type, state>
{
    sha1_hasher hasher;
    hasher.process_bytes(data);
    hasher.finalize();
    return hasher.get_digest();
}

#if !BOOST_CRYPT_HAS_CUDA


template <concepts::file_system_path T>
[[nodiscard]] BOOST_CRYPT_EXPORT inline
auto sha1_file(const T& filepath) -> compat::expected<sha1_hasher::return_type, state>
{
    return hash_detail::hash_file_impl<sha1_hasher>(filepath);
}

#endif // BOOST_CRYPT_HAS_CUDA

} // Namespace boost::crypt

#endif // BOOST_CRYPT2_HASH_SHA1_HPP
