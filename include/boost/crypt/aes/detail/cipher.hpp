// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_AES_DETAIL_CIPHER_HPP
#define BOOST_CRYPT_AES_DETAIL_CIPHER_HPP

#include <boost/crypt/utility/state.hpp>
#include <boost/crypt/utility/array.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/cstddef.hpp>

namespace boost {
namespace crypt {
namespace aes {

template <boost::crypt::size_t Nr>
class cipher
{
private:

    static constexpr boost::crypt::size_t Nb {4}; // Block size
    static constexpr boost::crypt::size_t Nk {Nr == 10 ? 4 :
                                              Nr == 12 ? 6 :
                                              Nr == 14 ? 8 : 0}; // Key length
    static_assert(Nk != 0, "Invalid number of rounds");

    static constexpr boost::crypt::array<boost::crypt::uint8_t, 256> sbox = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    static constexpr boost::crypt::array<boost::crypt::uint8_t, 11> Rcon = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    boost::crypt::array<boost::crypt::array<boost::crypt::uint8_t, 4U>, 4U> state {};

    BOOST_CRYPT_GPU_ENABLED constexpr auto rot_word(boost::crypt::array<boost::crypt::uint8_t, 4>& temp) noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto sub_word(boost::crypt::array<boost::crypt::uint8_t, 4>& temp) noexcept -> void;

    template <typename ForwardIterator>
    BOOST_CRYPT_GPU_ENABLED constexpr auto key_expansion(ForwardIterator key) noexcept -> boost::crypt::array<boost::crypt::uint8_t, Nk>;

    BOOST_CRYPT_GPU_ENABLED constexpr auto sub_bytes() noexcept -> void;
};

template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::rot_word(boost::crypt::array<boost::crypt::uint8_t, 4>& temp) noexcept -> void
{
    const auto temp0 {temp[0]};
    temp[0] = temp[1];
    temp[1] = temp[2];
    temp[2] = temp[3];
    temp[3] = temp0;
}

template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::sub_word(boost::crypt::array<boost::crypt::uint8_t, 4>& temp) noexcept -> void
{
    temp[0] = sbox[temp[0]];
    temp[1] = sbox[temp[1]];
    temp[2] = sbox[temp[2]];
    temp[3] = sbox[temp[3]];
}

template <boost::crypt::size_t Nr>
template <typename ForwardIterator>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::key_expansion(ForwardIterator key) noexcept -> boost::crypt::array<boost::crypt::uint8_t, Nk>
{
    boost::crypt::array<boost::crypt::uint8_t, Nk> w {};
    boost::crypt::array<boost::crypt::uint8_t, 4> temp {};

    for (boost::crypt::size_t i {}; i < Nk; ++i)
    {
        const auto k {i * 4U};
        w[k + 0U] = key[k + 0U];
        w[k + 1U] = key[k + 1U];
        w[k + 2U] = key[k + 2U];
        w[k + 3U] = key[k + 3U];
    }

    for (boost::crypt::size_t i {Nk}; i < Nb * (Nr + 1); ++i)
    {
        const auto k {(i - 1) * 4U};
        temp[0] = w[k + 0U];
        temp[1] = w[k + 1U];
        temp[2] = w[k + 2U];
        temp[3] = w[k + 3U];

        if (i % Nk == 0)
        {
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= Rcon[i / Nk];
        }
        BOOST_CRYPT_IF_CONSTEXPR (Nk > 6U)
        {
            if (i % Nk == 4U)
            {
                sub_word(temp);
            }
        }
        const auto j {i * 4U};
        const auto l {(i - Nk) * 4U};
        w[j + 0U] = w[l + 0U] ^ temp[0];
        w[j + 1U] = w[l + 1U] ^ temp[1];
        w[j + 2U] = w[l + 2U] ^ temp[2];
        w[j + 3U] = w[l + 3U] ^ temp[3];
    }

    return w;
}

template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::sub_bytes() noexcept -> void
{
    for (auto& line : state)
    {
        for (auto& val : line)
        {
            val = sbox[val];
        }
    }
}

} // namespace aes
} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_AES_DETAIL_CIPHER_HPP
