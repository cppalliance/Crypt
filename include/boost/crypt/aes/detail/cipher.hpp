// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_AES_DETAIL_CIPHER_HPP
#define BOOST_CRYPT_AES_DETAIL_CIPHER_HPP

#include <boost/crypt/aes/detail/cipher_mode.hpp>
#include <boost/crypt/utility/state.hpp>
#include <boost/crypt/utility/array.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/cstddef.hpp>
#include <boost/crypt/utility/null.hpp>

namespace boost {
namespace crypt {
namespace aes {

BOOST_CRYPT_INLINE_CONSTEXPR boost::crypt::array<boost::crypt::uint8_t, 256> sbox = {
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

BOOST_CRYPT_INLINE_CONSTEXPR boost::crypt::array<boost::crypt::uint8_t, 11> Rcon = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

template <boost::crypt::size_t Nr>
class cipher
{
private:

    static constexpr boost::crypt::size_t Nb {4}; // Block size
    static constexpr boost::crypt::size_t Nk {Nr == 10 ? 4 :
                                              Nr == 12 ? 6 :
                                              Nr == 14 ? 8 : 0}; // Key length in 32-bit words

    static_assert(Nk != 0, "Invalid key length");

    static constexpr boost::crypt::size_t key_expansion_size {Nr == 10 ? 176 :
                                                              Nr == 12 ? 208 :
                                                              Nr == 14 ? 240 : 0};

    boost::crypt::array<boost::crypt::array<boost::crypt::uint8_t, Nb>, Nb> state {};
    boost::crypt::array<boost::crypt::uint8_t, key_expansion_size> round_key {};

    BOOST_CRYPT_GPU_ENABLED constexpr auto rot_word(boost::crypt::array<boost::crypt::uint8_t, 4>& temp) noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto sub_word(boost::crypt::array<boost::crypt::uint8_t, 4>& temp) noexcept -> void;

    template <typename ForwardIterator>
    BOOST_CRYPT_GPU_ENABLED constexpr auto key_expansion(ForwardIterator key, boost::crypt::size_t) noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto sub_bytes() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto shift_rows() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto xtimes(boost::crypt::uint8_t b) noexcept -> boost::crypt::uint8_t;

    BOOST_CRYPT_GPU_ENABLED constexpr auto mix_columns() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto add_round_key(boost::crypt::uint8_t round) noexcept -> void;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto cipher_impl(ForwardIter buffer) noexcept -> void;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto encrypt_impl(ForwardIter buffer, boost::crypt::size_t buffer_size, const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::ecb>&) noexcept -> void;

public:

    BOOST_CRYPT_GPU_ENABLED constexpr cipher() noexcept = default;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr cipher(ForwardIter key, boost::crypt::size_t key_length) noexcept { init(key, key_length); }
    
    #ifdef BOOST_CRYPT_HAS_CXX20_CONSTEXPR
    BOOST_CRYPT_GPU_ENABLED constexpr ~cipher() noexcept { destroy(); }
    #endif

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(ForwardIter key, boost::crypt::size_t key_length) noexcept -> boost::crypt::state;

    template <boost::crypt::aes::cipher_mode mode, typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto encrypt(ForwardIter data, boost::crypt::size_t data_length = Nk) noexcept -> boost::crypt::state;

    BOOST_CRYPT_GPU_ENABLED constexpr auto destroy() noexcept;
};

template <boost::crypt::size_t Nr>
template <typename ForwardIter>
constexpr auto cipher<Nr>::init(ForwardIter key, boost::crypt::size_t key_length) noexcept -> boost::crypt::state
{
    if (utility::is_null(key))
    {
        return state::null;
    }
    else if (key_length < Nk)
    {
        return state::insufficient_key_length;
    }

    key_expansion(key, key_length);
    return state::success;
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter>
constexpr auto cipher<Nr>::cipher_impl(ForwardIter buffer) noexcept -> void
{
    // Write the buffer to state and then perform operations
    boost::crypt::ptrdiff_t offset {};
    for (boost::crypt::size_t i {}; i < Nb; ++i)
    {
        for (boost::crypt::size_t j {}; j < Nb; ++j)
        {
            state[i][j] = static_cast<boost::crypt::uint8_t>(buffer[offset++]);
        }
    }

    boost::crypt::uint8_t round {};

    add_round_key(round);

    for (round = static_cast<boost::crypt::uint8_t>(1); round < static_cast<boost::crypt::uint8_t>(Nr); ++round)
    {
        sub_bytes();
        shift_rows();
        mix_columns();
        add_round_key(round);
    }

    BOOST_CRYPT_ASSERT(round == Nr);
    sub_bytes();
    shift_rows();
    add_round_key(Nr);

    // Write the cipher text back
    offset = 0U;
    for (boost::crypt::size_t i {}; i < Nb; ++i)
    {
        for (boost::crypt::size_t j {}; j < Nb; ++j)
        {
            buffer[offset++] = static_cast<boost::crypt::uint8_t>(state[i][j]);
        }
    }
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter>
constexpr auto cipher<Nr>::encrypt_impl(ForwardIter buffer, boost::crypt::size_t buffer_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::ecb>&) noexcept -> void
{
    constexpr auto state_complete_size {Nb * Nb};
    while (buffer_size >= state_complete_size)
    {
        cipher_impl(buffer);
        buffer_size -= state_complete_size;
        buffer += static_cast<boost::crypt::ptrdiff_t>(state_complete_size);
    }
}

template <boost::crypt::size_t Nr>
template <boost::crypt::aes::cipher_mode mode, typename ForwardIter>
constexpr auto cipher<Nr>::encrypt(ForwardIter data, boost::crypt::size_t data_length) noexcept -> boost::crypt::state
{
    if (utility::is_null(data) || data_length == 0U)
    {
        return state::null;
    }

    encrypt_impl(data, data_length, boost::crypt::integral_constant<aes::cipher_mode, mode>{});
    return state::success;
}

template <boost::crypt::size_t Nr>
constexpr auto cipher<Nr>::destroy() noexcept
{
    for (auto& line : state)
    {
        for (auto& byte : line)
        {
            byte = static_cast<boost::crypt::uint8_t>(0x00);
        }
    }
    round_key.fill(0x00);
}

// The transformation of words in which the four bytes of the word
// are permuted cyclically.
template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::rot_word(boost::crypt::array<boost::crypt::uint8_t, 4>& temp) noexcept -> void
{
    const auto temp0 {temp[0]};
    temp[0] = temp[1];
    temp[1] = temp[2];
    temp[2] = temp[3];
    temp[3] = temp0;
}

// The transformation of words in which the S-box is applied to each
// of the four bytes of the word.
template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::sub_word(boost::crypt::array<boost::crypt::uint8_t, 4>& temp) noexcept -> void
{
    temp[0] = sbox[temp[0]];
    temp[1] = sbox[temp[1]];
    temp[2] = sbox[temp[2]];
    temp[3] = sbox[temp[3]];
}

// The routine that generates the round keys from the key.
template <boost::crypt::size_t Nr>
template <typename ForwardIterator>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::key_expansion(ForwardIterator key, boost::crypt::size_t) noexcept -> void
{
    boost::crypt::array<boost::crypt::uint8_t, 4> temp {};

    for (boost::crypt::size_t i {}; i < Nk; ++i)
    {
        const auto k {i * 4U};
        round_key[k + 0U] = key[k + 0U];
        round_key[k + 1U] = key[k + 1U];
        round_key[k + 2U] = key[k + 2U];
        round_key[k + 3U] = key[k + 3U];
    }

    for (boost::crypt::size_t i {Nk}; i < Nb * (Nr + 1); ++i)
    {
        const auto k {(i - 1) * 4U};
        temp[0] = round_key[k + 0U];
        temp[1] = round_key[k + 1U];
        temp[2] = round_key[k + 2U];
        temp[3] = round_key[k + 3U];

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
        round_key[j + 0U] = round_key[l + 0U] ^ temp[0];
        round_key[j + 1U] = round_key[l + 1U] ^ temp[1];
        round_key[j + 2U] = round_key[l + 2U] ^ temp[2];
        round_key[j + 3U] = round_key[l + 3U] ^ temp[3];
    }
}

// The transformation of the state that applies the S-box independently
// to each byte of the state.
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

// The transformation of the state in which the last three rows are
// cyclically shifted by different offsets.
template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::shift_rows() noexcept -> void
{
    boost::crypt::uint8_t temp {};

    temp        = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = temp;

    temp        = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp        = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    temp        = state[0][3];
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = temp;
}

// The transformation of bytes in which the polynomial representation
// of the input byte is multiplied by x, modulo m(x), to produce the
// polynomial representation of the output byte.
template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::xtimes(boost::crypt::uint8_t b) noexcept -> boost::crypt::uint8_t
{
    return static_cast<boost::crypt::uint8_t>(static_cast<boost::crypt::uint8_t>(b << 1U) ^ static_cast<boost::crypt::uint8_t>(((b >> 7U) & 1U) * 0x1BU));
}

// The transformation of the state that takes all of the columns of the
// state and mixes their data (independently of one another) to produce
// new columns.
template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::mix_columns() noexcept -> void
{
    for (auto& column : state)
    {
        const auto s0 {column[0]};
        const auto all_c {static_cast<boost::crypt::uint8_t>(column[0] ^ column[1] ^ column[2] ^ column[3])};

        // s'_0,c = ({02} * s_0,c) ^ ({03} * s_1,c) ^ s_2,c ^ s_3,c
        auto temp  {static_cast<boost::crypt::uint8_t>(column[0] ^ column[1])};
        temp = xtimes(temp);
        column[0] ^= temp ^ all_c;

        // s'_1,c = s_0,c ^ ({02} * s_1,c) ^ ({03} * s_2,c) ^ s_3,c
        temp = static_cast<boost::crypt::uint8_t>(column[1] ^ column[2]);
        temp = xtimes(temp);
        column[1] ^= temp ^ all_c;

        // s`_2,c = s_0,c ^ s_1,c ^ ({02} * s_2,c) ^ ({03} * s_3,c)
        temp = static_cast<boost::crypt::uint8_t>(column[2] ^ column[3]);
        temp = xtimes(temp);
        column[2] ^= temp ^ all_c;

        // s`_3,c = ({03} * s_0,c) ^ s_1,c ^ s_2,c ^ ({02} * s_3,c)
        temp = static_cast<boost::crypt::uint8_t>(column[3] ^ s0);
        temp = xtimes(temp);
        column[3] ^= temp ^ all_c ;
    }
}

// The transformation of the state in which a round key is combined
// with the state.
template <boost::crypt::size_t Nr>
constexpr auto cipher<Nr>::add_round_key(boost::crypt::uint8_t round) noexcept -> void
{
    for (boost::crypt::size_t i {}; i < Nb; ++i)
    {
        for (boost::crypt::size_t j {}; j < Nb; ++j)
        {
            const auto round_key_value {round_key[(round * Nb * 4U) + (i * Nb) + j]};
            state[i][j] ^= round_key_value;
        }
    }
}

} // namespace aes
} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_AES_DETAIL_CIPHER_HPP
