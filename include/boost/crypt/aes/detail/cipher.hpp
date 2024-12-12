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

BOOST_CRYPT_INLINE_CONSTEXPR boost::crypt::array<boost::crypt::uint8_t, 256> rsbox = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
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

    static constexpr boost::crypt::size_t state_total_size {Nb * Nb};
    boost::crypt::array<boost::crypt::array<boost::crypt::uint8_t, Nb>, Nb> state {};
    boost::crypt::array<boost::crypt::uint8_t, key_expansion_size> round_key {};
    boost::crypt::array<boost::crypt::uint8_t, state_total_size> current_iv {};
    bool initialized {false};
    bool initial_iv {false};

    BOOST_CRYPT_GPU_ENABLED constexpr auto rot_word(boost::crypt::array<boost::crypt::uint8_t, 4>& temp) noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto sub_word(boost::crypt::array<boost::crypt::uint8_t, 4>& temp) noexcept -> void;

    template <typename ForwardIterator>
    BOOST_CRYPT_GPU_ENABLED constexpr auto key_expansion(ForwardIterator key, boost::crypt::size_t) noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto sub_bytes() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto inv_sub_bytes() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto shift_rows() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto inv_shift_rows() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto xtimes(boost::crypt::uint8_t b) noexcept -> boost::crypt::uint8_t;

    BOOST_CRYPT_GPU_ENABLED constexpr auto mix_columns() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto gf28_multiply(boost::crypt::uint8_t x, boost::crypt::uint8_t y) noexcept -> boost::crypt::uint8_t;

    BOOST_CRYPT_GPU_ENABLED constexpr auto inv_mix_columns() noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED constexpr auto add_round_key(boost::crypt::uint8_t round) noexcept -> void;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto cipher_impl(ForwardIter buffer) noexcept -> void;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto inv_cipher_impl(ForwardIter buffer) noexcept -> void;

    template <boost::crypt::size_t cfb_size, typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generic_cfb_encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                                    ForwardIter2 iv, boost::crypt::size_t iv_size) noexcept -> void;

    template <boost::crypt::size_t cfb_size, typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto generic_cfb_decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                                    ForwardIter2 iv, boost::crypt::size_t iv_size) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2, boost::crypt::size_t,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::ecb>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::cbc>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::ofb>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::ctr>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::cfb8>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::cfb64>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::cfb128>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2, boost::crypt::size_t,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::ecb>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::cbc>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::ofb>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::ctr>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::cfb8>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::cfb64>&) noexcept -> void;

    template <typename ForwardIter1, typename ForwardIter2>
    BOOST_CRYPT_GPU_ENABLED constexpr auto decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                                        const boost::crypt::integral_constant<aes::cipher_mode, aes::cipher_mode::cfb128>&) noexcept -> void;

public:

    BOOST_CRYPT_GPU_ENABLED constexpr cipher() noexcept = default;

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr cipher(ForwardIter key, boost::crypt::size_t key_length) noexcept { init(key, key_length); }
    
    #ifdef BOOST_CRYPT_HAS_CXX20_CONSTEXPR
    BOOST_CRYPT_GPU_ENABLED constexpr ~cipher() noexcept { destroy(); }
    #endif

    template <typename ForwardIter>
    BOOST_CRYPT_GPU_ENABLED constexpr auto init(ForwardIter key, boost::crypt::size_t key_length) noexcept -> boost::crypt::state;

    template <boost::crypt::aes::cipher_mode mode, typename ForwardIter1, typename ForwardIter2 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto encrypt(ForwardIter1 data, boost::crypt::size_t data_length = Nk,
                                                   ForwardIter2 iv = nullptr, boost::crypt::size_t iv_length = 0U) noexcept -> boost::crypt::state;

    template <boost::crypt::aes::cipher_mode mode, typename ForwardIter1, typename ForwardIter2 = boost::crypt::uint8_t*>
    BOOST_CRYPT_GPU_ENABLED constexpr auto decrypt(ForwardIter1 data, boost::crypt::size_t data_length = Nk,
                                                   ForwardIter2 iv = nullptr, boost::crypt::size_t iv_length = 0U) noexcept -> boost::crypt::state;

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
    initialized = true;
    return state::success;
}

#if defined(__GNUC__) && __GNUC__ >= 5
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wsign-conversion"
#elif defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wsign-conversion"
#endif

template <boost::crypt::size_t Nr>
template <boost::crypt::size_t cfb_size, typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::generic_cfb_encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                    ForwardIter2 iv, boost::crypt::size_t iv_size) noexcept -> void
{
    static_assert(cfb_size == 1 || cfb_size == 8 || cfb_size == 16, "Only CFB8, 64, and 128 are supported");

    // In CFB modes
    // I1 = IV
    // I_j = LSB_b-s(I_j-1) | C#_j-1    for j = 2, 3, ..., n
    // O_j = CIPH_k(I_j)                for j = 1, 2, ..., n
    // C#_j = P#_j xor MSB_s(O_j)       for j = 1, 2, ..., n

    // Make an initial copy of the IV
    if (iv_size >= current_iv.size())
    {
        for (boost::crypt::size_t i {}; i < current_iv.size(); ++i)
        {
            current_iv[i] = iv[i];
        }
    }

    auto iv_copy {current_iv};
    while (buffer_size)
    {
        const auto iv_imin1 {iv_copy};
        cipher_impl(iv_copy.begin());

        for (boost::crypt::size_t i {}; i < cfb_size; ++i)
        {
            buffer[i] ^= iv_copy[i];
        }

        // We now need (b-s) bits of IV | s bits of cipher text
        // First we shift the values in iv_copy and then add in the contents of the buffer
        for (boost::crypt::size_t i {}; i < iv_copy.size() - cfb_size; ++i)
        {
            iv_copy[i] = iv_imin1[i + cfb_size];
        }
        for (boost::crypt::size_t i {iv_copy.size() - cfb_size}, buffer_i {}; i < iv_copy.size(); ++i, ++buffer_i)
        {
            iv_copy[i] = buffer[buffer_i];
        }

        buffer_size -= cfb_size;
        buffer += cfb_size;
    }

    // Store the last block for MCT mode
    current_iv = iv_copy;
}

template <boost::crypt::size_t Nr>
template <boost::crypt::size_t cfb_size, typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::generic_cfb_decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                                    ForwardIter2 iv, boost::crypt::size_t iv_size) noexcept -> void
{
    static_assert(cfb_size == 1 || cfb_size == 8 || cfb_size == 16, "Only CFB8, 64, and 128 are supported");

    // CFB Decryption
    // I1 = IV
    // I_j = LSB_b-s(I_j-1) | C#_j-1    for j = 2, 3, ..., n
    // O_j = CIPH_k(I_j)                for j = 1, 2, ..., n
    // P#_j = C#_j xor MSB_s(O_j)       for j = 1, 2, ..., n

    if (iv_size >= current_iv.size())
    {
        // Make an initial copy of the IV
        for (boost::crypt::size_t i {}; i < current_iv.size(); ++i)
        {
            current_iv[i] = iv[i];
        }
    }

    auto iv_copy {current_iv};
    auto iv_min1 {iv_copy};
    cipher_impl(iv_copy.begin());

    boost::crypt::array<boost::crypt::uint8_t, cfb_size> carried_byte {};

    while (buffer_size)
    {
        for (boost::crypt::size_t i {}; i < cfb_size; ++i)
        {
            carried_byte[i] = buffer[i];
        }

        for (boost::crypt::size_t i {}; i < cfb_size; ++i)
        {
            buffer[i] ^= iv_copy[i];
        }

        for (boost::crypt::size_t i {}; i < current_iv.size() - cfb_size; ++i)
        {
            iv_copy[i] = iv_min1[i + cfb_size];
        }
        for (boost::crypt::size_t i {current_iv.size() - cfb_size}, buffer_i {}; i < current_iv.size(); ++i, ++buffer_i)
        {
            iv_copy[i] = carried_byte[buffer_i];
        }

        iv_min1 = iv_copy;
        cipher_impl(iv_copy.begin());

        buffer_size -= cfb_size;
        buffer += cfb_size;
    }

    current_iv = iv_min1;
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
    add_round_key(round);

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
constexpr auto cipher<Nr>::inv_cipher_impl(ForwardIter buffer) noexcept -> void
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

    boost::crypt::uint8_t round {Nr};

    add_round_key(round);

    for (--round; round > 0; --round)
    {
        inv_shift_rows();
        inv_sub_bytes();
        add_round_key(round);
        inv_mix_columns();
    }

    BOOST_CRYPT_ASSERT(round == 0);
    inv_shift_rows();
    inv_sub_bytes();
    add_round_key(round);

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
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size, ForwardIter2, boost::crypt::size_t,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::ecb>&) noexcept -> void
{
    while (buffer_size >= state_total_size)
    {
        cipher_impl(buffer);
        buffer_size -= state_total_size;
        buffer += static_cast<boost::crypt::ptrdiff_t>(state_total_size);
    }
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::cbc>&) noexcept -> void
{
    // In CBC mode:
    // C1 = CIPH_k(P1 xor IV)
    // Cj = CIPH_k(P_j xor C_j-1)
    const auto initial_buffer_size {buffer_size};
    const auto initial_buffer {buffer};

    if (iv_size != 0U)
    {
        initial_iv = true;
        BOOST_CRYPT_ASSERT(iv_size >= state_total_size);
        for (boost::crypt::size_t i {}; i < state_total_size; ++i)
        {
            current_iv[i] = iv[i];
        }
    }

    for (boost::crypt::size_t i {}; i < state_total_size; ++i)
    {
        buffer[i] ^= current_iv[i];
    }

    cipher_impl(buffer);
    buffer_size -= state_total_size;

    while (buffer_size >= state_total_size)
    {
        for (boost::crypt::size_t i {}; i < state_total_size; ++i)
        {
            buffer[state_total_size + i] ^= buffer[i];
        }

        buffer += static_cast<boost::crypt::ptrdiff_t>(state_total_size);
        cipher_impl(buffer);
        buffer_size -= state_total_size;
    }

    // Cache the value of IV for the next round
    // Need to get the values from the end of the buffer
    for (boost::crypt::size_t i {}; i < current_iv.size(); ++i)
    {
        const auto offset {initial_buffer_size - buffer_size - state_total_size + i};
        current_iv[i] = initial_buffer[offset];
    }
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::ofb>&) noexcept -> void
{
    // In OFB mode:
    // I_1 = IV
    // I_j = O_j-1
    // O_j = CIPH_k(I_j)
    // C_j* = P_j xor O_j
    // C*_n = P*_n xor MSB_u(O_n)

    // Make an initial copy of the IV
    if (iv_size >= current_iv.size())
    {
        for (boost::crypt::size_t i {}; i < current_iv.size(); ++i)
        {
            current_iv[i] = iv[i];
        }
    }

    while (buffer_size >= state_total_size)
    {
        cipher_impl(current_iv.begin());

        // We now have two paths, ciphered IV goes to generate the next block and gets xored with current block
        // to recover the C1
        for (boost::crypt::size_t i {}; i < current_iv.size(); ++i)
        {
            // Generate the ciphertext
            buffer[i] ^= current_iv[i];
        }

        buffer += state_total_size;
        buffer_size -= state_total_size;
    }
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::ctr>&) noexcept -> void
{
    // In CTR mode:
    // O_j = CIPH_k(T_j)
    // C_j* = P_j xor O_j
    // C*_n = P*_n xor MSB_u(O_n)

    // Make an initial copy of the IV
    if (iv_size >= current_iv.size())
    {
        for (boost::crypt::size_t i {}; i < current_iv.size(); ++i)
        {
            current_iv[i] = iv[i];
        }
    }

    while (buffer_size >= state_total_size)
    {
        auto iv_copy {current_iv};
        cipher_impl(iv_copy.begin());

        for (boost::crypt::size_t i {}; i < iv_copy.size(); ++i)
        {
            // Generate the ciphertext
            buffer[i] ^= iv_copy[i];
        }

        // The increment function is just bignum addition
        for (boost::crypt::size_t i {current_iv.size()}; i <= 0; --i)
        {
            if (current_iv[i] != static_cast<boost::crypt::uint8_t>(0xFF))
            {
                current_iv[i] += static_cast<boost::crypt::uint8_t>(1);
                break;
            }
            else
            {
                current_iv[i] = static_cast<boost::crypt::uint8_t>(0x00);
            }
        }

        buffer += state_total_size;
        buffer_size -= state_total_size;
    }

    // We should not be reusing information
    current_iv.fill(0x00);
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::cfb8>&) noexcept -> void
{
    generic_cfb_encrypt_impl<1>(buffer, buffer_size, iv, iv_size);
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::cfb64>&) noexcept -> void
{
    generic_cfb_encrypt_impl<8>(buffer, buffer_size, iv, iv_size);
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::encrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::cfb128>&) noexcept -> void
{
    generic_cfb_encrypt_impl<16>(buffer, buffer_size, iv, iv_size);
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size, ForwardIter2, boost::crypt::size_t,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::ecb>&) noexcept -> void
{
    while (buffer_size >= state_total_size)
    {
        inv_cipher_impl(buffer);
        buffer_size -= state_total_size;
        buffer += static_cast<boost::crypt::ptrdiff_t>(state_total_size);
    }
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::cbc>&) noexcept -> void
{
    // In CBC mode:
    // P_1 = CIPHInv_K(C_1) xor IV
    // P_J = CIPHInv_K(C_j) xor C_j-1
    //
    // Therefore we need to carry forward 2 different blocks at the same time
    
    boost::crypt::array<boost::crypt::uint8_t, state_total_size> carry_forward_1 {};
    boost::crypt::array<boost::crypt::uint8_t, state_total_size> carry_forward_2 {};

    for (boost::crypt::size_t i {}; i < carry_forward_1.size(); ++i)
    {
        carry_forward_1[i] = buffer[i];
    }

    inv_cipher_impl(buffer);

    // We need to capture the initial iv if we have not done so already
    // This is carried state such as in the CAVS MCT testing
    if (iv_size != 0U)
    {
        initial_iv = true;
        BOOST_CRYPT_ASSERT(iv_size >= current_iv.size());
        for (boost::crypt::size_t i {}; i < current_iv.size(); ++i)
        {
            current_iv[i] = iv[i];
        }
    }

    for (boost::crypt::size_t i {}; i < current_iv.size(); ++i)
    {
        buffer[i] ^= current_iv[i];
    }

    buffer_size -= state_total_size;
    buffer += static_cast<boost::crypt::ptrdiff_t>(state_total_size);

    boost::crypt::size_t counter {};
    while (buffer_size >= state_total_size)
    {
        if (counter & 1U)
        {
            for (boost::crypt::size_t i {}; i < carry_forward_1.size(); ++i)
            {
                carry_forward_1[i] = buffer[i];
            }
        }
        else
        {
            for (boost::crypt::size_t i {}; i < carry_forward_2.size(); ++i)
            {
                carry_forward_2[i] = buffer[i];
            }
        }

        inv_cipher_impl(buffer);

        if (counter & 1U)
        {
            for (boost::crypt::size_t i {}; i < carry_forward_2.size(); ++i)
            {
                buffer[i] ^= carry_forward_2[i];
            }
        }
        else
        {
            for (boost::crypt::size_t i {}; i < carry_forward_1.size(); ++i)
            {
                buffer[i] ^= carry_forward_1[i];
            }
        }

        ++counter;
        buffer_size -= state_total_size;
        buffer += static_cast<boost::crypt::ptrdiff_t>(state_total_size);
    }

    // Store the next carry in case the caller is doing discontinuous decryption
    if (counter & 1U)
    {
        current_iv = carry_forward_2;
    }
    else
    {
        current_iv = carry_forward_1;
    }
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::ofb>&) noexcept -> void
{
    // OFB decryption:
    // I_1 = IV
    // I_j = O_j-1
    // O_j = CIPH_k(I_j)
    // P_j* = C_j xor O_j
    // P_n = C*_n xor MSB_u(O_n)

    if (iv_size >= current_iv.size())
    {
        // Make an initial copy of the IV
        for (boost::crypt::size_t i {}; i < current_iv.size(); ++i)
        {
            current_iv[i] = iv[i];
        }
    }

    while (buffer_size >= state_total_size)
    {
        cipher_impl(current_iv.begin());

        // We now have two paths, ciphered IV goes to generate the next block and gets xored with current block
        // to recover the C1
        for (boost::crypt::size_t i {}; i < current_iv.size(); ++i)
        {
            // Recover the plaintext
            buffer[i] ^= current_iv[i];
        }

        buffer += state_total_size;
        buffer_size -= state_total_size;
    }
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::ctr>&) noexcept -> void
{
    // CTR encrypt and decrypt is a symmetric operation
    encrypt_impl(buffer, buffer_size, iv, iv_size, integral_constant<aes::cipher_mode, aes::cipher_mode::ctr>{});
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::cfb8>&) noexcept -> void
{
    generic_cfb_decrypt_impl<1>(buffer, buffer_size, iv, iv_size);
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::cfb64>&) noexcept -> void
{
    generic_cfb_decrypt_impl<8>(buffer, buffer_size, iv, iv_size);
}

template <boost::crypt::size_t Nr>
template <typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::decrypt_impl(ForwardIter1 buffer, boost::crypt::size_t buffer_size,
                                        ForwardIter2 iv, boost::crypt::size_t iv_size,
                                        const integral_constant<aes::cipher_mode, aes::cipher_mode::cfb128>&) noexcept -> void
{
    generic_cfb_decrypt_impl<16>(buffer, buffer_size, iv, iv_size);
}

#if defined(__GNUC__) && __GNUC__ >= 5
#  pragma GCC diagnostic pop
#elif defined(__clang__)
#  pragma clang diagnostic pop
#endif

template <boost::crypt::size_t Nr>
template <boost::crypt::aes::cipher_mode mode, typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::encrypt(ForwardIter1 data, boost::crypt::size_t data_length,
                                   ForwardIter2 iv, boost::crypt::size_t iv_length) noexcept -> boost::crypt::state
{
    if (utility::is_null(data) || data_length == 0U)
    {
        return state::null;
    }
    else if (!initialized)
    {
        return state::uninitialized;
    }

    #if defined(_MSC_VER)
    #  pragma warning( push )
    #  pragma warning( disable : 4127 ) // Conditional expression is constant (which is true before C++17 in BOOST_CRYPT_IF_CONSTEXPR)
    #endif

    BOOST_CRYPT_IF_CONSTEXPR (mode != aes::cipher_mode::ecb)
    {
        if ((utility::is_null(iv) || iv_length == 0U) && !initial_iv)
        {
            return state::null;
        }
        else if (iv_length < state_total_size)
        {
            if (!initial_iv)
            {
                return state::insufficient_key_length;
            }
            else
            {
                iv_length = 0;
            }
        }
    }

    #if defined(_MSC_VER)
    #  pragma warning( pop )
    #endif

    encrypt_impl(data, data_length, iv, iv_length, boost::crypt::integral_constant<aes::cipher_mode, mode>{});
    return state::success;
}

template <boost::crypt::size_t Nr>
template <boost::crypt::aes::cipher_mode mode, typename ForwardIter1, typename ForwardIter2>
constexpr auto cipher<Nr>::decrypt(ForwardIter1 data, boost::crypt::size_t data_length,
                                   ForwardIter2 iv, boost::crypt::size_t iv_length) noexcept -> boost::crypt::state
{
    if (utility::is_null(data) || data_length == 0U)
    {
        return state::null;
    }
    else if (!initialized)
    {
        return state::uninitialized;
    }

    #if defined(_MSC_VER)
    #  pragma warning( push )
    #  pragma warning( disable : 4127 ) // Conditional expression is constant (which is true before C++17 in BOOST_CRYPT_IF_CONSTEXPR)
    #endif

    BOOST_CRYPT_IF_CONSTEXPR (mode != aes::cipher_mode::ecb)
    {
        if ((utility::is_null(iv) || iv_length == 0U) && !initial_iv)
        {
            return state::null;
        }
        else if (iv_length < state_total_size)
        {
            if (!initial_iv)
            {
                return state::insufficient_key_length;
            }
            else
            {
                iv_length = 0;
            }
        }
    }

    #if defined(_MSC_VER)
    #  pragma warning( pop )
    #endif

    decrypt_impl(data, data_length, iv, iv_length, boost::crypt::integral_constant<aes::cipher_mode, mode>{});
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
    initialized = false;
    current_iv.fill(0x00);
    initial_iv = false;
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

    // Since we take pointers or iterators the sign of the offset can be incorrect
    #if defined(__GNUC__) && __GNUC__ >= 5
    #  pragma GCC diagnostic push
    #  pragma GCC diagnostic ignored "-Wconversion"
    #  pragma GCC diagnostic ignored "-Wsign-conversion"
    #elif defined(__clang__)
    #  pragma clang diagnostic push
    #  pragma clang diagnostic ignored "-Wsign-conversion"
    #elif defined(_MSC_VER)
    #  pragma warning( push )
    #  pragma warning( disable : 4127 ) // Conditional expression is constant (which is true before C++17 in BOOST_CRYPT_IF_CONSTEXPR)
    #endif

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

    #if defined(__GNUC__) && __GNUC__ >= 5
    #  pragma GCC diagnostic pop
    #elif defined(__clang__)
    #  pragma clang diagnostic pop
    #elif defined(_MSC_VER)
    #  pragma warning( pop )
    #endif
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

// The inverse of sub_bytes (above), in which rsbox is applied to each byte
template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::inv_sub_bytes() noexcept -> void
{
    for (auto& line : state)
    {
        for (auto& val : line)
        {
            val = rsbox[val];
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

// inv_shift_rows in the inverse of shift rows (above).
// In particular, the bytes in the last three rows of the state are shifted cyclically
//
// s'_r,c = s_r,(c-r) mod 4 for 0 <= r < 4 and 0 <= c < 4
template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::inv_shift_rows() noexcept -> void
{
    boost::crypt::uint8_t temp {};

    temp        = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = temp;

    temp        = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp        = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    temp        = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = temp;
}

// The transformation of bytes in which the polynomial representation
// of the input byte is multiplied by x, modulo m(x), to produce the
// polynomial representation of the output byte.
template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::xtimes(boost::crypt::uint8_t b) noexcept -> boost::crypt::uint8_t
{
    #if defined(__GNUC__) && __GNUC__ >= 7 && __GNUC__ <= 9
    #  pragma GCC diagnostic push
    #  pragma GCC diagnostic ignored "-Wsign-conversion"
    #endif

    return static_cast<boost::crypt::uint8_t>(static_cast<boost::crypt::uint8_t>(b << 1U) ^ static_cast<boost::crypt::uint8_t>(((b >> 7U) & 1U) * 0x1BU));

    #if defined(__GNUC__) && __GNUC__ >= 7 && __GNUC__ <= 9
    #  pragma GCC diagnostic pop
    #endif
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

template <boost::crypt::size_t Nr>
constexpr auto cipher<Nr>::gf28_multiply(boost::crypt::uint8_t x, boost::crypt::uint8_t y) noexcept -> boost::crypt::uint8_t
{
    #if defined(__GNUC__) && __GNUC__ >= 7 && __GNUC__ <= 9
    #  pragma GCC diagnostic push
    #  pragma GCC diagnostic ignored "-Wsign-conversion"
    #endif

    return static_cast<boost::crypt::uint8_t>(
            ((y & 1U) * x) ^
            ((y >> 1U & 1U) * xtimes(x)) ^
            ((y >> 2U & 1U) * xtimes(xtimes(x))) ^
            ((y >> 3U & 1U) * xtimes(xtimes(xtimes(x)))) ^
            ((y >> 4U & 1U) * xtimes(xtimes(xtimes(xtimes(x)))))
            );

    #if defined(__GNUC__) && __GNUC__ >= 7 && __GNUC__ <= 9
    #  pragma GCC diagnostic pop
    #endif
}

template <boost::crypt::size_t Nr>
BOOST_CRYPT_GPU_ENABLED constexpr auto cipher<Nr>::inv_mix_columns() noexcept -> void
{
    for (auto& column : state)
    {
        const auto s0 {column[0]};
        const auto s1 {column[1]};
        const auto s2 {column[2]};
        const auto s3 {column[3]};

        // s'_0,c = ({0e} * s_0,c) ^ ({0b} * s_1,c) ^ ({0d} * s_2,c) ^ ({09} * s_3,c)
        column[0] = gf28_multiply(s0, 0x0e) ^ gf28_multiply(s1, 0x0b) ^ gf28_multiply(s2, 0x0d) ^ gf28_multiply(s3, 0x09);

        // s'_1,c = ({09} * s_0,c) ^ ({0e} * s_1,c) ^ ({0b} * s_2,c) ^ ({0d} * s_3,c)
        column[1] = gf28_multiply(s0, 0x09) ^ gf28_multiply(s1, 0x0e) ^ gf28_multiply(s2, 0x0b) ^ gf28_multiply(s3, 0x0d);

        // s`_2,c = ({0d} * s_0,c) ^ ({09} * s_1,c) ^ ({0e} * s_2,c) ^ ({0b} * s_3,c)
        column[2] = gf28_multiply(s0, 0x0d) ^ gf28_multiply(s1, 0x09) ^ gf28_multiply(s2, 0x0e) ^ gf28_multiply(s3, 0x0b);

        // s`_3,c = ({0b} * s_0,c) ^ ({0d} * s_1,c) ^ ({09} * s_2,c) ^ ({0e} * s_3,c)
        column[3] = gf28_multiply(s0, 0x0b) ^ gf28_multiply(s1, 0x0d) ^ gf28_multiply(s2, 0x09) ^ gf28_multiply(s3, 0x0e);
    }
}

// The transformation of the state in which a round key is combined
// with the state.
//
// Add round_key is its own inverse so there is no separate inverse function
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
