// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc6234
// See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=31

#ifndef BOOST_CRYPT2_HASH_DETAIL_SHA512_BASE_HPP
#define BOOST_CRYPT2_HASH_DETAIL_SHA512_BASE_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/state.hpp>

namespace boost::crypt::hash_detail {

template <compat::size_t digest_size>
class sha512_base final
{
public:

    static constexpr compat::size_t block_size {128U};

private:

    static_assert(digest_size == 28U || digest_size == 32U || digest_size == 48U || digest_size == 64U,
                  "Digest size must be 28 (SHA512/224), 32 (SHA512/256), 48 (SHA384), or 64 (SHA512)");

    compat::array<compat::uint64_t, 8U> intermediate_hash_ {};
    compat::array<compat::byte, 128U> buffer_ {};
    compat::size_t buffer_index_ {};
    compat::uint64_t low_ {};
    compat::uint64_t high_ {};
    bool computed_ {};
    bool corrupted_ {};

public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha512_base() noexcept { init(); }

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init() noexcept -> void;
};

template <compat::size_t digest_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha512_base<digest_size>::init() noexcept -> void
{
    intermediate_hash_.fill(0ULL);
    buffer_.fill(compat::byte{});
    buffer_index_ = 0U;
    low_ = 0ULL;
    high_ = 0ULL;
    computed_ = false;
    corrupted_ = false;

    if constexpr (digest_size == 28U)
    {
        // Constants for SHA512/224
        intermediate_hash_[0] = 0x8C3D37C819544DA2ULL;
        intermediate_hash_[1] = 0x73E1996689DCD4D6ULL;
        intermediate_hash_[2] = 0x1DFAB7AE32FF9C82ULL;
        intermediate_hash_[3] = 0x679DD514582F9FCFULL;
        intermediate_hash_[4] = 0x0F6D2B697BD44DA8ULL;
        intermediate_hash_[5] = 0x77E36F7304C48942ULL;
        intermediate_hash_[6] = 0x3F9D85A86A1D36C8ULL;
        intermediate_hash_[7] = 0x1112E6AD91D692A1ULL;
    }
    else if constexpr (digest_size == 32U)
    {
        // Constants for SHA512/256
        intermediate_hash_[0] = 0x22312194FC2BF72CULL;
        intermediate_hash_[1] = 0x9F555FA3C84C64C2ULL;
        intermediate_hash_[2] = 0x2393B86B6F53B151ULL;
        intermediate_hash_[3] = 0x963877195940EABDULL;
        intermediate_hash_[4] = 0x96283EE2A88EFFE3ULL;
        intermediate_hash_[5] = 0xBE5E1E2553863992ULL;
        intermediate_hash_[6] = 0x2B0199FC2C85B8AAULL;
        intermediate_hash_[7] = 0x0EB72DDC81C52CA2ULL;
    }
    else if constexpr (digest_size == 48U)
    {
        // Constants for SHA384
        intermediate_hash_[0] = 0xcbbb9d5dc1059ed8ULL;
        intermediate_hash_[1] = 0x629a292a367cd507ULL;
        intermediate_hash_[2] = 0x9159015a3070dd17ULL;
        intermediate_hash_[3] = 0x152fecd8f70e5939ULL;
        intermediate_hash_[4] = 0x67332667ffc00b31ULL;
        intermediate_hash_[5] = 0x8eb44a8768581511ULL;
        intermediate_hash_[6] = 0xdb0c2e0d64f98fa7ULL;
        intermediate_hash_[7] = 0x47b5481dbefa4fa4ULL;
    }
    else
    {
        // Constants for SHA512
        intermediate_hash_[0] = 0x6a09e667f3bcc908ULL;
        intermediate_hash_[1] = 0xbb67ae8584caa73bULL;
        intermediate_hash_[2] = 0x3c6ef372fe94f82bULL;
        intermediate_hash_[3] = 0xa54ff53a5f1d36f1ULL;
        intermediate_hash_[4] = 0x510e527fade682d1ULL;
        intermediate_hash_[5] = 0x9b05688c2b3e6c1fULL;
        intermediate_hash_[6] = 0x1f83d9abfb41bd6bULL;
        intermediate_hash_[7] = 0x5be0cd19137e2179ULL;
    }
}

} // namespace boost::crypt::hash_detail

#endif //BOOST_CRYPT2_HASH_DETAIL_SHA512_BASE_HPP
