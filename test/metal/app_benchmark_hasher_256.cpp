///////////////////////////////////////////////////////////////////////////////
//  Copyright Christopher Kormanyos 2024.
//  Distributed under the Boost Software License,
//  Version 1.0. (See accompanying file LICENSE_1_0.txt
//  or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// cd /mnt/c/ChrisGitRepos/cppalliance/crypt/test/metal
// mkdir -p bin
// arm-none-eabi-g++ -std=c++20 -Wall -Wextra -Wpedantic -Os -g -gdwarf-2 -ffunction-sections -fdata-sections -x c++ -fno-rtti -fno-use-cxa-atexit -fno-exceptions -fno-nonansi-builtins -fno-threadsafe-statics -fno-enforce-eh-specs -ftemplate-depth=128 -mcpu=cortex-m4 -mtune=cortex-m4 -mthumb -mfloat-abi=soft -mno-unaligned-access -mno-long-calls -I../../include -DBOOST_CRYPT_DISABLE_IOSTREAM -DBOOST_CRYPT_NO_EXCEPTIONS -DAPP_BENCHMARK_STANDALONE_MAIN app_benchmark_hasher_256.cpp ./target/micros/stm32f429/make/single/crt.cpp ./target/micros/stm32f429/make/single/mcal_gcc_cxx_completion_with_stdlib.cpp -nostartfiles -Wl,--gc-sections -Wl,-Map,./bin/app_benchmark_hasher_256.map -T ./target/micros/stm32f429/make/stm32f429.ld --specs=nano.specs --specs=nosys.specs -Wl,--print-memory-usage -o ./bin/app_benchmark_hasher_256.elf
// arm-none-eabi-objcopy ./bin/app_benchmark_hasher_256.elf -O ihex ./bin/app_benchmark_hasher_256.hex
// ls -la ./bin/app_benchmark_hasher_256.elf ./bin/app_benchmark_hasher_256.hex ./bin/app_benchmark_hasher_256.map

#if !defined(BOOST_CRYPT_STANDALONE)
#define BOOST_DECIMAL_STANDALONE
#endif

#include <boost/crypt/hash/sha256.hpp>

namespace app { namespace benchmark {

namespace detail {

} // namespace detail

auto run_hasher_256() -> bool;

} // namespace benchmark
} // namespace app

namespace local
{

  using hasher_type = boost::crypt::sha256_hasher;

} // namespace local

auto app::benchmark::run_hasher_256() -> bool
{
  auto app_benchmark_result_is_ok = true;

  // "abc"
  const std::array<std::uint8_t, 3U> message =
  {{
    0x61U, 0x62U, 0x63U
  }};

  using local_hasher_type = local::hasher_type;
  using local_result_type = typename local_hasher_type::return_type;

  constexpr local_result_type control = 
  {{
    0xBAU, 0x78U, 0x16U, 0xBFU, 0x8FU, 0x01U, 0xCFU, 0xEAU,
    0x41U, 0x41U, 0x40U, 0xDEU, 0x5DU, 0xAEU, 0x22U, 0x23U,
    0xB0U, 0x03U, 0x61U, 0xA3U, 0x96U, 0x17U, 0x7AU, 0x9CU,
    0xB4U, 0x10U, 0xFFU, 0x61U, 0xF2U, 0x00U, 0x15U, 0xADU,
  }};

  local_hasher_type my_hasher { };

  my_hasher.init();

  my_hasher.process_bytes(message.data(), message.size());

  const local_result_type result { my_hasher.get_digest() };

  const bool result_hash_is_ok { result == control };

  app_benchmark_result_is_ok = (result_hash_is_ok && app_benchmark_result_is_ok);

  return app_benchmark_result_is_ok;
}

#if defined(APP_BENCHMARK_STANDALONE_MAIN)
constexpr auto app_benchmark_standalone_foodcafe = static_cast<std::uint32_t>(UINT32_C(0xF00DCAFE));

extern "C"
{
  extern volatile std::uint32_t app_benchmark_standalone_result;

  auto app_benchmark_run_standalone       (void) -> bool;
  auto app_benchmark_get_standalone_result(void) -> bool;

  auto app_benchmark_run_standalone(void) -> bool
  {
    auto result_is_ok = true;

    for(unsigned i = 0U; i < 64U; ++i)
    {
      result_is_ok &= app::benchmark::run_hasher_256();
    }

    app_benchmark_standalone_result =
      static_cast<std::uint32_t>
      (
        result_is_ok ? app_benchmark_standalone_foodcafe : static_cast<std::uint32_t>(UINT32_C(0xFFFFFFFF))
      );

    return result_is_ok;
  }

  auto app_benchmark_get_standalone_result(void) -> bool
  {
    volatile auto result_is_ok = (app_benchmark_standalone_result == static_cast<std::uint32_t>(UINT32_C(0xF00DCAFE)));

    return result_is_ok;
  }
}

auto main() -> int
{
  auto result_is_ok = true;

  result_is_ok = (::app_benchmark_run_standalone       () && result_is_ok);
  result_is_ok = (::app_benchmark_get_standalone_result() && result_is_ok);

  return (result_is_ok ? 0 : -1);
}

extern "C"
{
  volatile std::uint32_t app_benchmark_standalone_result;
}
#endif // APP_BENCHMARK_STANDALONE_MAIN

