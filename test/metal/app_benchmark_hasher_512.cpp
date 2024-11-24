///////////////////////////////////////////////////////////////////////////////
//  Copyright Christopher Kormanyos 2024.
//  Distributed under the Boost Software License,
//  Version 1.0. (See accompanying file LICENSE_1_0.txt
//  or copy at http://www.boost.org/LICENSE_1_0.txt)
//

// cd /mnt/c/ChrisGitRepos/cppalliance/crypt/test/metal
// mkdir -p bin
// arm-none-eabi-g++ -std=c++20 -Wall -Wextra -Wpedantic -Os -g -gdwarf-2 -ffunction-sections -fdata-sections -x c++ -fno-rtti -fno-use-cxa-atexit -fno-exceptions -fno-nonansi-builtins -fno-threadsafe-statics -fno-enforce-eh-specs -ftemplate-depth=128 -mcpu=cortex-m4 -mtune=cortex-m4 -mthumb -mfloat-abi=soft -mno-unaligned-access -mno-long-calls -I../../include -DBOOST_CRYPT_DISABLE_IOSTREAM -DBOOST_CRYPT_NO_EXCEPTIONS -DAPP_BENCHMARK_STANDALONE_MAIN app_benchmark_hasher_512.cpp ./target/micros/stm32f429/make/single/crt.cpp ./target/micros/stm32f429/make/single/mcal_gcc_cxx_completion_with_stdlib.cpp -nostartfiles -Wl,--gc-sections -Wl,-Map,./bin/app_benchmark_hasher_512.map -T ./target/micros/stm32f429/make/stm32f429.ld --specs=nano.specs --specs=nosys.specs -Wl,--print-memory-usage -o ./bin/app_benchmark_hasher_512.elf
// arm-none-eabi-objcopy ./bin/app_benchmark_hasher_512.elf -O ihex ./bin/app_benchmark_hasher_512.hex
// ls -la ./bin/app_benchmark_hasher_512.elf ./bin/app_benchmark_hasher_512.hex ./bin/app_benchmark_hasher_512.map

#if !defined(BOOST_CRYPT_STANDALONE)
#define BOOST_DECIMAL_STANDALONE
#endif

#include <boost/crypt/hash/sha512.hpp>

namespace app { namespace benchmark {

namespace detail {

} // namespace detail

auto run_hasher_512() -> bool;

} // namespace benchmark
} // namespace app

namespace local
{

  using hasher_type = boost::crypt::sha512_hasher;

} // namespace local

auto app::benchmark::run_hasher_512() -> bool
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
    0xDDU, 0xAFU, 0x35U, 0xA1U, 0x93U, 0x61U, 0x7AU, 0xBAU,
    0xCCU, 0x41U, 0x73U, 0x49U, 0xAEU, 0x20U, 0x41U, 0x31U,
    0x12U, 0xE6U, 0xFAU, 0x4EU, 0x89U, 0xA9U, 0x7EU, 0xA2U,
    0x0AU, 0x9EU, 0xEEU, 0xE6U, 0x4BU, 0x55U, 0xD3U, 0x9AU,
    0x21U, 0x92U, 0x99U, 0x2AU, 0x27U, 0x4FU, 0xC1U, 0xA8U,
    0x36U, 0xBAU, 0x3CU, 0x23U, 0xA3U, 0xFEU, 0xEBU, 0xBDU,
    0x45U, 0x4DU, 0x44U, 0x23U, 0x64U, 0x3CU, 0xE8U, 0x0EU,
    0x2AU, 0x9AU, 0xC9U, 0x4FU, 0xA5U, 0x4CU, 0xA4U, 0x9FU,
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

  auto app_benchmark_run_standalone() -> bool;
  auto app_benchmark_get_standalone_result() noexcept -> bool;

  auto app_benchmark_run_standalone() -> bool
  {
    bool result_is_ok { true };

    for(unsigned i = 0U; i < 64U; ++i)
    {
      result_is_ok = (app::benchmark::run_hasher_512() && result_is_ok);
    }

    app_benchmark_standalone_result =
      static_cast<std::uint32_t>
      (
        result_is_ok ? app_benchmark_standalone_foodcafe : static_cast<std::uint32_t>(UINT32_C(0xFFFFFFFF))
      );

    return result_is_ok;
  }

  auto app_benchmark_get_standalone_result() noexcept -> bool
  {
    return (app_benchmark_standalone_result == static_cast<std::uint32_t>(UINT32_C(0xF00DCAFE)));
  }
}

auto main() -> int
{
  bool result_is_ok { true };

  result_is_ok = (::app_benchmark_run_standalone       () && result_is_ok);
  result_is_ok = (::app_benchmark_get_standalone_result() && result_is_ok);

  return (result_is_ok ? 0 : -1);
}

extern "C"
{
  volatile std::uint32_t app_benchmark_standalone_result { };
}
#endif // APP_BENCHMARK_STANDALONE_MAIN

