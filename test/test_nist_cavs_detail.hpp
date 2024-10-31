// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_TEST_NIST_CAVS_DETAIL_HPP
#define BOOST_CRYPT_TEST_NIST_CAVS_DETAIL_HPP

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <fstream>
#include <string>
#include <vector>

namespace nist { namespace cavs {

namespace detail {

inline auto convert_hex_string_to_byte_container(const std::string& str_in) -> std::deque<std::uint8_t>
{
  std::deque<std::uint8_t> container_out { };

  for(std::size_t pos = 0U; pos < str_in.length(); pos += 2U)
  {
    // Get the next two characters represented as a substring of 2 chars.
    const std::string str = str_in.substr(pos, 2U);

    // Convert a 2-char hex string to unsigned long.
    const unsigned long ul = std::strtoul(str.c_str(), nullptr, 16);

    container_out.push_back(std::uint8_t(ul));
  }

  return container_out;
}

struct test_object_hash
{
public:
  using size_type    = std::size_t;
  using message_type = std::vector<std::uint8_t>;
  using result_type  = std::vector<std::uint8_t>;

  test_object_hash() = delete;

  // Construct this hash test object by setting the result only.
  // There is no message and there is no length available for
  // this hash test object.

  explicit test_object_hash(const std::string& str_result)
      : my_result // LCOV_EXCL_LINE
        {
          [&str_result]()
          {
            const auto byte_data { detail::convert_hex_string_to_byte_container(str_result) };
            return message_type(byte_data.cbegin(), byte_data.cend());
          }()
        }
  { }

  // Construct this hash test object with all of message, length and result.

  explicit test_object_hash(const std::string& str_data, const std::string& str_result)
      : my_length { str_data.size() / static_cast<size_type>(UINT8_C(2)) },
        my_msg
        {
          [&str_data]()
          {
            const auto byte_data { detail::convert_hex_string_to_byte_container(str_data) };
            return message_type(byte_data.cbegin(),   byte_data.cend());
          }()
        },
        my_result
        {
          [&str_result]()
          {
            const auto byte_data { detail::convert_hex_string_to_byte_container(str_result) };
            return message_type(byte_data.cbegin(), byte_data.cend());
          }()
        }
  { }

  const size_type    my_length { };
  const message_type my_msg    { };
  const result_type  my_result { };
};

using test_vector_container_type = std::deque<test_object_hash>;

auto where_file_shabytesvectors(const std::string& test_vectors_filename) -> std::string
{
  // Try to open the file in each of the known relative paths
  // in order to find out where it is located.

  // Boost-root
  std::string test_vectors_filename_relative = "libs/crypt/test/nist_cavs/vectors/shabytesvectors/" + test_vectors_filename;

  std::ifstream in_01(test_vectors_filename_relative.c_str());

  const bool file_01_is_open { in_01.is_open() };

  // LCOV_EXCL_START
  if(file_01_is_open)
  {
    in_01.close();
  }
  else
  {
    // Local test directory or IDE
    test_vectors_filename_relative = "nist_cavs/vectors/shabytesvectors/" + test_vectors_filename;

    std::ifstream in_02(test_vectors_filename_relative.c_str());

    const bool file_02_is_open { in_02.is_open() };

    if(file_02_is_open)
    {
      in_02.close();
    }
    else
    {
      // test/cover
      test_vectors_filename_relative = "../nist_cavs/vectors/shabytesvectors/" + test_vectors_filename;

      std::ifstream in_03(test_vectors_filename_relative.c_str());

      const bool file_03_is_open { in_03.is_open() };

      if(file_03_is_open)
      {
        in_03.close();
      }
      else
      {
        // CMake builds
        test_vectors_filename_relative = "../../../../libs/crypt/test/nist_cavs/vectors/shabytesvectors/" + test_vectors_filename;

        std::ifstream in_04(test_vectors_filename_relative.c_str());

        const bool file_04_is_open { in_04.is_open() };

        if(file_04_is_open)
        {
          in_04.close();
        }
        else
        {
          // Try to open the file from the absolute path.
          test_vectors_filename_relative = test_vectors_filename;

          std::ifstream in_05(test_vectors_filename_relative.c_str());

          const bool file_05_is_open { in_05.is_open() };

          if(file_05_is_open)
          {
            in_05.close();
          }
          else
          {
            test_vectors_filename_relative = "";
          }
        }
      }
    }
  }
  // LCOV_EXCL_STOP

  return test_vectors_filename_relative;
}

auto parse_file_vectors(const std::string& test_vectors_filename, test_vector_container_type& test_vectors_to_get) -> bool
{
  bool result_parse_is_ok { false };

  const std::string test_vectors_filename_relative { where_file_shabytesvectors(test_vectors_filename) };

  const bool result_filename_plausible_is_ok { (!test_vectors_filename_relative.empty()) };

  BOOST_TEST(result_filename_plausible_is_ok);

  if(result_filename_plausible_is_ok)
  {
    std::string str_message { };
    std::string str_result  { };

    // Read the file for creating the test cases.
    std::ifstream in(test_vectors_filename_relative.c_str());

    const bool file_is_open = in.is_open();

    if(file_is_open)
    {
      result_parse_is_ok = true;

      std::string line    { };
      std::size_t length  { };
      std::string message { };
      std::string result  { };

      while(getline(in, line))
      {
        const std::string::size_type pos_len = line.find("Len =", 0U);
        const std::string::size_type pos_msg = line.find("Msg =", 0U);
        const std::string::size_type pos_md  = line.find("MD =",  0U);

        const bool line_is_representation_is_len = (pos_len != std::string::npos);
        const bool line_is_representation_is_msg = (pos_msg != std::string::npos);
        const bool line_is_representation_is_md  = (pos_md  != std::string::npos);

        // Get the next length.
        if(line_is_representation_is_len)
        {
          const std::string str_len = line.substr(6U, line.length() - 6U);

          const unsigned long length_from_file = std::strtoul(str_len.c_str(), nullptr, 10U);

          length = static_cast<std::size_t>(length_from_file / 8U);
        }

        // Get the next message.
        if(line_is_representation_is_msg)
        {
          message = line.substr(6U, line.length() - 6U);
        }

        // Get the next (expected) result.
        if(line_is_representation_is_md)
        {
          result = line.substr(5U, line.length() - 5U);

          // Use special handling for message = "00" with length = 0.
          if((message == "00") && (length == 0U))
          {
            message = "";
          }

          // Add the new test object to v.
          const test_object_hash test_obj(message, result);

          test_vectors_to_get.push_back(test_obj);
        }
      }

      in.close();

      result_parse_is_ok = ((!test_vectors_to_get.empty()) && result_parse_is_ok);
    }
  }

  BOOST_TEST(result_parse_is_ok);

  return result_parse_is_ok;
}

auto parse_file_vectors_variable_xof(const std::string& test_vectors_filename, test_vector_container_type& test_vectors_to_get, std::vector<std::size_t>& lengths) -> bool
{
    bool result_parse_is_ok { false };

    const std::string test_vectors_filename_relative { where_file_shabytesvectors(test_vectors_filename) };

    const bool result_filename_plausible_is_ok { (!test_vectors_filename_relative.empty()) };

    BOOST_TEST(result_filename_plausible_is_ok);

    if(result_filename_plausible_is_ok)
    {
        std::string str_message { };
        std::string str_result  { };

        // Read the file for creating the test cases.
        std::ifstream in(test_vectors_filename_relative.c_str());

        const bool file_is_open = in.is_open();

        if(file_is_open)
        {
            result_parse_is_ok = true;

            std::string line    { };
            std::size_t length  { };
            std::string message { };
            std::string result  { };

            while(getline(in, line))
            {
                const std::string::size_type pos_len = line.find("Outputlen =", 0U);
                const std::string::size_type pos_msg = line.find("Msg =", 0U);
                const std::string::size_type pos_md  = line.find("Output =",  0U);

                const bool line_is_representation_is_len = (pos_len != std::string::npos);
                const bool line_is_representation_is_msg = (pos_msg != std::string::npos);
                const bool line_is_representation_is_md  = (pos_md  != std::string::npos);

                // Get the next length.
                if(line_is_representation_is_len)
                {
                    const std::string str_len = line.substr(12U, line.length() - 12U);

                    const auto length_from_file = static_cast<std::size_t>(std::strtoul(str_len.c_str(), nullptr, 10U));

                    lengths.push_back(length_from_file/CHAR_BIT);
                }

                // Get the next message.
                if(line_is_representation_is_msg)
                {
                    message = line.substr(6U, line.length() - 6U);
                }

                // Get the next (expected) result.
                if(line_is_representation_is_md)
                {
                    result = line.substr(9U, line.length() - 9U);

                    // Use special handling for message = "00" with length = 0.
                    if((message == "00") && (length == 0U))
                    {
                        message = "";
                    }

                    // Add the new test object to v.
                    const test_object_hash test_obj(message, result);

                    test_vectors_to_get.push_back(test_obj);
                }
            }

            in.close();

            result_parse_is_ok = ((!test_vectors_to_get.empty()) && result_parse_is_ok);
        }
    }

    BOOST_TEST(result_parse_is_ok);

    return result_parse_is_ok;
}

auto parse_file_monte(const std::string& test_monte_filename, test_vector_container_type& test_vectors_to_get) -> bool
{
  bool result_parse_is_ok { false };

  const std::string test_vectors_filename_relative { where_file_shabytesvectors(test_monte_filename) };

  const bool result_filename_plausible_is_ok { (!test_vectors_filename_relative.empty()) };

  BOOST_TEST(result_filename_plausible_is_ok);

  if(result_filename_plausible_is_ok)
  {
    std::string str_result  { };

    // Read the file for creating the test cases.
    std::ifstream in(test_vectors_filename_relative.c_str());

    const bool file_is_open = in.is_open();

    unsigned count { };

    if(file_is_open)
    {
      result_parse_is_ok = true;

      std::string line    { };
      std::string result  { };

      while(getline(in, line))
      {
        const std::string::size_type pos_cnt = line.find("COUNT =", 0U);
        const std::string::size_type pos_md  = line.find("MD =",  0U);

        const bool line_is_representation_is_cnt = (pos_cnt != std::string::npos);
        const bool line_is_representation_is_md  = (pos_md  != std::string::npos);

        // Get the next count.
        if(line_is_representation_is_cnt)
        {
          const std::string str_cnt = line.substr(8U, line.length() - 8U);

          const unsigned long count_from_file = std::strtoul(str_cnt.c_str(), nullptr, 10U);

          count = static_cast<unsigned>(count_from_file);
        }

        // Get the next (expected) result.
        if(line_is_representation_is_md)
        {
          result = line.substr(5U, line.length() - 5U);

          // Add the new test object to v.
          const test_object_hash test_obj(result);

          test_vectors_to_get.push_back(test_obj);
        }
      }

      in.close();

      result_parse_is_ok = ((!test_vectors_to_get.empty()) && (count == 99U) && result_parse_is_ok);
    }
  }

  BOOST_TEST(result_parse_is_ok);

  return result_parse_is_ok;
}

auto parse_file_monte_xof(const std::string& test_monte_filename, test_vector_container_type& test_vectors_to_get, std::vector<std::size_t>& lengths) -> bool
{
    bool result_parse_is_ok { false };

    const std::string test_vectors_filename_relative { where_file_shabytesvectors(test_monte_filename) };

    const bool result_filename_plausible_is_ok { (!test_vectors_filename_relative.empty()) };

    BOOST_TEST(result_filename_plausible_is_ok);

    if(result_filename_plausible_is_ok)
    {
        std::string str_result  { };

        // Read the file for creating the test cases.
        std::ifstream in(test_vectors_filename_relative.c_str());

        const bool file_is_open = in.is_open();

        unsigned count { };

        if(file_is_open)
        {
            result_parse_is_ok = true;

            std::string line    { };
            std::string result  { };

            while(getline(in, line))
            {
                const std::string::size_type pos_cnt = line.find("COUNT =", 0U);
                const std::string::size_type pos_output_len = line.find("Outputlen =", 0U);
                const std::string::size_type pos_output  = line.find("Output =",  0U);

                const bool line_is_representation_is_cnt = (pos_cnt != std::string::npos);
                const bool line_is_representation_is_output_len = (pos_output_len != std::string::npos);
                const bool line_is_representation_is_output  = (pos_output  != std::string::npos);

                // Get the next count.
                if(line_is_representation_is_cnt)
                {
                    const std::string str_cnt = line.substr(8U, line.length() - 8U);

                    const unsigned long count_from_file = std::strtoul(str_cnt.c_str(), nullptr, 10U);

                    count = static_cast<unsigned>(count_from_file);
                }

                if (line_is_representation_is_output_len)
                {
                    const std::string str_cnt = line.substr(1U, line.length() - 1U);

                    const auto len_from_file = static_cast<std::size_t>(std::strtoul(str_cnt.c_str(), nullptr, 10U));

                    lengths.emplace_back(len_from_file);
                }

                // Get the next (expected) result.
                if(line_is_representation_is_output)
                {
                    result = line.substr(9U, line.length() - 9U);

                    // Add the new test object to v.
                    const test_object_hash test_obj(result);

                    test_vectors_to_get.push_back(test_obj);
                }
            }

            in.close();

            result_parse_is_ok = ((!test_vectors_to_get.empty()) && (count == 99U) && result_parse_is_ok);
        }
    }

    BOOST_TEST(result_parse_is_ok);

    return result_parse_is_ok;
}

} // namespace detail

using detail::test_vector_container_type;
using detail::parse_file_vectors;
using detail::parse_file_monte;

template<typename HasherType>
auto test_vectors_oneshot(const test_vector_container_type& test_vectors) -> bool
{
  using local_hasher_type = HasherType;
  using local_result_type = typename local_hasher_type::return_type;

  BOOST_TEST((!test_vectors.empty()));

  bool result_is_ok { true };

  for(const auto& test_vector : test_vectors)
  {
    local_hasher_type this_hash { };

    // Make pass 1 through the messages.
    // Use the triple-combination of init/process/get-result functions.

    this_hash.init();

    this_hash.process_bytes(test_vector.my_msg.data(), test_vector.my_msg.size());

    const local_result_type result_01 { this_hash.get_digest() };

    const bool result_hash_01_is_ok { std::equal(test_vector.my_result.cbegin(), test_vector.my_result.cend(), result_01.cbegin()) };

    BOOST_TEST(result_hash_01_is_ok);

    // Make pass 2 through the messages.
    // Use the triple-combination of init/process/get-result functions.
    // Even though this is not required in CAVS testing, it is
    // done in order to ensure that the init() function properly
    // puts the hasher-object into its initialized state.

    this_hash.init();

    this_hash.process_bytes(test_vector.my_msg.data(), test_vector.my_msg.size());

    const local_result_type result_02 { this_hash.get_digest() };

    const bool result_hash_02_is_ok { std::equal(test_vector.my_result.cbegin(), test_vector.my_result.cend(), result_02.cbegin()) };

    BOOST_TEST(result_hash_02_is_ok);

    // Collect the combined results of pass 1 and pass 2.
    const bool result_hash_is_ok = (result_hash_01_is_ok && result_hash_02_is_ok);

    result_is_ok = (result_hash_is_ok && result_is_ok);
  }

  return result_is_ok;
}

template<typename HasherType>
auto test_vectors_variable(const test_vector_container_type& test_vectors, const std::vector<std::size_t>& lengths) -> bool
{
    using local_hasher_type = HasherType;

    BOOST_TEST((!test_vectors.empty()));

    int false_counter = 0;
    std::size_t i {};
    for(const auto& test_vector : test_vectors)
    {
        local_hasher_type this_hash { };

        // Make pass 1 through the messages.
        // Use the triple-combination of init/process/get-result functions.

        this_hash.init();

        this_hash.process_bytes(test_vector.my_msg.data(), test_vector.my_msg.size());

        std::vector<std::uint8_t> bits {};
        bits.resize(lengths[i]);

        const auto result_01 { this_hash.get_digest(bits) };

        BOOST_CRYPT_ASSERT(test_vector.my_result.size() == result_01);
        for (std::size_t j {}; j < test_vector.my_result.size(); ++j)
        {
            if (!BOOST_TEST_EQ(test_vector.my_result[j], bits[j]))
            {
                false_counter++; // LCOV_EXCL_LINE
            }
        }

        BOOST_TEST_EQ(lengths[i], result_01);

        // Make pass 2 through the messages.
        // Use the triple-combination of init/process/get-result functions.
        // Even though this is not required in CAVS testing, it is
        // done in order to ensure that the init() function properly
        // puts the hasher-object into its initialized state.

        this_hash.init();

        this_hash.process_bytes(test_vector.my_msg.data(), test_vector.my_msg.size());

        for (auto& bit : bits)
        {
            bit = static_cast<std::uint8_t>(0);
        }

        const auto result_02 { this_hash.get_digest(bits) };

        BOOST_TEST_EQ(lengths[i], result_02);

        for (std::size_t j {}; j < test_vector.my_result.size(); ++j)
        {
            if (!BOOST_TEST_EQ(test_vector.my_result[j], bits[j]))
            {
                false_counter++; // LCOV_EXCL_LINE
            }
        }

        ++i;
    }

    return false_counter == 0;
}

template<typename HasherType>
auto test_vectors_monte(const nist::cavs::test_vector_container_type& test_vectors_monte, const std::vector<std::uint8_t>& seed_init) -> bool
{
  bool result_is_ok { (!test_vectors_monte.empty()) };

  if(result_is_ok)
  {
    using local_hasher_type = HasherType;
    using local_result_type = typename local_hasher_type::return_type;

    using local_array_type = local_result_type;

    // Obtain the test-specific initial seed.

    local_array_type MDi { };

    const std::size_t
      copy_len
      {
        (std::min)(static_cast<std::size_t>(MDi.size()), static_cast<std::size_t>(seed_init.size()))
      };

    static_cast<void>
    (
      std::copy
      (
        seed_init.cbegin(),
        seed_init.cbegin() + static_cast<typename std::vector<std::uint8_t>::difference_type>(copy_len),
        MDi.begin()
      )
    );

    // See pseudocode on page 9 of "The Secure Hash Algorithm Validation System (SHAVS)".

    for(std::size_t j { }; j < 100U; ++j)
    {
      local_array_type MD[3U] { { }, { }, { } };

      MD[0U] = MD[1U] = MD[2U] = MDi;

      for(std::size_t i { 3U } ; i < 1003U; ++i)
      {
        using local_wide_array_type = boost::crypt::array<std::uint8_t, boost::crypt::tuple_size<local_array_type>::value * 3U>;

        std::vector<std::uint8_t> result_vector;

        result_vector.reserve(boost::crypt::tuple_size<local_wide_array_type>::value);

        result_vector.insert(result_vector.end(), MD[0U].cbegin(), MD[0U].cend());
        result_vector.insert(result_vector.end(), MD[1U].cbegin(), MD[1U].cend());
        result_vector.insert(result_vector.end(), MD[2U].cbegin(), MD[2U].cend());

        local_wide_array_type Mi { };

        std::copy(result_vector.cbegin(), result_vector.cend(), Mi.begin());

        local_hasher_type this_hash { };

        this_hash.init();

        this_hash.process_bytes(Mi.data(), Mi.size());

        MDi = this_hash.get_digest();

        MD[0U] = MD[1U];
        MD[1U] = MD[2U];
        MD[2U] = MDi;
      }

      // The output at this point is MDi.

      const bool result_this_monte_step_is_ok =
        std::equal
        (
          MDi.cbegin(),
          MDi.cend(),
          test_vectors_monte[j].my_result.cbegin()
        );

      result_is_ok = (result_this_monte_step_is_ok && result_is_ok);

      BOOST_TEST(result_this_monte_step_is_ok);
    }
  }

  BOOST_TEST(result_is_ok);

  return result_is_ok;
}

// See: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
// Section 6.2.3
template<typename HasherType>
auto test_vectors_monte_sha3(const nist::cavs::test_vector_container_type& test_vectors_monte, const std::vector<std::uint8_t>& seed_init) -> bool
{
    bool result_is_ok { (!test_vectors_monte.empty()) };

    if (result_is_ok)
    {
        using local_hasher_type = HasherType;
        using local_result_type = typename local_hasher_type::return_type;

        using local_array_type = local_result_type;

        // Obtain the test-specific initial seed.

        local_array_type MDi { };

        const std::size_t copy_len
        {
                (std::min)(static_cast<std::size_t>(MDi.size()), static_cast<std::size_t>(seed_init.size()))
        };

        static_cast<void>
        (
            std::copy
            (
                seed_init.cbegin(),
                seed_init.cbegin() + static_cast<typename std::vector<std::uint8_t>::difference_type>(copy_len),
                MDi.begin()
            )
        );

        for (size_t j = 0; j < 100; j++)
        {
            for (size_t i = 1; i < 1001; i++)
            {
                local_hasher_type this_hash { };

                this_hash.init();

                this_hash.process_bytes(MDi.data(), MDi.size());

                MDi = this_hash.get_digest();
            }

            // The output at this point is MDi.

            const bool result_this_monte_step_is_ok =
            std::equal
            (
                MDi.cbegin(),
                MDi.cend(),
                test_vectors_monte[j].my_result.cbegin()
            );

            result_is_ok = (result_this_monte_step_is_ok && result_is_ok);

            BOOST_TEST(result_this_monte_step_is_ok);
        }
    }

    BOOST_TEST(result_is_ok);

    return result_is_ok;
}

template<typename HasherType>
auto test_vectors_monte_xof(const nist::cavs::test_vector_container_type& test_vectors_monte, const std::vector<std::size_t>& lengths, const std::vector<std::uint8_t>& seed_init) -> bool
{
    bool result_is_ok { (!test_vectors_monte.empty()) };

    if (result_is_ok)
    {
        using local_hasher_type = HasherType;

        // Obtain the test-specific initial seed.

        std::vector<std::uint8_t> MDi { };

        const std::size_t copy_len
        {
            (std::min)(static_cast<std::size_t>(MDi.size()), static_cast<std::size_t>(seed_init.size()))
        };

        static_cast<void>
        (
            std::copy
            (
                seed_init.cbegin(),
                seed_init.cbegin() + static_cast<typename std::vector<std::uint8_t>::difference_type>(copy_len),
                MDi.begin()
            )
        );

        for (size_t j = 0; j < 100; j++)
        {
            MDi.resize(lengths[j]);

            for (size_t i = 1; i < 1001; i++)
            {
                local_hasher_type this_hash { };

                this_hash.init();

                // Only process the leftmost 128 bit of output
                this_hash.process_bytes(MDi.data(), 16);

                MDi.clear();

                const auto output_length = this_hash.get_digest(MDi);
                BOOST_TEST_EQ(output_length, lengths[j]);
            }

            // The output at this point is MDi.

            const bool result_this_monte_step_is_ok =
            std::equal
            (
                MDi.cbegin(),
                MDi.cend(),
                test_vectors_monte[j].my_result.cbegin()
            );

            result_is_ok = (result_this_monte_step_is_ok && result_is_ok);

            BOOST_TEST(result_this_monte_step_is_ok);
        }
    }

    BOOST_TEST(result_is_ok);

    return result_is_ok;
}

} // namespace cavs
} // namespace nist

#endif // BOOST_CRYPT_TEST_NIST_CAVS_DETAIL_HPP
