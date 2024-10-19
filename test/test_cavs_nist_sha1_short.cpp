// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/core/lightweight_test.hpp>
#include <boost/crypt/hash/sha1.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace local {

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
            return message_type(byte_data.cbegin(),   byte_data.cend());
          }()
        }
  { }

  const size_type    my_length { };
  const message_type my_msg    { };
  const result_type  my_result { };
};

using test_vector_container_type = std::deque<test_object_hash>;

auto where_file(const std::string& test_vectors_filename) -> std::string
{
  // Try to open the file in the relative path.
  std::string test_vectors_filename_relative = "../" + test_vectors_filename;

  std::ifstream in_01(test_vectors_filename_relative.c_str());

  const bool file_01_is_open { in_01.is_open() };

  // LCOV_EXCL_START
  if(file_01_is_open)
  {
    in_01.close();
  }
  else
  {
    // Try to open the file from the cover path.
    test_vectors_filename_relative = "../../../" + test_vectors_filename;

    std::ifstream in_02(test_vectors_filename_relative.c_str());

    const bool file_02_is_open { in_02.is_open() };

    if(file_02_is_open)
    {
      in_02.close();
    }
    else
    {
      // Try to open the file from the CMake working path.
      test_vectors_filename_relative = "../../../libs/" + test_vectors_filename;

      std::ifstream in_03(test_vectors_filename_relative.c_str());

      const bool file_03_is_open { in_03.is_open() };

      if(file_03_is_open)
      {
        in_03.close();
      }
      else
      {
        // Try to open the file from the absolute path.
        test_vectors_filename_relative = test_vectors_filename;

        std::ifstream in_04(test_vectors_filename_relative.c_str());

        const bool file_04_is_open { in_04.is_open() };

        if(file_04_is_open)
        {
          in_04.close();
        }
        else
        {
          test_vectors_filename_relative = "";
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

  const std::string test_vectors_filename_relative { where_file(test_vectors_filename) };

  const bool result_filename_plausible_is_ok { (!test_vectors_filename_relative.empty()) };

  BOOST_TEST_EQ(result_filename_plausible_is_ok, true);

  if(result_filename_plausible_is_ok)
  {
    std::string str_message { };
    std::string str_result  { };

    // Read the file for creating the test cases.
    std::ifstream in(test_vectors_filename_relative.c_str());

    const bool file_is_open = in.is_open();

    BOOST_TEST_EQ(file_is_open, true);

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
    }
  }

  return (result_parse_is_ok && (!test_vectors_to_get.empty()));
}

} // namespace detail

using detail::test_vector_container_type;
using detail::parse_file_vectors;

template<typename HasherType>
auto test_vectors_oneshot(const test_vector_container_type& test_vectors) -> bool
{
  using local_hasher_type = HasherType;
  using local_result_type = typename local_hasher_type::return_type;

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

} // namespace local

auto main(int argc, char** argv) -> int
{
  static_cast<void>(argc);

  const std::string str_where { argv[static_cast<std::size_t>(0U)] };

  std::cout << "str_where: " << str_where << std::endl;

  local::test_vector_container_type test_vectors { };

  //static_cast<void>(local::detail::parse_file_vectors("C:/ChrisGitRepos/cppalliance/crypt/test/nist_cavs/vectors/shabytesvectors/SHA1ShortMsg.rsp", test_vectors));
  static_cast<void>(local::detail::parse_file_vectors("crypt/test/nist_cavs/vectors/shabytesvectors/SHA1ShortMsg.rsp", test_vectors));

  const bool result_is_ok { local::test_vectors_oneshot<boost::crypt::sha1_hasher>(test_vectors) };

  static_cast<void>(result_is_ok);

  return boost::report_errors();
}
