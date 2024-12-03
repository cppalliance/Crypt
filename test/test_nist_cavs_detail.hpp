// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_TEST_NIST_CAVS_DETAIL_HPP
#define BOOST_CRYPT_TEST_NIST_CAVS_DETAIL_HPP

#include <boost/core/lightweight_test.hpp>
#include "boost/crypt/mac/hmac.hpp"
#include "boost/crypt/aes/detail/cipher_mode.hpp"
#include <cstddef>
#include <cstdint>
#include <deque>
#include <fstream>
#include <string>
#include <vector>

namespace nist { namespace cavs {

namespace detail {

enum class test_type : unsigned
{
    sha,
    hmac,
    drbg_no_reseed,
    drbg_pr_false,
    drbg_pr_true,
    aes_kat,
    aes_mmt,
    aes_mct
};

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
  using key_type     = std::vector<std::uint8_t>;
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

    explicit test_object_hash(const std::string& key_data, const std::string& msg_data, const std::string& mac_data)
    : my_msg
      {
          [&msg_data]()
          {
              const auto byte_data { detail::convert_hex_string_to_byte_container(msg_data) };
              return message_type(byte_data.cbegin(),   byte_data.cend());
          }()
      },
      my_result
      {
          [&mac_data]()
          {
              const auto byte_data { detail::convert_hex_string_to_byte_container(mac_data) };
              return message_type(byte_data.cbegin(), byte_data.cend());
          }()
      },
      my_key
      {
          [&key_data]()
          {
              const auto byte_data { detail::convert_hex_string_to_byte_container(key_data) };
              return message_type(byte_data.cbegin(), byte_data.cend());
          }()
      }
        { }

  const size_type    my_length { };
  const message_type my_msg    { };
  const result_type  my_result { };
  const key_type     my_key    { };
};

using test_vector_container_type = std::deque<test_object_hash>;

// Each drbg test has its own data structures
template <test_type>
struct test_object_drbg;

template <>
struct test_object_drbg<test_type::drbg_no_reseed>
{
public:
    using size_type             = std::size_t;
    using entropy_type          = std::vector<std::uint8_t>;
    using nonce_type            = std::vector<std::uint8_t>;
    using additional_input_type = std::vector<std::uint8_t>;
    using result_type           = std::vector<std::uint8_t>;

    test_object_drbg() = delete;

    // Construct this hash test object by setting the result only.
    // There is no message and there is no length available for
    // this hash test object.

    explicit test_object_drbg(const std::string& entropy_input,
                              const std::string& nonce,
                              const std::string& returned_bits)
        : initial_entropy
          {
                  [&entropy_input]()
                  {
                      const auto byte_data { detail::convert_hex_string_to_byte_container(entropy_input) };
                      return entropy_type(byte_data.cbegin(),   byte_data.cend());
                  }()
          },
          drbg_nonce
          {
                  [&nonce]()
                  {
                      const auto byte_data { detail::convert_hex_string_to_byte_container(nonce) };
                      return nonce_type(byte_data.cbegin(), byte_data.cend());
                  }()
          },
          result
          {
                  [&returned_bits]()
                  {
                      const auto byte_data { detail::convert_hex_string_to_byte_container(returned_bits) };
                      return result_type(byte_data.cbegin(), byte_data.cend());
                  }()
          }
    { }

    explicit test_object_drbg(const std::string& entropy_input,
                              const std::string& nonce,
                              const std::string& personalization,
                              const std::string& returned_bits)
    : initial_entropy
              {
                      [&entropy_input]()
                      {
                          const auto byte_data { detail::convert_hex_string_to_byte_container(entropy_input) };
                          return entropy_type(byte_data.cbegin(),   byte_data.cend());
                      }()
              },
      drbg_nonce
              {
                      [&nonce]()
                      {
                          const auto byte_data { detail::convert_hex_string_to_byte_container(nonce) };
                          return nonce_type(byte_data.cbegin(), byte_data.cend());
                      }()
              },
      personalization_string
              {
                      [&personalization]()
                      {
                          const auto byte_data { detail::convert_hex_string_to_byte_container(personalization) };
                          return additional_input_type(byte_data.cbegin(), byte_data.cend());
                      }()
              },
      result
              {
                      [&returned_bits]()
                      {
                          const auto byte_data { detail::convert_hex_string_to_byte_container(returned_bits) };
                          return result_type(byte_data.cbegin(), byte_data.cend());
                      }()
              }
    { }

    explicit test_object_drbg(const std::string& entropy_input,
                              const std::string& nonce,
                              const std::string& additional_input_first,
                              const std::string& additional_input_second,
                              const std::string& returned_bits)
        : initial_entropy
          {
                  [&entropy_input]()
                  {
                      const auto byte_data { detail::convert_hex_string_to_byte_container(entropy_input) };
                      return entropy_type(byte_data.cbegin(),   byte_data.cend());
                  }()
          },
          drbg_nonce
          {
                  [&nonce]()
                  {
                      const auto byte_data { detail::convert_hex_string_to_byte_container(nonce) };
                      return nonce_type(byte_data.cbegin(), byte_data.cend());
                  }()
          },
          additional_input_1
          {
                  [&additional_input_first]()
                  {
                      const auto byte_data { detail::convert_hex_string_to_byte_container(additional_input_first) };
                      return additional_input_type(byte_data.cbegin(), byte_data.cend());
                  }()
          },
          additional_input_2
          {
                  [&additional_input_second]()
                  {
                      const auto byte_data { detail::convert_hex_string_to_byte_container(additional_input_second) };
                      return additional_input_type(byte_data.cbegin(), byte_data.cend());
                  }()
          },
          result
          {
                  [&returned_bits]()
                  {
                      const auto byte_data { detail::convert_hex_string_to_byte_container(returned_bits) };
                      return result_type(byte_data.cbegin(), byte_data.cend());
                  }()
          }
    { }

    explicit test_object_drbg(const std::string& entropy_input,
                              const std::string& nonce,
                              const std::string& personalization,
                              const std::string& additional_input_first,
                              const std::string& additional_input_second,
                              const std::string& returned_bits)
    : initial_entropy
      {
              [&entropy_input]()
              {
                  const auto byte_data { detail::convert_hex_string_to_byte_container(entropy_input) };
                  return entropy_type(byte_data.cbegin(),   byte_data.cend());
              }()
      },
      drbg_nonce
      {
              [&nonce]()
              {
                  const auto byte_data { detail::convert_hex_string_to_byte_container(nonce) };
                  return nonce_type(byte_data.cbegin(), byte_data.cend());
              }()
      },
      personalization_string
      {
              [&personalization]()
              {
                  const auto byte_data { detail::convert_hex_string_to_byte_container(personalization) };
                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
              }()
      },
      additional_input_1
      {
              [&additional_input_first]()
              {
                  const auto byte_data { detail::convert_hex_string_to_byte_container(additional_input_first) };
                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
              }()
      },
      additional_input_2
      {
              [&additional_input_second]()
              {
                  const auto byte_data { detail::convert_hex_string_to_byte_container(additional_input_second) };
                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
              }()
      },
      result
      {
              [&returned_bits]()
              {
                  const auto byte_data { detail::convert_hex_string_to_byte_container(returned_bits) };
                  return result_type(byte_data.cbegin(), byte_data.cend());
              }()
      }
    { }


    const entropy_type initial_entropy {};
    const nonce_type drbg_nonce {};
    const additional_input_type personalization_string {};
    const additional_input_type additional_input_1 {};
    const additional_input_type additional_input_2 {};
    const result_type result {};
};

template <>
struct test_object_drbg<test_type::drbg_pr_false>
{
public:
    using size_type             = std::size_t;
    using entropy_type          = std::vector<std::uint8_t>;
    using nonce_type            = std::vector<std::uint8_t>;
    using additional_input_type = std::vector<std::uint8_t>;
    using result_type           = std::vector<std::uint8_t>;

    test_object_drbg() = delete;

    explicit test_object_drbg(const std::string& entropy_input,
                              const std::string& nonce,
                              const std::string& personalization,
                              const std::string& entropy_reseed,
                              const std::string& additional_input_reseed,
                              const std::string& additional_input_first,
                              const std::string& additional_input_second,
                              const std::string& returned_bits)
            : initial_entropy
                      {
                              [&entropy_input]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(entropy_input) };
                                  return entropy_type(byte_data.cbegin(),   byte_data.cend());
                              }()
                      },
              drbg_nonce
                      {
                              [&nonce]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(nonce) };
                                  return nonce_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              personalization_string
                      {
                              [&personalization]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(personalization) };
                                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              reseed_entropy
                      {
                              [&entropy_reseed]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(entropy_reseed) };
                                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              reseed_additional_input
                      {
                              [&additional_input_reseed]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(additional_input_reseed) };
                                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              additional_input_1
                      {
                              [&additional_input_first]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(additional_input_first) };
                                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              additional_input_2
                      {
                              [&additional_input_second]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(additional_input_second) };
                                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              result
                      {
                              [&returned_bits]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(returned_bits) };
                                  return result_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      }
    { }


    const entropy_type initial_entropy {};
    const nonce_type drbg_nonce {};
    const additional_input_type personalization_string {};
    const additional_input_type reseed_entropy {};
    const additional_input_type reseed_additional_input {};
    const additional_input_type additional_input_1 {};
    const additional_input_type additional_input_2 {};
    const result_type result {};
};

template <>
struct test_object_drbg<test_type::drbg_pr_true>
{
public:
    using size_type             = std::size_t;
    using entropy_type          = std::vector<std::uint8_t>;
    using nonce_type            = std::vector<std::uint8_t>;
    using additional_input_type = std::vector<std::uint8_t>;
    using result_type           = std::vector<std::uint8_t>;

    test_object_drbg() = delete;

    explicit test_object_drbg(const std::string& entropy_input,
                              const std::string& nonce,
                              const std::string& personalization,
                              const std::string& additional_input_first,
                              const std::string& entropy_input_first,
                              const std::string& additional_input_second,
                              const std::string& entropy_input_second,
                              const std::string& returned_bits)
            : initial_entropy
                      {
                              [&entropy_input]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(entropy_input) };
                                  return entropy_type(byte_data.cbegin(),   byte_data.cend());
                              }()
                      },
              drbg_nonce
                      {
                              [&nonce]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(nonce) };
                                  return nonce_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              personalization_string
                      {
                              [&personalization]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(personalization) };
                                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              additional_input_1
                      {
                              [&additional_input_first]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(additional_input_first) };
                                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              additional_entropy_1
                      {
                              [&entropy_input_first]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(entropy_input_first) };
                                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              additional_input_2
                      {
                              [&additional_input_second]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(additional_input_second) };
                                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              additional_entropy_2
                      {
                              [&entropy_input_second]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(entropy_input_second) };
                                  return additional_input_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              result
                      {
                              [&returned_bits]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(returned_bits) };
                                  return result_type(byte_data.cbegin(), byte_data.cend());
                              }()
                      }
    { }


    const entropy_type initial_entropy {};
    const nonce_type drbg_nonce {};
    const additional_input_type personalization_string {};
    const additional_input_type additional_input_1 {};
    const additional_input_type additional_entropy_1 {};
    const additional_input_type additional_input_2 {};
    const additional_input_type additional_entropy_2 {};
    const result_type result {};
};


using test_vector_container_drbg_no_reseed = std::deque<test_object_drbg<test_type::drbg_no_reseed>>;
using test_vector_container_drbg_pr_false = std::deque<test_object_drbg<test_type::drbg_pr_false>>;
using test_vector_container_drbg_pr_true = std::deque<test_object_drbg<test_type::drbg_pr_true>>;

struct test_object_aes
{
public:
    using size_type             = std::size_t;
    using key_type              = std::vector<std::uint8_t>;
    using iv_type               = std::vector<std::uint8_t>;
    using plaintext_type        = std::vector<std::uint8_t>;
    using ciphertext_type       = std::vector<std::uint8_t>;

    test_object_aes() = delete;

    explicit test_object_aes (const std::string& key_input,
                              const std::string& plaintext_input,
                              const std::string& ciphertext_input)
            : key
                      {
                              [&key_input]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(key_input) };
                                  return key_type (byte_data.cbegin(),   byte_data.cend());
                              }()
                      },
              plaintext
                      {
                              [&plaintext_input]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(plaintext_input) };
                                  return plaintext_type (byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              ciphertext
                      {
                              [&ciphertext_input]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(ciphertext_input) };
                                  return ciphertext_type (byte_data.cbegin(), byte_data.cend());
                              }()
                      }
    { }

    explicit test_object_aes (const std::string& key_input,
                              const std::string& iv_input,
                              const std::string& plaintext_input,
                              const std::string& ciphertext_input)
            : key
                      {
                              [&key_input]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(key_input) };
                                  return key_type (byte_data.cbegin(),   byte_data.cend());
                              }()
                      },
              iv
                      {
                              [&iv_input]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(iv_input) };
                                  return iv_type (byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              plaintext
                      {
                              [&plaintext_input]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(plaintext_input) };
                                  return plaintext_type (byte_data.cbegin(), byte_data.cend());
                              }()
                      },
              ciphertext
                      {
                              [&ciphertext_input]()
                              {
                                  const auto byte_data { detail::convert_hex_string_to_byte_container(ciphertext_input) };
                                  return ciphertext_type (byte_data.cbegin(), byte_data.cend());
                              }()
                      }
    { }


    const key_type key {};
    const iv_type  iv {};
    const plaintext_type plaintext {};
    const ciphertext_type ciphertext {};
};

using test_vector_container_aes = std::deque<test_object_aes>;

auto where_file(const std::string& test_vectors_filename, test_type test) -> std::string
{
  // Try to open the file in each of the known relative paths
  // in order to find out where it is located.

    std::string folder_path;
    switch (test)
    {
        case test_type::sha:
            folder_path = "shabytesvectors/";
            break;
        case test_type::hmac:
            folder_path = "hmac/";
            break;
        case test_type::drbg_no_reseed:
        case test_type::drbg_pr_false:
        case test_type::drbg_pr_true:
            folder_path = "drbg/";
            break;
        case test_type::aes_kat:
        case test_type::aes_mct:
        case test_type::aes_mmt:
            folder_path = "aes/";
            break;
    }

    // Boost-root
    std::string test_vectors_filename_relative = "libs/crypt/test/nist_cavs/vectors/" + folder_path + test_vectors_filename;

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
        test_vectors_filename_relative = "nist_cavs/vectors/" + folder_path + test_vectors_filename;

        std::ifstream in_02(test_vectors_filename_relative.c_str());

        const bool file_02_is_open { in_02.is_open() };

        if(file_02_is_open)
        {
            in_02.close();
        }
        else
        {
            // test/cover
            test_vectors_filename_relative = "../nist_cavs/vectors/" + folder_path + test_vectors_filename;

            std::ifstream in_03(test_vectors_filename_relative.c_str());

            const bool file_03_is_open { in_03.is_open() };

            if(file_03_is_open)
            {
                in_03.close();
            }
            else
            {
                // CMake builds
                test_vectors_filename_relative = "../../../../libs/crypt/test/nist_cavs/vectors/" + folder_path + test_vectors_filename;

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
                        // Clion Cmake builds
                        test_vectors_filename_relative = "../../../libs/crypt/test/nist_cavs/vectors/" + folder_path + test_vectors_filename;

                        std::ifstream in_06(test_vectors_filename_relative.c_str());

                        const bool file_06_is_open { in_06.is_open() };
                        if (file_06_is_open)
                        {
                            in_06.close();
                        }
                        else
                        {
                            test_vectors_filename_relative = "";
                        }
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

  const std::string test_vectors_filename_relative { where_file(test_vectors_filename, test_type::sha) };

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

auto parse_file_vectors_hmac(const std::string& test_vectors_filename, test_vector_container_type& test_vectors_to_get) -> bool
{
    bool result_parse_is_ok { false };

    const std::string test_vectors_filename_relative { where_file(test_vectors_filename, test_type::hmac) };

    const bool result_filename_plausible_is_ok { (!test_vectors_filename_relative.empty()) };

    BOOST_TEST(result_filename_plausible_is_ok);

    if(result_filename_plausible_is_ok)
    {
        // Read the file for creating the test cases.
        std::ifstream in(test_vectors_filename_relative.c_str());

        const bool file_is_open = in.is_open();

        if(file_is_open)
        {
            result_parse_is_ok = true;

            std::string line    { };
            std::string message { };
            std::string result  { };
            std::string key     { };

            while(getline(in, line))
            {
                const std::string::size_type pos_key = line.find("Key =", 0U);
                const std::string::size_type pos_msg = line.find("Msg =", 0U);
                const std::string::size_type pos_md  = line.find("Mac =",  0U);

                const bool line_is_representation_is_key = (pos_key != std::string::npos);
                const bool line_is_representation_is_msg = (pos_msg != std::string::npos);
                const bool line_is_representation_is_md  = (pos_md  != std::string::npos);

                // Get the next key.
                if (line_is_representation_is_key)
                {
                    key = line.substr(6U, line.length() - 6U);
                }

                // Get the next message.
                if(line_is_representation_is_msg)
                {
                    message = line.substr(6U, line.length() - 6U);
                }

                // Get the next (expected) result.
                if(line_is_representation_is_md)
                {
                    result = line.substr(6U, line.length() - 6U);

                    // Use special handling for message = "00" with length = 0.
                    if((message == "00"))
                    {
                        message = "";
                    }

                    // Add the new test object to v.
                    const test_object_hash test_obj(key, message, result);

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

    const std::string test_vectors_filename_relative { where_file(test_vectors_filename, test_type::sha) };

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

  const std::string test_vectors_filename_relative { where_file(test_monte_filename, test_type::sha) };

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

    const std::string test_vectors_filename_relative { where_file(test_monte_filename, test_type::sha) };

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

template <test_type test>
auto parse_file_drbg(const std::string& test_vectors_filename, std::deque<test_object_drbg<test>>& test_vectors_to_get) -> bool;

template <>
auto parse_file_drbg<test_type::drbg_no_reseed>(const std::string& test_vectors_filename, test_vector_container_drbg_no_reseed& test_vectors_to_get) -> bool
{
    bool result_parse_is_ok { false };

    const std::string test_vectors_filename_relative { where_file(test_vectors_filename, test_type::drbg_no_reseed) };

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
            std::string line {};

            std::string entropy {};
            std::string nonce {};
            std::string personalization_string {};
            std::string additional_input_1 {};
            std::string additional_input_2 {};
            std::string returned_bits {};

            while(getline(in, line))
            {
                const auto pos_cnt = line.find("COUNT =", 0U);
                const auto pos_entropy_input = line.find("EntropyInput =", 0U);
                const auto pos_nonce = line.find("Nonce =", 0U);
                const auto pos_personalization_string = line.find("PersonalizationString =", 0U);
                const auto pos_additional_input = line.find("AdditionalInput =", 0U);
                const auto pos_returned_bits = line.find("ReturnedBits =", 0U);

                const bool line_is_representation_is_cnt = (pos_cnt != std::string::npos);
                const bool line_is_representation_is_entropy = (pos_entropy_input != std::string::npos);
                const bool line_is_representation_is_nonce  = (pos_nonce  != std::string::npos);
                const bool line_is_representation_is_personalization = (pos_personalization_string != std::string::npos);
                const bool line_is_representation_is_additional_input = (pos_additional_input != std::string::npos);
                const bool line_is_representation_is_returned_bits = (pos_returned_bits != std::string::npos);

                // Get the next count.
                if (line_is_representation_is_cnt)
                {
                    entropy = "";
                    nonce = "";
                    personalization_string = "";
                    additional_input_1 = "";
                    additional_input_2 = "";
                    returned_bits = "";

                    ++count;
                }
                else if (line_is_representation_is_entropy)
                {
                    entropy = line.substr(15U, line.length() - 15U);
                }
                else if (line_is_representation_is_nonce)
                {
                    nonce = line.substr(8U, line.length() - 8U);
                }
                else if (line_is_representation_is_personalization)
                {
                    if (line.size() >= 24U)
                    {
                        personalization_string = line.substr(24U, line.length() - 24U);
                    }
                }
                else if (line_is_representation_is_additional_input)
                {
                    if (line.size() >= 18U)
                    {
                        if (additional_input_1.empty())
                        {
                            additional_input_1 = line.substr(18U, line.length() - 18U);
                        }
                        else
                        {
                            additional_input_2 = line.substr(18U, line.length() - 18U);
                        }
                    }
                }
                else if (line_is_representation_is_returned_bits)
                {
                    returned_bits = line.substr(15U, line.length() - 15U);

                    // Add the new test object to v.
                    const test_object_drbg<test_type::drbg_no_reseed> test_obj(entropy, nonce, personalization_string, additional_input_1, additional_input_2, returned_bits);

                    test_vectors_to_get.push_back(test_obj);
                }
            }

            in.close();

            result_parse_is_ok = ((!test_vectors_to_get.empty()) && (count == 240U) && result_parse_is_ok);
        }
    }

    BOOST_TEST(result_parse_is_ok);

    return result_parse_is_ok;
}

template <>
auto parse_file_drbg<test_type::drbg_pr_false>(const std::string& test_vectors_filename, test_vector_container_drbg_pr_false& test_vectors_to_get) -> bool
{
    bool result_parse_is_ok { false };

    const std::string test_vectors_filename_relative { where_file(test_vectors_filename, test_type::drbg_pr_false) };

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
            std::string line {};

            std::string entropy {};
            std::string nonce {};
            std::string personalization_string {};
            std::string reseed_entropy {};
            std::string reseed_additional_input {};
            std::string additional_input_1 {};
            std::string additional_input_2 {};
            std::string returned_bits {};

            while(getline(in, line))
            {
                const auto pos_cnt = line.find("COUNT =", 0U);
                const auto pos_entropy_input = line.find("EntropyInput =", 0U);
                const auto pos_nonce = line.find("Nonce =", 0U);
                const auto pos_personalization_string = line.find("PersonalizationString =", 0U);
                const auto pos_entropy_input_reseed = line.find("EntropyInputReseed =", 0U);
                const auto pos_additional_input_reseed = line.find("AdditionalInputReseed =", 0U);
                const auto pos_additional_input = line.find("AdditionalInput =", 0U);
                const auto pos_returned_bits = line.find("ReturnedBits =", 0U);

                const bool line_is_representation_is_cnt = (pos_cnt != std::string::npos);
                const bool line_is_representation_is_entropy = (pos_entropy_input != std::string::npos);
                const bool line_is_representation_is_nonce  = (pos_nonce  != std::string::npos);
                const bool line_is_representation_is_personalization = (pos_personalization_string != std::string::npos);
                const bool line_is_representation_is_entropy_reseed = (pos_entropy_input_reseed != std::string::npos);
                const bool line_is_representation_is_additional_input_reseed = (pos_additional_input_reseed != std::string::npos);
                const bool line_is_representation_is_additional_input = (pos_additional_input != std::string::npos);
                const bool line_is_representation_is_returned_bits = (pos_returned_bits != std::string::npos);

                // Get the next count.
                if (line_is_representation_is_cnt)
                {
                    entropy = "";
                    nonce = "";
                    personalization_string = "";
                    reseed_entropy = "";
                    reseed_additional_input = "";
                    additional_input_1 = "";
                    additional_input_2 = "";
                    returned_bits = "";

                    ++count;
                }
                else if (line_is_representation_is_entropy)
                {
                    entropy = line.substr(15U, line.length() - 15U);
                }
                else if (line_is_representation_is_nonce)
                {
                    nonce = line.substr(8U, line.length() - 8U);
                }
                else if (line_is_representation_is_personalization)
                {
                    if (line.size() >= 24U)
                    {
                        personalization_string = line.substr(24U, line.length() - 24U);
                    }
                }
                else if (line_is_representation_is_entropy_reseed)
                {
                    reseed_entropy = line.substr(21U, line.length() - 21U);
                }
                else if (line_is_representation_is_additional_input_reseed)
                {
                    if (line.size() >= 24U)
                    {
                        reseed_additional_input = line.substr(24U, line.length() - 24U);
                    }
                }
                else if (line_is_representation_is_additional_input)
                {
                    if (line.size() >= 18U)
                    {
                        if (additional_input_1.empty())
                        {
                            additional_input_1 = line.substr(18U, line.length() - 18U);
                        }
                        else
                        {
                            additional_input_2 = line.substr(18U, line.length() - 18U);
                        }
                    }
                }
                else if (line_is_representation_is_returned_bits)
                {
                    returned_bits = line.substr(15U, line.length() - 15U);

                    // Add the new test object to v.
                    const test_object_drbg<test_type::drbg_pr_false> test_obj(entropy, nonce, personalization_string, reseed_entropy, reseed_additional_input, additional_input_1, additional_input_2, returned_bits);

                    test_vectors_to_get.push_back(test_obj);
                }
            }

            in.close();

            result_parse_is_ok = ((!test_vectors_to_get.empty()) && (count == 240U) && result_parse_is_ok);
        }
    }

    BOOST_TEST(result_parse_is_ok);

    return result_parse_is_ok;
}

template <>
auto parse_file_drbg<test_type::drbg_pr_true>(const std::string& test_vectors_filename, test_vector_container_drbg_pr_true & test_vectors_to_get) -> bool
{
    bool result_parse_is_ok { false };

    const std::string test_vectors_filename_relative { where_file(test_vectors_filename, test_type::drbg_pr_true) };

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
            std::string line {};

            std::string entropy {};
            std::string nonce {};
            std::string personalization_string {};
            std::string additional_input_1 {};
            std::string additional_entropy_1 {};
            std::string additional_input_2 {};
            std::string additional_entropy_2 {};
            std::string returned_bits {};

            while(getline(in, line))
            {
                const auto pos_cnt = line.find("COUNT =", 0U);
                const auto pos_entropy_input = line.find("EntropyInput =", 0U);
                const auto pos_nonce = line.find("Nonce =", 0U);
                const auto pos_personalization_string = line.find("PersonalizationString =", 0U);
                const auto pos_additional_input = line.find("AdditionalInput =", 0U);
                const auto pos_additional_entropy = line.find("EntropyInputPR =", 0U);
                const auto pos_returned_bits = line.find("ReturnedBits =", 0U);

                const bool line_is_representation_is_cnt = (pos_cnt != std::string::npos);
                const bool line_is_representation_is_entropy = (pos_entropy_input != std::string::npos);
                const bool line_is_representation_is_nonce  = (pos_nonce  != std::string::npos);
                const bool line_is_representation_is_personalization = (pos_personalization_string != std::string::npos);
                const bool line_is_representation_is_additional_input = (pos_additional_input != std::string::npos);
                const bool line_is_representation_is_additional_entropy = (pos_additional_entropy != std::string::npos);
                const bool line_is_representation_is_returned_bits = (pos_returned_bits != std::string::npos);

                // Get the next count.
                if (line_is_representation_is_cnt)
                {
                    entropy = "";
                    nonce = "";
                    personalization_string = "";
                    additional_input_1 = "";
                    additional_entropy_1 = "";
                    additional_input_2 = "";
                    additional_entropy_2 = "";
                    returned_bits = "";

                    ++count;
                }
                else if (line_is_representation_is_entropy)
                {
                    entropy = line.substr(15U, line.length() - 15U);
                }
                else if (line_is_representation_is_nonce)
                {
                    nonce = line.substr(8U, line.length() - 8U);
                }
                else if (line_is_representation_is_personalization)
                {
                    if (line.size() >= 24U)
                    {
                        personalization_string = line.substr(24U, line.length() - 24U);
                    }
                }
                else if (line_is_representation_is_additional_input)
                {
                    if (line.size() >= 18U)
                    {
                        if (additional_input_1.empty())
                        {
                            additional_input_1 = line.substr(18U, line.length() - 18U);
                        }
                        else
                        {
                            additional_input_2 = line.substr(18U, line.length() - 18U);
                        }
                    }
                }
                else if (line_is_representation_is_additional_entropy)
                {
                    if (additional_entropy_1.empty())
                    {
                        additional_entropy_1 = line.substr(17U, line.length() - 17U);
                    }
                    else
                    {
                        additional_entropy_2 = line.substr(17U, line.length() - 17U);
                    }
                }
                else if (line_is_representation_is_returned_bits)
                {
                    returned_bits = line.substr(15U, line.length() - 15U);

                    // Add the new test object to v.
                    const test_object_drbg<test_type::drbg_pr_true> test_obj(entropy, nonce, personalization_string, additional_input_1, additional_entropy_1, additional_input_2, additional_entropy_2, returned_bits);

                    test_vectors_to_get.push_back(test_obj);
                }
            }

            in.close();

            result_parse_is_ok = ((!test_vectors_to_get.empty()) && (count == 240U) && result_parse_is_ok);
        }
    }

    BOOST_TEST(result_parse_is_ok);

    return result_parse_is_ok;
}

auto parse_file_aes(const std::string& test_vectors_filename, std::deque<test_object_aes>& test_vectors_to_get) -> bool
{
    bool result_parse_is_ok { false };

    const std::string test_vectors_filename_relative { where_file(test_vectors_filename, test_type::aes_kat) };

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
            std::string line {};

            std::string key {};
            std::string iv {};
            std::string plaintext {};
            std::string ciphertext {};

            while(getline(in, line))
            {
                const auto pos_cnt = line.find("COUNT =", 0U);
                const auto pos_key = line.find("KEY =", 0U);
                const auto pos_iv = line.find("IV =", 0U);
                const auto pos_plaintext = line.find("PLAINTEXT =", 0U);
                const auto pos_ciphertext = line.find("CIPHERTEXT =", 0U);

                const bool line_is_representation_is_cnt = (pos_cnt != std::string::npos);
                const bool line_is_representation_is_key = (pos_key != std::string::npos);
                const bool line_is_representation_is_iv = (pos_iv != std::string::npos);
                const bool line_is_representation_is_plaintext  = (pos_plaintext  != std::string::npos);
                const bool line_is_representation_is_ciphertext = (pos_ciphertext != std::string::npos);

                // Get the next count.
                if (line_is_representation_is_cnt)
                {
                    ++count;
                }
                else if (line_is_representation_is_key)
                {
                    key = line.substr(6U, line.length() - 6U);
                }
                else if (line_is_representation_is_iv)
                {
                    iv = line.substr(5U, line.length() - 5U);
                }
                else if (line_is_representation_is_plaintext)
                {
                    plaintext = line.substr(12U, line.length() - 12U);
                }
                else if (line_is_representation_is_ciphertext)
                {
                    ciphertext = line.substr(13U, line.length() - 13U);
                }
                if (!plaintext.empty() && !ciphertext.empty())
                {
                    // Add the new test object to v.
                    const test_object_aes test_obj(key, iv, plaintext, ciphertext);

                    test_vectors_to_get.push_back(test_obj);

                    key.clear();
                    iv.clear();
                    plaintext.clear();
                    ciphertext.clear();
                }
            }

            in.close();

            result_parse_is_ok = ((!test_vectors_to_get.empty()) && count > 0U && result_parse_is_ok);
        }
    }

    BOOST_TEST(result_parse_is_ok);

    return result_parse_is_ok;
}

} // namespace detail

using detail::test_vector_container_type;
using detail::parse_file_vectors;
using detail::parse_file_monte;
using detail::parse_file_aes;
using detail::test_vector_container_drbg_no_reseed;
using detail::test_vector_container_drbg_pr_false;
using detail::test_vector_container_drbg_pr_true;
using detail::test_vector_container_aes;
using detail::test_type;

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

                for (auto& val : MDi)
                {
                    // LCOV skips the following line even though MDi is not empty
                    val = static_cast<std::uint8_t>(0); // LCOV_EXCL_LINE
                }

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


// See: https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/mac/hmacvs.pdf
template <typename HasherType>
auto test_vectors_hmac(const nist::cavs::test_vector_container_type& test_vectors) -> bool
{
    using local_hasher_type = HasherType;
    using local_result_type = typename local_hasher_type::return_type;

    BOOST_TEST((!test_vectors.empty()));

    bool result_is_ok { true };

    for(const auto& test_vector : test_vectors)
    {
        boost::crypt::hmac<HasherType> this_hash { };

        // Make pass 1 through the messages.
        // Use the triple-combination of init/process/get-result functions.

        this_hash.init(test_vector.my_key);

        this_hash.process_bytes(test_vector.my_msg.data(), test_vector.my_msg.size());

        const local_result_type result_01 { this_hash.get_digest() };

        const bool result_hash_01_is_ok { std::equal(test_vector.my_result.cbegin(), test_vector.my_result.cend(), result_01.cbegin()) };

        BOOST_TEST(result_hash_01_is_ok);

        // Make pass 2 through the messages.
        // Use the triple-combination of init/process/get-result functions.
        // Even though this is not required in CAVS testing, it is
        // done in order to ensure that the init() function properly
        // puts the hasher-object into its initialized state.

        this_hash.init(test_vector.my_key);

        this_hash.process_bytes(test_vector.my_msg);

        const local_result_type result_02 { this_hash.get_digest() };

        const bool result_hash_02_is_ok { std::equal(test_vector.my_result.cbegin(), test_vector.my_result.cend(), result_02.cbegin()) };

        BOOST_TEST(result_hash_02_is_ok);

        // Collect the combined results of pass 1 and pass 2.
        const bool result_hash_is_ok = (result_hash_01_is_ok && result_hash_02_is_ok);

        result_is_ok = (result_hash_is_ok && result_is_ok);
    }

    return result_is_ok;
}

template <typename DRBGType>
auto test_vectors_drbg_no_reseed(const nist::cavs::test_vector_container_drbg_no_reseed& test_vectors) -> bool
{
    BOOST_TEST(!test_vectors.empty());

    bool result_is_ok { true };

    std::size_t count {};
    for (const auto& test_vector : test_vectors)
    {
        DRBGType rng;
        rng.init(test_vector.initial_entropy.begin(), test_vector.initial_entropy.size(),
                 test_vector.drbg_nonce.begin(), test_vector.drbg_nonce.size(),
                 test_vector.personalization_string.begin(), test_vector.personalization_string.size());

        std::vector<boost::crypt::uint8_t> return_bits {};
        return_bits.resize(test_vector.result.size());

        rng.generate(return_bits.begin(), return_bits.size() * 8U,
                     test_vector.additional_input_1.begin(), test_vector.additional_input_1.size());

        rng.generate(return_bits.begin(), return_bits.size() * 8U,
                     test_vector.additional_input_2.begin(), test_vector.additional_input_2.size());

        for (boost::crypt::size_t i {}; i < return_bits.size(); ++i)
        {
            if (return_bits[i] != test_vector.result[i])
            {
                // LCOV_EXCL_START
                result_is_ok = false;
                std::cerr << "Error with vector: " << count
                          << "\nBeginning of entropy: " << std::to_string(test_vector.initial_entropy[0]) << ", "
                          << std::to_string(test_vector.initial_entropy[1]) << ", "
                          << std::to_string(test_vector.initial_entropy[2]) << std::endl;
                break;
                // LCOV_EXCL_STOP
            }
        }
        ++count;
    }

    return result_is_ok;
}

template <typename DRBGType>
auto test_vectors_drbg_pr_false(const nist::cavs::test_vector_container_drbg_pr_false & test_vectors) -> bool
{
    BOOST_TEST(!test_vectors.empty());

    bool result_is_ok { true };

    std::size_t count {};
    for (const auto& test_vector : test_vectors)
    {
        DRBGType rng;
        rng.init(test_vector.initial_entropy.begin(), test_vector.initial_entropy.size(),
                 test_vector.drbg_nonce.begin(), test_vector.drbg_nonce.size(),
                 test_vector.personalization_string.begin(), test_vector.personalization_string.size());

        rng.reseed(test_vector.reseed_entropy.begin(), test_vector.reseed_entropy.size(),
                   test_vector.reseed_additional_input.begin(), test_vector.reseed_additional_input.size());

        std::vector<boost::crypt::uint8_t> return_bits {};
        return_bits.resize(test_vector.result.size());

        rng.generate(return_bits.begin(), return_bits.size() * 8U,
                     test_vector.additional_input_1.begin(), test_vector.additional_input_1.size());

        rng.generate(return_bits.begin(), return_bits.size() * 8U,
                     test_vector.additional_input_2.begin(), test_vector.additional_input_2.size());

        for (boost::crypt::size_t i {}; i < return_bits.size(); ++i)
        {
            if (return_bits[i] != test_vector.result[i])
            {
                // LCOV_EXCL_START
                result_is_ok = false;
                std::cerr << "Error with vector: " << count
                          << "\nBeginning of entropy: " << std::to_string(test_vector.initial_entropy[0]) << ", "
                          << std::to_string(test_vector.initial_entropy[1]) << ", "
                          << std::to_string(test_vector.initial_entropy[2]) << std::endl;
                break;
                // LCOV_EXCL_STOP
            }
        }
        ++count;
    }

    return result_is_ok;
}

template <typename DRBGType>
auto test_vectors_drbg_pr_true(const nist::cavs::test_vector_container_drbg_pr_true & test_vectors) -> bool
{
    BOOST_TEST(!test_vectors.empty());

    bool result_is_ok { true };

    std::size_t count {};
    for (const auto& test_vector : test_vectors)
    {
        DRBGType rng;
        rng.init(test_vector.initial_entropy.begin(), test_vector.initial_entropy.size(),
                 test_vector.drbg_nonce.begin(), test_vector.drbg_nonce.size(),
                 test_vector.personalization_string.begin(), test_vector.personalization_string.size());

        std::vector<boost::crypt::uint8_t> return_bits {};
        return_bits.resize(test_vector.result.size());

        rng.generate(return_bits.begin(), return_bits.size() * 8U,
                     test_vector.additional_entropy_1.begin(), test_vector.additional_entropy_1.size(),
                     test_vector.additional_input_1.begin(), test_vector.additional_input_1.size());

        rng.generate(return_bits.begin(), return_bits.size() * 8U,
                     test_vector.additional_entropy_2.begin(), test_vector.additional_entropy_2.size(),
                     test_vector.additional_input_2.begin(), test_vector.additional_input_2.size());

        for (boost::crypt::size_t i {}; i < return_bits.size(); ++i)
        {
            if (return_bits[i] != test_vector.result[i])
            {
                // LCOV_EXCL_START
                result_is_ok = false;
                std::cerr << "Error with vector: " << count
                          << "\nBeginning of entropy: " << std::to_string(test_vector.initial_entropy[0]) << ", "
                          << std::to_string(test_vector.initial_entropy[1]) << ", "
                          << std::to_string(test_vector.initial_entropy[2]) << std::endl;
                break;
                // LCOV_EXCL_STOP
            }
        }
        ++count;
    }

    return result_is_ok;
}

template <boost::crypt::aes::cipher_mode mode, typename AESType>
auto test_vectors_aes_kat(const nist::cavs::test_vector_container_aes& test_vectors) -> bool
{
    BOOST_TEST(!test_vectors.empty());

    bool result_is_ok { true };

    std::size_t count {};
    for (const auto& test_vector : test_vectors)
    {
        auto plaintext {test_vector.plaintext};
        auto ciphertext {test_vector.ciphertext};

        AESType aes;
        if (mode == boost::crypt::aes::cipher_mode::ecb)
        {
            aes.init(test_vector.key.begin(), test_vector.key.size());
        }

        if (count < 8)
        {
            // Encrypt Path
            aes.template encrypt<mode>(plaintext.begin(), plaintext.size());
        }
        else
        {
            // Decrypt Path
            aes.template decrypt<mode>(ciphertext.begin(), ciphertext.size());
        }

        if (plaintext != ciphertext)
        {
            // LCOV_EXCL_START
            result_is_ok = false;
            std::cerr << "Error with vector: " << count << std::endl;
            // LCOV_EXCL_STOP
        }

        ++count;
    }

    return result_is_ok;
}

} // namespace cavs
} // namespace nist

#endif // BOOST_CRYPT_TEST_NIST_CAVS_DETAIL_HPP
