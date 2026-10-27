// Unit tests of the internal AES Key Wrap primitives (ekicore::aes_256_key_wrap and
// aes_256_key_unwrap): the RFC 3394 vector for a 256-bit KEK and 256 bits of key data, integrity
// failures, size checks, zero-on-failure and the caller's OpenSSL error queue.

#include "error_queue_support.hpp"

#include <ekicore/primitives.hpp>

#include <gtest/gtest.h>

#include <ekicore.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

// GoogleTest assertion macros expand to branches, which inflates the cognitive complexity score of
// table-driven tests well past the threshold without making them harder to read.
// NOLINTBEGIN(readability-function-cognitive-complexity)
namespace {

using bytes = std::vector<std::uint8_t>;

std::uint8_t nibble(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint8_t>(c - '0');
  }
  return static_cast<std::uint8_t>(c - 'A' + 10);
}

bytes unhex(std::string_view hex) {
  bytes out(hex.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    const auto high = static_cast<unsigned>(nibble(hex.at(2 * i)));
    const auto low = static_cast<unsigned>(nibble(hex.at((2 * i) + 1)));
    out.at(i) = static_cast<std::uint8_t>((high << 4U) | low);
  }
  return out;
}

bool all_equal(std::span<const std::uint8_t> buf, std::uint8_t value) {
  return std::ranges::all_of(buf, [value](std::uint8_t b) { return b == value; });
}

constexpr std::uint8_t fill = 0xA5;

// RFC 3394 section 4.6: wrap 256 bits of key data with a 256-bit KEK.
constexpr std::string_view rfc3394_kek =
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
constexpr std::string_view rfc3394_key =
    "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
constexpr std::string_view rfc3394_blob =
    "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";

using blob_array = std::array<std::uint8_t, EKI_WRAPPED_KEY_LEN>;
using key_array = std::array<std::uint8_t, 32>;

TEST(PrimitivesKeywrap, Rfc3394Section4_6Wrap) {
  const bytes kek = unhex(rfc3394_kek);
  const bytes key = unhex(rfc3394_key);
  blob_array out{};
  out.fill(fill);
  ASSERT_EQ(ekicore::aes_256_key_wrap(kek, key, out), EKI_OK);
  const bytes expected = unhex(rfc3394_blob);
  EXPECT_TRUE(std::ranges::equal(out, expected));
}

TEST(PrimitivesKeywrap, Rfc3394Section4_6Unwrap) {
  const bytes kek = unhex(rfc3394_kek);
  const bytes blob = unhex(rfc3394_blob);
  key_array out{};
  out.fill(fill);
  ASSERT_EQ(ekicore::aes_256_key_unwrap(kek, blob, out), EKI_OK);
  const bytes expected = unhex(rfc3394_key);
  EXPECT_TRUE(std::ranges::equal(out, expected));
}

// Every bit of the blob is covered by the integrity check; the output is zero after each failure.
TEST(PrimitivesKeywrap, FlippedBlobIsAuthFailedWithZeroedOutput) {
  const bytes kek = unhex(rfc3394_kek);
  const bytes blob = unhex(rfc3394_blob);
  for (std::size_t i = 0; i < blob.size(); ++i) {
    for (unsigned bit = 0; bit < 8; ++bit) {
      bytes bad = blob;
      bad.at(i) = static_cast<std::uint8_t>(bad.at(i) ^ (1U << bit));
      key_array out{};
      out.fill(fill);
      EXPECT_EQ(ekicore::aes_256_key_unwrap(kek, bad, out), EKI_ERR_AUTH_FAILED)
          << "byte " << i << " bit " << bit;
      EXPECT_TRUE(all_equal(out, 0)) << "byte " << i << " bit " << bit;
    }
  }
}

TEST(PrimitivesKeywrap, WrongKekIsAuthFailedWithZeroedOutput) {
  bytes kek = unhex(rfc3394_kek);
  kek.back() = static_cast<std::uint8_t>(kek.back() ^ 1U);
  const bytes blob = unhex(rfc3394_blob);
  key_array out{};
  out.fill(fill);
  EXPECT_EQ(ekicore::aes_256_key_unwrap(kek, blob, out), EKI_ERR_AUTH_FAILED);
  EXPECT_TRUE(all_equal(out, 0));
}

// A wrong input size gives INVALID_ARGUMENT and zeroes an output of the right size; an output of
// the wrong size is left untouched.
TEST(PrimitivesKeywrap, WrongSizesAreInvalid) {
  const bytes kek = unhex(rfc3394_kek);
  const bytes key = unhex(rfc3394_key);
  const bytes blob = unhex(rfc3394_blob);
  for (const std::size_t size :
       {std::size_t{0}, std::size_t{16}, std::size_t{31}, std::size_t{33}, std::size_t{64}}) {
    SCOPED_TRACE(size);
    const bytes other(size, 0x42);
    blob_array wrapped{};
    wrapped.fill(fill);
    EXPECT_EQ(ekicore::aes_256_key_wrap(other, key, wrapped), EKI_ERR_INVALID_ARGUMENT) << "kek";
    EXPECT_TRUE(all_equal(wrapped, 0));
    wrapped.fill(fill);
    EXPECT_EQ(ekicore::aes_256_key_wrap(kek, other, wrapped), EKI_ERR_INVALID_ARGUMENT) << "key";
    EXPECT_TRUE(all_equal(wrapped, 0));
    key_array unwrapped{};
    unwrapped.fill(fill);
    EXPECT_EQ(ekicore::aes_256_key_unwrap(other, blob, unwrapped), EKI_ERR_INVALID_ARGUMENT)
        << "kek";
    EXPECT_TRUE(all_equal(unwrapped, 0));
  }
  for (const std::size_t size :
       {std::size_t{0}, std::size_t{32}, std::size_t{39}, std::size_t{41}, std::size_t{48}}) {
    SCOPED_TRACE(size);
    const bytes other(size, 0x42);
    key_array unwrapped{};
    unwrapped.fill(fill);
    EXPECT_EQ(ekicore::aes_256_key_unwrap(kek, other, unwrapped), EKI_ERR_INVALID_ARGUMENT)
        << "blob";
    EXPECT_TRUE(all_equal(unwrapped, 0));
    bytes out(size, fill);
    EXPECT_EQ(ekicore::aes_256_key_wrap(kek, key, out), EKI_ERR_INVALID_ARGUMENT) << "out";
    EXPECT_TRUE(all_equal(out, fill));
  }
  for (const std::size_t size : {std::size_t{0}, std::size_t{31}, std::size_t{33}}) {
    SCOPED_TRACE(size);
    bytes out(size, fill);
    EXPECT_EQ(ekicore::aes_256_key_unwrap(kek, blob, out), EKI_ERR_INVALID_ARGUMENT) << "out";
    EXPECT_TRUE(all_equal(out, fill));
  }
}

// The key store allows wrapping a KEK under itself, so the two inputs may be the same memory.
TEST(PrimitivesKeywrap, SelfWrapRoundTrips) {
  const bytes kek = unhex(rfc3394_kek);
  blob_array wrapped{};
  ASSERT_EQ(ekicore::aes_256_key_wrap(kek, kek, wrapped), EKI_OK);
  key_array unwrapped{};
  ASSERT_EQ(ekicore::aes_256_key_unwrap(kek, wrapped, unwrapped), EKI_OK);
  EXPECT_TRUE(std::ranges::equal(unwrapped, kek));
}

TEST(PrimitivesKeywrap, CallersErrorQueueIsLeftAlone) {
  const bytes kek = unhex(rfc3394_kek);
  const bytes key = unhex(rfc3394_key);
  bytes blob = unhex(rfc3394_blob);
  blob_array wrapped{};
  key_array unwrapped{};

  unsigned long caller = eki_test::push_caller_error();
  EXPECT_EQ(ekicore::aes_256_key_wrap(kek, key, wrapped), EKI_OK);
  EXPECT_EQ(ekicore::aes_256_key_unwrap(kek, blob, unwrapped), EKI_OK);
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "success";

  blob.at(5) = static_cast<std::uint8_t>(blob.at(5) ^ 1U);
  caller = eki_test::push_caller_error();
  EXPECT_EQ(ekicore::aes_256_key_unwrap(kek, blob, unwrapped), EKI_ERR_AUTH_FAILED);
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "integrity failure";

  caller = eki_test::push_caller_error();
  EXPECT_EQ(ekicore::aes_256_key_unwrap(kek, std::span(blob).first(39), unwrapped),
            EKI_ERR_INVALID_ARGUMENT);
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "wrong size";
}

} // namespace
// NOLINTEND(readability-function-cognitive-complexity)
