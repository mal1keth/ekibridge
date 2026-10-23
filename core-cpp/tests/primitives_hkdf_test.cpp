// Unit tests of the internal HKDF-SHA256 primitive (ekicore::hkdf_sha256): RFC 5869 vectors and
// the HKDF rows of the ABI error matrix.

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

namespace {

using bytes = std::vector<std::uint8_t>;

std::uint8_t nibble(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint8_t>(c - '0');
  }
  return static_cast<std::uint8_t>(c - 'a' + 10);
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

struct hkdf_vector {
  std::string_view section;
  std::string_view ikm;
  std::string_view salt;
  std::string_view info;
  std::string_view okm; // L is the length of okm
};

// RFC 5869 appendix A.1 to A.3 (the SHA-256 cases). A.3 has empty salt and info.
constexpr auto rfc5869 = std::to_array<hkdf_vector>({
    {
        .section = "A.1",
        .ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .salt = "000102030405060708090a0b0c",
        .info = "f0f1f2f3f4f5f6f7f8f9",
        .okm =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    },
    {
        .section = "A.2",
        .ikm =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a"
            "2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        .salt =
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a"
            "8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        .info =
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9da"
            "dbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .okm =
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41"
            "c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    },
    {
        .section = "A.3",
        .ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .salt = "",
        .info = "",
        .okm =
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    },
});

TEST(PrimitivesHkdf, Rfc5869Vectors) {
  for (const auto& v : rfc5869) {
    SCOPED_TRACE(v.section);
    const bytes expected = unhex(v.okm);
    bytes okm(expected.size(), fill);
    ASSERT_EQ(ekicore::hkdf_sha256(unhex(v.ikm), unhex(v.salt), unhex(v.info), okm), EKI_OK);
    EXPECT_EQ(okm, expected);
  }
}

TEST(PrimitivesHkdf, EmptySaltIsTheRfcDefault) {
  // RFC 5869 section 2.2: an absent salt is HashLen zero bytes.
  const bytes ikm = unhex(rfc5869.at(0).ikm);
  const bytes zeros(32, 0);
  bytes with_default(42);
  bytes with_zeros(42);
  ASSERT_EQ(ekicore::hkdf_sha256(ikm, {}, {}, with_default), EKI_OK);
  ASSERT_EQ(ekicore::hkdf_sha256(ikm, zeros, {}, with_zeros), EKI_OK);
  EXPECT_EQ(with_default, with_zeros);
}

TEST(PrimitivesHkdf, ShorterOutputIsAPrefix) {
  const hkdf_vector& v = rfc5869.at(1);
  const bytes expected = unhex(v.okm);
  for (const std::size_t len :
       {std::size_t{1}, std::size_t{31}, std::size_t{32}, std::size_t{33}}) {
    SCOPED_TRACE(len);
    bytes okm(len);
    ASSERT_EQ(ekicore::hkdf_sha256(unhex(v.ikm), unhex(v.salt), unhex(v.info), okm), EKI_OK);
    EXPECT_TRUE(std::equal(okm.begin(), okm.end(), expected.begin()));
  }
}

TEST(PrimitivesHkdf, LimitsAreInclusive) {
  const bytes max_input(EKI_HKDF_MAX_INPUT_LEN, 0x42);
  bytes okm(EKI_HKDF_MAX_OKM_LEN, fill);
  EXPECT_EQ(ekicore::hkdf_sha256(max_input, max_input, max_input, okm), EKI_OK);
  EXPECT_FALSE(all_equal(okm, fill));
  bytes one(1);
  EXPECT_EQ(ekicore::hkdf_sha256(std::span(max_input).first(1), {}, {}, one), EKI_OK);
}

struct invalid_row {
  const char* name;
  std::size_t ikm_len;
  std::size_t salt_len;
  std::size_t info_len;
  std::size_t okm_len;
};

TEST(PrimitivesHkdf, InvalidLengthsZeroOutputInRange) {
  constexpr std::size_t over = EKI_HKDF_MAX_INPUT_LEN + 1;
  constexpr std::size_t okm_over = EKI_HKDF_MAX_OKM_LEN + 1;
  const auto rows = std::to_array<invalid_row>({
      {.name = "ikm_len 0", .ikm_len = 0, .salt_len = 0, .info_len = 0, .okm_len = 42},
      {.name = "ikm_len 32769", .ikm_len = over, .salt_len = 0, .info_len = 0, .okm_len = 42},
      {.name = "salt_len 32769", .ikm_len = 22, .salt_len = over, .info_len = 0, .okm_len = 42},
      {.name = "info_len 32769", .ikm_len = 22, .salt_len = 0, .info_len = over, .okm_len = 42},
      {.name = "okm_len 0", .ikm_len = 22, .salt_len = 0, .info_len = 0, .okm_len = 0},
      {.name = "okm_len 8161", .ikm_len = 22, .salt_len = 0, .info_len = 0, .okm_len = okm_over},
  });
  const bytes source(over, 0x0b);
  for (const auto& row : rows) {
    SCOPED_TRACE(row.name);
    const auto input = [&source](std::size_t len) { return std::span(source).first(len); };
    bytes okm(row.okm_len, fill);
    EXPECT_EQ(
        ekicore::hkdf_sha256(input(row.ikm_len), input(row.salt_len), input(row.info_len), okm),
        EKI_ERR_INVALID_ARGUMENT);
    // An okm length outside 1..=8160 is not a valid output length, so it is left untouched.
    const bool in_range = row.okm_len >= 1 && row.okm_len <= EKI_HKDF_MAX_OKM_LEN;
    EXPECT_TRUE(all_equal(okm, in_range ? std::uint8_t{0} : fill));
  }
}

// HKDF has no error_scope: its only failures after an OpenSSL call are BACKEND. A successful
// derivation, and a length rejected before any OpenSSL call, leave the queue as found.
TEST(PrimitivesHkdf, CallersErrorQueueIsLeftAlone) {
  const bytes ikm(22, 0x0b);
  bytes okm(42);
  unsigned long caller = eki_test::push_caller_error();
  EXPECT_EQ(ekicore::hkdf_sha256(ikm, {}, {}, okm), EKI_OK);
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "success";

  caller = eki_test::push_caller_error();
  EXPECT_EQ(ekicore::hkdf_sha256({}, {}, {}, okm), EKI_ERR_INVALID_ARGUMENT);
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "empty ikm";
}

} // namespace
