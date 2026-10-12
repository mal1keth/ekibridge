// Unit tests of the internal HMAC-SHA256 primitive (ekicore::hmac_sha256 and _verify): RFC 4231
// vectors and the HMAC rows of the ABI error matrix.

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

struct hmac_vector {
  std::string_view section;
  std::string_view key;
  std::string_view data;
  std::string_view mac; // test case 5 publishes only the first 16 bytes
};

// RFC 4231 section 4.2 to 4.8, HMAC-SHA-256 lines.
constexpr auto rfc4231 = std::to_array<hmac_vector>({
    {
        .section = "4.2 test case 1",
        .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .data = "4869205468657265",
        .mac = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    },
    {
        .section = "4.3 test case 2",
        .key = "4a656665",
        .data = "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        .mac = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    },
    {
        .section = "4.4 test case 3",
        .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .data =
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            "dddddddddddddd",
        .mac = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    },
    {
        .section = "4.5 test case 4",
        .key = "0102030405060708090a0b0c0d0e0f10111213141516171819",
        .data =
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
            "cdcdcdcdcdcdcd",
        .mac = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    },
    {
        .section = "4.6 test case 5",
        .key = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        .data = "546573742057697468205472756e636174696f6e",
        .mac = "a3b6167473100ee06e0c796c2955552b",
    },
    {
        .section = "4.7 test case 6",
        .key =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaa",
        .data =
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d20486173"
            "68204b6579204669727374",
        .mac = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    },
    {
        .section = "4.8 test case 7",
        .key =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaa",
        .data =
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d7369"
            "7a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e2054"
            "6865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e672075736564"
            "2062792074686520484d414320616c676f726974686d2e",
        .mac = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    },
});

TEST(PrimitivesHmac, Rfc4231Vectors) {
  for (const auto& v : rfc4231) {
    SCOPED_TRACE(v.section);
    const bytes key = unhex(v.key);
    const bytes data = unhex(v.data);
    const bytes expected = unhex(v.mac);
    std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> out{};
    ASSERT_EQ(ekicore::hmac_sha256(key, data, out), EKI_OK);
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), out.begin()));
    if (expected.size() == out.size()) {
      EXPECT_EQ(ekicore::hmac_sha256_verify(key, data, expected), EKI_OK);
    }
  }
}

TEST(PrimitivesHmac, EmptyKeyIsInvalidAndZeroesOutput) {
  const bytes msg = unhex("00010203");
  std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> out{};
  out.fill(fill);
  EXPECT_EQ(ekicore::hmac_sha256({}, msg, out), EKI_ERR_INVALID_ARGUMENT);
  EXPECT_TRUE(all_equal(out, 0));
}

TEST(PrimitivesHmac, EmptyMessageIsOk) {
  const bytes key = unhex("0b0b0b0b");
  std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> from_null{};
  std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> from_non_null{};
  const std::uint8_t dummy = 0;
  ASSERT_EQ(ekicore::hmac_sha256(key, {}, from_null), EKI_OK);
  ASSERT_EQ(ekicore::hmac_sha256(key, std::span<const std::uint8_t>(&dummy, 0), from_non_null),
            EKI_OK);
  EXPECT_EQ(from_null, from_non_null);
  EXPECT_FALSE(all_equal(from_null, 0));
  EXPECT_EQ(ekicore::hmac_sha256_verify(key, {}, from_null), EKI_OK);
}

TEST(PrimitivesHmac, WrongOutputSizeIsInvalidAndUntouched) {
  const bytes key = unhex("0b0b0b0b");
  for (const std::size_t size : {std::size_t{0}, std::size_t{31}, std::size_t{33}}) {
    SCOPED_TRACE(size);
    bytes out(size, fill);
    EXPECT_EQ(ekicore::hmac_sha256(key, {}, out), EKI_ERR_INVALID_ARGUMENT);
    EXPECT_TRUE(all_equal(out, fill));
  }
}

TEST(PrimitivesHmac, VerifyRejectsBadLengths) {
  const bytes key = unhex(rfc4231.at(0).key);
  const bytes data = unhex(rfc4231.at(0).data);
  const bytes tag = unhex(rfc4231.at(0).mac);
  EXPECT_EQ(ekicore::hmac_sha256_verify({}, data, tag), EKI_ERR_INVALID_ARGUMENT);
  EXPECT_EQ(ekicore::hmac_sha256_verify(key, data, std::span(tag).first(31)),
            EKI_ERR_INVALID_ARGUMENT);
  EXPECT_EQ(ekicore::hmac_sha256_verify(key, data, {}), EKI_ERR_INVALID_ARGUMENT);
  bytes longer = tag;
  longer.push_back(0);
  EXPECT_EQ(ekicore::hmac_sha256_verify(key, data, longer), EKI_ERR_INVALID_ARGUMENT);
  // Key length is checked before tag length.
  EXPECT_EQ(ekicore::hmac_sha256_verify({}, data, {}), EKI_ERR_INVALID_ARGUMENT);
}

TEST(PrimitivesHmac, VerifyRejectsAnyFlippedBit) {
  const bytes key = unhex(rfc4231.at(1).key);
  const bytes data = unhex(rfc4231.at(1).data);
  const bytes tag = unhex(rfc4231.at(1).mac);
  ASSERT_EQ(ekicore::hmac_sha256_verify(key, data, tag), EKI_OK);
  for (std::size_t i = 0; i < tag.size(); ++i) {
    for (unsigned bit = 0; bit < 8; ++bit) {
      bytes bad = tag;
      bad.at(i) = static_cast<std::uint8_t>(bad.at(i) ^ (1U << bit));
      EXPECT_EQ(ekicore::hmac_sha256_verify(key, data, bad), EKI_ERR_AUTH_FAILED)
          << "byte " << i << " bit " << bit;
    }
  }
}

TEST(PrimitivesHmac, VerifyRejectsOtherMessageAndKey) {
  const bytes key = unhex(rfc4231.at(1).key);
  const bytes data = unhex(rfc4231.at(1).data);
  const bytes tag = unhex(rfc4231.at(1).mac);
  bytes other_data = data;
  other_data.pop_back();
  EXPECT_EQ(ekicore::hmac_sha256_verify(key, other_data, tag), EKI_ERR_AUTH_FAILED);
  bytes other_key = key;
  other_key.back() = static_cast<std::uint8_t>(other_key.back() ^ 1U);
  EXPECT_EQ(ekicore::hmac_sha256_verify(other_key, data, tag), EKI_ERR_AUTH_FAILED);
  // HMAC zero-pads short keys to the block size, so appending zero bytes gives the same key.
  bytes padded_key = key;
  padded_key.push_back(0);
  EXPECT_EQ(ekicore::hmac_sha256_verify(padded_key, data, tag), EKI_OK);
}

TEST(PrimitivesHmac, LongMessageRoundTrip) {
  // A message spanning many SHA-256 blocks verifies, and the tag depends on its last byte.
  const bytes key = unhex("000102030405060708090a0b0c0d0e0f");
  bytes msg(100000);
  for (std::size_t i = 0; i < msg.size(); ++i) {
    msg.at(i) = static_cast<std::uint8_t>(i * 31U);
  }
  std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> tag{};
  ASSERT_EQ(ekicore::hmac_sha256(key, msg, tag), EKI_OK);
  EXPECT_EQ(ekicore::hmac_sha256_verify(key, msg, tag), EKI_OK);
  msg.back() = static_cast<std::uint8_t>(msg.back() ^ 1U);
  EXPECT_EQ(ekicore::hmac_sha256_verify(key, msg, tag), EKI_ERR_AUTH_FAILED);
}

} // namespace
