// Smoke test: the library loads, answers the metadata calls, and computes one HMAC end to end.

#include <gtest/gtest.h>

#include <ekicore.h>

#include <array>
#include <cstdint>
#include <string_view>

namespace {

TEST(Smoke, AbiVersionIsOne) {
  EXPECT_EQ(eki_abi_version(), 1U);
}

TEST(Smoke, VersionNamesTheImplementation) {
  const std::string_view version{eki_version()};
  EXPECT_TRUE(version.starts_with("ekicore-cpp 0.1.0")) << version;
}

TEST(Smoke, StatusNames) {
  EXPECT_STREQ(eki_status_name(0), "EKI_OK");
  EXPECT_STREQ(eki_status_name(10), "EKI_ERR_INTERNAL");
}

TEST(Smoke, UnknownStatusValuesShareOneName) {
  EXPECT_STREQ(eki_status_name(11), "EKI_STATUS_UNKNOWN");
  EXPECT_STREQ(eki_status_name(-1), "EKI_STATUS_UNKNOWN");
}

// RFC 4231 test case 1 through the C ABI.
TEST(Smoke, HmacSha256Rfc4231Case1) {
  std::array<std::uint8_t, 20> key{};
  key.fill(0x0b);
  constexpr std::string_view msg = "Hi There";
  constexpr std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> expected{
      0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
      0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
      0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
  };
  std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> out{};
  out.fill(0xA5);
  EXPECT_EQ(eki_hmac_sha256(key.data(), key.size(),
                            reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size(),
                            out.data()),
            EKI_OK);
  EXPECT_EQ(out, expected);
}

} // namespace
