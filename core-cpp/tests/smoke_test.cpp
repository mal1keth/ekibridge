// Smoke test: the library loads, answers the metadata calls, and the stubs report UNSUPPORTED.

#include <gtest/gtest.h>

#include <ekicore.h>

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

// Replaced by real checks when HMAC is implemented (lesson L2).
TEST(Smoke, StubReturnsUnsupported) {
  EXPECT_EQ(eki_hmac_sha256(nullptr, 0, nullptr, 0, nullptr), EKI_ERR_UNSUPPORTED);
}

} // namespace
