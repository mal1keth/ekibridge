// Key lifecycle and dual control through the C ABI on the software backend (ABI 2 contract sections
// 3, 4, 6 and 7). The same scenarios run on a token in ffi_lifecycle_pkcs11_test.cpp.

#include "lifecycle_support.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <ekicore.h>

#include <array>
#include <cstdint>
#include <string>

namespace {

using eki_test::name;
using eki_test::software_config;
namespace lifecycle = eki_test::lifecycle;

TEST(FfiLifecycle, StateTable) {
  lifecycle::state_table(software_config());
}

TEST(FfiLifecycle, CheckOrder) {
  lifecycle::check_order(software_config());
}

TEST(FfiLifecycle, GetInfoV2) {
  lifecycle::info_v2_rows(software_config());
}

TEST(FfiLifecycle, DualControl) {
  lifecycle::dual_control(software_config());
}

TEST(FfiLifecycle, NoApprovers) {
  lifecycle::no_approvers(software_config());
}

TEST(FfiLifecycle, OpenV2Rows) {
  lifecycle::open_v2_rows(software_config());
}

TEST(FfiLifecycle, NullRows) {
  lifecycle::null_rows(software_config());
}

// eki_ks_open equals eki_ks_open_v2 with no log and no approvers: same answers for the selector,
// and the PKCS#11 fields are ignored for the software backend by both.
TEST(FfiLifecycle, OpenIsOpenV2WithoutLogAndApprovers) {
  eki_ks_config v1 = software_config();
  v1.pkcs11_token_label = "";
  eki_ks_config bad_selector = software_config();
  bad_selector.backend = 99;
  EXPECT_TRUE(eki_test::open_fails(bad_selector, EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(lifecycle::open_v2_fails(lifecycle::widen(bad_selector), EKI_ERR_INVALID_ARGUMENT));
  eki_test::Store store;
  ASSERT_TRUE(store.open(v1));
  EXPECT_TRUE(lifecycle::open_v2_succeeds(lifecycle::widen(v1)));
  // A handle from eki_ks_open has neither a log nor approvers.
  std::array<std::uint8_t, EKI_AUDIT_HASH_LEN> hash{};
  std::uint64_t seq = 0;
  EKI_EXPECT_STATUS(eki_ks_audit_head(store.get(), hash.data(), &seq), EKI_ERR_UNSUPPORTED);
  eki_key_id id{};
  ASSERT_TRUE(store.generate(EKI_KEY_AES_256, "v1", id));
  std::array<std::uint8_t, EKI_DESTROY_REQUEST_LEN> request{};
  EKI_EXPECT_STATUS(eki_ks_destroy_request(store.get(), &id, request.data()), EKI_ERR_UNSUPPORTED);
  // The lifecycle functions work on it, and its keys are ACTIVE.
  eki_key_info_v2 info{};
  EKI_EXPECT_STATUS(eki_ks_get_info_v2(store.get(), &id, &info), EKI_OK);
  EXPECT_EQ(info.state, EKI_KEY_STATE_ACTIVE);
  EKI_EXPECT_STATUS(eki_ks_revoke(store.get(), &id), EKI_OK);
  EKI_EXPECT_STATUS(eki_ks_get_info_v2(store.get(), &id, &info), EKI_OK);
  EXPECT_EQ(info.state, EKI_KEY_STATE_REVOKED);
}

// Without EKI_WITH_PKCS11 the selector names a backend that is not compiled in: UNSUPPORTED
// before any field is looked at, by both open functions.
TEST(FfiLifecycle, OpenV2Pkcs11Selector) {
  if (eki_test::kWithPkcs11) {
    GTEST_SKIP() << "built with EKI_WITH_PKCS11: the PKCS#11 rows run on a token";
  }
  eki_ks_config v1 = software_config();
  v1.backend = EKI_KS_PKCS11;
  EXPECT_TRUE(lifecycle::open_v2_fails(lifecycle::widen(v1, "", nullptr, 2), EKI_ERR_UNSUPPORTED));
}

// Every status value ABI version 2 adds has its name; the next ones are unknown.
TEST(FfiLifecycle, StatusNames) {
  EXPECT_EQ(std::string{eki_status_name(11)}, "EKI_ERR_KEY_STATE");
  EXPECT_EQ(std::string{eki_status_name(12)}, "EKI_ERR_APPROVAL_REQUIRED");
  EXPECT_EQ(std::string{eki_status_name(13)}, "EKI_STATUS_UNKNOWN");
  EXPECT_EQ(std::string{eki_status_name(99)}, "EKI_STATUS_UNKNOWN");
  EXPECT_EQ(eki_abi_version(), 2U);
}

} // namespace
