// The PKCS#11 key store through the C ABI. Disabled until lesson L7 (pkcs11.cpp). Mirrors
// core-rs/tests/ffi_keystore_pkcs11.rs: plan §4.4 ks_open (PKCS#11) and every store row; §4.3
// object mapping and lifecycle.
//
// Needs a token: `source scripts/softhsm-init.sh` exports EKI_PKCS11_MODULE,
// EKI_PKCS11_TOKEN_LABEL and EKI_PKCS11_PIN; when any is unset the tests are skipped. Within this
// process the tests are serialised by one mutex (C_Initialize and the login state are per
// process), every store is closed before its test ends, and keys a test creates are destroyed by
// the Store guard. Separate ctest processes must not run them in parallel either: the ctest
// property RESOURCE_LOCK softhsm belongs on these tests.

#include "test_support.hpp"

#include <gtest/gtest.h>

#include <ekicore.h>

#include <cstdlib>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace {

using eki_test::bytes;
using eki_test::info_is;
using eki_test::label_of_len;
using eki_test::name;
using eki_test::open_fails;
using eki_test::Store;
using eki_test::try_open;
namespace scenarios = eki_test::scenarios;

// Token parameters from the environment.
struct Token {
  std::string module;
  std::string label;
  std::string pin;

  [[nodiscard]] eki_ks_config config() const {
    return eki_ks_config{
        .backend = EKI_KS_PKCS11,
        .pkcs11_module_path = module.c_str(),
        .pkcs11_token_label = label.c_str(),
        .pkcs11_user_pin = pin.c_str(),
    };
  }
};

std::optional<std::string> env(const char* variable) {
  // NOLINTNEXTLINE(concurrency-mt-unsafe): read while holding the token mutex; nothing sets it.
  const char* value = std::getenv(variable);
  if (value == nullptr || *value == '\0') {
    return std::nullopt;
  }
  return std::string{value};
}

std::optional<Token> token_from_env() {
  auto module = env("EKI_PKCS11_MODULE");
  auto label = env("EKI_PKCS11_TOKEN_LABEL");
  auto pin = env("EKI_PKCS11_PIN");
  if (!module || !label || !pin) {
    return std::nullopt;
  }
  return Token{.module = *module, .label = *label, .pin = *pin};
}

std::mutex& token_mutex() {
  static std::mutex mutex;
  return mutex;
}

// Holds the token mutex for the whole test and skips when no token is configured. Tests that need
// a store open one with ASSERT_TRUE(open_store()). The open-failure tests deliberately run with no
// other handle open: while any handle of this process is logged in, C_Login answers
// CKR_USER_ALREADY_LOGGED_IN, which §4.3 maps to "proceed", so a wrong PIN would not be noticed.
// Members are destroyed in reverse order: the store closes before the lock is released.
class FfiKeystorePkcs11 : public testing::Test {
protected:
  void SetUp() override {
    lock_ = std::unique_lock<std::mutex>(token_mutex());
    std::optional<Token> from_env = token_from_env();
    if (!from_env) {
      GTEST_SKIP() << "set EKI_PKCS11_MODULE, EKI_PKCS11_TOKEN_LABEL and EKI_PKCS11_PIN "
                      "(source scripts/softhsm-init.sh)";
    }
    token_ = std::move(*from_env);
  }

  testing::AssertionResult open_store() {
    return store_.open(token_.config());
  }

  [[nodiscard]] const Token& token() const {
    return token_;
  }
  Store& store() {
    return store_;
  }

private:
  std::unique_lock<std::mutex> lock_;
  Token token_;
  Store store_;
};

// --- open ----------------------------------------------------------------------------------

// Lesson L7.
TEST_F(FfiKeystorePkcs11, DISABLED_OpenAndClose) {
  ASSERT_TRUE(open_store());
  eki_key_id id{};
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test", id));
  eki_key_info info{};
  ASSERT_TRUE(store().info(id, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_HMAC_SHA256, "eki-test"));
}

// Lesson L7. §4.4: wrong PIN → BACKEND.
TEST_F(FfiKeystorePkcs11, DISABLED_OpenWrongPinIsBackend) {
  for (const std::string& pin :
       {std::string{"0000"}, std::string{"12345"}, std::string(255, '9')}) {
    const eki_ks_config config{
        .backend = EKI_KS_PKCS11,
        .pkcs11_module_path = token().module.c_str(),
        .pkcs11_token_label = token().label.c_str(),
        .pkcs11_user_pin = pin.c_str(),
    };
    EXPECT_TRUE(open_fails(config, EKI_ERR_BACKEND)) << "pin of " << pin.size() << " bytes";
  }
}

// Lesson L7. §4.4: unknown token label → BACKEND.
TEST_F(FfiKeystorePkcs11, DISABLED_OpenUnknownTokenLabelIsBackend) {
  for (const std::string& label : {std::string{"no-such-token"}, std::string(32, 'z')}) {
    const eki_ks_config config{
        .backend = EKI_KS_PKCS11,
        .pkcs11_module_path = token().module.c_str(),
        .pkcs11_token_label = label.c_str(),
        .pkcs11_user_pin = token().pin.c_str(),
    };
    EXPECT_TRUE(open_fails(config, EKI_ERR_BACKEND)) << label;
  }
}

// Lesson L7. Module load failure → BACKEND.
TEST_F(FfiKeystorePkcs11, DISABLED_OpenMissingModuleIsBackend) {
  const eki_ks_config config{
      .backend = EKI_KS_PKCS11,
      .pkcs11_module_path = "/nonexistent/libnot-a-pkcs11-module.so",
      .pkcs11_token_label = token().label.c_str(),
      .pkcs11_user_pin = token().pin.c_str(),
  };
  EXPECT_TRUE(open_fails(config, EKI_ERR_BACKEND));
}

// Lesson L7. §4.2 ks_open: NULL config fields (field order) → NULL_POINTER.
TEST_F(FfiKeystorePkcs11, DISABLED_OpenNullConfigFields) {
  const char* m = token().module.c_str();
  const char* l = token().label.c_str();
  const char* p = token().pin.c_str();
  EXPECT_TRUE(open_fails(eki_ks_config{EKI_KS_PKCS11, nullptr, l, p}, EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(open_fails(eki_ks_config{EKI_KS_PKCS11, m, nullptr, p}, EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(open_fails(eki_ks_config{EKI_KS_PKCS11, m, l, nullptr}, EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(
      open_fails(eki_ks_config{EKI_KS_PKCS11, nullptr, nullptr, nullptr}, EKI_ERR_NULL_POINTER));
}

// Lesson L7. §4.2 ks_open lists the NULL checks of all three fields before the format checks: a
// malformed token label together with a NULL PIN is NULL_POINTER.
TEST_F(FfiKeystorePkcs11, DISABLED_OpenNullFieldBeforeFormatOfAnotherField) {
  EXPECT_TRUE(open_fails(eki_ks_config{EKI_KS_PKCS11, token().module.c_str(), "", nullptr},
                         EKI_ERR_NULL_POINTER));
}

// Lesson L7. Token label not 1..=32 printable bytes → INVALID_ARGUMENT.
TEST_F(FfiKeystorePkcs11, DISABLED_OpenTokenLabelFormatIsInvalid) {
  const std::string long_label = label_of_len(33);
  for (const char* label : {
           long_label.c_str(),
           "",
           "eki\x01"
           "bridge",
           "eki\x80",
       }) {
    const eki_ks_config config{
        .backend = EKI_KS_PKCS11,
        .pkcs11_module_path = token().module.c_str(),
        .pkcs11_token_label = label,
        .pkcs11_user_pin = token().pin.c_str(),
    };
    EXPECT_TRUE(open_fails(config, EKI_ERR_INVALID_ARGUMENT));
  }
}

// Lesson L7. PIN not 1..=255 bytes → INVALID_ARGUMENT.
TEST_F(FfiKeystorePkcs11, DISABLED_OpenPinLengthIsInvalid) {
  const std::string long_pin(256, '1');
  for (const char* pin : {"", long_pin.c_str()}) {
    const eki_ks_config config{
        .backend = EKI_KS_PKCS11,
        .pkcs11_module_path = token().module.c_str(),
        .pkcs11_token_label = token().label.c_str(),
        .pkcs11_user_pin = pin,
    };
    EXPECT_TRUE(open_fails(config, EKI_ERR_INVALID_ARGUMENT));
  }
}

// --- shared scenarios ------------------------------------------------------------------------

// Lesson L7.
TEST_F(FfiKeystorePkcs11, DISABLED_Lifecycle) {
  ASSERT_TRUE(open_store());
  scenarios::lifecycle(store());
}

// Lesson L7.
TEST_F(FfiKeystorePkcs11, DISABLED_WrapUnwrapRoundTrip) {
  ASSERT_TRUE(open_store());
  scenarios::wrap_unwrap_round_trip(store());
}

// Lesson L7.
TEST_F(FfiKeystorePkcs11, DISABLED_GenerateRows) {
  ASSERT_TRUE(open_store());
  scenarios::generate_rows(store());
}

// Lesson L7.
TEST_F(FfiKeystorePkcs11, DISABLED_GenerateNullRows) {
  ASSERT_TRUE(open_store());
  scenarios::generate_null_rows(store());
}

// Lesson L7.
TEST_F(FfiKeystorePkcs11, DISABLED_LookupRows) {
  ASSERT_TRUE(open_store());
  scenarios::lookup_rows(store());
}

// Lesson L7.
TEST_F(FfiKeystorePkcs11, DISABLED_LookupNullRows) {
  ASSERT_TRUE(open_store());
  scenarios::lookup_null_rows(store());
}

// Lesson L7.
TEST_F(FfiKeystorePkcs11, DISABLED_WrapRows) {
  ASSERT_TRUE(open_store());
  scenarios::wrap_rows(store());
}

// Lesson L7.
TEST_F(FfiKeystorePkcs11, DISABLED_UnwrapRows) {
  ASSERT_TRUE(open_store());
  scenarios::unwrap_rows(store());
}

// Lesson L7.
TEST_F(FfiKeystorePkcs11, DISABLED_LastErrorRows) {
  ASSERT_TRUE(open_store());
  scenarios::last_error_rows(store());
}

// --- PKCS#11-specific ------------------------------------------------------------------------

// Lesson L7. §4.4: `msg_len 0` for ks_hmac and ks_sign → OK. SoftHSM2 rejects a NULL data
// pointer even with length 0 (§4.3), so the library must substitute a dummy pointer.
TEST_F(FfiKeystorePkcs11, DISABLED_EmptyMessageHmacAndSignAreOk) {
  ASSERT_TRUE(open_store());
  eki_key_id mac{};
  eki_key_id ec{};
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  ASSERT_TRUE(store().generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa", ec));
  scenarios::PublicKey pk{};
  ASSERT_TRUE(store().public_key(ec, pk));
  const auto empty = bytes("x").subspan(0, 0);
  for (const std::uint8_t* msg : {static_cast<const std::uint8_t*>(nullptr), empty.data()}) {
    scenarios::Mac out = eki_test::prefilled<32>();
    EXPECT_EQ(name(eki_ks_hmac_sha256(store().get(), &mac, msg, 0, out.data())), name(EKI_OK));
    scenarios::Signature sig = eki_test::prefilled<64>();
    EXPECT_EQ(name(eki_ks_sign(store().get(), &ec, msg, 0, sig.data())), name(EKI_OK));
    EXPECT_EQ(name(eki_ecdsa_p256_verify(pk.data(), nullptr, 0, sig.data())), name(EKI_OK));
  }
}

// Lesson L7. Token objects outlive the handle that created them.
TEST_F(FfiKeystorePkcs11, DISABLED_KeysPersistInTheTokenAcrossHandles) {
  eki_key_id id{};
  {
    Store first;
    ASSERT_TRUE(first.open(token().config()));
    ASSERT_TRUE(first.generate(EKI_KEY_HMAC_SHA256, "eki-test persistent", id));
    first.forget(id);
  }
  ASSERT_TRUE(open_store());
  store().track(id);
  eki_key_info info{};
  ASSERT_TRUE(store().info(id, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_HMAC_SHA256, "eki-test persistent"));
  ASSERT_TRUE(store().destroy(id));
}

// Lesson L7. §4.3 lifecycle: close never logs out and finalizes only at zero open handles.
TEST_F(FfiKeystorePkcs11, DISABLED_SecondHandleSurvivesClosingTheFirst) {
  ASSERT_TRUE(open_store());
  eki_key_id mac{};
  {
    Store first;
    ASSERT_TRUE(first.open(token().config()));
    ASSERT_TRUE(first.generate(EKI_KEY_HMAC_SHA256, "eki-test shared", mac));
    first.forget(mac);
    store().track(mac);
    scenarios::Mac a{};
    scenarios::Mac b{};
    ASSERT_TRUE(first.hmac(mac, bytes("m"), a));
    ASSERT_TRUE(store().hmac(mac, bytes("m"), b));
    EXPECT_EQ(a, b);
  }
  scenarios::Mac out{};
  ASSERT_TRUE(store().hmac(mac, bytes("m"), out));
  eki_key_id ec{};
  ASSERT_TRUE(store().generate(EKI_KEY_ECDSA_P256, "eki-test after close", ec));
  scenarios::Signature sig{};
  scenarios::PublicKey pk{};
  ASSERT_TRUE(store().sign(ec, bytes("m"), sig));
  ASSERT_TRUE(store().public_key(ec, pk));
  EXPECT_EQ(name(scenarios::verify(pk, bytes("m"), sig)), name(EKI_OK));
}

// Lesson L7. §4.3: destroy removes every object with the id (private and public halves).
TEST_F(FfiKeystorePkcs11, DISABLED_DestroyRemovesBothHalvesOfAKeyPair) {
  ASSERT_TRUE(open_store());
  eki_key_id kek{};
  eki_key_id mac{};
  eki_key_id ec{};
  ASSERT_TRUE(store().generate(EKI_KEY_AES_256, "eki-test kek", kek));
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  ASSERT_TRUE(store().generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa", ec));
  ASSERT_TRUE(store().destroy(ec));
  scenarios::PublicKey pk = eki_test::prefilled<65>();
  EXPECT_EQ(name(eki_ks_get_public_key(store().get(), &ec, pk.data())),
            name(EKI_ERR_KEY_NOT_FOUND));
  // If the public half were left behind, the id would still be taken.
  scenarios::Blob blob{};
  ASSERT_TRUE(store().wrap(kek, mac, blob));
  ASSERT_TRUE(store().unwrap(kek, blob, EKI_KEY_HMAC_SHA256, "eki-test reused id", ec));
  eki_key_info info{};
  ASSERT_TRUE(store().info(ec, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_HMAC_SHA256, "eki-test reused id"));
}

} // namespace
