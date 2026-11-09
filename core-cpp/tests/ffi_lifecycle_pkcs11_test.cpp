// Key lifecycle, dual control and the audit log on a PKCS#11 token (ABI 2 contract sections 3, 4
// and 6). The scenarios of lifecycle_support.hpp run on the token; the token-only rows check the
// usage attributes that hold the state, that the token itself refuses what the state forbids,
// that a combination of attributes outside the table makes the key foreign, that state is shared
// between handles, and that a state change stays when its audit record cannot be written.
//
// Needs a token, as ffi_keystore_pkcs11_test.cpp: EKI_PKCS11_MODULE, EKI_PKCS11_TOKEN_LABEL and
// EKI_PKCS11_PIN; skipped otherwise or when the library is built without EKI_WITH_PKCS11.

#include "lifecycle_support.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <ekicore.h>

#include <pkcs11.h>

#include <dlfcn.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

using eki_test::bytes;
using eki_test::name;
using eki_test::lifecycle::Approvers;
using eki_test::lifecycle::Handle;
using eki_test::lifecycle::Request;
using eki_test::lifecycle::TempDir;
using eki_test::lifecycle::widen;
namespace lifecycle = eki_test::lifecycle;

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

std::mutex& token_mutex() {
  static std::mutex mutex;
  return mutex;
}

// The objects of one key as the token holds them, reached through a session of this test's own on
// the module the library has initialised and logged in to (login state belongs to the process).
class RawToken {
public:
  RawToken() = default;
  RawToken(const RawToken&) = delete;
  RawToken& operator=(const RawToken&) = delete;
  RawToken(RawToken&&) = delete;
  RawToken& operator=(RawToken&&) = delete;
  ~RawToken() {
    if (session_ != CK_INVALID_HANDLE) {
      static_cast<void>(functions_->C_CloseSession(session_));
    }
  }

  // Call while a store handle is open, so that the module is initialised and logged in.
  testing::AssertionResult open(const Token& token) {
    void* module = dlopen(token.module.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (module == nullptr) {
      return testing::AssertionFailure() << "dlopen: " << dlerror();
    }
    auto* get_function_list =
        reinterpret_cast<CK_C_GetFunctionList>(dlsym(module, "C_GetFunctionList"));
    if (get_function_list == nullptr || get_function_list(&functions_) != CKR_OK) {
      return testing::AssertionFailure() << "C_GetFunctionList";
    }
    std::array<CK_SLOT_ID, 16> slots{};
    CK_ULONG count = slots.size();
    if (functions_->C_GetSlotList(CK_TRUE, slots.data(), &count) != CKR_OK) {
      return testing::AssertionFailure() << "C_GetSlotList (is a store open?)";
    }
    std::array<CK_UTF8CHAR, 32> wanted{};
    std::ranges::fill(wanted, static_cast<CK_UTF8CHAR>(' '));
    std::ranges::copy(token.label, wanted.begin());
    for (const CK_SLOT_ID slot :
         std::span{slots}.first(std::min<std::size_t>(count, slots.size()))) {
      CK_TOKEN_INFO info{};
      if (functions_->C_GetTokenInfo(slot, &info) == CKR_OK &&
          std::ranges::equal(info.label, wanted)) {
        const CK_RV rv = functions_->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                                   nullptr, nullptr, &session_);
        return rv == CKR_OK ? testing::AssertionSuccess()
                            : testing::AssertionFailure() << "C_OpenSession returned " << rv;
      }
    }
    return testing::AssertionFailure() << "no token labelled " << token.label;
  }

  // The one object of class object_class that carries id, or CK_INVALID_HANDLE.
  CK_OBJECT_HANDLE object(const eki_key_id& id, CK_OBJECT_CLASS object_class) {
    eki_key_id id_value = id;
    std::array search{
        CK_ATTRIBUTE{.type = CKA_CLASS, .pValue = &object_class, .ulValueLen = sizeof object_class},
        CK_ATTRIBUTE{
            .type = CKA_ID,
            .pValue = std::data(id_value.bytes),
            .ulValueLen = sizeof id_value.bytes,
        },
    };
    std::array<CK_OBJECT_HANDLE, 4> found{};
    CK_ULONG count = 0;
    if (functions_->C_FindObjectsInit(session_, search.data(), search.size()) != CKR_OK) {
      return CK_INVALID_HANDLE;
    }
    const CK_RV rv = functions_->C_FindObjects(session_, found.data(), found.size(), &count);
    static_cast<void>(functions_->C_FindObjectsFinal(session_));
    return rv == CKR_OK && count == 1 ? found.front() : CK_INVALID_HANDLE;
  }

  // The number of objects whose CKA_LABEL is label.
  std::size_t count_labelled(const std::string& label) {
    std::string value = label;
    std::array search{
        CK_ATTRIBUTE{.type = CKA_LABEL, .pValue = value.data(), .ulValueLen = value.size()},
    };
    std::array<CK_OBJECT_HANDLE, 16> found{};
    CK_ULONG count = 0;
    if (functions_->C_FindObjectsInit(session_, search.data(), search.size()) != CKR_OK) {
      return 0;
    }
    static_cast<void>(functions_->C_FindObjects(session_, found.data(), found.size(), &count));
    static_cast<void>(functions_->C_FindObjectsFinal(session_));
    return count;
  }

  // CK_BBOOL attributes of an object, by type; a missing one is absent from the map.
  std::map<CK_ATTRIBUTE_TYPE, bool> flags(CK_OBJECT_HANDLE object,
                                          std::initializer_list<CK_ATTRIBUTE_TYPE> types) {
    std::map<CK_ATTRIBUTE_TYPE, bool> out;
    for (const CK_ATTRIBUTE_TYPE type : types) {
      CK_BBOOL value = CK_FALSE;
      CK_ATTRIBUTE attribute{.type = type, .pValue = &value, .ulValueLen = sizeof value};
      if (functions_->C_GetAttributeValue(session_, object, &attribute, 1) == CKR_OK) {
        out[type] = value != CK_FALSE;
      }
    }
    return out;
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters): PKCS#11 types are all CK_ULONG
  CK_RV set_flag(CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type, bool value) {
    CK_BBOOL raw = value ? CK_TRUE : CK_FALSE;
    CK_ATTRIBUTE attribute{.type = type, .pValue = &raw, .ulValueLen = sizeof raw};
    return functions_->C_SetAttributeValue(session_, object, &attribute, 1);
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters): PKCS#11 types are all CK_ULONG
  CK_RV sign_init(CK_OBJECT_HANDLE key, CK_MECHANISM_TYPE type) {
    CK_MECHANISM mechanism{.mechanism = type, .pParameter = nullptr, .ulParameterLen = 0};
    const CK_RV rv = functions_->C_SignInit(session_, &mechanism, key);
    if (rv == CKR_OK) {
      // Ends the operation: a sign with a too-small buffer would not.
      std::array<CK_BYTE, 1> data{};
      std::array<CK_BYTE, 64> out{};
      CK_ULONG len = out.size();
      static_cast<void>(functions_->C_Sign(session_, data.data(), data.size(), out.data(), &len));
    }
    return rv;
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters): PKCS#11 types are all CK_ULONG
  CK_RV verify_init(CK_OBJECT_HANDLE key, CK_MECHANISM_TYPE type) {
    CK_MECHANISM mechanism{.mechanism = type, .pParameter = nullptr, .ulParameterLen = 0};
    const CK_RV rv = functions_->C_VerifyInit(session_, &mechanism, key);
    if (rv == CKR_OK) {
      std::array<CK_BYTE, 1> data{};
      std::array<CK_BYTE, 64> sig{};
      static_cast<void>(
          functions_->C_Verify(session_, data.data(), data.size(), sig.data(), sig.size()));
    }
    return rv;
  }

  CK_RV wrap(CK_OBJECT_HANDLE kek, CK_OBJECT_HANDLE key) {
    CK_MECHANISM mechanism{
        .mechanism = CKM_AES_KEY_WRAP,
        .pParameter = nullptr,
        .ulParameterLen = 0,
    };
    std::array<CK_BYTE, 40> out{};
    CK_ULONG len = out.size();
    return functions_->C_WrapKey(session_, &mechanism, kek, key, out.data(), &len);
  }

private:
  CK_FUNCTION_LIST* functions_ = nullptr;
  CK_SESSION_HANDLE session_ = CK_INVALID_HANDLE;
};

using Flags = std::map<CK_ATTRIBUTE_TYPE, bool>;

// The usage attributes of each state (ABI 2 contract section 3, second table).
Flags aes_flags(eki_key_state state) {
  const bool active = state == EKI_KEY_STATE_ACTIVE;
  const bool live = state != EKI_KEY_STATE_REVOKED;
  return {{CKA_WRAP, active}, {CKA_ENCRYPT, active}, {CKA_UNWRAP, live}, {CKA_DECRYPT, live}};
}
Flags sign_flag(eki_key_state state) {
  return {{CKA_SIGN, state == EKI_KEY_STATE_ACTIVE}};
}
Flags verify_flag(eki_key_state state) {
  return {{CKA_VERIFY, state != EKI_KEY_STATE_REVOKED}};
}
Flags hmac_flags(eki_key_state state) {
  Flags flags = sign_flag(state);
  flags.merge(verify_flag(state));
  return flags;
}

class FfiLifecyclePkcs11 : public testing::Test {
protected:
  void SetUp() override {
    lock_ = std::unique_lock<std::mutex>(token_mutex());
    if (!eki_test::kWithPkcs11) {
      GTEST_SKIP() << "built without EKI_WITH_PKCS11 (FfiLifecycle.OpenV2Pkcs11Selector)";
    }
    auto module = env("EKI_PKCS11_MODULE");
    auto label = env("EKI_PKCS11_TOKEN_LABEL");
    auto pin = env("EKI_PKCS11_PIN");
    if (!module || !label || !pin) {
      GTEST_SKIP() << "set EKI_PKCS11_MODULE, EKI_PKCS11_TOKEN_LABEL and EKI_PKCS11_PIN";
    }
    token_ = Token{.module = *module, .label = *label, .pin = *pin};
  }

  [[nodiscard]] eki_ks_config config() const {
    return token_.config();
  }
  [[nodiscard]] const Token& token() const {
    return token_;
  }

private:
  std::unique_lock<std::mutex> lock_;
  Token token_;
};

// NOLINTBEGIN(readability-function-cognitive-complexity)

TEST_F(FfiLifecyclePkcs11, StateTable) {
  lifecycle::state_table(config());
}

TEST_F(FfiLifecyclePkcs11, CheckOrder) {
  lifecycle::check_order(config());
}

TEST_F(FfiLifecyclePkcs11, GetInfoV2) {
  lifecycle::info_v2_rows(config());
}

TEST_F(FfiLifecyclePkcs11, DualControl) {
  lifecycle::dual_control(config());
}

TEST_F(FfiLifecyclePkcs11, NoApprovers) {
  lifecycle::no_approvers(config());
}

TEST_F(FfiLifecyclePkcs11, OpenV2Rows) {
  lifecycle::open_v2_rows(config());
}

TEST_F(FfiLifecyclePkcs11, NullRows) {
  lifecycle::null_rows(config());
}

// The PKCS#11 fields come first among the field checks: NULL checks of every field before any
// format check, and every format check before the backend is opened.
TEST_F(FfiLifecyclePkcs11, OpenV2Pkcs11FieldOrder) {
  const TempDir dir;
  const std::string log = dir.file("pkcs11-open.log");
  const Approvers approvers(2);
  eki_ks_config base = config();
  base.pkcs11_token_label = "";
  EXPECT_TRUE(lifecycle::open_v2_fails(widen(base, nullptr, nullptr, 2), EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(lifecycle::open_v2_fails(widen(base, log.c_str()), EKI_ERR_INVALID_ARGUMENT));
  base = config();
  base.pkcs11_user_pin = nullptr;
  EXPECT_TRUE(lifecycle::open_v2_fails(widen(base, ""), EKI_ERR_NULL_POINTER));
  base = config();
  base.pkcs11_module_path = "/nonexistent/libnot-a-module.so";
  EXPECT_TRUE(lifecycle::open_v2_fails(widen(base, ""), EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(lifecycle::open_v2_fails(widen(base, nullptr, approvers.keys(), 1),
                                       EKI_ERR_INVALID_ARGUMENT));
  // The backend opens before the log: a backend failure leaves no log file.
  EXPECT_TRUE(lifecycle::open_v2_fails(widen(base, log.c_str()), EKI_ERR_BACKEND));
  EXPECT_FALSE(lifecycle::file_exists(log));
  // A log that fails verification closes the backend it opened again.
  lifecycle::write_file(log, "not a log\n");
  EXPECT_TRUE(lifecycle::open_v2_fails(widen(config(), log.c_str()), EKI_ERR_AUTH_FAILED));
  EXPECT_TRUE(lifecycle::open_v2_succeeds(widen(config())));
}

// The usage attributes of each key type in each state are those of the table, and the token
// itself refuses what the state forbids.
TEST_F(FfiLifecyclePkcs11, StateLivesInTheUsageAttributes) {
  Handle h(config());
  ASSERT_TRUE(h.open(widen(config())));
  RawToken raw;
  ASSERT_TRUE(raw.open(token()));
  for (const eki_key_state state : lifecycle::kStates) {
    SCOPED_TRACE(lifecycle::state_name(state));
    eki_key_id aes{};
    eki_key_id mac{};
    eki_key_id ec{};
    ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "token aes", aes));
    ASSERT_TRUE(h.generate(EKI_KEY_HMAC_SHA256, "token hmac", mac));
    ASSERT_TRUE(h.generate(EKI_KEY_ECDSA_P256, "token ecdsa", ec));
    for (const eki_key_id& id : {aes, mac, ec}) {
      ASSERT_TRUE(h.put_in(id, state));
    }
    const CK_OBJECT_HANDLE aes_object = raw.object(aes, CKO_SECRET_KEY);
    const CK_OBJECT_HANDLE mac_object = raw.object(mac, CKO_SECRET_KEY);
    const CK_OBJECT_HANDLE private_key = raw.object(ec, CKO_PRIVATE_KEY);
    const CK_OBJECT_HANDLE public_key = raw.object(ec, CKO_PUBLIC_KEY);
    ASSERT_NE(aes_object, CK_INVALID_HANDLE);
    ASSERT_NE(mac_object, CK_INVALID_HANDLE);
    ASSERT_NE(private_key, CK_INVALID_HANDLE);
    ASSERT_NE(public_key, CK_INVALID_HANDLE);
    EXPECT_EQ(raw.flags(aes_object, {CKA_WRAP, CKA_ENCRYPT, CKA_UNWRAP, CKA_DECRYPT}),
              aes_flags(state));
    EXPECT_EQ(raw.flags(mac_object, {CKA_SIGN, CKA_VERIFY}), hmac_flags(state));
    EXPECT_EQ(raw.flags(private_key, {CKA_SIGN}), sign_flag(state));
    EXPECT_EQ(raw.flags(public_key, {CKA_VERIFY}), verify_flag(state));

    const bool active = state == EKI_KEY_STATE_ACTIVE;
    const bool live = state != EKI_KEY_STATE_REVOKED;
    const auto refused = [](CK_RV rv, bool allowed) {
      return allowed ? rv == CKR_OK : rv == CKR_KEY_FUNCTION_NOT_PERMITTED;
    };
    EXPECT_TRUE(refused(raw.sign_init(mac_object, CKM_SHA256_HMAC), active));
    EXPECT_TRUE(refused(raw.verify_init(mac_object, CKM_SHA256_HMAC), live));
    EXPECT_TRUE(refused(raw.sign_init(private_key, CKM_ECDSA), active));
    EXPECT_TRUE(refused(raw.verify_init(public_key, CKM_ECDSA), live));
    EXPECT_TRUE(refused(raw.wrap(aes_object, mac_object), active));
  }
}

// A key retired or revoked through one handle has that state through another: the state is in the
// token, not in the handle.
TEST_F(FfiLifecyclePkcs11, StateIsSharedBetweenHandles) {
  Handle a(config());
  ASSERT_TRUE(a.open(widen(config())));
  Handle b(config());
  ASSERT_TRUE(b.open(widen(config())));
  eki_key_id mac{};
  ASSERT_TRUE(a.generate(EKI_KEY_HMAC_SHA256, "shared", mac));
  eki_key_id rotated{};
  EKI_EXPECT_STATUS(a.rotate(mac, rotated), EKI_OK);
  EXPECT_EQ(b.state(mac), EKI_KEY_STATE_RETIRED);
  EXPECT_EQ(b.state(rotated), EKI_KEY_STATE_ACTIVE);
  lifecycle::Tag tag{};
  const std::span<const std::uint8_t> msg = bytes("shared");
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256(b.get(), &mac, msg.data(), msg.size(), tag.data()),
                    EKI_ERR_KEY_STATE);
  EKI_EXPECT_STATUS(eki_ks_revoke(b.get(), &mac), EKI_OK);
  EXPECT_EQ(a.state(mac), EKI_KEY_STATE_REVOKED);
}

// Usage attributes that spell no state make the key foreign: operations that need it answer
// BACKEND, while destroy still removes it.
TEST_F(FfiLifecyclePkcs11, OtherAttributeCombinationsAreForeign) {
  Handle h(config());
  ASSERT_TRUE(h.open(widen(config())));
  RawToken raw;
  ASSERT_TRUE(raw.open(token()));
  eki_key_id mac{};
  eki_key_id aes{};
  eki_key_id ec{};
  ASSERT_TRUE(h.generate(EKI_KEY_HMAC_SHA256, "foreign hmac", mac));
  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "foreign aes", aes));
  ASSERT_TRUE(h.generate(EKI_KEY_ECDSA_P256, "foreign ecdsa", ec));
  // HMAC: SIGN TRUE, VERIFY FALSE. AES: WRAP TRUE, ENCRYPT FALSE. ECDSA: public VERIFY FALSE with
  // the private SIGN TRUE.
  ASSERT_EQ(raw.set_flag(raw.object(mac, CKO_SECRET_KEY), CKA_VERIFY, false), CKR_OK);
  ASSERT_EQ(raw.set_flag(raw.object(aes, CKO_SECRET_KEY), CKA_ENCRYPT, false), CKR_OK);
  ASSERT_EQ(raw.set_flag(raw.object(ec, CKO_PUBLIC_KEY), CKA_VERIFY, false), CKR_OK);
  const std::span<const std::uint8_t> msg = bytes("foreign");
  lifecycle::Tag tag{};
  lifecycle::Signature sig{};
  eki_key_info info{};
  EKI_EXPECT_STATUS(eki_ks_get_info(h.get(), &mac, &info), EKI_ERR_BACKEND);
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256(h.get(), &mac, msg.data(), msg.size(), tag.data()),
                    EKI_ERR_BACKEND);
  EKI_EXPECT_STATUS(eki_ks_revoke(h.get(), &aes), EKI_ERR_BACKEND);
  EKI_EXPECT_STATUS(eki_ks_sign(h.get(), &ec, msg.data(), msg.size(), sig.data()), EKI_ERR_BACKEND);
  const eki_key_id kek_free = eki_test::fixed_id(0x7E);
  lifecycle::Blob blob{};
  EKI_EXPECT_STATUS(
      eki_ks_unwrap(h.get(), &mac, blob.data(), blob.size(), EKI_KEY_AES_256, "x", &kek_free),
      EKI_ERR_BACKEND);
  for (const eki_key_id& id : {mac, aes, ec}) {
    EKI_EXPECT_STATUS(eki_ks_destroy(h.get(), &id), EKI_OK);
    EKI_EXPECT_STATUS(eki_ks_get_info(h.get(), &id, &info), EKI_ERR_KEY_NOT_FOUND);
  }
}

// When the key is destroyed elsewhere while a request is pending, the completing approval is
// KEY_NOT_FOUND and the request is removed (ABI 2 contract section 6).
TEST_F(FfiLifecyclePkcs11, CompletingApprovalForAKeyDestroyedElsewhere) {
  const Approvers approvers(2);
  Handle h(config());
  ASSERT_TRUE(h.open(widen(config(), nullptr, approvers.keys(), approvers.count())));
  Handle plain(config());
  ASSERT_TRUE(plain.open(widen(config())));
  eki_key_id key{};
  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "vanishing", key));
  Request request{};
  EKI_EXPECT_STATUS(eki_ks_destroy_request(h.get(), &key, request.data()), EKI_OK);
  std::uint32_t remaining = 0;
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(h.get(), request.data(), approvers.key(0).data(),
                                           approvers.sign(0, request, key).data(), &remaining),
                    EKI_OK);
  EXPECT_EQ(remaining, 1U);
  EKI_EXPECT_STATUS(eki_ks_destroy(plain.get(), &key), EKI_OK);
  remaining = lifecycle::kFillU32;
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(h.get(), request.data(), approvers.key(1).data(),
                                           approvers.sign(1, request, key).data(), &remaining),
                    EKI_ERR_KEY_NOT_FOUND);
  EXPECT_EQ(remaining, 0U);
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(h.get(), request.data(), approvers.key(0).data(),
                                           approvers.sign(0, request, key).data(), &remaining),
                    EKI_ERR_KEY_NOT_FOUND);
}

// A rotate and a revoke whose audit record cannot be written: the new key is destroyed again, and
// the state change stays on the token (no state leads back), in the usage attributes.
TEST_F(FfiLifecyclePkcs11, StateChangeStaysWhenTheRecordCannotBeWritten) {
  const TempDir dir;
  const std::string path = dir.file("token.log");
  Handle h(config());
  ASSERT_TRUE(h.open(widen(config(), path.c_str())));
  RawToken raw;
  ASSERT_TRUE(raw.open(token()));
  const std::string label = "rollback " + std::to_string(::getpid());
  eki_key_id ec{};
  eki_key_id aes{};
  ASSERT_TRUE(h.generate(EKI_KEY_ECDSA_P256, label, ec));
  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, label, aes));
  ASSERT_EQ(raw.count_labelled(label), 3U);
  {
    const auto previous = std::signal(SIGXFSZ, SIG_IGN);
    rlimit saved{};
    ASSERT_EQ(getrlimit(RLIMIT_FSIZE, &saved), 0);
    rlimit lowered = saved;
    lowered.rlim_cur = static_cast<rlim_t>(lifecycle::read_file(path).size());
    ASSERT_EQ(setrlimit(RLIMIT_FSIZE, &lowered), 0);
    eki_key_id rotated{};
    const eki_status rotate_ec = eki_ks_rotate(h.get(), &ec, &rotated);
    const eki_status rotate_aes = eki_ks_rotate(h.get(), &aes, &rotated);
    const eki_status revoke_aes = eki_ks_revoke(h.get(), &aes);
    EXPECT_EQ(setrlimit(RLIMIT_FSIZE, &saved), 0);
    static_cast<void>(std::signal(SIGXFSZ, previous));
    EKI_EXPECT_STATUS(rotate_ec, EKI_ERR_BACKEND);
    EKI_EXPECT_STATUS(rotate_aes, EKI_ERR_BACKEND);
    EKI_EXPECT_STATUS(revoke_aes, EKI_ERR_BACKEND);
  }
  EXPECT_EQ(raw.count_labelled(label), 3U) << "no new key is left behind";
  EXPECT_EQ(h.state(ec), EKI_KEY_STATE_RETIRED);
  EXPECT_EQ(h.state(aes), EKI_KEY_STATE_REVOKED);
  EXPECT_EQ(raw.flags(raw.object(ec, CKO_PRIVATE_KEY), {CKA_SIGN}),
            sign_flag(EKI_KEY_STATE_RETIRED));
  EXPECT_EQ(raw.flags(raw.object(ec, CKO_PUBLIC_KEY), {CKA_VERIFY}),
            verify_flag(EKI_KEY_STATE_RETIRED));
  EXPECT_EQ(
      raw.flags(raw.object(aes, CKO_SECRET_KEY), {CKA_WRAP, CKA_ENCRYPT, CKA_UNWRAP, CKA_DECRYPT}),
      aes_flags(EKI_KEY_STATE_REVOKED));
  std::uint64_t n = 0;
  EKI_EXPECT_STATUS(eki_audit_verify(path.c_str(), nullptr, &n), EKI_OK);
}

// NOLINTEND(readability-function-cognitive-complexity)

} // namespace
