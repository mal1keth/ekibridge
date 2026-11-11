// The PKCS#11 key store through the C ABI. Mirrors core-rs/tests/ffi_keystore_pkcs11.rs: plan
// §4.4 ks_open (PKCS#11) and every store row; §4.3 object mapping and lifecycle.
//
// Needs a token: `source scripts/softhsm-init.sh` exports EKI_PKCS11_MODULE,
// EKI_PKCS11_TOKEN_LABEL and EKI_PKCS11_PIN; when any is unset, or the library is built without
// EKI_WITH_PKCS11, the tests are skipped. Within this process the tests are serialised by one
// mutex (C_Initialize and the login state are per process), every store is closed before its test
// ends, and keys a test creates are destroyed by the Store guard. Separate ctest processes must
// not run them in parallel either: the ctest property RESOURCE_LOCK softhsm belongs on these
// tests.

#include "error_queue_support.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <ekicore.h>
#include <ekicore/primitives.hpp>

#include <pkcs11.h>

#include <dlfcn.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

using eki_test::all_zero;
using eki_test::bytes;
using eki_test::info_is;
using eki_test::info_zero;
using eki_test::label_of_len;
using eki_test::last_error;
using eki_test::name;
using eki_test::open_fails;
using eki_test::prefilled;
using eki_test::prefilled_info;
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

// Holds the token mutex for the whole test and skips when no token is configured or PKCS#11 is not
// compiled in. Tests that need a store open one with ASSERT_TRUE(open_store()). The open-failure
// tests deliberately run with no other handle open: while any handle of this process is logged
// in, C_Login answers CKR_USER_ALREADY_LOGGED_IN, which §4.3 maps to "proceed", so a wrong PIN
// would not be noticed.
// Members are destroyed in reverse order: the store closes before the lock is released.
class FfiKeystorePkcs11 : public testing::Test {
protected:
  void SetUp() override {
    lock_ = std::unique_lock<std::mutex>(token_mutex());
    if (!eki_test::kWithPkcs11) {
      GTEST_SKIP() << "built without EKI_WITH_PKCS11: eki_ks_open answers EKI_KS_PKCS11 with "
                      "EKI_ERR_UNSUPPORTED (FfiKeystoreSoftware.OpenPkcs11WithNullModulePath)";
    }
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

TEST_F(FfiKeystorePkcs11, OpenAndClose) {
  ASSERT_TRUE(open_store());
  eki_key_id id{};
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test", id));
  eki_key_info info{};
  ASSERT_TRUE(store().info(id, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_HMAC_SHA256, "eki-test"));
}

// §4.4: wrong PIN → BACKEND.
TEST_F(FfiKeystorePkcs11, OpenWrongPinIsBackend) {
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

// §4.4: unknown token label → BACKEND.
TEST_F(FfiKeystorePkcs11, OpenUnknownTokenLabelIsBackend) {
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

// Module load failure → BACKEND.
TEST_F(FfiKeystorePkcs11, OpenMissingModuleIsBackend) {
  const eki_ks_config config{
      .backend = EKI_KS_PKCS11,
      .pkcs11_module_path = "/nonexistent/libnot-a-pkcs11-module.so",
      .pkcs11_token_label = token().label.c_str(),
      .pkcs11_user_pin = token().pin.c_str(),
  };
  EXPECT_TRUE(open_fails(config, EKI_ERR_BACKEND));
}

// §4.2 ks_open: NULL config fields (field order) → NULL_POINTER.
TEST_F(FfiKeystorePkcs11, OpenNullConfigFields) {
  const char* m = token().module.c_str();
  const char* l = token().label.c_str();
  const char* p = token().pin.c_str();
  EXPECT_TRUE(open_fails(eki_ks_config{EKI_KS_PKCS11, nullptr, l, p}, EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(open_fails(eki_ks_config{EKI_KS_PKCS11, m, nullptr, p}, EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(open_fails(eki_ks_config{EKI_KS_PKCS11, m, l, nullptr}, EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(
      open_fails(eki_ks_config{EKI_KS_PKCS11, nullptr, nullptr, nullptr}, EKI_ERR_NULL_POINTER));
}

// §4.2 ks_open lists the NULL checks of all three fields before the format checks: a
// malformed token label together with a NULL PIN is NULL_POINTER.
TEST_F(FfiKeystorePkcs11, OpenNullFieldBeforeFormatOfAnotherField) {
  EXPECT_TRUE(open_fails(eki_ks_config{EKI_KS_PKCS11, token().module.c_str(), "", nullptr},
                         EKI_ERR_NULL_POINTER));
}

// Token label not 1..=32 printable bytes → INVALID_ARGUMENT.
TEST_F(FfiKeystorePkcs11, OpenTokenLabelFormatIsInvalid) {
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

// PIN not 1..=255 bytes → INVALID_ARGUMENT.
TEST_F(FfiKeystorePkcs11, OpenPinLengthIsInvalid) {
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

TEST_F(FfiKeystorePkcs11, Lifecycle) {
  ASSERT_TRUE(open_store());
  scenarios::lifecycle(store());
}

TEST_F(FfiKeystorePkcs11, WrapUnwrapRoundTrip) {
  ASSERT_TRUE(open_store());
  scenarios::wrap_unwrap_round_trip(store());
}

TEST_F(FfiKeystorePkcs11, GenerateRows) {
  ASSERT_TRUE(open_store());
  scenarios::generate_rows(store());
}

TEST_F(FfiKeystorePkcs11, GenerateNullRows) {
  ASSERT_TRUE(open_store());
  scenarios::generate_null_rows(store());
}

TEST_F(FfiKeystorePkcs11, LookupRows) {
  ASSERT_TRUE(open_store());
  scenarios::lookup_rows(store());
}

TEST_F(FfiKeystorePkcs11, LookupNullRows) {
  ASSERT_TRUE(open_store());
  scenarios::lookup_null_rows(store());
}

TEST_F(FfiKeystorePkcs11, WrapRows) {
  ASSERT_TRUE(open_store());
  scenarios::wrap_rows(store());
}

TEST_F(FfiKeystorePkcs11, UnwrapRows) {
  ASSERT_TRUE(open_store());
  scenarios::unwrap_rows(store());
}

TEST_F(FfiKeystorePkcs11, LastErrorRows) {
  ASSERT_TRUE(open_store());
  scenarios::last_error_rows(store());
}

// --- PKCS#11-specific ------------------------------------------------------------------------

// §4.4: `msg_len 0` for ks_hmac and ks_sign → OK. SoftHSM2 rejects a NULL data
// pointer even with length 0 (§4.3), so the library must substitute a dummy pointer.
TEST_F(FfiKeystorePkcs11, EmptyMessageHmacAndSignAreOk) {
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

// Token objects outlive the handle that created them.
TEST_F(FfiKeystorePkcs11, KeysPersistInTheTokenAcrossHandles) {
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

// §4.3 lifecycle: close never logs out and finalizes only at zero open handles.
TEST_F(FfiKeystorePkcs11, SecondHandleSurvivesClosingTheFirst) {
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

// §4.3: destroy removes every object with the id (private and public halves).
TEST_F(FfiKeystorePkcs11, DestroyRemovesBothHalvesOfAKeyPair) {
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

// A failed open leaves no session open and the module finalised, so the next open with the right
// parameters works.
TEST_F(FfiKeystorePkcs11, OpenSucceedsAfterFailedOpens) {
  const eki_ks_config wrong_pin{
      .backend = EKI_KS_PKCS11,
      .pkcs11_module_path = token().module.c_str(),
      .pkcs11_token_label = token().label.c_str(),
      .pkcs11_user_pin = "0000",
  };
  const eki_ks_config unknown_label{
      .backend = EKI_KS_PKCS11,
      .pkcs11_module_path = token().module.c_str(),
      .pkcs11_token_label = "no-such-token",
      .pkcs11_user_pin = token().pin.c_str(),
  };
  ASSERT_TRUE(open_fails(wrong_pin, EKI_ERR_BACKEND));
  ASSERT_TRUE(open_fails(unknown_label, EKI_ERR_BACKEND));
  ASSERT_TRUE(open_fails(wrong_pin, EKI_ERR_BACKEND));
  ASSERT_TRUE(open_store());
  eki_key_id id{};
  ASSERT_TRUE(store().generate(EKI_KEY_AES_256, "eki-test after failures", id));
}

// §4.3 lifecycle: login state belongs to the process, so while a handle is logged in, C_Login
// answers CKR_USER_ALREADY_LOGGED_IN and a second open succeeds whatever PIN it passes.
TEST_F(FfiKeystorePkcs11, OpenWithWrongPinWhileLoggedInSucceeds) {
  ASSERT_TRUE(open_store());
  const eki_ks_config wrong_pin{
      .backend = EKI_KS_PKCS11,
      .pkcs11_module_path = token().module.c_str(),
      .pkcs11_token_label = token().label.c_str(),
      .pkcs11_user_pin = "0000",
  };
  Store second;
  ASSERT_TRUE(second.open(wrong_pin));
  eki_key_id id{};
  ASSERT_TRUE(second.generate(EKI_KEY_HMAC_SHA256, "eki-test second handle", id));
}

// A path that names no PKCS#11 module → BACKEND: the empty path (which dlopen would take as the
// main program), a file that is not a shared library, and a shared library (the C library)
// without C_GetFunctionList.
TEST_F(FfiKeystorePkcs11, OpenNonModuleIsBackend) {
  Dl_info libc{};
  ASSERT_NE(dladdr(reinterpret_cast<void*>(&std::strlen), &libc), 0);
  ASSERT_NE(libc.dli_fname, nullptr);
  for (const char* path : {"", "/dev/null", libc.dli_fname}) {
    const eki_ks_config config{
        .backend = EKI_KS_PKCS11,
        .pkcs11_module_path = path,
        .pkcs11_token_label = token().label.c_str(),
        .pkcs11_user_pin = token().pin.c_str(),
    };
    EXPECT_TRUE(open_fails(config, EKI_ERR_BACKEND)) << path;
  }
}

// The module may share this library's libcrypto (distribution packages of SoftHSM2 do): whatever
// it pushes onto the thread's OpenSSL error queue while a store opens, works and closes stays
// inside those calls, and the caller's entries are left as they were.
TEST_F(FfiKeystorePkcs11, StoreLeavesTheCallersErrorQueueAsFound) {
  const unsigned long caller = eki_test::push_caller_error();
  {
    Store first;
    ASSERT_TRUE(first.open(token().config()));
    eki_key_id mac{};
    ASSERT_TRUE(first.generate(EKI_KEY_HMAC_SHA256, "eki-test error queue", mac));
    scenarios::Mac out{};
    ASSERT_TRUE(first.hmac(mac, bytes("m"), out));
  }
  EXPECT_TRUE(eki_test::queue_holds_only(caller));
}

// --- objects the library did not create (§4.3) ---------------------------------------------------

// A key id for objects made directly through the module: "eki-test-raw-id" and a tag byte.
eki_key_id raw_id(char tag) {
  constexpr std::string_view prefix = "eki-test-raw-id";
  static_assert(prefix.size() == EKI_KEY_ID_LEN - 1);
  eki_key_id id{};
  std::ranges::copy(prefix, std::begin(id.bytes));
  std::span{id.bytes}.back() = static_cast<std::uint8_t>(tag);
  return id;
}

template <typename Value> CK_ATTRIBUTE attribute(CK_ATTRIBUTE_TYPE type, Value& value) {
  return CK_ATTRIBUTE{.type = type, .pValue = &value, .ulValueLen = sizeof value};
}

CK_ATTRIBUTE attribute(CK_ATTRIBUTE_TYPE type, std::span<std::uint8_t> value) {
  return CK_ATTRIBUTE{.type = type, .pValue = value.data(), .ulValueLen = value.size()};
}

CK_ATTRIBUTE attribute(CK_ATTRIBUTE_TYPE type, std::string& value) {
  return CK_ATTRIBUTE{.type = type, .pValue = value.data(), .ulValueLen = value.size()};
}

// The token reached directly through the module, standing in for another program that shares
// it. Opened while a store of the library is open: C_Initialize then answers
// CKR_CRYPTOKI_ALREADY_INITIALIZED, so finalising stays the library's job, and the store's login
// covers this session too (login state is per process). The module is never dlclosed, as in the
// library.
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
    CK_C_INITIALIZE_ARGS args{};
    args.flags = CKF_OS_LOCKING_OK;
    const CK_RV initialized = functions_->C_Initialize(&args);
    if (initialized != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
      if (initialized == CKR_OK) {
        static_cast<void>(functions_->C_Finalize(nullptr));
      }
      return testing::AssertionFailure()
             << "C_Initialize returned " << initialized << ": open a store first";
    }
    std::array<CK_SLOT_ID, 16> slots{};
    CK_ULONG count = slots.size();
    if (functions_->C_GetSlotList(CK_TRUE, slots.data(), &count) != CKR_OK) {
      return testing::AssertionFailure() << "C_GetSlotList";
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
        if (rv != CKR_OK) {
          return testing::AssertionFailure() << "C_OpenSession returned " << rv;
        }
        return testing::AssertionSuccess();
      }
    }
    return testing::AssertionFailure() << "no token labelled " << token.label;
  }

  // A token certificate object that carries id. The module does not parse CKA_VALUE, so any
  // bytes do. (CKO_DATA would not do: data objects have no CKA_ID.)
  testing::AssertionResult create_certificate(const eki_key_id& id) {
    CK_OBJECT_CLASS object_class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certificate_type = CKC_X_509;
    CK_BBOOL yes = CK_TRUE;
    eki_key_id id_value = id;
    std::string label = "eki-test certificate";
    std::string subject = "not a DER name";
    std::string value = "not a DER certificate";
    std::array attributes{
        attribute(CKA_CLASS, object_class), attribute(CKA_CERTIFICATE_TYPE, certificate_type),
        attribute(CKA_TOKEN, yes),          attribute(CKA_ID, std::span{id_value.bytes}),
        attribute(CKA_LABEL, label),        attribute(CKA_SUBJECT, subject),
        attribute(CKA_VALUE, value),
    };
    return create(attributes);
  }

  // A private token secret key of key_type (CKK_AES, CKK_GENERIC_SECRET) with the given value and
  // label, carrying the usage attributes of its row in the §4.3 table.
  testing::AssertionResult create_secret(const eki_key_id& id, CK_KEY_TYPE key_type,
                                         std::string label, std::span<const std::uint8_t> value) {
    CK_OBJECT_CLASS object_class = CKO_SECRET_KEY;
    CK_BBOOL yes = CK_TRUE;
    eki_key_id id_value = id;
    std::vector<std::uint8_t> key_value(value.begin(), value.end());
    std::vector<CK_ATTRIBUTE> attributes{
        attribute(CKA_CLASS, object_class),
        attribute(CKA_KEY_TYPE, key_type),
        attribute(CKA_TOKEN, yes),
        attribute(CKA_PRIVATE, yes),
        attribute(CKA_ID, std::span{id_value.bytes}),
        attribute(CKA_LABEL, label),
        attribute(CKA_VALUE, std::span{key_value}),
        attribute(CKA_SENSITIVE, yes),
        attribute(CKA_EXTRACTABLE, yes),
    };
    for (const CK_ATTRIBUTE_TYPE usage :
         key_type == CKK_AES
             ? std::vector<CK_ATTRIBUTE_TYPE>{CKA_WRAP, CKA_UNWRAP, CKA_ENCRYPT, CKA_DECRYPT}
             : std::vector<CK_ATTRIBUTE_TYPE>{CKA_SIGN, CKA_VERIFY}) {
      attributes.push_back(attribute(usage, yes));
    }
    return create(attributes);
  }

  // Destroys the objects of object_class that carry id.
  testing::AssertionResult destroy(const eki_key_id& id, CK_OBJECT_CLASS object_class) {
    eki_key_id id_value = id;
    std::array search{
        attribute(CKA_CLASS, object_class),
        attribute(CKA_ID, std::span{id_value.bytes}),
    };
    std::array<CK_OBJECT_HANDLE, 16> found{};
    CK_ULONG count = 0;
    if (functions_->C_FindObjectsInit(session_, search.data(), search.size()) != CKR_OK) {
      return testing::AssertionFailure() << "C_FindObjectsInit";
    }
    const CK_RV rv = functions_->C_FindObjects(session_, found.data(), found.size(), &count);
    static_cast<void>(functions_->C_FindObjectsFinal(session_));
    if (rv != CKR_OK || count == 0) {
      return testing::AssertionFailure() << "no object found";
    }
    for (const CK_OBJECT_HANDLE object : std::span{found}.first(count)) {
      if (functions_->C_DestroyObject(session_, object) != CKR_OK) {
        return testing::AssertionFailure() << "C_DestroyObject";
      }
    }
    return testing::AssertionSuccess();
  }

private:
  testing::AssertionResult create(std::span<CK_ATTRIBUTE> attributes) {
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    const CK_RV rv =
        functions_->C_CreateObject(session_, attributes.data(), attributes.size(), &object);
    if (rv != CKR_OK) {
      return testing::AssertionFailure() << "C_CreateObject returned " << rv;
    }
    return testing::AssertionSuccess();
  }

  CK_FUNCTION_LIST* functions_ = nullptr;
  CK_SESSION_HANDLE session_ = CK_INVALID_HANDLE;
};

// The id is taken by any object of any class: an operation that needs the key answers BACKEND with
// a message, unwrap into the id answers KEY_EXISTS, and destroy removes the object.
TEST_F(FfiKeystorePkcs11, ForeignObjectTakesTheIdAndCanBeDestroyed) {
  ASSERT_TRUE(open_store());
  RawToken raw;
  ASSERT_TRUE(raw.open(token()));
  const eki_key_id id = raw_id('c');
  store().track(id);
  ASSERT_TRUE(raw.create_certificate(id));

  eki_key_info info = prefilled_info();
  EXPECT_EQ(name(eki_ks_get_info(store().get(), &id, &info)), name(EKI_ERR_BACKEND));
  EXPECT_TRUE(info_zero(info));
  EXPECT_FALSE(last_error(store().get()).value_or("").empty());
  scenarios::Mac mac = prefilled<32>();
  EXPECT_EQ(name(eki_ks_hmac_sha256(store().get(), &id, nullptr, 0, mac.data())),
            name(EKI_ERR_BACKEND));
  EXPECT_FALSE(last_error(store().get()).value_or("").empty());

  eki_key_id kek{};
  eki_key_id key{};
  ASSERT_TRUE(store().generate(EKI_KEY_AES_256, "eki-test kek", kek));
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", key));
  scenarios::Blob blob{};
  ASSERT_TRUE(store().wrap(kek, key, blob));
  EXPECT_EQ(name(eki_ks_unwrap(store().get(), &kek, blob.data(), blob.size(), EKI_KEY_HMAC_SHA256,
                               "eki-test unwrapped", &id)),
            name(EKI_ERR_KEY_EXISTS));

  ASSERT_TRUE(store().destroy(id));
  info = prefilled_info();
  EXPECT_EQ(name(eki_ks_get_info(store().get(), &id, &info)), name(EKI_ERR_KEY_NOT_FOUND));
  EXPECT_EQ(name(eki_ks_destroy(store().get(), &id)), name(EKI_ERR_KEY_NOT_FOUND));
}

// ks_wrap checks that both ids exist before it describes either (plan 4.2): a foreign kek with a
// missing key is KEY_NOT_FOUND, and a foreign object is a backend failure only at the step that
// needs its algorithm, after the type check of the kek.
TEST_F(FfiKeystorePkcs11, WrapChecksBothIdsBeforeDescribingAForeignObject) {
  ASSERT_TRUE(open_store());
  RawToken raw;
  ASSERT_TRUE(raw.open(token()));
  const eki_key_id foreign = raw_id('f');
  const eki_key_id missing = raw_id('n');
  const std::array<std::uint8_t, 32> value{};
  store().track(foreign);
  ASSERT_TRUE(raw.create_secret(foreign, CKK_AES, "", value));

  scenarios::Blob blob = prefilled<40>();
  EXPECT_EQ(name(eki_ks_wrap(store().get(), &foreign, &missing, blob.data())),
            name(EKI_ERR_KEY_NOT_FOUND));
  EXPECT_TRUE(all_zero(blob));

  eki_key_id kek{};
  eki_key_id mac{};
  ASSERT_TRUE(store().generate(EKI_KEY_AES_256, "eki-test kek", kek));
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  EXPECT_EQ(name(eki_ks_wrap(store().get(), &kek, &missing, blob.data())),
            name(EKI_ERR_KEY_NOT_FOUND));
  EXPECT_EQ(name(eki_ks_wrap(store().get(), &foreign, &mac, blob.data())), name(EKI_ERR_BACKEND));
  EXPECT_FALSE(last_error(store().get()).value_or("").empty());
  EXPECT_EQ(name(eki_ks_wrap(store().get(), &kek, &foreign, blob.data())), name(EKI_ERR_BACKEND));
  EXPECT_FALSE(last_error(store().get()).value_or("").empty());
  EXPECT_EQ(name(eki_ks_wrap(store().get(), &mac, &foreign, blob.data())),
            name(EKI_ERR_WRONG_KEY_TYPE));
  ASSERT_TRUE(store().destroy(foreign));
}

// The token reports a failed integrity check with a code other causes share, so the AUTH_FAILED of
// unwrap carries the code as its message.
TEST_F(FfiKeystorePkcs11, FailedUnwrapNamesTheReturnCode) {
  ASSERT_TRUE(open_store());
  eki_key_id kek{};
  eki_key_id mac{};
  ASSERT_TRUE(store().generate(EKI_KEY_AES_256, "eki-test kek", kek));
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  scenarios::Blob blob{};
  ASSERT_TRUE(store().wrap(kek, mac, blob));
  blob.at(20) = static_cast<std::uint8_t>(blob.at(20) ^ 0x01U);
  const eki_key_id id = raw_id('u');
  EXPECT_EQ(name(eki_ks_unwrap(store().get(), &kek, blob.data(), blob.size(), EKI_KEY_HMAC_SHA256,
                               "eki-test copy", &id)),
            name(EKI_ERR_AUTH_FAILED));
  EXPECT_TRUE(last_error(store().get()).value_or("").starts_with("C_UnwrapKey failed: CKR_"))
      << last_error(store().get()).value_or("");
}

// A secret key whose CKA_LABEL breaks the label rule is not a key the library can report.
TEST_F(FfiKeystorePkcs11, SecretKeyWithAnInvalidLabelIsForeign) {
  ASSERT_TRUE(open_store());
  RawToken raw;
  ASSERT_TRUE(raw.open(token()));
  const eki_key_id id = raw_id('l');
  const std::array<std::uint8_t, 32> value{};
  for (const std::string& label :
       {std::string{}, label_of_len(65), std::string{"eki\x01test"}, std::string{"eki\x80test"}}) {
    store().track(id);
    ASSERT_TRUE(raw.create_secret(id, CKK_GENERIC_SECRET, label, value));
    eki_key_info info = prefilled_info();
    EXPECT_EQ(name(eki_ks_get_info(store().get(), &id, &info)), name(EKI_ERR_BACKEND))
        << label.size() << "-byte label";
    scenarios::Mac mac = prefilled<32>();
    EXPECT_EQ(name(eki_ks_hmac_sha256(store().get(), &id, nullptr, 0, mac.data())),
              name(EKI_ERR_BACKEND));
    ASSERT_TRUE(store().destroy(id));
  }
}

// A key pair that lost its public half is no longer one of the library's shapes.
TEST_F(FfiKeystorePkcs11, KeyPairWithoutItsPublicHalfIsForeign) {
  ASSERT_TRUE(open_store());
  RawToken raw;
  ASSERT_TRUE(raw.open(token()));
  eki_key_id ec{};
  ASSERT_TRUE(store().generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa", ec));
  ASSERT_TRUE(raw.destroy(ec, CKO_PUBLIC_KEY));

  eki_key_info info = prefilled_info();
  EXPECT_EQ(name(eki_ks_get_info(store().get(), &ec, &info)), name(EKI_ERR_BACKEND));
  scenarios::Signature sig = prefilled<64>();
  EXPECT_EQ(name(eki_ks_sign(store().get(), &ec, nullptr, 0, sig.data())), name(EKI_ERR_BACKEND));
  scenarios::PublicKey pk = prefilled<65>();
  EXPECT_EQ(name(eki_ks_get_public_key(store().get(), &ec, pk.data())), name(EKI_ERR_BACKEND));
  ASSERT_TRUE(store().destroy(ec));
  EXPECT_EQ(name(eki_ks_get_info(store().get(), &ec, &info)), name(EKI_ERR_KEY_NOT_FOUND));
}

// Secret keys that another program created with the §4.3 attributes are keys of the library, and
// the token computes what the stateless functions compute from the same key bytes: HMAC-SHA256
// (CKM_SHA256_HMAC) and RFC 3394 key wrap (CKM_AES_KEY_WRAP).
TEST_F(FfiKeystorePkcs11, SecretKeysCreatedElsewhereAreUsable) {
  ASSERT_TRUE(open_store());
  RawToken raw;
  ASSERT_TRUE(raw.open(token()));
  std::array<std::uint8_t, 32> kek_value{};
  std::array<std::uint8_t, 32> mac_value{};
  std::uint8_t next = 0;
  std::ranges::generate(kek_value, [&next] { return next++; });
  std::ranges::generate(mac_value, [&next] { return next++; });
  const eki_key_id kek = raw_id('k');
  const eki_key_id mac = raw_id('m');
  store().track(kek);
  store().track(mac);
  ASSERT_TRUE(raw.create_secret(kek, CKK_AES, "eki-test raw kek", kek_value));
  ASSERT_TRUE(raw.create_secret(mac, CKK_GENERIC_SECRET, "eki-test raw hmac", mac_value));

  eki_key_info info{};
  ASSERT_TRUE(store().info(kek, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_AES_256, "eki-test raw kek"));
  ASSERT_TRUE(store().info(mac, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_HMAC_SHA256, "eki-test raw hmac"));

  scenarios::Mac from_token{};
  scenarios::Mac expected = prefilled<32>();
  ASSERT_TRUE(store().hmac(mac, bytes("message"), from_token));
  ASSERT_EQ(name(eki_hmac_sha256(mac_value.data(), mac_value.size(), bytes("message").data(),
                                 bytes("message").size(), expected.data())),
            name(EKI_OK));
  EXPECT_EQ(from_token, expected);

  scenarios::Blob blob{};
  scenarios::Blob expected_blob = prefilled<40>();
  ASSERT_TRUE(store().wrap(kek, mac, blob));
  ASSERT_EQ(name(ekicore::aes_256_key_wrap(kek_value, mac_value, expected_blob)), name(EKI_OK));
  EXPECT_EQ(blob, expected_blob);
}

} // namespace
