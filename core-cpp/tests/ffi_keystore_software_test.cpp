// The software key store through the C ABI. Mirrors core-rs/tests/ffi_keystore_software.rs: plan
// §4.4 ks_open and every store row; §4.2 sequences, labels, outputs on error, last error and
// thread safety. The scenarios shared with the PKCS#11 suite are in test_support.hpp.

#include "test_support.hpp"

#include <gtest/gtest.h>

#include <ekicore.h>

#include <array>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace {

using eki_test::all_zero;
using eki_test::bytes;
using eki_test::id_bytes;
using eki_test::info_is;
using eki_test::info_zero;
using eki_test::label_of_len;
using eki_test::name;
using eki_test::open_fails;
using eki_test::prefilled_id;
using eki_test::prefilled_info;
using eki_test::software_config;
using eki_test::Store;
using eki_test::try_open;
namespace scenarios = eki_test::scenarios;

// --- open / close ------------------------------------------------------------------------------

TEST(FfiKeystoreSoftware, OpenAndClose) {
  const eki_ks_config config = software_config();
  const eki_test::Opened opened = try_open(&config);
  EXPECT_EQ(name(opened.status), name(EKI_OK));
  ASSERT_FALSE(opened.out_is_null);
  eki_ks_close(opened.handle);
  eki_ks_close(nullptr); // NULL-safe
}

// Software ignores the PKCS#11 fields.
TEST(FfiKeystoreSoftware, OpenIgnoresThePkcs11Fields) {
  const eki_ks_config config{
      .backend = EKI_KS_SOFTWARE,
      .pkcs11_module_path = "not a module",
      .pkcs11_token_label = "not a token",
      .pkcs11_user_pin = "not a pin",
  };
  Store store;
  ASSERT_TRUE(store.open(config));
  eki_key_id id{};
  ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, "eki-test", id));
}

// §4.4: `backend 0`; `backend 99` → INVALID_ARGUMENT.
TEST(FfiKeystoreSoftware, OpenUnknownBackendIsInvalid) {
  for (const eki_ks_backend backend : {0, 3, 99, -1, INT32_MIN, INT32_MAX}) {
    EXPECT_TRUE(
        open_fails(eki_ks_config{backend, nullptr, nullptr, nullptr}, EKI_ERR_INVALID_ARGUMENT))
        << "backend " << backend;
  }
}

// §4.4: PKCS#11 with `module_path NULL` → NULL_POINTER (UNSUPPORTED if PKCS#11 is not compiled
// in: the selector check, step 2, answers first). Disabled until the PKCS#11 backend exists: until
// then the library answers EKI_KS_PKCS11 as not compiled in even when EKI_WITH_PKCS11 is on, while
// kWithPkcs11 follows EKI_WITH_PKCS11.
TEST(FfiKeystoreSoftware, DISABLED_OpenPkcs11WithNullModulePath) {
  const eki_status expected = eki_test::kWithPkcs11 ? EKI_ERR_NULL_POINTER : EKI_ERR_UNSUPPORTED;
  EXPECT_TRUE(open_fails(eki_ks_config{EKI_KS_PKCS11, nullptr, "ekibridge", "1234"}, expected));
}

// §4.4: required pointer NULL → NULL_POINTER; `*out` is NULL on failure.
TEST(FfiKeystoreSoftware, OpenNullPointers) {
  const eki_test::Opened opened = try_open(nullptr);
  EXPECT_EQ(name(opened.status), name(EKI_ERR_NULL_POINTER)) << "config NULL";
  EXPECT_TRUE(opened.out_is_null);
  const eki_ks_config config = software_config();
  EXPECT_EQ(name(eki_ks_open(&config, nullptr)), name(EKI_ERR_NULL_POINTER)) << "out NULL";
  const eki_ks_config bad{
      .backend = 99,
      .pkcs11_module_path = nullptr,
      .pkcs11_token_label = nullptr,
      .pkcs11_user_pin = nullptr,
  };
  EXPECT_EQ(name(eki_ks_open(&bad, nullptr)), name(EKI_ERR_NULL_POINTER))
      << "out NULL before backend 99";
}

TEST(FfiKeystoreSoftware, StoresAreIndependent) {
  Store a;
  Store b;
  ASSERT_TRUE(a.open(software_config()));
  ASSERT_TRUE(b.open(software_config()));
  eki_key_id id{};
  ASSERT_TRUE(a.generate(EKI_KEY_HMAC_SHA256, "eki-test", id));
  eki_key_info info = prefilled_info();
  EXPECT_EQ(name(eki_ks_get_info(b.get(), &id, &info)), name(EKI_ERR_KEY_NOT_FOUND));
  EXPECT_TRUE(info_zero(info));
}

TEST(FfiKeystoreSoftware, KeysAreGoneAfterCloseAndReopen) {
  eki_key_id id{};
  {
    Store store;
    ASSERT_TRUE(store.open(software_config()));
    ASSERT_TRUE(store.generate(EKI_KEY_AES_256, "eki-test", id));
    store.forget(id);
  }
  Store store;
  ASSERT_TRUE(store.open(software_config()));
  eki_key_info info = prefilled_info();
  EXPECT_EQ(name(eki_ks_get_info(store.get(), &id, &info)), name(EKI_ERR_KEY_NOT_FOUND));
}

// --- shared scenarios --------------------------------------------------------------------------

class FfiKeystoreSoftwareScenario : public testing::Test {
protected:
  void SetUp() override {
    ASSERT_TRUE(store_.open(software_config()));
  }
  Store& store() {
    return store_;
  }

private:
  Store store_;
};

TEST_F(FfiKeystoreSoftwareScenario, Lifecycle) {
  scenarios::lifecycle(store());
}

TEST_F(FfiKeystoreSoftwareScenario, WrapUnwrapRoundTrip) {
  scenarios::wrap_unwrap_round_trip(store());
}

TEST_F(FfiKeystoreSoftwareScenario, GenerateRows) {
  scenarios::generate_rows(store());
}

TEST_F(FfiKeystoreSoftwareScenario, GenerateNullRows) {
  scenarios::generate_null_rows(store());
}

TEST_F(FfiKeystoreSoftwareScenario, LookupRows) {
  scenarios::lookup_rows(store());
}

TEST_F(FfiKeystoreSoftwareScenario, LookupNullRows) {
  scenarios::lookup_null_rows(store());
}

TEST_F(FfiKeystoreSoftwareScenario, WrapRows) {
  scenarios::wrap_rows(store());
}

TEST_F(FfiKeystoreSoftwareScenario, UnwrapRows) {
  scenarios::unwrap_rows(store());
}

TEST_F(FfiKeystoreSoftwareScenario, LastErrorRows) {
  scenarios::last_error_rows(store());
}

// --- software-only -----------------------------------------------------------------------------

// A 64-byte label is the maximum; 65 non-NUL bytes in an allocation of exactly 65
// bytes are rejected without reading past the end (ASan reports an over-read).
TEST_F(FfiKeystoreSoftwareScenario, LabelBoundedScan) {
  const std::string text = label_of_len(64);
  eki_key_id id{};
  ASSERT_TRUE(store().generate(EKI_KEY_ECDSA_P256, text, id));
  eki_key_info info{};
  ASSERT_TRUE(store().info(id, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_ECDSA_P256, text));
  EXPECT_EQ(info.label[64], '\0');

  const std::vector<char> unterminated(65, 'x');
  id = prefilled_id();
  EXPECT_EQ(name(eki_ks_generate(store().get(), EKI_KEY_AES_256, unterminated.data(), &id)),
            name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(all_zero(id_bytes(id)));
}

// §4.2 "Thread safety": one handle shared by several threads.
TEST_F(FfiKeystoreSoftwareScenario, OneHandleSharedByThreads) {
  eki_key_id mac{};
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test shared", mac));
  scenarios::Mac expected{};
  ASSERT_TRUE(store().hmac(mac, bytes("message"), expected));
  eki_ks* ks = store().get();
  const auto msg = bytes("message");
  std::vector<std::thread> threads;
  std::array<int, 8> failures{};
  threads.reserve(failures.size());
  for (std::size_t t = 0; t < failures.size(); ++t) {
    threads.emplace_back([&, t] {
      for (int i = 0; i < 50; ++i) {
        scenarios::Mac out{};
        if (eki_ks_hmac_sha256(ks, &mac, msg.data(), msg.size(), out.data()) != EKI_OK ||
            out != expected) {
          ++failures.at(t);
        }
        // Interleave generate/destroy so writers contend for the lock too.
        eki_key_id id{};
        const std::string text = "eki-test t" + std::to_string(t) + " i" + std::to_string(i);
        if (eki_ks_generate(ks, EKI_KEY_AES_256, text.c_str(), &id) != EKI_OK ||
            eki_ks_destroy(ks, &id) != EKI_OK) {
          ++failures.at(t);
        }
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  EXPECT_EQ(failures, (std::array<int, 8>{}));
}

// Wrap/unwrap preserves the key under many labels and ids (the Rust suite uses
// proptest; here a deterministic sweep). The metadata is unauthenticated (plan §2): the same blob
// may be unwrapped as either secret-key algorithm.
TEST_F(FfiKeystoreSoftwareScenario, WrapUnwrapPreservesTheKey) {
  eki_key_id kek{};
  eki_key_id mac{};
  ASSERT_TRUE(store().generate(EKI_KEY_AES_256, "eki-test kek", kek));
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  scenarios::Blob blob{};
  ASSERT_TRUE(store().wrap(kek, mac, blob));
  for (std::uint8_t i = 1; i <= 32; ++i) {
    const eki_key_id id = eki_test::fixed_id(static_cast<std::uint8_t>(0x80U + i));
    std::string text(static_cast<std::size_t>(i) * 2, ' ');
    for (std::size_t j = 0; j < text.size(); ++j) {
      text.at(j) = static_cast<char>(0x20 + (((j * 7) + i) % 95));
    }
    const eki_key_alg alg = (i % 2 == 0) ? EKI_KEY_AES_256 : EKI_KEY_HMAC_SHA256;
    ASSERT_TRUE(store().unwrap(kek, blob, alg, text, id));
    eki_key_info info{};
    ASSERT_TRUE(store().info(id, info));
    EXPECT_TRUE(info_is(info, alg, text));
    if (alg == EKI_KEY_HMAC_SHA256) {
      scenarios::Mac a{};
      scenarios::Mac b{};
      const std::vector<std::uint8_t> msg(i, i);
      ASSERT_TRUE(store().hmac(id, msg, a));
      ASSERT_TRUE(store().hmac(mac, msg, b));
      EXPECT_EQ(a, b);
    }
    scenarios::Blob again{};
    ASSERT_TRUE(store().wrap(kek, id, again));
    EXPECT_EQ(again, blob) << "re-wrapping the copy gives the same blob";
  }
}

// §4.3: a failed unwrap creates nothing and leaves existing keys unchanged. Beyond their metadata
// (checked in the unwrap rows), the keys still work exactly as before.
TEST_F(FfiKeystoreSoftwareScenario, FailedUnwrapLeavesExistingKeysUsable) {
  eki_ks* ks = store().get();
  eki_key_id kek{};
  eki_key_id mac{};
  ASSERT_TRUE(store().generate(EKI_KEY_AES_256, "eki-test kek", kek));
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  scenarios::Mac before{};
  scenarios::Blob blob{};
  ASSERT_TRUE(store().hmac(mac, bytes("message"), before));
  ASSERT_TRUE(store().wrap(kek, mac, blob));

  scenarios::Blob flipped = blob;
  flipped.at(0) = static_cast<std::uint8_t>(flipped.at(0) ^ 0x01U);
  const eki_key_id fresh = eki_test::fixed_id(0x31);
  EXPECT_EQ(name(eki_ks_unwrap(ks, &kek, flipped.data(), flipped.size(), EKI_KEY_HMAC_SHA256,
                               "eki-test copy", &fresh)),
            name(EKI_ERR_AUTH_FAILED));
  EXPECT_EQ(name(eki_ks_unwrap(ks, &kek, blob.data(), blob.size(), EKI_KEY_AES_256,
                               "eki-test overwrite", &mac)),
            name(EKI_ERR_KEY_EXISTS));
  EXPECT_EQ(name(eki_ks_unwrap(ks, &kek, blob.data(), blob.size(), EKI_KEY_HMAC_SHA256,
                               "eki-test overwrite", &kek)),
            name(EKI_ERR_KEY_EXISTS));

  scenarios::Mac after{};
  ASSERT_TRUE(store().hmac(mac, bytes("message"), after));
  EXPECT_EQ(after, before) << "the HMAC key is unchanged";
  scenarios::Blob again{};
  ASSERT_TRUE(store().wrap(kek, mac, again));
  EXPECT_EQ(again, blob) << "the KEK is unchanged";
  eki_key_info info = prefilled_info();
  EXPECT_EQ(name(eki_ks_get_info(ks, &fresh, &info)), name(EKI_ERR_KEY_NOT_FOUND));
  EXPECT_TRUE(info_zero(info));

  ASSERT_TRUE(store().unwrap(kek, blob, EKI_KEY_HMAC_SHA256, "eki-test copy", fresh));
  ASSERT_TRUE(store().hmac(fresh, bytes("message"), after));
  EXPECT_EQ(after, before);
}

// §4.2: an id is taken while any object carries it, and only then. Once destroyed, an id can be
// given to an unwrapped key, which has the new algorithm and label.
TEST_F(FfiKeystoreSoftwareScenario, DestroyedIdIsFreeForUnwrap) {
  eki_ks* ks = store().get();
  eki_key_id kek{};
  eki_key_id mac{};
  eki_key_id ec{};
  ASSERT_TRUE(store().generate(EKI_KEY_AES_256, "eki-test kek", kek));
  ASSERT_TRUE(store().generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  ASSERT_TRUE(store().generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa", ec));
  scenarios::Blob blob{};
  ASSERT_TRUE(store().wrap(kek, mac, blob));
  ASSERT_TRUE(store().destroy(ec));

  ASSERT_TRUE(store().unwrap(kek, blob, EKI_KEY_HMAC_SHA256, "eki-test reused id", ec));
  eki_key_info info{};
  ASSERT_TRUE(store().info(ec, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_HMAC_SHA256, "eki-test reused id"));
  scenarios::PublicKey pk = eki_test::prefilled<65>();
  EXPECT_EQ(name(eki_ks_get_public_key(ks, &ec, pk.data())), name(EKI_ERR_WRONG_KEY_TYPE));
  EXPECT_TRUE(all_zero(pk));
  scenarios::Mac a{};
  scenarios::Mac b{};
  ASSERT_TRUE(store().hmac(ec, bytes("message"), a));
  ASSERT_TRUE(store().hmac(mac, bytes("message"), b));
  EXPECT_EQ(a, b);
}

// eki_ks_sign cross-checked with the stateless eki_ecdsa_p256_verify over several message
// lengths: each signature verifies under its own key's public key and under no other.
TEST_F(FfiKeystoreSoftwareScenario, SignaturesVerifyOnlyUnderTheirOwnPublicKey) {
  eki_key_id first{};
  eki_key_id second{};
  ASSERT_TRUE(store().generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa 1", first));
  ASSERT_TRUE(store().generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa 2", second));
  scenarios::PublicKey first_pk{};
  scenarios::PublicKey second_pk{};
  ASSERT_TRUE(store().public_key(first, first_pk));
  ASSERT_TRUE(store().public_key(second, second_pk));
  EXPECT_NE(first_pk, second_pk);

  for (const std::size_t len : {
           std::size_t{0},
           std::size_t{1},
           std::size_t{55},
           std::size_t{64},
           std::size_t{1000},
           std::size_t{1} << 16U,
       }) {
    std::vector<std::uint8_t> msg(len);
    for (std::size_t i = 0; i < len; ++i) {
      msg.at(i) = static_cast<std::uint8_t>(i * 13U);
    }
    scenarios::Signature sig{};
    ASSERT_TRUE(store().sign(first, msg, sig));
    EXPECT_EQ(name(scenarios::verify(first_pk, msg, sig)), name(EKI_OK)) << "length " << len;
    EXPECT_EQ(name(scenarios::verify(second_pk, msg, sig)), name(EKI_ERR_AUTH_FAILED))
        << "length " << len;
  }
}

} // namespace
