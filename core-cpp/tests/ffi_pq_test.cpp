// Hybrid X25519 + ML-KEM-768 KEM through the C ABI. Disabled until lesson L9 (pq.cpp). Mirrors
// core-rs/tests/ffi_pq.rs: plan §4.4 hybrid rows and the KEM sequence of §4.2 (NULL checks, then
// UNSUPPORTED when not compiled in, then the all-zero X25519 and ML-KEM key checks; decapsulation
// never fails). Which half runs depends on EKI_WITH_PQ (eki_test::kWithPq); the other half skips.

#include "test_support.hpp"

#include <gtest/gtest.h>

#include <ekicore.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

// Test bodies are flat sequences of assertions; the gtest macros inflate the complexity score.
// NOLINTBEGIN(readability-function-cognitive-complexity)
namespace {

using eki_test::all_zero;
using eki_test::kWithPq;
using eki_test::name;
using eki_test::prefilled;

using Pk = std::array<std::uint8_t, EKI_HYBRID_PK_LEN>;
using Sk = std::array<std::uint8_t, EKI_HYBRID_SK_LEN>;
using Ct = std::array<std::uint8_t, EKI_HYBRID_CT_LEN>;
using Ss = std::array<std::uint8_t, EKI_HYBRID_SS_LEN>;

// Length of the X25519 part, which is also the offset of the ML-KEM part, of pk, sk and ct.
constexpr std::size_t kX25519Len = 32;
constexpr auto kX25519Off = static_cast<std::ptrdiff_t>(kX25519Len);

// Lesson L9. NULL pointers are reported before anything else, with or without PQ.
TEST(FfiPq, DISABLED_NullPointers) {
  const Pk pk = prefilled<EKI_HYBRID_PK_LEN>();
  const Sk sk = prefilled<EKI_HYBRID_SK_LEN>();
  const Ct ct = prefilled<EKI_HYBRID_CT_LEN>();

  Sk sk_out = sk;
  EXPECT_EQ(name(eki_hybrid_kem_keygen(nullptr, sk_out.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(sk_out));
  Pk pk_out = pk;
  EXPECT_EQ(name(eki_hybrid_kem_keygen(pk_out.data(), nullptr)), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(pk_out));

  Ct ct_out = ct;
  Ss ss = prefilled<EKI_HYBRID_SS_LEN>();
  EXPECT_EQ(name(eki_hybrid_kem_encap(nullptr, ct_out.data(), ss.data())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(ct_out));
  EXPECT_TRUE(all_zero(ss));
  EXPECT_EQ(name(eki_hybrid_kem_encap(pk.data(), nullptr, ss.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_EQ(name(eki_hybrid_kem_encap(pk.data(), ct_out.data(), nullptr)),
            name(EKI_ERR_NULL_POINTER));

  ss = prefilled<EKI_HYBRID_SS_LEN>();
  EXPECT_EQ(name(eki_hybrid_kem_decap(nullptr, ct.data(), ss.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(ss));
  EXPECT_EQ(name(eki_hybrid_kem_decap(sk.data(), nullptr, ss.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_EQ(name(eki_hybrid_kem_decap(sk.data(), ct.data(), nullptr)), name(EKI_ERR_NULL_POINTER));
}

// Lesson L9. §4.4: hybrid (feature off), valid pointers → UNSUPPORTED, outputs zero-filled.
TEST(FfiPq, DISABLED_UnsupportedWithoutPq) {
  if (kWithPq) {
    GTEST_SKIP() << "built with EKI_WITH_PQ";
  }
  Pk pk = prefilled<EKI_HYBRID_PK_LEN>();
  Sk sk = prefilled<EKI_HYBRID_SK_LEN>();
  EXPECT_EQ(name(eki_hybrid_kem_keygen(pk.data(), sk.data())), name(EKI_ERR_UNSUPPORTED));
  EXPECT_TRUE(all_zero(pk));
  EXPECT_TRUE(all_zero(sk));

  const Pk pk_in = prefilled<EKI_HYBRID_PK_LEN>();
  Ct ct = prefilled<EKI_HYBRID_CT_LEN>();
  Ss ss = prefilled<EKI_HYBRID_SS_LEN>();
  EXPECT_EQ(name(eki_hybrid_kem_encap(pk_in.data(), ct.data(), ss.data())),
            name(EKI_ERR_UNSUPPORTED));
  EXPECT_TRUE(all_zero(ct));
  EXPECT_TRUE(all_zero(ss));

  const Sk sk_in = prefilled<EKI_HYBRID_SK_LEN>();
  const Ct ct_in = prefilled<EKI_HYBRID_CT_LEN>();
  ss = prefilled<EKI_HYBRID_SS_LEN>();
  EXPECT_EQ(name(eki_hybrid_kem_decap(sk_in.data(), ct_in.data(), ss.data())),
            name(EKI_ERR_UNSUPPORTED));
  EXPECT_TRUE(all_zero(ss));
}

// Tests of the real KEM; skipped when the library is built without EKI_WITH_PQ.
class FfiPqEnabled : public testing::Test {
protected:
  void SetUp() override {
    if (!kWithPq) {
      GTEST_SKIP() << "built without EKI_WITH_PQ";
    }
  }

  static testing::AssertionResult keypair(Pk& pk, Sk& sk) {
    pk = prefilled<EKI_HYBRID_PK_LEN>();
    sk = prefilled<EKI_HYBRID_SK_LEN>();
    const eki_status status = eki_hybrid_kem_keygen(pk.data(), sk.data());
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "keygen returned " << name(status);
    }
    return testing::AssertionSuccess();
  }

  static testing::AssertionResult encapsulate(const Pk& pk, Ct& ct, Ss& ss) {
    ct = prefilled<EKI_HYBRID_CT_LEN>();
    ss = prefilled<EKI_HYBRID_SS_LEN>();
    const eki_status status = eki_hybrid_kem_encap(pk.data(), ct.data(), ss.data());
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "encap returned " << name(status);
    }
    return testing::AssertionSuccess();
  }

  static eki_status decapsulate(const Sk& sk, const Ct& ct, Ss& ss) {
    ss = prefilled<EKI_HYBRID_SS_LEN>();
    return eki_hybrid_kem_decap(sk.data(), ct.data(), ss.data());
  }
};

// Lesson L9.
TEST_F(FfiPqEnabled, DISABLED_RoundTrip) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  Ss ss2{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));
  EXPECT_EQ(name(decapsulate(sk, ct, ss2)), name(EKI_OK));
  EXPECT_EQ(ss, ss2) << "both sides derive the same secret";

  // Fresh randomness everywhere.
  Pk pk2{};
  Sk sk2{};
  ASSERT_TRUE(keypair(pk2, sk2));
  EXPECT_NE(pk, pk2);
  EXPECT_NE(sk, sk2);
  Ct ct2{};
  Ss ss3{};
  ASSERT_TRUE(encapsulate(pk, ct2, ss3));
  EXPECT_NE(ct, ct2);
  EXPECT_NE(ss, ss3);

  // Decapsulation is deterministic.
  EXPECT_EQ(name(decapsulate(sk, ct, ss2)), name(EKI_OK));
  EXPECT_EQ(ss, ss2);
}

// Lesson L9. §4.2: implicit rejection; a tampered ML-KEM ciphertext gives OK and another secret.
TEST_F(FfiPqEnabled, DISABLED_TamperedMlkemCiphertextGivesADifferentSecret) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));
  for (const std::size_t index : {kX25519Len, kX25519Len + 500, ct.size() - 1}) {
    Ct bad = ct;
    bad.at(index) = static_cast<std::uint8_t>(bad.at(index) ^ 0x01U);
    Ss other{};
    EXPECT_EQ(name(decapsulate(sk, bad, other)), name(EKI_OK)) << "byte " << index;
    EXPECT_NE(other, ss) << "byte " << index;
  }
}

// Lesson L9.
TEST_F(FfiPqEnabled, DISABLED_TamperedX25519CiphertextGivesADifferentSecret) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));
  ct.at(0) = static_cast<std::uint8_t>(ct.at(0) ^ 0x02U);
  Ss other{};
  EXPECT_EQ(name(decapsulate(sk, ct, other)), name(EKI_OK));
  EXPECT_NE(other, ss);
}

// Lesson L9.
TEST_F(FfiPqEnabled, DISABLED_WrongSecretKeyGivesADifferentSecret) {
  Pk pk{};
  Sk sk{};
  Pk other_pk{};
  Sk other_sk{};
  Ct ct{};
  Ss ss{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(keypair(other_pk, other_sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));
  Ss other{};
  EXPECT_EQ(name(decapsulate(other_sk, ct, other)), name(EKI_OK));
  EXPECT_NE(other, ss);
}

// Lesson L9. §4.4: hybrid_encap, pk with all-zero x25519 part → INVALID_ARGUMENT.
TEST_F(FfiPqEnabled, DISABLED_EncapToAllZeroX25519PartIsInvalid) {
  Pk pk{};
  Sk sk{};
  ASSERT_TRUE(keypair(pk, sk));
  std::fill(pk.begin(), pk.begin() + kX25519Off, std::uint8_t{0});
  Ct ct = prefilled<EKI_HYBRID_CT_LEN>();
  Ss ss = prefilled<EKI_HYBRID_SS_LEN>();
  EXPECT_EQ(name(eki_hybrid_kem_encap(pk.data(), ct.data(), ss.data())),
            name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(all_zero(ct));
  EXPECT_TRUE(all_zero(ss));
}

// Lesson L9. The all-zero X25519 point gives an all-zero shared secret (§4.2) → INVALID_ARGUMENT.
TEST_F(FfiPqEnabled, DISABLED_DecapWithAllZeroX25519PartIsInvalid) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));
  std::fill(ct.begin(), ct.begin() + kX25519Off, std::uint8_t{0});
  Ss out{};
  EXPECT_EQ(name(decapsulate(sk, ct, out)), name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(all_zero(out));
}

// Lesson L9. ML-KEM encapsulation-key check (FIPS 203 modulus check): 0xff bytes encode 12-bit
// coefficients of 4095 >= q = 3329 → INVALID_ARGUMENT.
TEST_F(FfiPqEnabled, DISABLED_EncapToMlkemKeyFailingTheModulusCheckIsInvalid) {
  Pk pk{};
  Sk sk{};
  ASSERT_TRUE(keypair(pk, sk));
  std::fill(pk.begin() + kX25519Off, pk.begin() + kX25519Off + 384, std::uint8_t{0xff});
  Ct ct = prefilled<EKI_HYBRID_CT_LEN>();
  Ss ss = prefilled<EKI_HYBRID_SS_LEN>();
  EXPECT_EQ(name(eki_hybrid_kem_encap(pk.data(), ct.data(), ss.data())),
            name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(all_zero(ct));
  EXPECT_TRUE(all_zero(ss));
}

} // namespace
// NOLINTEND(readability-function-cognitive-complexity)
