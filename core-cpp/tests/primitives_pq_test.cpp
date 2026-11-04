// Unit tests of the internal hybrid KEM primitives (ekicore::hybrid_kem_keygen, hybrid_kem_encap,
// hybrid_kem_decap) for what the ABI tests in ffi_pq_test.cpp do not reach: the shared secret
// checked against the combiner rebuilt from parts that OpenSSL produces directly, the layout of
// the seed, a pinned known answer, size handling and the caller's OpenSSL error queue.
//
// The primitives answer EKI_ERR_UNSUPPORTED in a build without EKI_WITH_PQ and the ABI test covers
// that, so this file has content only when EKI_TEST_WITH_PQ is 1.

#include "error_queue_support.hpp"
#include "test_support.hpp"

#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <gtest/gtest.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <ekicore.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if defined(EKI_TEST_WITH_PQ) && EKI_TEST_WITH_PQ != 0

// Test bodies are flat sequences of assertions; the gtest macros inflate the complexity score.
// NOLINTBEGIN(readability-function-cognitive-complexity)
namespace {

using eki_test::all_zero;
using eki_test::name;
using eki_test::prefilled;
using eki_test::untouched;

using Pk = std::array<std::uint8_t, EKI_HYBRID_PK_LEN>;
using Sk = std::array<std::uint8_t, EKI_HYBRID_SK_LEN>;
using Ct = std::array<std::uint8_t, EKI_HYBRID_CT_LEN>;
using Ss = std::array<std::uint8_t, EKI_HYBRID_SS_LEN>;
using Bytes = std::span<const std::uint8_t>;

// Length of the X25519 part, which is also the offset of the ML-KEM part, of pk, sk and ct.
constexpr std::size_t x25519_len = 32;
constexpr std::size_t seed_len = 64;
constexpr std::size_t mlkem_ct_len = 1088;
constexpr std::size_t mlkem_ek_len = 1184;
constexpr std::size_t polynomial_bytes = 384;
// The three polynomials of the vector part of an encapsulation key; rho follows them.
constexpr std::size_t coefficient_bytes = 3 * polynomial_bytes;
constexpr std::string_view combiner_label = "ekibridge-hybrid-x25519-mlkem768-v1";

Bytes x25519_half(Bytes whole) {
  return whole.first(x25519_len);
}

Bytes mlkem_half(Bytes whole) {
  return whole.subspan(x25519_len);
}

std::uint8_t flip(std::uint8_t byte, unsigned bit) {
  return static_cast<std::uint8_t>(byte ^ (1U << bit));
}

testing::AssertionResult keypair(Pk& pk, Sk& sk) {
  pk = prefilled<EKI_HYBRID_PK_LEN>();
  sk = prefilled<EKI_HYBRID_SK_LEN>();
  const eki_status status = ekicore::hybrid_kem_keygen(pk, sk);
  if (status != EKI_OK) {
    return testing::AssertionFailure() << "keygen returned " << name(status);
  }
  return testing::AssertionSuccess();
}

testing::AssertionResult encapsulate(const Pk& pk, Ct& ct, Ss& ss) {
  ct = prefilled<EKI_HYBRID_CT_LEN>();
  ss = prefilled<EKI_HYBRID_SS_LEN>();
  const eki_status status = ekicore::hybrid_kem_encap(pk, ct, ss);
  if (status != EKI_OK) {
    return testing::AssertionFailure() << "encap returned " << name(status);
  }
  return testing::AssertionSuccess();
}

eki_status decapsulate(const Sk& sk, const Ct& ct, Ss& ss) {
  ss = prefilled<EKI_HYBRID_SS_LEN>();
  return ekicore::hybrid_kem_decap(sk, ct, ss);
}

// ---------------------------------------------------------------------------------------------
// An oracle that uses OpenSSL's EVP interfaces directly and none of the library's code, so that the
// library's results are compared with parts produced another way.
// ---------------------------------------------------------------------------------------------
namespace oracle {

using Key32 = std::array<std::uint8_t, 32>;
using Ek = std::array<std::uint8_t, mlkem_ek_len>;

// OSSL_PARAM has no const variant; OpenSSL only reads input parameters.
OSSL_PARAM octets(const char* param, Bytes value) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
  return OSSL_PARAM_construct_octet_string(param, const_cast<std::uint8_t*>(value.data()),
                                           value.size());
}

Key32 x25519_public(Bytes secret) {
  const ekicore::ossl::pkey key{
      EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, secret.data(), secret.size())};
  Key32 out{};
  std::size_t len = out.size();
  if (!key || EVP_PKEY_get_raw_public_key(key.get(), out.data(), &len) != 1) {
    ADD_FAILURE() << "oracle: X25519 public key";
  }
  return out;
}

// X25519(secret, peer); nothing when OpenSSL refuses, which it does for an all-zero result.
std::optional<Key32> x25519_shared(Bytes secret, Bytes peer) {
  const ekicore::ossl::pkey own{
      EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, secret.data(), secret.size())};
  const ekicore::ossl::pkey other{
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer.data(), peer.size())};
  const ekicore::ossl::pkey_ctx ctx{own ? EVP_PKEY_CTX_new(own.get(), nullptr) : nullptr};
  Key32 out{};
  std::size_t len = out.size();
  if (!other || !ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
      EVP_PKEY_derive_set_peer(ctx.get(), other.get()) != 1 ||
      EVP_PKEY_derive(ctx.get(), out.data(), &len) != 1) {
    return std::nullopt;
  }
  return out;
}

// The ML-KEM-768 key pair that a 64-byte seed generates.
ekicore::ossl::pkey mlkem_key(Bytes seed) {
  const ekicore::ossl::pkey_ctx ctx{EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr)};
  const std::array<OSSL_PARAM, 2> params{
      octets(OSSL_PKEY_PARAM_ML_KEM_SEED, seed),
      OSSL_PARAM_construct_end(),
  };
  EVP_PKEY* raw = nullptr;
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
      EVP_PKEY_CTX_set_params(ctx.get(), params.data()) != 1 ||
      EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
    ADD_FAILURE() << "oracle: ML-KEM key from seed";
    return nullptr;
  }
  return ekicore::ossl::pkey{raw};
}

Ek mlkem_public(const ekicore::ossl::pkey& key) {
  Ek out{};
  std::size_t len = out.size();
  if (EVP_PKEY_get_raw_public_key(key.get(), out.data(), &len) != 1 || len != out.size()) {
    ADD_FAILURE() << "oracle: ML-KEM encapsulation key";
  }
  return out;
}

Key32 mlkem_decapsulate(const ekicore::ossl::pkey& key, Bytes ct) {
  const ekicore::ossl::pkey_ctx ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr)};
  Key32 out{};
  std::size_t len = out.size();
  if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) != 1 ||
      EVP_PKEY_decapsulate(ctx.get(), out.data(), &len, ct.data(), ct.size()) != 1) {
    ADD_FAILURE() << "oracle: ML-KEM decapsulation";
  }
  return out;
}

// HKDF-SHA256 with the default (absent) salt, straight from EVP_KDF.
Key32 hkdf(Bytes ikm, Bytes info) {
  const ekicore::ossl::kdf kdf{EVP_KDF_fetch(nullptr, "HKDF", nullptr)};
  const ekicore::ossl::kdf_ctx ctx{EVP_KDF_CTX_new(kdf.get())};
  std::array<char, sizeof("SHA256")> digest{"SHA256"};
  const std::array<OSSL_PARAM, 4> params{
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest.data(), 0),
      octets(OSSL_KDF_PARAM_KEY, ikm),
      octets(OSSL_KDF_PARAM_INFO, info),
      OSSL_PARAM_construct_end(),
  };
  Key32 out{};
  if (!ctx || EVP_KDF_derive(ctx.get(), out.data(), out.size(), params.data()) != 1) {
    ADD_FAILURE() << "oracle: HKDF";
  }
  return out;
}

// FIPS 203 implicit rejection (Algorithm 18): a ciphertext that fails the re-encryption check
// decapsulates to SHAKE256(z || c), 32 bytes.
Key32 implicit_rejection_secret(Bytes z, Bytes mlkem_ct) {
  const std::unique_ptr<EVP_MD_CTX, ekicore::ossl::deleter<&EVP_MD_CTX_free>> ctx{EVP_MD_CTX_new()};
  Key32 out{};
  if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_shake256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx.get(), z.data(), z.size()) != 1 ||
      EVP_DigestUpdate(ctx.get(), mlkem_ct.data(), mlkem_ct.size()) != 1 ||
      EVP_DigestFinalXOF(ctx.get(), out.data(), out.size()) != 1) {
    ADD_FAILURE() << "oracle: SHAKE256";
  }
  return out;
}

// The combiner of the contract, written out: HKDF(ss_x25519 || ss_mlkem, "", label || ct || pk).
Key32 combine(const Key32& ss_x25519, const Key32& ss_mlkem, Bytes ct, Bytes pk) {
  std::vector<std::uint8_t> ikm(ss_x25519.begin(), ss_x25519.end());
  ikm.insert(ikm.end(), ss_mlkem.begin(), ss_mlkem.end());
  std::vector<std::uint8_t> info(combiner_label.begin(), combiner_label.end());
  info.insert(info.end(), ct.begin(), ct.end());
  info.insert(info.end(), pk.begin(), pk.end());
  return hkdf(ikm, info);
}

// The public key that sk determines: X25519 public key of sk[0..32) || ek of the seed sk[32..96).
Pk public_key_of(const Sk& sk) {
  Pk pk{};
  const Key32 x = x25519_public(x25519_half(sk));
  const Ek ek = mlkem_public(mlkem_key(mlkem_half(sk)));
  std::ranges::copy(x, pk.begin());
  std::ranges::copy(ek, pk.begin() + static_cast<std::ptrdiff_t>(x25519_len));
  return pk;
}

} // namespace oracle

// ---------------------------------------------------------------------------------------------
// Round trips and independence of the results
// ---------------------------------------------------------------------------------------------

TEST(PrimitivesPq, RoundTripAgrees) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  Ss ss2{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));
  EXPECT_EQ(name(decapsulate(sk, ct, ss2)), name(EKI_OK));
  EXPECT_EQ(ss, ss2);
  EXPECT_FALSE(all_zero(ss));
}

TEST(PrimitivesPq, TwoEncapsulationsToOneKeyDiffer) {
  Pk pk{};
  Sk sk{};
  Ct first_ct{};
  Ct second_ct{};
  Ss first_ss{};
  Ss second_ss{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, first_ct, first_ss));
  ASSERT_TRUE(encapsulate(pk, second_ct, second_ss));
  EXPECT_FALSE(std::ranges::equal(x25519_half(first_ct), x25519_half(second_ct)))
      << "fresh ephemeral X25519 key";
  EXPECT_FALSE(std::ranges::equal(mlkem_half(first_ct), mlkem_half(second_ct)))
      << "fresh ML-KEM randomness";
  EXPECT_NE(first_ss, second_ss);
}

// A bit flipped anywhere in the X25519 half of ct gives a success and a different secret. The top
// bit of the last byte is the one that X25519 ignores (RFC 7748 masks bit 255): there the two
// Diffie-Hellman results are equal and only the binding of ct into the combiner separates the
// secrets.
TEST(PrimitivesPq, FlippedBitInTheX25519HalfOfCtGivesADifferentSecret) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));
  for (std::size_t index = 0; index < x25519_len; ++index) {
    Ct bad = ct;
    bad.at(index) = flip(bad.at(index), 0);
    Ss other{};
    EXPECT_EQ(name(decapsulate(sk, bad, other)), name(EKI_OK)) << "byte " << index;
    EXPECT_NE(other, ss) << "byte " << index;
  }

  Ct masked = ct;
  masked.at(x25519_len - 1) = flip(masked.at(x25519_len - 1), 7);
  const auto original_dh = oracle::x25519_shared(x25519_half(sk), x25519_half(ct));
  const auto masked_dh = oracle::x25519_shared(x25519_half(sk), x25519_half(masked));
  ASSERT_TRUE(original_dh && masked_dh);
  EXPECT_EQ(original_dh.value_or(oracle::Key32{}), masked_dh.value_or(oracle::Key32{}))
      << "X25519 ignores the top bit of the point";
  Ss other{};
  EXPECT_EQ(name(decapsulate(sk, masked, other)), name(EKI_OK));
  EXPECT_NE(other, ss);
}

TEST(PrimitivesPq, FlippedBitInTheMlkemHalfOfCtGivesADifferentSecret) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));
  for (const std::size_t offset :
       {std::size_t{0}, std::size_t{1}, mlkem_ct_len / 2, mlkem_ct_len - 1}) {
    for (const unsigned bit : {0U, 7U}) {
      Ct bad = ct;
      bad.at(x25519_len + offset) = flip(bad.at(x25519_len + offset), bit);
      Ss other{};
      EXPECT_EQ(name(decapsulate(sk, bad, other)), name(EKI_OK)) << offset << " bit " << bit;
      EXPECT_NE(other, ss) << offset << " bit " << bit;
    }
  }
}

TEST(PrimitivesPq, SecretKeyOfAnotherPairGivesADifferentSecret) {
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

  // Each half of the secret key matters: the right X25519 key with the wrong seed and the
  // reverse both fail to reproduce the secret.
  Sk mixed = sk;
  std::ranges::copy(mlkem_half(other_sk), mixed.begin() + static_cast<std::ptrdiff_t>(x25519_len));
  EXPECT_EQ(name(decapsulate(mixed, ct, other)), name(EKI_OK));
  EXPECT_NE(other, ss) << "other seed";
  mixed = other_sk;
  std::ranges::copy(mlkem_half(sk), mixed.begin() + static_cast<std::ptrdiff_t>(x25519_len));
  EXPECT_EQ(name(decapsulate(mixed, ct, other)), name(EKI_OK));
  EXPECT_NE(other, ss) << "other X25519 key";
}

// The secret equals the contract's combiner over parts that OpenSSL produces on its own: X25519
// with the recipient's key and the ephemeral public key in ct, ML-KEM decapsulation with the key
// that the seed generates, HKDF-SHA256 from EVP_KDF. This fixes the order of the two parts, the
// empty salt, and the content and order of info.
TEST(PrimitivesPq, SharedSecretIsTheCombinerOverPartsFromOpenSsl) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  Ss ss2{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));
  const auto ss_x25519 = oracle::x25519_shared(x25519_half(sk), x25519_half(ct));
  ASSERT_TRUE(ss_x25519.has_value());
  const oracle::Key32 ss_mlkem =
      oracle::mlkem_decapsulate(oracle::mlkem_key(mlkem_half(sk)), mlkem_half(ct));
  const oracle::Key32 ss_x = ss_x25519.value_or(oracle::Key32{});
  const oracle::Key32 expected = oracle::combine(ss_x, ss_mlkem, ct, pk);
  EXPECT_TRUE(std::ranges::equal(ss, expected)) << "encap";
  EXPECT_EQ(name(decapsulate(sk, ct, ss2)), name(EKI_OK));
  EXPECT_TRUE(std::ranges::equal(ss2, expected)) << "decap";
}

// pk is a function of sk and of nothing else: the X25519 public key of sk[0..32) and the
// encapsulation key that the seed sk[32..96) generates, rebuilt here by OpenSSL calls alone.
TEST(PrimitivesPq, PublicKeyIsADeterministicFunctionOfTheSecretKey) {
  Pk pk{};
  Sk sk{};
  ASSERT_TRUE(keypair(pk, sk));
  EXPECT_EQ(oracle::public_key_of(sk), pk);
  EXPECT_EQ(oracle::public_key_of(sk), oracle::public_key_of(sk));

  Pk other_pk{};
  Sk other_sk{};
  ASSERT_TRUE(keypair(other_pk, other_sk));
  EXPECT_NE(oracle::public_key_of(other_sk), pk);
}

// The seed is d || z (FIPS 203). The encapsulation key, hence the pk that decapsulation rebuilds,
// depends on d, the first half, and not on z. z only feeds implicit rejection: for a valid ct the
// secret does not depend on it, for a tampered ML-KEM ct it does.
TEST(PrimitivesPq, SeedIsDThenZ) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));

  Sk other_z = sk;
  other_z.at(x25519_len + (seed_len / 2)) = flip(other_z.at(x25519_len + (seed_len / 2)), 3);
  EXPECT_EQ(oracle::public_key_of(other_z), pk) << "ek does not depend on z";
  Ss out{};
  EXPECT_EQ(name(decapsulate(other_z, ct, out)), name(EKI_OK));
  EXPECT_EQ(out, ss) << "a valid ciphertext decapsulates without z";

  Ct tampered = ct;
  tampered.at(x25519_len + 100) = flip(tampered.at(x25519_len + 100), 0);
  Ss rejected{};
  Ss rejected_other_z{};
  EXPECT_EQ(name(decapsulate(sk, tampered, rejected)), name(EKI_OK));
  EXPECT_EQ(name(decapsulate(other_z, tampered, rejected_other_z)), name(EKI_OK));
  EXPECT_NE(rejected, rejected_other_z) << "implicit rejection is keyed with z";
  const Bytes z = mlkem_half(sk).subspan(seed_len / 2);
  EXPECT_EQ(oracle::mlkem_decapsulate(oracle::mlkem_key(mlkem_half(sk)), mlkem_half(tampered)),
            oracle::implicit_rejection_secret(z, mlkem_half(tampered)))
      << "the rejection secret of FIPS 203 is SHAKE256(z || c), z being the last 32 bytes";

  Sk other_d = sk;
  other_d.at(x25519_len) = flip(other_d.at(x25519_len), 0);
  EXPECT_NE(oracle::public_key_of(other_d), pk) << "ek depends on d";
  EXPECT_EQ(name(decapsulate(other_d, ct, out)), name(EKI_OK));
  EXPECT_NE(out, ss);
}

// ---------------------------------------------------------------------------------------------
// A pinned known answer, built once from fixed inputs with OpenSSL calls alone and the combiner of
// the contract. The inputs: the X25519 half of sk is Alice's secret of RFC 7748 section 6.1 (stored
// as printed there, not clamped), its seed is the bytes 00 01 .. 3f, the ephemeral X25519 secret is
// Bob's of the same section, and the ML-KEM encapsulation randomness (OpenSSL's test-only "ikme",
// the message m of FIPS 203) is the bytes 80 81 .. 9f. The X25519 shared secret of the two is the
// one printed in RFC 7748, 4a5d9d5b ... 161742. The known-answer test of the Rust library takes
// the same inputs and arrives at the same ss.
// ---------------------------------------------------------------------------------------------

constexpr std::string_view kat_sk =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a0001020304050607"
    "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f";

constexpr std::string_view kat_ct =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f04c1e43bd82139e4"
    "600aa87fddc0793f7c147e0eb7dccc377f019d22c16ecdcbd22e05bb45e2fd38ca184e7bcc5bb504"
    "cdc13fc6d915cc029057311814bd916923de25330a22a53b6061dc17d892c437276108f1cb12bbbb"
    "37dce17eb4fecff68859850dbac4e0b6fc218a24caa82a4434b0886e63e824632aa32b0dce207636"
    "cbeb40a22b8432c094f07f54af3793d6449322066890576e7d191347e34578f264c5406379e7c0c4"
    "6dbc1857dcd07ced02dd14a5e882cb8073a0906ae293e7a639499321751b7d9b3de1e38eebf20fc0"
    "957fe72643106eb8a87b3862e680c235d99a7e432f7bce65ccbed16973ed46f23c207e4096a563a9"
    "45a867feaadb2a01d570d3bff7585c5f276a23e8f8995076904f89d0d044acf66a93550309326731"
    "ef4c0509047015e0068862de943e84cc9fab33850c86e295dca82d44b3ce236c186aad8120d9134d"
    "4f6597e7278534f42339286987c06c4ba0d52c82e451041106ceddb3c6154d72a8214de6ab4e7af9"
    "6623684a36130d96498698724e4b5fe02f98e602e5d89f35335412bb7d3d9350bd61b99dd8f529b8"
    "f61e5d4f6cb78733d3048e491f3296fb9972ca8af433870287f2ee52ccf487166d7edbbafe475bd3"
    "0c1aa831e5c34975e9b227c5005cce483d9feac2b392efbe5e7c1b81d72d61ef6a9c55f37170c694"
    "b40bae5e6b89274b25613db3de07d426bfb21db9a8f8cd2beb8756fdc9af863c904c2ff9453d21ce"
    "147c96c56e2e052dfaea6ad0ec6dc7eba35af185d2df99ee3d0ae22886d3135da04d90dc384857d1"
    "28d38ea128f794d37d7c2dc74d5406455f04be7d75b5bcffc2b20fa34a5cb633c53874a3930abf38"
    "7f16f5b0da53320dc5747956015f28a6ab54519d0528e4fe56515ace0109cbea117fefae7846e4c1"
    "67734880ea6adb062abb7a530f5855133017fcdf4b25617881eb16538bf69f363d6f4bf9800b3687"
    "e0b18f63489a5da21acb78258f36c30e76b6d268c77131df64e8625aaf8fd1d43de92a1fa8578fb2"
    "2ccde5b97e840fe97503c612199e7e99d7b4849035b3bd274228de0ad486fb788017e2124e34ebfb"
    "0885cfa1c5445d12f64da3694ca0eee205506950a08495f1be86ba0d756ce35c599e9507a3dbeea8"
    "403f78e71e1f0972a4b95519d34ab20b302a93902139666a6000f4549ed2db07ae211733c9050a10"
    "153dd55f3b02e9c345ffb4a58c0bd2ca34e23c3d3dc45ecd875321420f921527e7d1de27bf9525ae"
    "4c014ab52d147771be029d1dc18352d93f47c3ac7a2d2d6004d1a70da2207cb7de664166e2be537f"
    "dee44d9697f9a5ad80934cf189cd34c6160f05852de601efc8e745543369ca94d7d6f661de020c32"
    "b63fffa0e5f85da87494f8286b49f03a3e3006df6a8b9cbc4dd7846809d24d23d0a1ae191cb8fd19"
    "46d713762a14a2c4e68927774570c1f6e472047550ed8b83e5a77cc150d700f80433502daf12c33d"
    "a4409e0f776add4b990dc6ed9a4202ea3eca5dec9fbe0281ca2e9e62c218d3dc5cd92ffc040a9ce0";

constexpr std::string_view kat_ss =
    "a30f25540a394e757913e0f387d2463ac99d3906623d5bf020e23c9133b4d942";

TEST(PrimitivesPq, DecapReproducesAKnownAnswer) {
  const auto sk = eki_test::hex_array<EKI_HYBRID_SK_LEN>(kat_sk);
  const auto ct = eki_test::hex_array<EKI_HYBRID_CT_LEN>(kat_ct);
  const auto expected = eki_test::hex_array<EKI_HYBRID_SS_LEN>(kat_ss);
  Ss ss{};
  EXPECT_EQ(name(decapsulate(sk, ct, ss)), name(EKI_OK));
  EXPECT_EQ(ss, expected);

  // The same exchange through the oracle, which does not use the library's combiner. Its X25519
  // part is the shared secret that RFC 7748 section 6.1 prints for these two keys.
  const oracle::Key32 ss_x25519 =
      oracle::x25519_shared(x25519_half(sk), x25519_half(ct)).value_or(oracle::Key32{});
  EXPECT_EQ(ss_x25519, eki_test::hex_array<32>(
                           "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
  const oracle::Key32 ss_mlkem =
      oracle::mlkem_decapsulate(oracle::mlkem_key(mlkem_half(sk)), mlkem_half(ct));
  EXPECT_TRUE(std::ranges::equal(
      oracle::combine(ss_x25519, ss_mlkem, ct, oracle::public_key_of(sk)), expected));
}

// ---------------------------------------------------------------------------------------------
// Rejected input
// ---------------------------------------------------------------------------------------------

// A wrong size gives INVALID_ARGUMENT, zero-fills the outputs that have their size, and leaves an
// output of another size alone.
TEST(PrimitivesPq, WrongSizesAreInvalid) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));

  const auto wrong_sizes = [](std::size_t size) {
    return std::array<std::size_t, 3>{0, size - 1, size + 1};
  };
  for (const std::size_t size : wrong_sizes(EKI_HYBRID_PK_LEN)) {
    SCOPED_TRACE(size);
    std::vector<std::uint8_t> bad_pk(size, eki_test::kFill);
    Sk sk_out = prefilled<EKI_HYBRID_SK_LEN>();
    EXPECT_EQ(name(ekicore::hybrid_kem_keygen(bad_pk, sk_out)), name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(untouched(bad_pk));
    EXPECT_TRUE(all_zero(sk_out));

    Ct ct_out = prefilled<EKI_HYBRID_CT_LEN>();
    Ss ss_out = prefilled<EKI_HYBRID_SS_LEN>();
    EXPECT_EQ(name(ekicore::hybrid_kem_encap(bad_pk, ct_out, ss_out)),
              name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(ct_out));
    EXPECT_TRUE(all_zero(ss_out));
  }
  for (const std::size_t size : wrong_sizes(EKI_HYBRID_SK_LEN)) {
    SCOPED_TRACE(size);
    std::vector<std::uint8_t> bad_sk(size, eki_test::kFill);
    Pk pk_out = prefilled<EKI_HYBRID_PK_LEN>();
    EXPECT_EQ(name(ekicore::hybrid_kem_keygen(pk_out, bad_sk)), name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(pk_out));
    EXPECT_TRUE(untouched(bad_sk));

    Ss ss_out = prefilled<EKI_HYBRID_SS_LEN>();
    EXPECT_EQ(name(ekicore::hybrid_kem_decap(bad_sk, ct, ss_out)), name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(ss_out));
  }
  for (const std::size_t size : wrong_sizes(EKI_HYBRID_CT_LEN)) {
    SCOPED_TRACE(size);
    std::vector<std::uint8_t> bad_ct(size, eki_test::kFill);
    Ss ss_out = prefilled<EKI_HYBRID_SS_LEN>();
    EXPECT_EQ(name(ekicore::hybrid_kem_decap(sk, bad_ct, ss_out)), name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(ss_out));

    Ss ss_other = prefilled<EKI_HYBRID_SS_LEN>();
    EXPECT_EQ(name(ekicore::hybrid_kem_encap(pk, bad_ct, ss_other)),
              name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(ss_other));
    EXPECT_TRUE(untouched(bad_ct));
  }
  for (const std::size_t size : wrong_sizes(EKI_HYBRID_SS_LEN)) {
    SCOPED_TRACE(size);
    std::vector<std::uint8_t> bad_ss(size, eki_test::kFill);
    Ct ct_out = prefilled<EKI_HYBRID_CT_LEN>();
    EXPECT_EQ(name(ekicore::hybrid_kem_encap(pk, ct_out, bad_ss)), name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(ct_out));
    EXPECT_TRUE(untouched(bad_ss));
    EXPECT_EQ(name(ekicore::hybrid_kem_decap(sk, ct, bad_ss)), name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(untouched(bad_ss));
  }
}

// X25519 points of small order: Diffie-Hellman gives an all-zero result, which OpenSSL refuses.
// These are the u-coordinates that the usual lists of small-order encodings start with (0, 1,
// p - 1 and two points of order 8) and the non-canonical encodings of 0 and 1 (u = p and
// u = p + 1), each also with the top bit set, which X25519 ignores.
std::vector<std::vector<std::uint8_t>> small_order_points() {
  const std::string ff30(60, 'f');
  std::vector<std::vector<std::uint8_t>> points;
  for (const std::string& text : {
           std::string(64, '0'),
           "01" + std::string(62, '0'),
           std::string{"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"},
           std::string{"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"},
           "ec" + ff30 + "7f",
           "ed" + ff30 + "7f",
           "ee" + ff30 + "7f",
       }) {
    std::vector<std::uint8_t> point = eki_test::hex(text);
    points.push_back(point);
    point.back() = static_cast<std::uint8_t>(point.back() | 0x80U);
    points.push_back(point);
  }
  return points;
}

TEST(PrimitivesPq, SmallOrderX25519PointIsInvalid) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};
  ASSERT_TRUE(keypair(pk, sk));
  ASSERT_TRUE(encapsulate(pk, ct, ss));
  const auto points = small_order_points();
  for (std::size_t index = 0; index < points.size(); ++index) {
    SCOPED_TRACE(index);
    const std::vector<std::uint8_t>& point = points.at(index);
    ASSERT_EQ(point.size(), x25519_len);

    Pk bad_pk = pk;
    std::ranges::copy(point, bad_pk.begin());
    Ct ct_out = prefilled<EKI_HYBRID_CT_LEN>();
    Ss ss_out = prefilled<EKI_HYBRID_SS_LEN>();
    EXPECT_EQ(name(ekicore::hybrid_kem_encap(bad_pk, ct_out, ss_out)),
              name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(ct_out));
    EXPECT_TRUE(all_zero(ss_out));

    Ct bad_ct = ct;
    std::ranges::copy(point, bad_ct.begin());
    EXPECT_EQ(name(decapsulate(sk, bad_ct, ss_out)), name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(ss_out));
  }
}

// Sets the first 12-bit coefficient of the encapsulation key in pk (coefficients are packed in
// pairs, two per three bytes, low bits first).
void set_first_coefficient(Pk& pk, unsigned value) {
  std::uint8_t& low = pk.at(x25519_len);
  std::uint8_t& high = pk.at(x25519_len + 1);
  low = static_cast<std::uint8_t>(value & 0xFFU);
  high = static_cast<std::uint8_t>((high & 0xF0U) | (value >> 8U));
}

// Sets the last coefficient of the vector part of the encapsulation key (the second of the last
// pair, whose high 8 bits are the third byte).
void set_last_coefficient(Pk& pk, unsigned value) {
  const std::size_t base = x25519_len + coefficient_bytes - 3;
  pk.at(base + 1) = static_cast<std::uint8_t>((pk.at(base + 1) & 0x0FU) | ((value & 0x0FU) << 4U));
  pk.at(base + 2) = static_cast<std::uint8_t>(value >> 4U);
}

// FIPS 203 modulus check on the encapsulation key: every coefficient must be below q = 3329. The
// last 32 bytes of the key are the public seed rho and are not range checked.
TEST(PrimitivesPq, EncapsulationKeyFailingTheModulusCheckIsInvalid) {
  Pk pk{};
  Sk sk{};
  ASSERT_TRUE(keypair(pk, sk));

  const auto encap_status = [](const Pk& key) {
    Ct ct = prefilled<EKI_HYBRID_CT_LEN>();
    Ss ss = prefilled<EKI_HYBRID_SS_LEN>();
    const eki_status status = ekicore::hybrid_kem_encap(key, ct, ss);
    EXPECT_EQ(all_zero(ct) && all_zero(ss), status != EKI_OK) << "outputs follow the status";
    return status;
  };
  constexpr unsigned q = 3329;

  Pk edited = pk;
  set_first_coefficient(edited, q - 1);
  EXPECT_EQ(name(encap_status(edited)), name(EKI_OK)) << "first coefficient q - 1";
  set_first_coefficient(edited, q);
  EXPECT_EQ(name(encap_status(edited)), name(EKI_ERR_INVALID_ARGUMENT)) << "first coefficient q";
  set_first_coefficient(edited, 4095);
  EXPECT_EQ(name(encap_status(edited)), name(EKI_ERR_INVALID_ARGUMENT)) << "first coefficient 4095";

  edited = pk;
  set_last_coefficient(edited, q - 1);
  EXPECT_EQ(name(encap_status(edited)), name(EKI_OK)) << "last coefficient q - 1";
  set_last_coefficient(edited, q);
  EXPECT_EQ(name(encap_status(edited)), name(EKI_ERR_INVALID_ARGUMENT)) << "last coefficient q";

  edited = pk;
  std::fill(edited.begin() + static_cast<std::ptrdiff_t>(x25519_len),
            edited.begin() + static_cast<std::ptrdiff_t>(x25519_len + coefficient_bytes),
            std::uint8_t{0xff});
  EXPECT_EQ(name(encap_status(edited)), name(EKI_ERR_INVALID_ARGUMENT)) << "every coefficient 4095";

  edited = pk;
  edited.back() = flip(edited.back(), 0);
  EXPECT_EQ(name(encap_status(edited)), name(EKI_OK)) << "rho is not range checked";
}

// ---------------------------------------------------------------------------------------------
// The caller's OpenSSL error queue
// ---------------------------------------------------------------------------------------------

// An entry on the queue before the call is still the only one after it, whether the call
// succeeded or was refused for its input: the entries that the provider raises for a refused
// input belong to the call and are removed.
TEST(PrimitivesPq, CallersErrorQueueIsLeftAlone) {
  Pk pk{};
  Sk sk{};
  Ct ct{};
  Ss ss{};

  unsigned long caller = eki_test::push_caller_error();
  EXPECT_EQ(name(ekicore::hybrid_kem_keygen(pk, sk)), name(EKI_OK));
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "keygen";

  caller = eki_test::push_caller_error();
  EXPECT_EQ(name(ekicore::hybrid_kem_encap(pk, ct, ss)), name(EKI_OK));
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "encap";

  caller = eki_test::push_caller_error();
  EXPECT_EQ(name(ekicore::hybrid_kem_decap(sk, ct, ss)), name(EKI_OK));
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "decap";

  Pk small_order_pk = pk;
  std::ranges::fill(std::span(small_order_pk).first(x25519_len), std::uint8_t{0});
  caller = eki_test::push_caller_error();
  EXPECT_EQ(name(ekicore::hybrid_kem_encap(small_order_pk, ct, ss)),
            name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "small-order public key";

  Pk bad_ek_pk = pk;
  std::ranges::fill(std::span(bad_ek_pk).subspan(x25519_len, coefficient_bytes),
                    std::uint8_t{0xff});
  caller = eki_test::push_caller_error();
  EXPECT_EQ(name(ekicore::hybrid_kem_encap(bad_ek_pk, ct, ss)), name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "encapsulation key out of range";

  Ct small_order_ct = ct;
  std::ranges::fill(std::span(small_order_ct).first(x25519_len), std::uint8_t{0});
  caller = eki_test::push_caller_error();
  EXPECT_EQ(name(ekicore::hybrid_kem_decap(sk, small_order_ct, ss)),
            name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "small-order ephemeral key";

  caller = eki_test::push_caller_error();
  EXPECT_EQ(name(ekicore::hybrid_kem_decap(std::span(sk).first(95), ct, ss)),
            name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "wrong size";
}

} // namespace
// NOLINTEND(readability-function-cognitive-complexity)

#endif // EKI_TEST_WITH_PQ
