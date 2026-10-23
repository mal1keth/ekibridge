// The stateless functions of the C ABI (HMAC, HKDF, AEAD, ECDSA verify), called through
// <ekicore.h> exactly as a C caller would; the C++ primitives themselves are tested directly in
// primitives_*_test.cpp.
//
// Mirrors core-rs/tests/ffi_{hmac,hkdf,aead,ecdsa}.rs: the same vectors (plan §4.5) and the same
// rows (plan §4.4), with validation order and zero-on-error from §4.2.

#include "test_support.hpp"

#include <gtest/gtest.h>

#include <ekicore.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

// Test bodies are flat sequences of assertions; the gtest macros inflate the complexity score.
// NOLINTBEGIN(readability-function-cognitive-complexity)
namespace {

using eki_test::all_zero;
using eki_test::bytes;
using eki_test::hex;
using eki_test::hex_array;
using eki_test::name;
using eki_test::prefill;
using eki_test::prefilled;
using eki_test::untouched;
using Bytes = std::vector<std::uint8_t>;

void flip(Bytes& buf, std::size_t index, std::uint8_t mask) {
  buf.at(index) = static_cast<std::uint8_t>(buf.at(index) ^ mask);
}

void flip_bit(Bytes& buf, std::size_t bit) {
  flip(buf, bit / 8, static_cast<std::uint8_t>(1U << (bit % 8)));
}

// =============================================================================================
// HMAC-SHA256: RFC 4231 §4.2–§4.8. Case 5 publishes a 16-byte prefix only: compared as a prefix
// and left out of the verify tests.
// =============================================================================================

struct HmacVector {
  int test_case;
  std::string_view key;
  std::string_view data;
  std::string_view mac;
};

constexpr std::string_view kAa131 =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaa";

constexpr std::array<HmacVector, 7> kRfc4231{
    {
        {
            .test_case = 1,
            .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            .data = "4869205468657265",
            .mac = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        },
        {
            .test_case = 2,
            .key = "4a656665",
            .data = "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            .mac = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        },
        {
            .test_case = 3,
            .key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .data = "dddddddddddddddddddddddddddddddddddddddddddddddddd"
                    "dddddddddddddddddddddddddddddddddddddddddddddddddd",
            .mac = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        },
        {
            .test_case = 4,
            .key = "0102030405060708090a0b0c0d0e0f10111213141516171819",
            .data = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            .mac = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        },
        {
            .test_case = 5,
            .key = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            .data = "546573742057697468205472756e636174696f6e",
            .mac = "a3b6167473100ee06e0c796c2955552b",
        },
        {
            .test_case = 6,
            .key = kAa131,
            .data = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
                    "65204b6579202d2048617368204b6579204669727374",
            .mac = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        },
        {
            .test_case = 7,
            .key = kAa131,
            .data = "5468697320697320612074657374207573696e672061206c6172676572207468"
                    "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
                    "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
                    "647320746f20626520686173686564206265666f7265206265696e6720757365"
                    "642062792074686520484d414320616c676f726974686d2e",
            .mac = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        },
    },
};

// HMAC-SHA256 of the empty message under the case 1 key (independent implementation).
constexpr std::string_view kEmptyMsgMac =
    "999a901219f032cd497cadb5e6051e97b6a29ab297bd6ae722bd6062a2f59542";

TEST(FfiHmac, Rfc4231Vectors) {
  for (const HmacVector& v : kRfc4231) {
    const Bytes key = hex(v.key);
    const Bytes data = hex(v.data);
    const Bytes mac = hex(v.mac);
    Bytes out = prefill(32);
    EXPECT_EQ(name(eki_hmac_sha256(key.data(), key.size(), data.data(), data.size(), out.data())),
              name(EKI_OK))
        << "case " << v.test_case;
    EXPECT_EQ(Bytes(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(mac.size())), mac)
        << "case " << v.test_case;
  }
}

TEST(FfiHmac, Rfc4231VerifyAcceptsFullTags) {
  for (const HmacVector& v : kRfc4231) {
    if (v.test_case == 5) {
      continue;
    }
    const Bytes key = hex(v.key);
    const Bytes data = hex(v.data);
    const Bytes mac = hex(v.mac);
    EXPECT_EQ(name(eki_hmac_sha256_verify(key.data(), key.size(), data.data(), data.size(),
                                          mac.data(), mac.size())),
              name(EKI_OK))
        << "case " << v.test_case;
  }
}

TEST(FfiHmac, VerifyRejectsEverySingleBitFlip) {
  const HmacVector& v = kRfc4231.at(1);
  const Bytes key = hex(v.key);
  const Bytes data = hex(v.data);
  const Bytes mac = hex(v.mac);
  for (std::size_t bit = 0; bit < mac.size() * 8; ++bit) {
    Bytes bad = mac;
    flip_bit(bad, bit);
    EXPECT_EQ(name(eki_hmac_sha256_verify(key.data(), key.size(), data.data(), data.size(),
                                          bad.data(), bad.size())),
              name(EKI_ERR_AUTH_FAILED))
        << "bit " << bit;
  }
}

TEST(FfiHmac, VerifyWrongMessageIsAuthFailed) {
  const Bytes key = hex(kRfc4231.at(0).key);
  const Bytes mac = hex(kRfc4231.at(0).mac);
  const auto msg = bytes("Hi there");
  EXPECT_EQ(name(eki_hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(), mac.data(),
                                        mac.size())),
            name(EKI_ERR_AUTH_FAILED));
}

// §4.4: `key_len 0` → INVALID_ARGUMENT, output zero-filled.
TEST(FfiHmac, KeyLenZeroIsInvalidAndZeroesOut) {
  const std::array<std::uint8_t, 1> dummy{0x0b};
  const auto msg = bytes("msg");
  for (const std::uint8_t* key : {static_cast<const std::uint8_t*>(nullptr), dummy.data()}) {
    Bytes out = prefill(32);
    EXPECT_EQ(name(eki_hmac_sha256(key, 0, msg.data(), msg.size(), out.data())),
              name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(out));
  }
}

// §4.4: `msg NULL, msg_len 0` → OK.
TEST(FfiHmac, MsgNullLenZeroIsOk) {
  const Bytes key = hex(kRfc4231.at(0).key);
  const Bytes expected = hex(kEmptyMsgMac);
  const std::array<std::uint8_t, 1> dummy{0};
  for (const std::uint8_t* msg : {static_cast<const std::uint8_t*>(nullptr), dummy.data()}) {
    Bytes out = prefill(32);
    EXPECT_EQ(name(eki_hmac_sha256(key.data(), key.size(), msg, 0, out.data())), name(EKI_OK));
    EXPECT_EQ(out, expected);
  }
}

TEST(FfiHmac, NullPointers) {
  const Bytes key = hex(kRfc4231.at(0).key);
  const auto msg = bytes("m");
  Bytes out = prefill(32);
  EXPECT_EQ(name(eki_hmac_sha256(nullptr, 20, msg.data(), msg.size(), out.data())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(out));
  out = prefill(32);
  EXPECT_EQ(name(eki_hmac_sha256(key.data(), key.size(), nullptr, 3, out.data())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(out));
  EXPECT_EQ(name(eki_hmac_sha256(key.data(), key.size(), msg.data(), msg.size(), nullptr)),
            name(EKI_ERR_NULL_POINTER));
  // NULL `out` is detected before `key_len 0` (§4.2 step 1 before step 3).
  EXPECT_EQ(name(eki_hmac_sha256(nullptr, 0, msg.data(), msg.size(), nullptr)),
            name(EKI_ERR_NULL_POINTER));
}

// §4.4: `tag_len 31` / `tag NULL, tag_len 0` → INVALID_ARGUMENT.
TEST(FfiHmac, VerifyTagLenNot32IsInvalid) {
  const Bytes key = hex(kRfc4231.at(0).key);
  const Bytes data = hex(kRfc4231.at(0).data);
  Bytes mac = hex(kRfc4231.at(0).mac);
  EXPECT_EQ(name(eki_hmac_sha256_verify(key.data(), key.size(), data.data(), data.size(),
                                        mac.data(), 31)),
            name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_EQ(
      name(eki_hmac_sha256_verify(key.data(), key.size(), data.data(), data.size(), nullptr, 0)),
      name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_EQ(
      name(eki_hmac_sha256_verify(key.data(), key.size(), data.data(), data.size(), mac.data(), 0)),
      name(EKI_ERR_INVALID_ARGUMENT));
  mac.push_back(0);
  EXPECT_EQ(name(eki_hmac_sha256_verify(key.data(), key.size(), data.data(), data.size(),
                                        mac.data(), mac.size())),
            name(EKI_ERR_INVALID_ARGUMENT));
}

// `key_len 0` is checked before `tag_len`.
TEST(FfiHmac, VerifyKeyLenZeroIsInvalid) {
  const Bytes mac = hex(kRfc4231.at(0).mac);
  const auto msg = bytes("m");
  EXPECT_EQ(name(eki_hmac_sha256_verify(nullptr, 0, msg.data(), msg.size(), mac.data(), 32)),
            name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_EQ(name(eki_hmac_sha256_verify(mac.data(), 0, msg.data(), msg.size(), mac.data(), 31)),
            name(EKI_ERR_INVALID_ARGUMENT));
}

TEST(FfiHmac, VerifyNullPointers) {
  const Bytes key = hex(kRfc4231.at(0).key);
  const Bytes data = hex(kRfc4231.at(0).data);
  const Bytes mac = hex(kRfc4231.at(0).mac);
  EXPECT_EQ(name(eki_hmac_sha256_verify(nullptr, 20, data.data(), data.size(), mac.data(), 32)),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_EQ(name(eki_hmac_sha256_verify(key.data(), key.size(), nullptr, 8, mac.data(), 32)),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_EQ(
      name(eki_hmac_sha256_verify(key.data(), key.size(), data.data(), data.size(), nullptr, 32)),
      name(EKI_ERR_NULL_POINTER));
  // NULL with a wrong length is still a NULL pointer: step 1 precedes step 3.
  EXPECT_EQ(
      name(eki_hmac_sha256_verify(key.data(), key.size(), data.data(), data.size(), nullptr, 31)),
      name(EKI_ERR_NULL_POINTER));
}

TEST(FfiHmac, VerifyEmptyMessage) {
  const Bytes key = hex(kRfc4231.at(0).key);
  const Bytes mac = hex(kEmptyMsgMac);
  EXPECT_EQ(name(eki_hmac_sha256_verify(key.data(), key.size(), nullptr, 0, mac.data(), 32)),
            name(EKI_OK));
}

// =============================================================================================
// HKDF-SHA256: RFC 5869 A.1–A.3.
// =============================================================================================

struct HkdfVector {
  std::string_view test_case;
  std::string_view ikm;
  std::string_view salt;
  std::string_view info;
  std::string_view okm;
};

constexpr std::array<HkdfVector, 3> kRfc5869{
    {
        {
            .test_case = "A.1",
            .ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            .salt = "000102030405060708090a0b0c",
            .info = "f0f1f2f3f4f5f6f7f8f9",
            .okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b8871"
                   "85865",
        },
        {
            .test_case = "A.2",
            .ikm = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                   "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                   "404142434445464748494a4b4c4d4e4f",
            .salt = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            .info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            .okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                   "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                   "cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        {
            .test_case = "A.3",
            .ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            .salt = "",
            .info = "",
            .okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61"
                   "a96c8",
        },
    },
};

// HKDF with the A.1 inputs into `okm`.
eki_status hkdf_a1(Bytes& okm) {
  const Bytes ikm = hex(kRfc5869.at(0).ikm);
  const Bytes salt = hex(kRfc5869.at(0).salt);
  const Bytes info = hex(kRfc5869.at(0).info);
  return eki_hkdf_sha256(ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(), info.size(),
                         okm.data(), okm.size());
}

TEST(FfiHkdf, Rfc5869Vectors) {
  for (const HkdfVector& v : kRfc5869) {
    const Bytes ikm = hex(v.ikm);
    const Bytes salt = hex(v.salt);
    const Bytes info = hex(v.info);
    const Bytes expected = hex(v.okm);
    Bytes okm = prefill(expected.size());
    EXPECT_EQ(name(eki_hkdf_sha256(ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(),
                                   info.size(), okm.data(), okm.size())),
              name(EKI_OK))
        << v.test_case;
    EXPECT_EQ(okm, expected) << v.test_case;
  }
}

// §4.4: `salt NULL,0`; `info NULL,0` → OK (A.3 has both empty).
TEST(FfiHkdf, SaltAndInfoNullLenZeroAreOk) {
  const Bytes ikm = hex(kRfc5869.at(2).ikm);
  const Bytes expected = hex(kRfc5869.at(2).okm);
  const std::array<std::uint8_t, 1> dummy{0};
  const std::uint8_t* const ptrs[] = {nullptr, dummy.data()};
  for (const std::uint8_t* salt : ptrs) {
    for (const std::uint8_t* info : ptrs) {
      Bytes okm = prefill(expected.size());
      EXPECT_EQ(
          name(eki_hkdf_sha256(ikm.data(), ikm.size(), salt, 0, info, 0, okm.data(), okm.size())),
          name(EKI_OK));
      EXPECT_EQ(okm, expected);
    }
  }
}

// §4.4: `okm_len 8160` → OK; the A.1 output is its prefix.
TEST(FfiHkdf, OkmLen8160IsOk) {
  Bytes okm = prefill(EKI_HKDF_MAX_OKM_LEN);
  EXPECT_EQ(name(hkdf_a1(okm)), name(EKI_OK));
  EXPECT_EQ(Bytes(okm.begin(), okm.begin() + 42), hex(kRfc5869.at(0).okm));
}

// §4.4: `okm_len 0` → INVALID_ARGUMENT.
TEST(FfiHkdf, OkmLenZeroIsInvalid) {
  Bytes okm;
  EXPECT_EQ(name(hkdf_a1(okm)), name(EKI_ERR_INVALID_ARGUMENT));
  const Bytes ikm = hex(kRfc5869.at(0).ikm);
  EXPECT_EQ(name(eki_hkdf_sha256(ikm.data(), ikm.size(), nullptr, 0, nullptr, 0, nullptr, 0)),
            name(EKI_ERR_INVALID_ARGUMENT));
}

// §4.4: `okm_len 8161` → INVALID_ARGUMENT; out of range, so `okm` is untouched.
TEST(FfiHkdf, OkmLen8161IsInvalidAndLeavesOkmUntouched) {
  Bytes okm = prefill(EKI_HKDF_MAX_OKM_LEN + 1);
  EXPECT_EQ(name(hkdf_a1(okm)), name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(untouched(okm));
}

// §4.4: `ikm_len 0` → INVALID_ARGUMENT, okm zero-filled.
TEST(FfiHkdf, IkmLenZeroIsInvalidAndZeroesOkm) {
  const std::array<std::uint8_t, 1> dummy{0x0b};
  for (const std::uint8_t* ikm : {static_cast<const std::uint8_t*>(nullptr), dummy.data()}) {
    Bytes okm = prefill(42);
    EXPECT_EQ(name(eki_hkdf_sha256(ikm, 0, nullptr, 0, nullptr, 0, okm.data(), okm.size())),
              name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(okm));
  }
}

// §4.4: `info_len 32769` (and the same cap on ikm and salt) → INVALID_ARGUMENT.
TEST(FfiHkdf, InputLengthsAbove32768AreInvalid) {
  const Bytes big(EKI_HKDF_MAX_INPUT_LEN + 1, 0x0b);
  const Bytes ikm = hex(kRfc5869.at(0).ikm);
  Bytes okm = prefill(42);
  EXPECT_EQ(
      name(eki_hkdf_sha256(big.data(), big.size(), nullptr, 0, nullptr, 0, okm.data(), okm.size())),
      name(EKI_ERR_INVALID_ARGUMENT))
      << "ikm_len 32769";
  EXPECT_TRUE(all_zero(okm));
  okm = prefill(42);
  EXPECT_EQ(name(eki_hkdf_sha256(ikm.data(), ikm.size(), big.data(), big.size(), nullptr, 0,
                                 okm.data(), okm.size())),
            name(EKI_ERR_INVALID_ARGUMENT))
      << "salt_len 32769";
  EXPECT_TRUE(all_zero(okm));
  okm = prefill(42);
  EXPECT_EQ(name(eki_hkdf_sha256(ikm.data(), ikm.size(), nullptr, 0, big.data(), big.size(),
                                 okm.data(), okm.size())),
            name(EKI_ERR_INVALID_ARGUMENT))
      << "info_len 32769";
  EXPECT_TRUE(all_zero(okm));
}

TEST(FfiHkdf, InputLengthsOfExactly32768AreOk) {
  const Bytes max(EKI_HKDF_MAX_INPUT_LEN, 0x0b);
  Bytes okm = prefill(32);
  EXPECT_EQ(name(eki_hkdf_sha256(max.data(), max.size(), max.data(), max.size(), max.data(),
                                 max.size(), okm.data(), okm.size())),
            name(EKI_OK));
}

TEST(FfiHkdf, NullPointers) {
  const Bytes ikm = hex(kRfc5869.at(0).ikm);
  Bytes okm = prefill(42);
  EXPECT_EQ(name(eki_hkdf_sha256(nullptr, 22, nullptr, 0, nullptr, 0, okm.data(), okm.size())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(okm));
  okm = prefill(42);
  EXPECT_EQ(name(eki_hkdf_sha256(ikm.data(), ikm.size(), nullptr, 13, nullptr, 0, okm.data(),
                                 okm.size())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(okm));
  okm = prefill(42);
  EXPECT_EQ(name(eki_hkdf_sha256(ikm.data(), ikm.size(), nullptr, 0, nullptr, 10, okm.data(),
                                 okm.size())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(okm));
  EXPECT_EQ(name(eki_hkdf_sha256(ikm.data(), ikm.size(), nullptr, 0, nullptr, 0, nullptr, 42)),
            name(EKI_ERR_NULL_POINTER));
  // NULL before length: a NULL ikm with ikm_len > 0 and okm_len 0.
  EXPECT_EQ(name(eki_hkdf_sha256(nullptr, 22, nullptr, 0, nullptr, 0, nullptr, 0)),
            name(EKI_ERR_NULL_POINTER));
}

// Output length is honoured: every prefix of the 8160-byte output is the output for
// that length (the Rust suite checks this with proptest; here a fixed set of lengths).
TEST(FfiHkdf, OutputLengthIsPrefixStable) {
  Bytes full = prefill(EKI_HKDF_MAX_OKM_LEN);
  ASSERT_EQ(name(hkdf_a1(full)), name(EKI_OK));
  for (const std::size_t len : {
           std::size_t{1},
           std::size_t{31},
           std::size_t{32},
           std::size_t{33},
           std::size_t{255},
           std::size_t{4096},
           std::size_t{8159},
       }) {
    Bytes okm = prefill(len);
    EXPECT_EQ(name(hkdf_a1(okm)), name(EKI_OK)) << len;
    EXPECT_EQ(okm, Bytes(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(len))) << len;
  }
}

// =============================================================================================
// AEAD: RFC 8439 §2.8.2 and A.5 (ChaCha20-Poly1305); GCM specification test cases 13–16
// (AES-256, 96-bit IVs; 17 and 18 use 8- and 60-byte IVs and are excluded).
// =============================================================================================

struct AeadVector {
  std::string_view source;
  eki_aead_alg alg;
  std::string_view key;
  std::string_view nonce;
  std::string_view aad;
  std::string_view pt;
  std::string_view ct;
  std::string_view tag;
};

constexpr std::string_view kGcmKey =
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
constexpr std::string_view kGcmPt =
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
constexpr std::string_view kGcmCt =
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
constexpr std::string_view kZero32 =
    "0000000000000000000000000000000000000000000000000000000000000000";

constexpr std::array<AeadVector, 6> kAeadVectors{
    {
        {
            .source = "RFC 8439 2.8.2",
            .alg = EKI_AEAD_CHACHA20_POLY1305,
            .key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            .nonce = "070000004041424344454647",
            .aad = "50515253c0c1c2c3c4c5c6c7",
            .pt = "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
                  "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
                  "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
                  "637265656e20776f756c642062652069742e",
            .ct = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                  "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                  "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                  "3ff4def08e4b7a9de576d26586cec64b6116",
            .tag = "1ae10b594f09e26a7e902ecbd0600691",
        },
        {
            .source = "RFC 8439 A.5",
            .alg = EKI_AEAD_CHACHA20_POLY1305,
            .key = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            .nonce = "000000000102030405060708",
            .aad = "f33388860000000000004e91",
            .pt = "496e7465726e65742d4472616674732061726520647261667420646f63756d65"
                  "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
                  "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
                  "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
                  "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
                  "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
                  "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
                  "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
                  "726573732e2fe2809d",
            .ct = "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
                  "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
                  "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
                  "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
                  "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
                  "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
                  "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
                  "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
                  "a6ad5cb4022b02709b",
            .tag = "eead9d67890cbb22392336fea1851f38",
        },
        {
            .source = "GCM spec test case 13",
            .alg = EKI_AEAD_AES_256_GCM,
            .key = kZero32,
            .nonce = "000000000000000000000000",
            .aad = "",
            .pt = "",
            .ct = "",
            .tag = "530f8afbc74536b9a963b4f1c4cb738b",
        },
        {
            .source = "GCM spec test case 14",
            .alg = EKI_AEAD_AES_256_GCM,
            .key = kZero32,
            .nonce = "000000000000000000000000",
            .aad = "",
            .pt = "00000000000000000000000000000000",
            .ct = "cea7403d4d606b6e074ec5d3baf39d18",
            .tag = "d0d1c8a799996bf0265b98b5d48ab919",
        },
        {
            .source = "GCM spec test case 15",
            .alg = EKI_AEAD_AES_256_GCM,
            .key = kGcmKey,
            .nonce = "cafebabefacedbaddecaf888",
            .aad = "",
            .pt = kGcmPt,
            .ct = kGcmCt,
            .tag = "b094dac5d93471bdec1a502270e3cc6c",
        },
        {
            .source = "GCM spec test case 16",
            .alg = EKI_AEAD_AES_256_GCM,
            .key = kGcmKey,
            .nonce = "cafebabefacedbaddecaf888",
            .aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            // The first 60 bytes of kGcmPt / kGcmCt.
            .pt = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                  "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            .ct = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                  "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            .tag = "76fc6ece0f4e1768cddf8853bb2d551b",
        },
    },
};

// Decoded form of an AeadVector.
struct AeadCase {
  eki_aead_alg alg;
  Bytes key;
  Bytes nonce;
  Bytes aad;
  Bytes pt;
  Bytes ct;
  Bytes tag;
};

AeadCase decode(const AeadVector& v) {
  return AeadCase{
      .alg = v.alg,
      .key = hex(v.key),
      .nonce = hex(v.nonce),
      .aad = hex(v.aad),
      .pt = hex(v.pt),
      .ct = hex(v.ct),
      .tag = hex(v.tag),
  };
}

AeadCase gcm16() {
  return decode(kAeadVectors.at(5));
}

AeadCase chacha282() {
  return decode(kAeadVectors.at(0));
}

// Seals c.pt with every input from c into fresh pre-filled buffers.
eki_status seal_case(const AeadCase& c, Bytes& ct, Bytes& tag) {
  ct = prefill(c.pt.size());
  tag = prefill(EKI_AEAD_TAG_LEN);
  return eki_aead_seal(c.alg, c.key.data(), c.key.size(), c.nonce.data(), c.nonce.size(),
                       c.aad.data(), c.aad.size(), c.pt.data(), c.pt.size(), ct.data(), tag.data());
}

// Opens ct/tag with key, nonce and alg from c into a fresh pre-filled buffer.
eki_status open_case(const AeadCase& c, const Bytes& aad, const Bytes& ct, const Bytes& tag,
                     Bytes& pt) {
  pt = prefill(ct.size());
  return eki_aead_open(c.alg, c.key.data(), c.key.size(), c.nonce.data(), c.nonce.size(),
                       aad.data(), aad.size(), ct.data(), ct.size(), tag.data(), pt.data());
}

TEST(FfiAead, VectorsSeal) {
  for (const AeadVector& v : kAeadVectors) {
    const AeadCase c = decode(v);
    Bytes ct;
    Bytes tag;
    EXPECT_EQ(name(seal_case(c, ct, tag)), name(EKI_OK)) << v.source;
    EXPECT_EQ(ct, c.ct) << v.source;
    EXPECT_EQ(tag, c.tag) << v.source;
  }
}

TEST(FfiAead, VectorsOpen) {
  for (const AeadVector& v : kAeadVectors) {
    const AeadCase c = decode(v);
    Bytes pt;
    EXPECT_EQ(name(open_case(c, c.aad, c.ct, c.tag, pt)), name(EKI_OK)) << v.source;
    EXPECT_EQ(pt, c.pt) << v.source;
  }
}

// §4.4: `alg 0`, `alg 3` → INVALID_ARGUMENT; outputs zero-filled.
TEST(FfiAead, SealUnknownAlgIsInvalid) {
  for (const eki_aead_alg alg : {0, 3, -1, 99, INT32_MIN, INT32_MAX}) {
    AeadCase c = gcm16();
    c.alg = alg;
    Bytes ct;
    Bytes tag;
    EXPECT_EQ(name(seal_case(c, ct, tag)), name(EKI_ERR_INVALID_ARGUMENT)) << "alg " << alg;
    EXPECT_TRUE(all_zero(ct));
    EXPECT_TRUE(all_zero(tag));
  }
}

// §4.4: `key_len 16` → INVALID_ARGUMENT (also 0, 31, 33).
TEST(FfiAead, SealKeyLenNot32IsInvalid) {
  for (const eki_aead_alg alg : {EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305}) {
    for (const std::size_t key_len : {std::size_t{0}, std::size_t{16}, std::size_t{31}}) {
      AeadCase c = gcm16();
      c.alg = alg;
      c.key.resize(key_len);
      Bytes ct;
      Bytes tag;
      EXPECT_EQ(name(seal_case(c, ct, tag)), name(EKI_ERR_INVALID_ARGUMENT))
          << "key_len " << key_len;
      EXPECT_TRUE(all_zero(ct));
      EXPECT_TRUE(all_zero(tag));
    }
    AeadCase c = gcm16();
    c.alg = alg;
    c.key.push_back(0);
    Bytes ct;
    Bytes tag;
    EXPECT_EQ(name(seal_case(c, ct, tag)), name(EKI_ERR_INVALID_ARGUMENT)) << "key_len 33";
    Bytes pt = prefill(16);
    EXPECT_EQ(name(eki_aead_seal(alg, nullptr, 0, c.nonce.data(), c.nonce.size(), nullptr, 0,
                                 pt.data(), pt.size(), ct.data(), tag.data())),
              name(EKI_ERR_INVALID_ARGUMENT))
        << "key NULL, key_len 0";
  }
}

// §4.4: `nonce_len 11/13` → INVALID_ARGUMENT.
TEST(FfiAead, SealNonceLenNot12IsInvalid) {
  for (const eki_aead_alg alg : {EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305}) {
    for (const std::size_t nonce_len : {std::size_t{0}, std::size_t{11}, std::size_t{13}}) {
      AeadCase c = gcm16();
      c.alg = alg;
      c.nonce.resize(nonce_len);
      Bytes ct;
      Bytes tag;
      EXPECT_EQ(name(seal_case(c, ct, tag)), name(EKI_ERR_INVALID_ARGUMENT))
          << "nonce_len " << nonce_len;
      EXPECT_TRUE(all_zero(ct));
      EXPECT_TRUE(all_zero(tag));
    }
  }
}

// §4.4: `pt NULL, pt_len 0, ct_out NULL`; `aad NULL,0` → OK (GCM test case 13).
TEST(FfiAead, SealEmptyPlaintextWithNullBuffersIsOk) {
  const AeadCase c = decode(kAeadVectors.at(2));
  Bytes tag = prefill(16);
  EXPECT_EQ(name(eki_aead_seal(c.alg, c.key.data(), c.key.size(), c.nonce.data(), c.nonce.size(),
                               nullptr, 0, nullptr, 0, nullptr, tag.data())),
            name(EKI_OK));
  EXPECT_EQ(tag, c.tag);
}

// §4.4: `aad NULL,0` → OK (GCM test case 15 has no AAD).
TEST(FfiAead, SealAadNullLenZeroIsOk) {
  const AeadCase c = decode(kAeadVectors.at(4));
  Bytes ct = prefill(c.pt.size());
  Bytes tag = prefill(16);
  EXPECT_EQ(name(eki_aead_seal(c.alg, c.key.data(), c.key.size(), c.nonce.data(), c.nonce.size(),
                               nullptr, 0, c.pt.data(), c.pt.size(), ct.data(), tag.data())),
            name(EKI_OK));
  EXPECT_EQ(ct, c.ct);
  EXPECT_EQ(tag, c.tag);
}

// §4.4: `ct_out NULL, pt_len 1, alg 99` → NULL_POINTER (NULL before selector).
TEST(FfiAead, SealNullCtOutIsCheckedBeforeTheSelector) {
  const AeadCase c = gcm16();
  const std::array<std::uint8_t, 1> pt{0x42};
  Bytes tag = prefill(16);
  EXPECT_EQ(name(eki_aead_seal(99, c.key.data(), c.key.size(), c.nonce.data(), c.nonce.size(),
                               nullptr, 0, pt.data(), pt.size(), nullptr, tag.data())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(tag));
}

TEST(FfiAead, SealNullPointers) {
  const AeadCase c = gcm16();
  const std::size_t n = c.pt.size();
  Bytes ct = prefill(n);
  Bytes tag = prefill(16);
  const auto expect_null = [&](eki_status status, const char* what) {
    EXPECT_EQ(name(status), name(EKI_ERR_NULL_POINTER)) << what;
    EXPECT_TRUE(all_zero(ct)) << what;
    EXPECT_TRUE(all_zero(tag)) << what;
    ct = prefill(n);
    tag = prefill(16);
  };
  expect_null(eki_aead_seal(c.alg, nullptr, 32, c.nonce.data(), 12, c.aad.data(), c.aad.size(),
                            c.pt.data(), n, ct.data(), tag.data()),
              "key");
  expect_null(eki_aead_seal(c.alg, c.key.data(), 32, nullptr, 12, c.aad.data(), c.aad.size(),
                            c.pt.data(), n, ct.data(), tag.data()),
              "nonce");
  expect_null(eki_aead_seal(c.alg, c.key.data(), 32, c.nonce.data(), 12, nullptr, 20, c.pt.data(),
                            n, ct.data(), tag.data()),
              "aad");
  expect_null(eki_aead_seal(c.alg, c.key.data(), 32, c.nonce.data(), 12, c.aad.data(), c.aad.size(),
                            nullptr, n, ct.data(), tag.data()),
              "pt");
  EXPECT_EQ(name(eki_aead_seal(c.alg, c.key.data(), 32, c.nonce.data(), 12, c.aad.data(),
                               c.aad.size(), c.pt.data(), n, nullptr, tag.data())),
            name(EKI_ERR_NULL_POINTER))
      << "ct_out";
  EXPECT_TRUE(all_zero(tag));
  EXPECT_EQ(name(eki_aead_seal(c.alg, c.key.data(), 32, c.nonce.data(), 12, c.aad.data(),
                               c.aad.size(), c.pt.data(), n, ct.data(), nullptr)),
            name(EKI_ERR_NULL_POINTER))
      << "tag_out";
  EXPECT_TRUE(all_zero(ct));
}

// `pt_len > EKI_AEAD_MAX_LEN` → INVALID_ARGUMENT; out of range, so `ct_out` is
// untouched. The buffers are 1 byte: a conforming library rejects the length before reading.
TEST(FfiAead, SealPtLenAboveMaxIsInvalid) {
  static_assert(sizeof(std::size_t) >= 8, "the length cap needs a 64-bit size_t");
  const AeadCase c = gcm16();
  const std::array<std::uint8_t, 1> pt{0};
  Bytes ct = prefill(1);
  Bytes tag = prefill(16);
  EXPECT_EQ(
      name(eki_aead_seal(c.alg, c.key.data(), 32, c.nonce.data(), 12, nullptr, 0, pt.data(),
                         static_cast<std::size_t>(EKI_AEAD_MAX_LEN) + 1, ct.data(), tag.data())),
      name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(untouched(ct));
  EXPECT_TRUE(all_zero(tag));
}

// §4.4: tag bit flipped → AUTH_FAILED, `pt_out` all zero.
TEST(FfiAead, OpenTagBitFlippedIsAuthFailed) {
  for (const AeadCase& c : {gcm16(), chacha282()}) {
    for (const std::size_t bit :
         {std::size_t{0}, std::size_t{7}, std::size_t{64}, std::size_t{127}}) {
      Bytes tag = c.tag;
      flip_bit(tag, bit);
      Bytes pt;
      EXPECT_EQ(name(open_case(c, c.aad, c.ct, tag, pt)), name(EKI_ERR_AUTH_FAILED))
          << "alg " << c.alg << " bit " << bit;
      EXPECT_TRUE(all_zero(pt));
    }
  }
}

// §4.4: aad changed → AUTH_FAILED, `pt_out` all zero.
TEST(FfiAead, OpenAadChangedIsAuthFailed) {
  for (const AeadCase& c : {gcm16(), chacha282()}) {
    Bytes aad = c.aad;
    flip(aad, 0, 0x01);
    Bytes pt;
    EXPECT_EQ(name(open_case(c, aad, c.ct, c.tag, pt)), name(EKI_ERR_AUTH_FAILED))
        << "alg " << c.alg;
    EXPECT_TRUE(all_zero(pt));
    EXPECT_EQ(name(open_case(c, Bytes{}, c.ct, c.tag, pt)), name(EKI_ERR_AUTH_FAILED))
        << "alg " << c.alg << ": AAD dropped";
    EXPECT_TRUE(all_zero(pt));
  }
}

// §4.4: ct truncated by 1 → AUTH_FAILED, `pt_out` all zero.
TEST(FfiAead, OpenCtTruncatedByOneIsAuthFailed) {
  for (const AeadCase& c : {gcm16(), chacha282()}) {
    const Bytes ct(c.ct.begin(), c.ct.end() - 1);
    Bytes pt;
    EXPECT_EQ(name(open_case(c, c.aad, ct, c.tag, pt)), name(EKI_ERR_AUTH_FAILED))
        << "alg " << c.alg;
    EXPECT_EQ(pt.size(), c.ct.size() - 1);
    EXPECT_TRUE(all_zero(pt));
  }
}

TEST(FfiAead, OpenCtByteFlippedIsAuthFailed) {
  for (const AeadCase& c : {gcm16(), chacha282()}) {
    for (const std::size_t index : {std::size_t{0}, c.ct.size() / 2, c.ct.size() - 1}) {
      Bytes ct = c.ct;
      flip(ct, index, 0x80);
      Bytes pt;
      EXPECT_EQ(name(open_case(c, c.aad, ct, c.tag, pt)), name(EKI_ERR_AUTH_FAILED))
          << "alg " << c.alg << " byte " << index;
      EXPECT_TRUE(all_zero(pt));
    }
  }
}

TEST(FfiAead, OpenWrongKeyOrNonceIsAuthFailed) {
  for (const AeadCase& c : {gcm16(), chacha282()}) {
    AeadCase wrong_key = c;
    flip(wrong_key.key, 0, 0x01);
    Bytes pt;
    EXPECT_EQ(name(open_case(wrong_key, c.aad, c.ct, c.tag, pt)), name(EKI_ERR_AUTH_FAILED));
    EXPECT_TRUE(all_zero(pt));
    AeadCase wrong_nonce = c;
    flip(wrong_nonce.nonce, 11, 0x01);
    EXPECT_EQ(name(open_case(wrong_nonce, c.aad, c.ct, c.tag, pt)), name(EKI_ERR_AUTH_FAILED));
    EXPECT_TRUE(all_zero(pt));
  }
}

// §4.4: `ct_len 0` with the right tag → OK (GCM test case 13, NULL buffers).
TEST(FfiAead, OpenCtLenZeroWithTheRightTagIsOk) {
  const AeadCase c = decode(kAeadVectors.at(2));
  EXPECT_EQ(name(eki_aead_open(c.alg, c.key.data(), 32, c.nonce.data(), 12, nullptr, 0, nullptr, 0,
                               c.tag.data(), nullptr)),
            name(EKI_OK));
  Bytes tag = c.tag;
  flip(tag, 15, 0x01);
  EXPECT_EQ(name(eki_aead_open(c.alg, c.key.data(), 32, c.nonce.data(), 12, nullptr, 0, nullptr, 0,
                               tag.data(), nullptr)),
            name(EKI_ERR_AUTH_FAILED));
}

TEST(FfiAead, OpenUnknownAlgKeyLenNonceLenAreInvalid) {
  const AeadCase base = gcm16();
  AeadCase bad_alg = base;
  bad_alg.alg = 0;
  AeadCase bad_key = base;
  bad_key.key.resize(16);
  AeadCase bad_nonce = base;
  bad_nonce.nonce.resize(11);
  for (const AeadCase& c : {bad_alg, bad_key, bad_nonce}) {
    Bytes pt;
    EXPECT_EQ(name(open_case(c, c.aad, c.ct, c.tag, pt)), name(EKI_ERR_INVALID_ARGUMENT));
    EXPECT_TRUE(all_zero(pt));
  }
}

TEST(FfiAead, OpenNullPointers) {
  const AeadCase c = gcm16();
  const std::size_t n = c.ct.size();
  Bytes pt = prefill(n);
  const auto expect_null = [&](eki_status status, const char* what) {
    EXPECT_EQ(name(status), name(EKI_ERR_NULL_POINTER)) << what;
    EXPECT_TRUE(all_zero(pt)) << what;
    pt = prefill(n);
  };
  expect_null(eki_aead_open(c.alg, nullptr, 32, c.nonce.data(), 12, c.aad.data(), c.aad.size(),
                            c.ct.data(), n, c.tag.data(), pt.data()),
              "key");
  expect_null(eki_aead_open(c.alg, c.key.data(), 32, nullptr, 12, c.aad.data(), c.aad.size(),
                            c.ct.data(), n, c.tag.data(), pt.data()),
              "nonce");
  expect_null(eki_aead_open(c.alg, c.key.data(), 32, c.nonce.data(), 12, nullptr, 20, c.ct.data(),
                            n, c.tag.data(), pt.data()),
              "aad");
  expect_null(eki_aead_open(c.alg, c.key.data(), 32, c.nonce.data(), 12, c.aad.data(), c.aad.size(),
                            nullptr, n, c.tag.data(), pt.data()),
              "ct");
  expect_null(eki_aead_open(c.alg, c.key.data(), 32, c.nonce.data(), 12, c.aad.data(), c.aad.size(),
                            c.ct.data(), n, nullptr, pt.data()),
              "tag");
  EXPECT_EQ(name(eki_aead_open(c.alg, c.key.data(), 32, c.nonce.data(), 12, c.aad.data(),
                               c.aad.size(), c.ct.data(), n, c.tag.data(), nullptr)),
            name(EKI_ERR_NULL_POINTER))
      << "pt_out";
  // The tag is a fixed-size input: NULL is an error even when ct_len is 0.
  EXPECT_EQ(name(eki_aead_open(c.alg, c.key.data(), 32, c.nonce.data(), 12, nullptr, 0, nullptr, 0,
                               nullptr, nullptr)),
            name(EKI_ERR_NULL_POINTER))
      << "tag NULL, ct_len 0";
  // NULL before the selector.
  EXPECT_EQ(name(eki_aead_open(99, c.key.data(), 32, c.nonce.data(), 12, nullptr, 0, c.ct.data(), n,
                               c.tag.data(), nullptr)),
            name(EKI_ERR_NULL_POINTER))
      << "pt_out NULL, alg 99";
}

// `ct_len > EKI_AEAD_MAX_LEN` → INVALID_ARGUMENT; `pt_out` untouched.
TEST(FfiAead, OpenCtLenAboveMaxIsInvalid) {
  const AeadCase c = gcm16();
  const std::array<std::uint8_t, 1> ct{0};
  Bytes pt = prefill(1);
  EXPECT_EQ(
      name(eki_aead_open(c.alg, c.key.data(), 32, c.nonce.data(), 12, nullptr, 0, ct.data(),
                         static_cast<std::size_t>(EKI_AEAD_MAX_LEN) + 1, c.tag.data(), pt.data())),
      name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(untouched(pt));
}

// Round trips for both algorithms over lengths 0..4096 (the Rust suite uses proptest;
// here a deterministic sweep), and any single-bit change is rejected.
TEST(FfiAead, SealOpenRoundTrip) {
  for (const eki_aead_alg alg : {EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305}) {
    for (const std::size_t len : {
             std::size_t{0},
             std::size_t{1},
             std::size_t{15},
             std::size_t{16},
             std::size_t{17},
             std::size_t{63},
             std::size_t{64},
             std::size_t{65},
             std::size_t{1000},
             std::size_t{4096},
         }) {
      AeadCase c{
          .alg = alg,
          .key = Bytes(32),
          .nonce = Bytes(12),
          .aad = Bytes(len % 37),
          .pt = Bytes(len),
          .ct = {},
          .tag = {},
      };
      for (std::size_t i = 0; i < len; ++i) {
        c.pt.at(i) = static_cast<std::uint8_t>((i * 7) + len);
      }
      for (std::size_t i = 0; i < 32; ++i) {
        c.key.at(i) = static_cast<std::uint8_t>(i + len);
      }
      Bytes ct;
      Bytes tag;
      ASSERT_EQ(name(seal_case(c, ct, tag)), name(EKI_OK)) << "alg " << alg << " len " << len;
      Bytes back;
      EXPECT_EQ(name(open_case(c, c.aad, ct, tag, back)), name(EKI_OK));
      EXPECT_EQ(back, c.pt);
      Bytes sealed = ct;
      sealed.insert(sealed.end(), tag.begin(), tag.end());
      flip_bit(sealed, ((len * 13) + 5) % (sealed.size() * 8));
      const Bytes bad_ct(sealed.begin(), sealed.begin() + static_cast<std::ptrdiff_t>(len));
      const Bytes bad_tag(sealed.begin() + static_cast<std::ptrdiff_t>(len), sealed.end());
      EXPECT_EQ(name(open_case(c, c.aad, bad_ct, bad_tag, back)), name(EKI_ERR_AUTH_FAILED));
      EXPECT_TRUE(all_zero(back));
    }
  }
}

// =============================================================================================
// ECDSA P-256 verify: RFC 6979 A.2.5 (SHA-256, messages "sample" and "test").
// =============================================================================================

constexpr std::string_view kPublicKey =
    "04"
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
constexpr std::string_view kSigSampleR =
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
constexpr std::string_view kSigSampleS =
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";
// n - s for the "sample" signature: the other member of the malleable pair. Both verify.
constexpr std::string_view kSigSampleOtherS =
    "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9";
constexpr std::string_view kSigTest =
    "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
    "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083";
// A signature over the empty message under the RFC key (independent implementation).
constexpr std::string_view kSigEmpty =
    "9b764e1b7356ce0afc0ef77f30ea035b156ca8f8f70209f213db5a4752b7c5f1"
    "d971d1b0f6cee519766877bc76afa8bc4c7b59a2781d1e5d8e6d37a4f9775dc0";
constexpr std::string_view kN = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
constexpr std::string_view kP = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

using PublicKey = std::array<std::uint8_t, 65>;
using Signature = std::array<std::uint8_t, 64>;

PublicKey public_key() {
  return hex_array<65>(kPublicKey);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): r then s, as in the RFC.
Signature sig_of(std::string_view r, std::string_view s) {
  Bytes joined = hex(r);
  const Bytes tail = hex(s);
  joined.insert(joined.end(), tail.begin(), tail.end());
  Signature out{};
  std::ranges::copy(joined, out.begin());
  return out;
}

Signature sig_sample() {
  return sig_of(kSigSampleR, kSigSampleS);
}

eki_status verify(const PublicKey& pk, std::string_view msg, const Signature& sig) {
  const auto m = bytes(msg);
  return eki_ecdsa_p256_verify(pk.data(), m.data(), m.size(), sig.data());
}

TEST(FfiEcdsa, Rfc6979Vectors) {
  EXPECT_EQ(name(verify(public_key(), "sample", sig_sample())), name(EKI_OK));
  EXPECT_EQ(name(verify(public_key(), "test", hex_array<64>(kSigTest))), name(EKI_OK));
}

// High-s signatures are accepted (§4.2).
TEST(FfiEcdsa, HighAndLowSBothVerify) {
  EXPECT_EQ(name(verify(public_key(), "sample", sig_of(kSigSampleR, kSigSampleOtherS))),
            name(EKI_OK));
}

TEST(FfiEcdsa, EmptyMessageWithNullPointer) {
  const PublicKey pk = public_key();
  const auto sig = hex_array<64>(kSigEmpty);
  EXPECT_EQ(name(eki_ecdsa_p256_verify(pk.data(), nullptr, 0, sig.data())), name(EKI_OK));
}

// §4.4: `public_key[0] = 0x02` → INVALID_ARGUMENT.
TEST(FfiEcdsa, PublicKeyPrefixNot04IsInvalid) {
  constexpr std::array<std::uint8_t, 7> kPrefixes{0x00, 0x02, 0x03, 0x05, 0x06, 0x07, 0xff};
  for (const std::uint8_t prefix : kPrefixes) {
    PublicKey pk = public_key();
    pk.at(0) = prefix;
    EXPECT_EQ(name(verify(pk, "sample", sig_sample())), name(EKI_ERR_INVALID_ARGUMENT))
        << "prefix " << int{prefix};
  }
}

// §4.4: off-curve point → INVALID_ARGUMENT.
TEST(FfiEcdsa, OffCurvePointIsInvalid) {
  PublicKey pk = public_key();
  pk.at(64) = static_cast<std::uint8_t>(pk.at(64) ^ 0x01U); // y - 1: not on the curve
  EXPECT_EQ(name(verify(pk, "sample", sig_sample())), name(EKI_ERR_INVALID_ARGUMENT));
  PublicKey zero{};
  zero.at(0) = 0x04;
  EXPECT_EQ(name(verify(zero, "sample", sig_sample())), name(EKI_ERR_INVALID_ARGUMENT)) << "(0, 0)";
}

// A coordinate ≥ p fails to parse → INVALID_ARGUMENT.
TEST(FfiEcdsa, CoordinateNotBelowPIsInvalid) {
  const Bytes p = hex(kP);
  PublicKey pk = public_key();
  std::ranges::copy(p, pk.begin() + 1);
  EXPECT_EQ(name(verify(pk, "sample", sig_sample())), name(EKI_ERR_INVALID_ARGUMENT)) << "x = p";
  pk = public_key();
  std::ranges::copy(p, pk.begin() + 33);
  EXPECT_EQ(name(verify(pk, "sample", sig_sample())), name(EKI_ERR_INVALID_ARGUMENT)) << "y = p";
}

// §4.4: `r = 0`; `s = n` → AUTH_FAILED (also s = 0, r = n, 2^256 - 1).
TEST(FfiEcdsa, ROrSOutOfRangeIsAuthFailed) {
  constexpr std::string_view kZero =
      "0000000000000000000000000000000000000000000000000000000000000000";
  constexpr std::string_view kMax =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  const PublicKey pk = public_key();
  EXPECT_EQ(name(verify(pk, "sample", sig_of(kZero, kSigSampleS))), name(EKI_ERR_AUTH_FAILED))
      << "r = 0";
  EXPECT_EQ(name(verify(pk, "sample", sig_of(kSigSampleR, kZero))), name(EKI_ERR_AUTH_FAILED))
      << "s = 0";
  EXPECT_EQ(name(verify(pk, "sample", sig_of(kN, kSigSampleS))), name(EKI_ERR_AUTH_FAILED))
      << "r = n";
  EXPECT_EQ(name(verify(pk, "sample", sig_of(kSigSampleR, kN))), name(EKI_ERR_AUTH_FAILED))
      << "s = n";
  EXPECT_EQ(name(verify(pk, "sample", sig_of(kMax, kSigSampleS))), name(EKI_ERR_AUTH_FAILED))
      << "r = 2^256 - 1";
  EXPECT_EQ(name(verify(pk, "sample", sig_of(kSigSampleR, kMax))), name(EKI_ERR_AUTH_FAILED))
      << "s = 2^256 - 1";
}

// §4.4: signature over another message → AUTH_FAILED.
TEST(FfiEcdsa, SignatureOverOtherMessageIsAuthFailed) {
  const PublicKey pk = public_key();
  const Signature sig = sig_sample();
  EXPECT_EQ(name(verify(pk, "test", sig)), name(EKI_ERR_AUTH_FAILED));
  EXPECT_EQ(name(eki_ecdsa_p256_verify(pk.data(), nullptr, 0, sig.data())),
            name(EKI_ERR_AUTH_FAILED))
      << "empty message";
}

TEST(FfiEcdsa, SignatureBitFlipIsAuthFailed) {
  for (const std::size_t index :
       {std::size_t{0}, std::size_t{31}, std::size_t{32}, std::size_t{63}}) {
    Signature sig = sig_sample();
    sig.at(index) = static_cast<std::uint8_t>(sig.at(index) ^ 0x01U);
    EXPECT_EQ(name(verify(public_key(), "sample", sig)), name(EKI_ERR_AUTH_FAILED))
        << "byte " << index;
  }
}

TEST(FfiEcdsa, NullPointers) {
  const PublicKey pk = public_key();
  const Signature sig = sig_sample();
  const auto msg = bytes("sample");
  EXPECT_EQ(name(eki_ecdsa_p256_verify(nullptr, msg.data(), msg.size(), sig.data())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_EQ(name(eki_ecdsa_p256_verify(pk.data(), nullptr, 6, sig.data())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_EQ(name(eki_ecdsa_p256_verify(pk.data(), msg.data(), msg.size(), nullptr)),
            name(EKI_ERR_NULL_POINTER));
  // NULL is reported before the public key format is looked at.
  PublicKey bad = public_key();
  bad.at(0) = 0x02;
  EXPECT_EQ(name(eki_ecdsa_p256_verify(bad.data(), msg.data(), msg.size(), nullptr)),
            name(EKI_ERR_NULL_POINTER));
}

} // namespace
// NOLINTEND(readability-function-cognitive-complexity)
