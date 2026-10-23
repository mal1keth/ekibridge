// Unit tests of the internal ECDSA P-256 / SHA-256 verification primitive
// (ekicore::ecdsa_p256_verify): RFC 6979 and Wycheproof vectors and the ECDSA rows of the ABI
// error matrix.

#include "error_queue_support.hpp"

#include <ekicore/primitives.hpp>

#include <gtest/gtest.h>

#include <ekicore.h>

#include <openssl/bn.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace {

using bytes = std::vector<std::uint8_t>;

std::uint8_t nibble(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint8_t>(c - '0');
  }
  return static_cast<std::uint8_t>(c - 'a' + 10);
}

bytes unhex(std::string_view hex) {
  bytes out(hex.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    const auto high = static_cast<unsigned>(nibble(hex.at(2 * i)));
    const auto low = static_cast<unsigned>(nibble(hex.at((2 * i) + 1)));
    out.at(i) = static_cast<std::uint8_t>((high << 4U) | low);
  }
  return out;
}

bytes text(std::string_view s) {
  return {s.begin(), s.end()};
}

bytes concat(std::initializer_list<std::span<const std::uint8_t>> parts) {
  bytes out;
  for (const auto part : parts) {
    out.insert(out.end(), part.begin(), part.end());
  }
  return out;
}

// RFC 6979 appendix A.2.5: the P-256 key pair's public key U = (Ux, Uy) in SEC1 uncompressed
// form, the group order q, and the SHA-256 signatures over "sample" and "test".
constexpr std::string_view rfc_public_key =
    "04"
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
constexpr std::string_view order_n =
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
constexpr std::string_view sample_r =
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
constexpr std::string_view sample_s =
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";
constexpr std::string_view test_r =
    "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367";
constexpr std::string_view test_s =
    "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083";

TEST(PrimitivesEcdsa, Rfc6979Signatures) {
  const bytes pk = unhex(rfc_public_key);
  EXPECT_EQ(
      ekicore::ecdsa_p256_verify(pk, text("sample"), concat({unhex(sample_r), unhex(sample_s)})),
      EKI_OK);
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("test"), concat({unhex(test_r), unhex(test_s)})),
            EKI_OK);
}

TEST(PrimitivesEcdsa, SignatureOverOtherMessageFails) {
  const bytes pk = unhex(rfc_public_key);
  const bytes sig = concat({unhex(sample_r), unhex(sample_s)});
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("test"), sig), EKI_ERR_AUTH_FAILED);
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("samplf"), sig), EKI_ERR_AUTH_FAILED);
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, {}, sig), EKI_ERR_AUTH_FAILED);
  const std::uint8_t dummy = 0;
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, std::span<const std::uint8_t>(&dummy, 0), sig),
            EKI_ERR_AUTH_FAILED);
}

TEST(PrimitivesEcdsa, HighSIsAccepted) {
  // (r, n - s) is the other valid encoding of the same signature.
  using bignum = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
  const bytes n_bytes = unhex(order_n);
  const bytes s_bytes = unhex(sample_s);
  const bignum n(BN_bin2bn(n_bytes.data(), 32, nullptr), &BN_free);
  const bignum s(BN_bin2bn(s_bytes.data(), 32, nullptr), &BN_free);
  const bignum high_s(BN_new(), &BN_free);
  ASSERT_TRUE(n && s && high_s);
  ASSERT_EQ(BN_sub(high_s.get(), n.get(), s.get()), 1);
  bytes high_s_bytes(32);
  ASSERT_EQ(BN_bn2binpad(high_s.get(), high_s_bytes.data(), 32), 32);
  ASSERT_NE(high_s_bytes, s_bytes);
  EXPECT_EQ(ekicore::ecdsa_p256_verify(unhex(rfc_public_key), text("sample"),
                                       concat({unhex(sample_r), high_s_bytes})),
            EKI_OK);
}

TEST(PrimitivesEcdsa, PublicKeyNotUncompressedIsInvalid) {
  const bytes sig = concat({unhex(sample_r), unhex(sample_s)});
  for (const std::uint8_t prefix :
       std::to_array<std::uint8_t>({0x00, 0x02, 0x03, 0x05, 0x06, 0x07, 0xFF})) {
    SCOPED_TRACE(static_cast<int>(prefix));
    bytes pk = unhex(rfc_public_key);
    pk.at(0) = prefix;
    EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), sig), EKI_ERR_INVALID_ARGUMENT);
  }
}

TEST(PrimitivesEcdsa, PointNotOnCurveIsInvalid) {
  const bytes sig = concat({unhex(sample_r), unhex(sample_s)});
  for (const std::size_t index :
       {std::size_t{1}, std::size_t{32}, std::size_t{33}, std::size_t{64}}) {
    SCOPED_TRACE(index);
    bytes pk = unhex(rfc_public_key);
    pk.at(index) = static_cast<std::uint8_t>(pk.at(index) ^ 0x01U);
    EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), sig), EKI_ERR_INVALID_ARGUMENT);
  }
  // The all-zero point (0, 0) is not on P-256 either.
  bytes zero(EKI_P256_PUBLIC_KEY_LEN, 0);
  zero.at(0) = 0x04;
  EXPECT_EQ(ekicore::ecdsa_p256_verify(zero, text("sample"), sig), EKI_ERR_INVALID_ARGUMENT);
}

TEST(PrimitivesEcdsa, CoordinateNotBelowPIsInvalid) {
  const bytes sig = concat({unhex(sample_r), unhex(sample_s)});
  bytes pk = unhex(rfc_public_key);
  std::fill(pk.begin() + 1, pk.begin() + 33, std::uint8_t{0xFF}); // X = 2^256 - 1 > p
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), sig), EKI_ERR_INVALID_ARGUMENT);
  pk = unhex(rfc_public_key);
  std::fill(pk.begin() + 33, pk.end(), std::uint8_t{0xFF}); // Y = 2^256 - 1 > p
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), sig), EKI_ERR_INVALID_ARGUMENT);
}

TEST(PrimitivesEcdsa, ScalarsOutOfRangeFail) {
  const bytes pk = unhex(rfc_public_key);
  const bytes zero(32, 0);
  const bytes n = unhex(order_n);
  const bytes ones(32, 0xFF);
  const bytes r = unhex(sample_r);
  const bytes s = unhex(sample_s);
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), concat({zero, s})), EKI_ERR_AUTH_FAILED)
      << "r = 0";
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), concat({r, zero})), EKI_ERR_AUTH_FAILED)
      << "s = 0";
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), concat({n, s})), EKI_ERR_AUTH_FAILED)
      << "r = n";
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), concat({r, n})), EKI_ERR_AUTH_FAILED)
      << "s = n";
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), concat({ones, s})), EKI_ERR_AUTH_FAILED)
      << "r = 2^256 - 1";
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), concat({r, ones})), EKI_ERR_AUTH_FAILED)
      << "s = 2^256 - 1";
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), bytes(64, 0)), EKI_ERR_AUTH_FAILED)
      << "r = s = 0";
}

TEST(PrimitivesEcdsa, InvalidKeyIsReportedBeforeBadSignature) {
  bytes pk = unhex(rfc_public_key);
  pk.at(0) = 0x02;
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), bytes(64, 0)), EKI_ERR_INVALID_ARGUMENT);
}

TEST(PrimitivesEcdsa, WrongBufferSizesAreInvalid) {
  const bytes pk = unhex(rfc_public_key);
  const bytes sig = concat({unhex(sample_r), unhex(sample_s)});
  EXPECT_EQ(ekicore::ecdsa_p256_verify(std::span(pk).first(64), text("sample"), sig),
            EKI_ERR_INVALID_ARGUMENT);
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), std::span(sig).first(63)),
            EKI_ERR_INVALID_ARGUMENT);
  EXPECT_EQ(ekicore::ecdsa_p256_verify({}, text("sample"), sig), EKI_ERR_INVALID_ARGUMENT);
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), {}), EKI_ERR_INVALID_ARGUMENT);
}

struct wycheproof_case {
  int tc_id;
  bool valid;
  std::string_view msg;
  std::string_view sig;
};

// Wycheproof ecdsa_secp256r1_sha256_p1363_test.json (C2SP testvectors_v1, Apache-2.0), first test
// group: the malleability case, r replaced by n - r, every special-case (r, s) pair built from
// 0, 1, n - 1, n, n + 1, p, p + 1, and the first special-case hashes. 64-byte signatures only.
constexpr std::string_view wycheproof_public_key =
    "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1"
    "498a60f4606766b3d9685001558d1a974e7341513e";

constexpr auto wycheproof_cases = std::to_array<wycheproof_case>({
    {
        .tc_id = 1,
        .valid = true,
        .msg = "313233343030",
        .sig =
            "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184cd60b855d442f5b3c7b"
            "11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
    },
    {
        .tc_id = 4,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739b329f479a2bbd0a5c384"
            "ee1493b1f5186a87139cac5df4087c134b49156847db",
    },
    {
        .tc_id = 11,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000",
    },
    {
        .tc_id = 12,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000001",
    },
    {
        .tc_id = 13,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632551",
    },
    {
        .tc_id = 14,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632550",
    },
    {
        .tc_id = 15,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632552",
    },
    {
        .tc_id = 16,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff000000010000"
            "00000000000000000000ffffffffffffffffffffffff",
    },
    {
        .tc_id = 17,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff000000010000"
            "00000000000000000001000000000000000000000000",
    },
    {
        .tc_id = 18,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "000000000000000000000000000000000000000000000000000000000000000100000000000000000000"
            "00000000000000000000000000000000000000000000",
    },
    {
        .tc_id = 19,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "000000000000000000000000000000000000000000000000000000000000000100000000000000000000"
            "00000000000000000000000000000000000000000001",
    },
    {
        .tc_id = 20,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632551",
    },
    {
        .tc_id = 21,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632550",
    },
    {
        .tc_id = 22,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632552",
    },
    {
        .tc_id = 23,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "0000000000000000000000000000000000000000000000000000000000000001ffffffff000000010000"
            "00000000000000000000ffffffffffffffffffffffff",
    },
    {
        .tc_id = 24,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "0000000000000000000000000000000000000000000000000000000000000001ffffffff000000010000"
            "00000000000000000001000000000000000000000000",
    },
    {
        .tc_id = 25,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63255100000000000000000000"
            "00000000000000000000000000000000000000000000",
    },
    {
        .tc_id = 26,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63255100000000000000000000"
            "00000000000000000000000000000000000000000001",
    },
    {
        .tc_id = 27,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632551",
    },
    {
        .tc_id = 28,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632550",
    },
    {
        .tc_id = 29,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632552",
    },
    {
        .tc_id = 30,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff000000010000"
            "00000000000000000000ffffffffffffffffffffffff",
    },
    {
        .tc_id = 31,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff000000010000"
            "00000000000000000001000000000000000000000000",
    },
    {
        .tc_id = 32,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63255000000000000000000000"
            "00000000000000000000000000000000000000000000",
    },
    {
        .tc_id = 33,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63255000000000000000000000"
            "00000000000000000000000000000000000000000001",
    },
    {
        .tc_id = 34,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632551",
    },
    {
        .tc_id = 35,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632550",
    },
    {
        .tc_id = 36,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632552",
    },
    {
        .tc_id = 37,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff000000010000"
            "00000000000000000000ffffffffffffffffffffffff",
    },
    {
        .tc_id = 38,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff000000010000"
            "00000000000000000001000000000000000000000000",
    },
    {
        .tc_id = 39,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63255200000000000000000000"
            "00000000000000000000000000000000000000000000",
    },
    {
        .tc_id = 40,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63255200000000000000000000"
            "00000000000000000000000000000000000000000001",
    },
    {
        .tc_id = 41,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632551",
    },
    {
        .tc_id = 42,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632550",
    },
    {
        .tc_id = 43,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632552",
    },
    {
        .tc_id = 44,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff000000010000"
            "00000000000000000000ffffffffffffffffffffffff",
    },
    {
        .tc_id = 45,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff000000010000"
            "00000000000000000001000000000000000000000000",
    },
    {
        .tc_id = 46,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff00000000000000000000"
            "00000000000000000000000000000000000000000000",
    },
    {
        .tc_id = 47,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff00000000000000000000"
            "00000000000000000000000000000000000000000001",
    },
    {
        .tc_id = 48,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632551",
    },
    {
        .tc_id = 49,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632550",
    },
    {
        .tc_id = 50,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632552",
    },
    {
        .tc_id = 51,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff000000010000"
            "00000000000000000000ffffffffffffffffffffffff",
    },
    {
        .tc_id = 52,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff000000010000"
            "00000000000000000001000000000000000000000000",
    },
    {
        .tc_id = 53,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff0000000100000000000000000000000100000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000",
    },
    {
        .tc_id = 54,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff0000000100000000000000000000000100000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000001",
    },
    {
        .tc_id = 55,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632551",
    },
    {
        .tc_id = 56,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632550",
    },
    {
        .tc_id = 57,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffff"
            "ffffffffffffbce6faada7179e84f3b9cac2fc632552",
    },
    {
        .tc_id = 58,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff000000010000"
            "00000000000000000000ffffffffffffffffffffffff",
    },
    {
        .tc_id = 59,
        .valid = false,
        .msg = "313233343030",
        .sig =
            "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff000000010000"
            "00000000000000000001000000000000000000000000",
    },
    {
        .tc_id = 60,
        .valid = true,
        .msg = "3639383139",
        .sig =
            "64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e6af015971cc30be6d1a2"
            "06d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
    },
    {
        .tc_id = 61,
        .valid = true,
        .msg = "343236343739373234",
        .sig =
            "16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf266252cd762130c6667cfe8"
            "b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
    },
    {
        .tc_id = 62,
        .valid = true,
        .msg = "37313338363834383931",
        .sig =
            "9cc98be2347d469bf476dfc26b9b733df2d26d6ef524af917c665baccb23c882093496459effe2d8d707"
            "27b82462f61d0ec1b7847929d10ea631dacb16b56c32",
    },
    {
        .tc_id = 63,
        .valid = true,
        .msg = "3130333539333331363638",
        .sig =
            "73b3c90ecd390028058164524dde892703dce3dea0d53fa8093999f07ab8aa432f67b0b8e20636695bb7"
            "d8bf0a651c802ed25a395387b5f4188c0c4075c88634",
    },
    {
        .tc_id = 64,
        .valid = true,
        .msg = "33393439343031323135",
        .sig =
            "bfab3098252847b328fadf2f89b95c851a7f0eb390763378f37e90119d5ba3ddbdd64e234e832b1067c2"
            "d058ccb44d978195ccebb65c2aaf1e2da9b8b4987e3b",
    },
    {
        .tc_id = 65,
        .valid = true,
        .msg = "31333434323933303739",
        .sig =
            "204a9784074b246d8bf8bf04a4ceb1c1f1c9aaab168b1596d17093c5cd21d2cd51cce41670636783dc06"
            "a759c8847868a406c2506fe17975582fe648d1d88b52",
    },
    {
        .tc_id = 66,
        .valid = true,
        .msg = "33373036323131373132",
        .sig =
            "ed66dc34f551ac82f63d4aa4f81fe2cb0031a91d1314f835027bca0f1ceeaa0399ca123aa09b13cd194a"
            "422e18d5fda167623c3f6e5d4d6abb8953d67c0c48c7",
    },
    {
        .tc_id = 67,
        .valid = true,
        .msg = "333433363838373132",
        .sig =
            "060b700bef665c68899d44f2356a578d126b062023ccc3c056bf0f60a237012b8d186c027832965f4fcc"
            "78a3366ca95dedbb410cbef3f26d6be5d581c11d3610",
    },
    {
        .tc_id = 68,
        .valid = true,
        .msg = "31333531353330333730",
        .sig =
            "9f6adfe8d5eb5b2c24d7aa7934b6cf29c93ea76cd313c9132bb0c8e38c96831db26a9c9e40e55ee0890c"
            "944cf271756c906a33e66b5bd15e051593883b5e9902",
    },
    {
        .tc_id = 69,
        .valid = true,
        .msg = "36353533323033313236",
        .sig =
            "a1af03ca91677b673ad2f33615e56174a1abf6da168cebfa8868f4ba273f16b720aa73ffe48afa6435cd"
            "258b173d0c2377d69022e7d098d75caf24c8c5e06b1c",
    },
    {
        .tc_id = 70,
        .valid = true,
        .msg = "31353634333436363033",
        .sig =
            "fdc70602766f8eed11a6c99a71c973d5659355507b843da6e327a28c11893db93df5349688a085b137b1"
            "eacf456a9e9e0f6d15ec0078ca60a7f83f2b10d21350",
    },
});

TEST(PrimitivesEcdsa, WycheproofSubset) {
  const bytes pk = unhex(wycheproof_public_key);
  for (const auto& c : wycheproof_cases) {
    SCOPED_TRACE(testing::Message() << "tcId " << c.tc_id);
    EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, unhex(c.msg), unhex(c.sig)),
              c.valid ? EKI_OK : EKI_ERR_AUTH_FAILED);
  }
}

// An expected failure (bad public key, bad signature) removes what OpenSSL queued for it and
// nothing else; a success leaves the queue as it found it.
TEST(PrimitivesEcdsa, CallersErrorQueueIsLeftAlone) {
  const bytes pk = unhex(rfc_public_key);
  const bytes sig = concat({unhex(sample_r), unhex(sample_s)});

  unsigned long caller = eki_test::push_caller_error();
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), sig), EKI_OK);
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "success";

  caller = eki_test::push_caller_error();
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("test"), sig), EKI_ERR_AUTH_FAILED);
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "signature over another message";

  caller = eki_test::push_caller_error();
  EXPECT_EQ(ekicore::ecdsa_p256_verify(pk, text("sample"), bytes(64, 0)), EKI_ERR_AUTH_FAILED);
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "r = s = 0";

  bytes off_curve = pk;
  off_curve.at(64) = static_cast<std::uint8_t>(off_curve.at(64) ^ 0x01U);
  caller = eki_test::push_caller_error();
  EXPECT_EQ(ekicore::ecdsa_p256_verify(off_curve, text("sample"), sig), EKI_ERR_INVALID_ARGUMENT);
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "point not on the curve";

  bytes x_too_large = pk;
  std::fill(x_too_large.begin() + 1, x_too_large.begin() + 33, std::uint8_t{0xFF});
  caller = eki_test::push_caller_error();
  EXPECT_EQ(ekicore::ecdsa_p256_verify(x_too_large, text("sample"), sig), EKI_ERR_INVALID_ARGUMENT);
  EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "X >= p";
}

} // namespace
