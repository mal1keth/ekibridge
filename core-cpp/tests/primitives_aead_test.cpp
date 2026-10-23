// Unit tests of the internal AEAD primitives (ekicore::aead_seal / aead_open): RFC 8439 and
// Wycheproof vectors, the AEAD rows of the ABI error matrix, zero-on-failure and round trips.

#include "error_queue_support.hpp"

#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <gtest/gtest.h>

#include <ekicore.h>

#include <sys/mman.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

// GoogleTest assertion macros expand to branches, which inflates the cognitive complexity score of
// table-driven tests well past the threshold without making them harder to read.
// NOLINTBEGIN(readability-function-cognitive-complexity)
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

bool all_equal(std::span<const std::uint8_t> buf, std::uint8_t value) {
  return std::ranges::all_of(buf, [value](std::uint8_t b) { return b == value; });
}

constexpr std::uint8_t fill = 0xA5;
constexpr std::array<eki_aead_alg, 2> algs{EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305};

struct aead_vector {
  int tc_id; // Wycheproof tcId, 0 for RFC vectors
  bool valid;
  std::string_view key;
  std::string_view nonce;
  std::string_view aad;
  std::string_view pt;
  std::string_view ct;
  std::string_view tag;
};

// RFC 8439 section 2.8.2 (nonce = 32-bit constant 07000000 || IV) and appendix A.5, then
// Wycheproof chacha20_poly1305_test.json (C2SP testvectors_v1, Apache-2.0), 96-bit IV group.
constexpr auto chacha_vectors = std::to_array<aead_vector>({
    // RFC 8439 section 2.8.2
    {
        .tc_id = 0,
        .valid = true,
        .key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        .nonce = "070000004041424344454647",
        .aad = "50515253c0c1c2c3c4c5c6c7",
        .pt =
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a2049"
            "66204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675"
            "747572652c2073756e73637265656e20776f756c642062652069742e",
        .ct =
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb"
            "69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad6"
            "75945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        .tag = "1ae10b594f09e26a7e902ecbd0600691",
    },
    // RFC 8439 appendix A.5
    {
        .tc_id = 0,
        .valid = true,
        .key = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        .nonce = "000000000102030405060708",
        .aad = "f33388860000000000004e91",
        .pt =
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c69642066"
            "6f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d6179206265207570646174"
            "65642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e"
            "747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520"
            "496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f"
            "2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f677265"
            "73732e2fe2809d",
        .ct =
            "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee9"
            "4e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d"
            "33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9"
            "166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b004771"
            "8cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a"
            "1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad"
            "5cb4022b02709b",
        .tag = "eead9d67890cbb22392336fea1851f38",
    },
    // tcId 2: valid
    {
        .tc_id = 2,
        .valid = true,
        .key = "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0",
        .nonce = "4da5bf8dfd5852c1ea12379d",
        .aad = "",
        .pt = "",
        .ct = "",
        .tag = "76acb342cf3166a5b63c0c0ea1383c8d",
    },
    // tcId 3: valid
    {
        .tc_id = 3,
        .valid = true,
        .key = "7a4cd759172e02eb204db2c3f5c746227df584fc1345196391dbb9577a250742",
        .nonce = "a92ef0ac991dd516a3c6f689",
        .aad = "bd506764f2d2c410",
        .pt = "",
        .ct = "",
        .tag = "906fa6284b52f87b7359cbaa7563c709",
    },
    // tcId 5: valid
    {
        .tc_id = 5,
        .valid = true,
        .key = "46f0254965f769d52bdb4a70b443199f8ef207520d1220c55e4b70f0fda620ee",
        .nonce = "ab0dca716ee051d2782f4403",
        .aad = "91ca6c592cbcca53",
        .pt = "51",
        .ct = "c4",
        .tag = "168310ca45b1f7c66cad4e99e43f72b9",
    },
    // tcId 36: valid
    {
        .tc_id = 36,
        .valid = true,
        .key = "3b2458d8176e1621c0cc24c0c0e24c1e80d72f7ee9149a4b166176629616d011",
        .nonce = "45aaa3e5d16d2d42dc03445d",
        .aad = "",
        .pt = "3ff1514b1c503915918f0c0c31094a6e1f",
        .ct = "02cc3acb5ee1fcdd12a03bb857976474d3",
        .tag = "d83b7463a2c3800fe958c28eaa290813",
    },
    // tcId 146: invalid (Flipped bit 0 in tag)
    {
        .tc_id = 146,
        .valid = false,
        .key = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        .nonce = "000102030405060708090a0b",
        .aad = "000102",
        .pt = "",
        .ct = "",
        .tag = "f5409bb729039d0814ac514054323f44",
    },
    // tcId 166: invalid (Flipped bit 0 in tag)
    {
        .tc_id = 166,
        .valid = false,
        .key = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        .nonce = "000102030405060708090a0b",
        .aad = "000102",
        .pt = "000102030405060708090a0b0c0d0e0f",
        .ct = "d03bcb3ca52d48d1d203b1e7b1a5995a",
        .tag = "28914007a6119dd3f109bba21ce9a7d6",
    },
    // tcId 186: invalid (Flipped bit 0 in tag)
    {
        .tc_id = 186,
        .valid = false,
        .key = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        .nonce = "000102030405060708090a0b",
        .aad = "000102",
        .pt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        .ct = "d03bcb3ca52d48d1d203b1e7b1a5995af1a0466a61bb386a2e12d189a2c4ea15e9",
        .tag = "67405a16e8b44eba92aa47f5cea52b7a",
    },
    // tcId 205: invalid (tag change to all 1)
    {
        .tc_id = 205,
        .valid = false,
        .key = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        .nonce = "000102030405060708090a0b",
        .aad = "000102",
        .pt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        .ct = "d03bcb3ca52d48d1d203b1e7b1a5995af1a0466a61bb386a2e12d189a2c4ea15e9",
        .tag = "ffffffffffffffffffffffffffffffff",
    },
});

// Wycheproof aes_gcm_test.json (C2SP testvectors_v1, Apache-2.0), group keySize 256, ivSize 96,
// tagSize 128.
constexpr auto gcm_vectors = std::to_array<aead_vector>({
    // tcId 91: valid
    {
        .tc_id = 91,
        .valid = true,
        .key = "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20",
        .nonce = "00112233445566778899aabb",
        .aad = "00000000ffffffff",
        .pt = "00010203040506070809",
        .ct = "e27abdd2d2a53d2f136b",
        .tag = "9a4a2579529301bcfb71c78d4060f52c",
    },
    // tcId 92: valid
    {
        .tc_id = 92,
        .valid = true,
        .key = "29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123",
        .nonce = "00112233445566778899aabb",
        .aad = "aabbccddeeff",
        .pt = "",
        .ct = "",
        .tag = "2a7d77fa526b8250cb296078926b5020",
    },
    // tcId 93: valid
    {
        .tc_id = 93,
        .valid = true,
        .key = "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0",
        .nonce = "4da5bf8dfd5852c1ea12379d",
        .aad = "",
        .pt = "",
        .ct = "",
        .tag = "4771a7c404a472966cea8f73c8bfe17a",
    },
    // tcId 94: valid
    {
        .tc_id = 94,
        .valid = true,
        .key = "cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273",
        .nonce = "99e23ec48985bccdeeab60f1",
        .aad = "",
        .pt = "2a",
        .ct = "06",
        .tag = "633c1e9703ef744ffffb40edf9d14355",
    },
    // tcId 101: valid
    {
        .tc_id = 101,
        .valid = true,
        .key = "cdccfe3f46d782ef47df4e72f0c02d9c7f774def970d23486f11a57f54247f17",
        .nonce = "376187894605a8d45e30de51",
        .aad = "956846a209e087ed",
        .pt = "e28e0e9f9d22463ac0e42639b530f42102fded75",
        .ct = "feca44952447015b5df1f456df8ca4bb4eee2ce2",
        .tag = "082e91924deeb77880e1b1c84f9b8d30",
    },
    // tcId 105: valid
    {
        .tc_id = 105,
        .valid = true,
        .key = "5b1d1035c0b17ee0b0444767f80a25b8c1b741f4b50a4d3052226baa1c6fb701",
        .nonce = "d61040a313ed492823cc065b",
        .aad = "",
        .pt = "d096803181beef9e008ff85d5ddc38ddacf0f09ee5f7e07f1e4079cb64d0dc8f5e6711cd4921a7887de7"
              "6e2678fdc67618f1185586bfea9d4c685d50e4bb9a82",
        .ct = "c7d191b601f86c28b6a1bdef6a57b4f6ee3ae417bc125c381cdf1c4dac184ed1d84f1196206d62cad112"
              "b038845720e02c061179a8836f02b93fa7008379a6bf",
        .tag = "f15612f6c40f2e0db6dc76fc4822fcfe",
    },
    // tcId 116: valid
    {
        .tc_id = 116,
        .valid = true,
        .key = "0f112e59cdccd851c3b8e76c9f05a3b7c2e4feca5846afeb351c1cbcace82f04",
        .nonce = "7147973339d86789a2c9a958",
        .aad =
            "37128be45f0a7f329546e1492c3c9c2d2534d5b1f5147e49ab91221e7c3edea21bbe47bfe3619437ce3c"
            "61e6e946c504f348296918219e51bf2c5598589cff",
        .pt = "102e5804dda1fb5d656077edb15cadb5d0bdee8c",
        .ct = "618ac626ae0e8d06c2fd2fb66be253dc26ed6e38",
        .tag = "d8d93ff975cb988f09174dcd439cb6a4",
    },
    // tcId 130: invalid (Flipped bit 0 in tag)
    {
        .tc_id = 130,
        .valid = false,
        .key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        .nonce = "505152535455565758595a5b",
        .aad = "",
        .pt = "202122232425262728292a2b2c2d2e2f",
        .ct = "b2061457c0759fc1749f174ee1ccadfa",
        .tag = "9de8fef6d8ab1bf1bf887232eab590dd",
    },
    // tcId 147: invalid (Flipped bit 126 in tag)
    {
        .tc_id = 147,
        .valid = false,
        .key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        .nonce = "505152535455565758595a5b",
        .aad = "",
        .pt = "202122232425262728292a2b2c2d2e2f",
        .ct = "b2061457c0759fc1749f174ee1ccadfa",
        .tag = "9ce8fef6d8ab1bf1bf887232eab5909d",
    },
    // tcId 152: invalid (all bits of tag flipped)
    {
        .tc_id = 152,
        .valid = false,
        .key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        .nonce = "505152535455565758595a5b",
        .aad = "",
        .pt = "202122232425262728292a2b2c2d2e2f",
        .ct = "b2061457c0759fc1749f174ee1ccadfa",
        .tag = "631701092754e40e40778dcd154a6f22",
    },
    // tcId 153: invalid (Tag changed to all zero)
    {
        .tc_id = 153,
        .valid = false,
        .key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        .nonce = "505152535455565758595a5b",
        .aad = "",
        .pt = "202122232425262728292a2b2c2d2e2f",
        .ct = "b2061457c0759fc1749f174ee1ccadfa",
        .tag = "00000000000000000000000000000000",
    },
});

void check_vectors(eki_aead_alg alg, std::span<const aead_vector> vectors) {
  for (const auto& v : vectors) {
    SCOPED_TRACE(testing::Message() << "tcId " << v.tc_id);
    const bytes key = unhex(v.key);
    const bytes nonce = unhex(v.nonce);
    const bytes aad = unhex(v.aad);
    const bytes pt = unhex(v.pt);
    const bytes ct = unhex(v.ct);
    const bytes tag = unhex(v.tag);

    bytes opened(ct.size(), fill);
    if (v.valid) {
      bytes sealed(pt.size(), fill);
      std::array<std::uint8_t, EKI_AEAD_TAG_LEN> sealed_tag{};
      ASSERT_EQ(ekicore::aead_seal(alg, key, nonce, aad, pt, sealed, sealed_tag), EKI_OK);
      EXPECT_EQ(sealed, ct);
      EXPECT_TRUE(std::ranges::equal(sealed_tag, tag));
      ASSERT_EQ(ekicore::aead_open(alg, key, nonce, aad, ct, tag, opened), EKI_OK);
      EXPECT_EQ(opened, pt);
    } else {
      EXPECT_EQ(ekicore::aead_open(alg, key, nonce, aad, ct, tag, opened), EKI_ERR_AUTH_FAILED);
      EXPECT_TRUE(all_equal(opened, 0));
    }
  }
}

TEST(PrimitivesAead, ChaCha20Poly1305Vectors) {
  check_vectors(EKI_AEAD_CHACHA20_POLY1305, chacha_vectors);
}

TEST(PrimitivesAead, Aes256GcmVectors) {
  check_vectors(EKI_AEAD_AES_256_GCM, gcm_vectors);
}

// A fixed message used by the error-row tests.
struct sample {
  bytes key = bytes(EKI_AEAD_KEY_LEN, 0x11);
  bytes nonce = bytes(EKI_AEAD_NONCE_LEN, 0x22);
  bytes aad = unhex("50515253c0c1c2c3");
  bytes pt = unhex("4c616469657320616e642047656e746c656d656e");
};

TEST(PrimitivesAead, UnknownAlgorithmIsInvalidAndZeroesOutputs) {
  const sample s;
  for (const eki_aead_alg alg : {0, 3, -1, 99, INT32_MIN, INT32_MAX}) {
    SCOPED_TRACE(alg);
    bytes ct(s.pt.size(), fill);
    std::array<std::uint8_t, EKI_AEAD_TAG_LEN> tag{};
    tag.fill(fill);
    EXPECT_EQ(ekicore::aead_seal(alg, s.key, s.nonce, s.aad, s.pt, ct, tag),
              EKI_ERR_INVALID_ARGUMENT);
    EXPECT_TRUE(all_equal(ct, 0));
    EXPECT_TRUE(all_equal(tag, 0));

    bytes pt(s.pt.size(), fill);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, s.aad, s.pt, tag, pt),
              EKI_ERR_INVALID_ARGUMENT);
    EXPECT_TRUE(all_equal(pt, 0));
  }
}

TEST(PrimitivesAead, BadKeyAndNonceLengthsAreInvalidAndZeroOutputs) {
  const sample s;
  const bytes long_buf(64, 0x33);
  const std::span<const std::uint8_t> src(long_buf);
  struct row {
    const char* name;
    std::size_t key_len;
    std::size_t nonce_len;
  };
  const auto rows = std::to_array<row>({
      {.name = "key_len 0", .key_len = 0, .nonce_len = 12},
      {.name = "key_len 16", .key_len = 16, .nonce_len = 12},
      {.name = "key_len 33", .key_len = 33, .nonce_len = 12},
      {.name = "nonce_len 0", .key_len = 32, .nonce_len = 0},
      {.name = "nonce_len 11", .key_len = 32, .nonce_len = 11},
      {.name = "nonce_len 13", .key_len = 32, .nonce_len = 13},
  });
  for (const eki_aead_alg alg : algs) {
    for (const auto& r : rows) {
      SCOPED_TRACE(testing::Message() << "alg " << alg << ", " << r.name);
      const auto key = src.first(r.key_len);
      const auto nonce = src.first(r.nonce_len);
      bytes ct(s.pt.size(), fill);
      std::array<std::uint8_t, EKI_AEAD_TAG_LEN> tag{};
      tag.fill(fill);
      EXPECT_EQ(ekicore::aead_seal(alg, key, nonce, s.aad, s.pt, ct, tag),
                EKI_ERR_INVALID_ARGUMENT);
      EXPECT_TRUE(all_equal(ct, 0));
      EXPECT_TRUE(all_equal(tag, 0));

      bytes pt(s.pt.size(), fill);
      EXPECT_EQ(ekicore::aead_open(alg, key, nonce, s.aad, s.pt, tag, pt),
                EKI_ERR_INVALID_ARGUMENT);
      EXPECT_TRUE(all_equal(pt, 0));
    }
  }
}

TEST(PrimitivesAead, MismatchedOutputSizesAreInvalid) {
  const sample s;
  for (const eki_aead_alg alg : algs) {
    SCOPED_TRACE(alg);
    std::array<std::uint8_t, EKI_AEAD_TAG_LEN> tag{};
    bytes short_ct(s.pt.size() - 1, fill);
    EXPECT_EQ(ekicore::aead_seal(alg, s.key, s.nonce, s.aad, s.pt, short_ct, tag),
              EKI_ERR_INVALID_ARGUMENT);
    EXPECT_TRUE(all_equal(short_ct, 0));

    bytes ct(s.pt.size(), fill);
    std::array<std::uint8_t, EKI_AEAD_TAG_LEN - 1> short_tag{};
    short_tag.fill(fill);
    EXPECT_EQ(ekicore::aead_seal(alg, s.key, s.nonce, s.aad, s.pt, ct, short_tag),
              EKI_ERR_INVALID_ARGUMENT);
    EXPECT_TRUE(all_equal(ct, 0));
    EXPECT_TRUE(all_equal(short_tag, fill)); // not a valid tag size, so untouched

    bytes long_pt(s.pt.size() + 1, fill);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, s.aad, s.pt, tag, long_pt),
              EKI_ERR_INVALID_ARGUMENT);
    EXPECT_TRUE(all_equal(long_pt, 0));
    bytes pt(s.pt.size(), fill);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, s.aad, s.pt, std::span(tag).first(15), pt),
              EKI_ERR_INVALID_ARGUMENT);
    EXPECT_TRUE(all_equal(pt, 0));
  }
}

// Seals s with alg and returns (ct, tag).
std::pair<bytes, std::array<std::uint8_t, EKI_AEAD_TAG_LEN>> seal(eki_aead_alg alg,
                                                                  const sample& s) {
  bytes ct(s.pt.size());
  std::array<std::uint8_t, EKI_AEAD_TAG_LEN> tag{};
  EXPECT_EQ(ekicore::aead_seal(alg, s.key, s.nonce, s.aad, s.pt, ct, tag), EKI_OK);
  return {ct, tag};
}

TEST(PrimitivesAead, TamperingFailsAndZeroesPlaintext) {
  const sample s;
  for (const eki_aead_alg alg : algs) {
    SCOPED_TRACE(alg);
    const auto [ct, tag] = seal(alg, s);

    auto bad_tag = tag;
    bad_tag.at(0) = static_cast<std::uint8_t>(bad_tag.at(0) ^ 1U);
    bytes pt(ct.size(), fill);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, s.aad, ct, bad_tag, pt), EKI_ERR_AUTH_FAILED);
    EXPECT_TRUE(all_equal(pt, 0)) << "tag bit flipped";

    bytes other_aad = s.aad;
    other_aad.back() = static_cast<std::uint8_t>(other_aad.back() ^ 0x80U);
    std::ranges::fill(pt, fill);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, other_aad, ct, tag, pt), EKI_ERR_AUTH_FAILED);
    EXPECT_TRUE(all_equal(pt, 0)) << "aad changed";

    std::ranges::fill(pt, fill);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, {}, ct, tag, pt), EKI_ERR_AUTH_FAILED);
    EXPECT_TRUE(all_equal(pt, 0)) << "aad dropped";

    bytes bad_ct = ct;
    bad_ct.at(3) = static_cast<std::uint8_t>(bad_ct.at(3) ^ 4U);
    std::ranges::fill(pt, fill);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, s.aad, bad_ct, tag, pt), EKI_ERR_AUTH_FAILED);
    EXPECT_TRUE(all_equal(pt, 0)) << "ciphertext bit flipped";

    const auto truncated = std::span(ct).first(ct.size() - 1);
    bytes short_pt(truncated.size(), fill);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, s.aad, truncated, tag, short_pt),
              EKI_ERR_AUTH_FAILED);
    EXPECT_TRUE(all_equal(short_pt, 0)) << "ciphertext truncated by one byte";

    bytes other_nonce = s.nonce;
    other_nonce.at(11) = static_cast<std::uint8_t>(other_nonce.at(11) ^ 1U);
    std::ranges::fill(pt, fill);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, other_nonce, s.aad, ct, tag, pt), EKI_ERR_AUTH_FAILED);
    EXPECT_TRUE(all_equal(pt, 0)) << "nonce changed";
  }
}

TEST(PrimitivesAead, EmptyPlaintextRoundTrip) {
  const sample s;
  for (const eki_aead_alg alg : algs) {
    SCOPED_TRACE(alg);
    for (const bool with_aad : {false, true}) {
      const std::span<const std::uint8_t> aad =
          with_aad ? std::span(s.aad) : std::span(s.aad).first(0);
      std::array<std::uint8_t, EKI_AEAD_TAG_LEN> tag{};
      // Empty spans with a null data(), as the FFI layer produces for (NULL, 0).
      ASSERT_EQ(ekicore::aead_seal(alg, s.key, s.nonce, aad, {}, {}, tag), EKI_OK);
      EXPECT_FALSE(all_equal(tag, 0));
      EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, aad, {}, tag, {}), EKI_OK);
      tag.at(15) = static_cast<std::uint8_t>(tag.at(15) ^ 0x80U);
      EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, aad, {}, tag, {}), EKI_ERR_AUTH_FAILED);
    }
  }
}

TEST(PrimitivesAead, RandomRoundTrips) {
  // A fixed seed keeps failures reproducible; these bytes are test data, not secrets.
  std::mt19937 rng(20261006U); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
  std::uniform_int_distribution<int> byte(0, 255);
  const auto random_bytes = [&](std::size_t n) {
    bytes out(n);
    std::ranges::generate(out, [&] { return static_cast<std::uint8_t>(byte(rng)); });
    return out;
  };
  for (const eki_aead_alg alg : algs) {
    for (const std::size_t len :
         std::to_array<std::size_t>({0, 1, 15, 16, 17, 63, 64, 65, 4096, 65537})) {
      for (const std::size_t aad_len : std::to_array<std::size_t>({0, 1, 13, 64})) {
        SCOPED_TRACE(testing::Message() << "alg " << alg << " len " << len << " aad " << aad_len);
        const bytes key = random_bytes(EKI_AEAD_KEY_LEN);
        const bytes nonce = random_bytes(EKI_AEAD_NONCE_LEN);
        const bytes aad = random_bytes(aad_len);
        const bytes pt = random_bytes(len);
        bytes ct(len, fill);
        std::array<std::uint8_t, EKI_AEAD_TAG_LEN> tag{};
        ASSERT_EQ(ekicore::aead_seal(alg, key, nonce, aad, pt, ct, tag), EKI_OK);
        if (len >= 16) {
          EXPECT_NE(ct, pt);
        }
        bytes opened(len, fill);
        ASSERT_EQ(ekicore::aead_open(alg, key, nonce, aad, ct, tag, opened), EKI_OK);
        EXPECT_EQ(opened, pt);
      }
    }
  }
}

TEST(PrimitivesAead, AlgorithmsDiffer) {
  const sample s;
  const auto [gcm_ct, gcm_tag] = seal(EKI_AEAD_AES_256_GCM, s);
  const auto [chacha_ct, chacha_tag] = seal(EKI_AEAD_CHACHA20_POLY1305, s);
  EXPECT_NE(gcm_ct, chacha_ct);
  EXPECT_NE(gcm_tag, chacha_tag);
  bytes pt(s.pt.size(), fill);
  EXPECT_EQ(
      ekicore::aead_open(EKI_AEAD_CHACHA20_POLY1305, s.key, s.nonce, s.aad, gcm_ct, gcm_tag, pt),
      EKI_ERR_AUTH_FAILED);
  EXPECT_TRUE(all_equal(pt, 0));
}

// Reserves size bytes of address space that may not be read or written: any access faults, which
// proves the code under test rejected the length without touching the buffer.
class reserved_region {
public:
  explicit reserved_region(std::size_t size)
      : size_(size),
        addr_(mmap(nullptr, size, PROT_NONE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0)) {}
  reserved_region(const reserved_region&) = delete;
  reserved_region& operator=(const reserved_region&) = delete;
  reserved_region(reserved_region&&) = delete;
  reserved_region& operator=(reserved_region&&) = delete;
  ~reserved_region() {
    if (ok()) {
      munmap(addr_, size_);
    }
  }
  [[nodiscard]] bool ok() const {
    return addr_ != MAP_FAILED;
  }
  [[nodiscard]] std::span<std::uint8_t> span() const {
    return {static_cast<std::uint8_t*>(addr_), size_};
  }

private:
  std::size_t size_;
  void* addr_;
};

TEST(PrimitivesAead, LengthAboveLimitIsInvalidAndOutputUntouched) {
  constexpr std::size_t too_long = EKI_AEAD_MAX_LEN + 1;
  const reserved_region in(too_long);
  const reserved_region out(too_long);
  if (!in.ok() || !out.ok()) {
    GTEST_SKIP() << "cannot reserve 2 x 64 GiB of address space";
  }
  const sample s;
  for (const eki_aead_alg alg : algs) {
    SCOPED_TRACE(alg);
    std::array<std::uint8_t, EKI_AEAD_TAG_LEN> tag{};
    tag.fill(fill);
    EXPECT_EQ(ekicore::aead_seal(alg, s.key, s.nonce, s.aad, in.span(), out.span(), tag),
              EKI_ERR_INVALID_ARGUMENT);
    EXPECT_TRUE(all_equal(tag, 0));
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, s.aad, in.span(), tag, out.span()),
              EKI_ERR_INVALID_ARGUMENT);
  }
}

TEST(PrimitivesAead, ChunksStayWithinIntRange) {
  std::vector<std::pair<std::size_t, std::size_t>> calls;
  const auto record = [&calls](std::size_t offset, std::size_t len) {
    calls.emplace_back(offset, len);
    return true;
  };
  EXPECT_TRUE(ekicore::ossl::for_each_chunk(0, record));
  EXPECT_TRUE(calls.empty());

  constexpr auto int_max = static_cast<std::size_t>(INT_MAX);
  EXPECT_TRUE(ekicore::ossl::for_each_chunk((2 * int_max) + 5, record));
  const std::vector<std::pair<std::size_t, std::size_t>> expected{
      {0, int_max},
      {int_max, int_max},
      {2 * int_max, 5},
  };
  EXPECT_EQ(calls, expected);

  calls.clear();
  int budget = 1;
  EXPECT_FALSE(ekicore::ossl::for_each_chunk(2 * int_max, [&](std::size_t offset, std::size_t len) {
    calls.emplace_back(offset, len);
    return budget-- > 0;
  }));
  EXPECT_EQ(calls.size(), 2U);
}

// An expected failure removes what OpenSSL queued for it and nothing else; a success leaves the
// queue as it found it.
TEST(PrimitivesAead, CallersErrorQueueIsLeftAlone) {
  const sample s;
  for (const eki_aead_alg alg : algs) {
    SCOPED_TRACE(alg);
    unsigned long caller = eki_test::push_caller_error();
    const auto [ct, tag] = seal(alg, s);
    bytes pt(ct.size(), fill);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, s.aad, ct, tag, pt), EKI_OK);
    EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "success";

    caller = eki_test::push_caller_error();
    auto bad_tag = tag;
    bad_tag.at(0) = static_cast<std::uint8_t>(bad_tag.at(0) ^ 1U);
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, s.aad, ct, bad_tag, pt), EKI_ERR_AUTH_FAILED);
    EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "tag mismatch";

    caller = eki_test::push_caller_error();
    EXPECT_EQ(ekicore::aead_open(alg, s.key, s.nonce, {}, ct, tag, pt), EKI_ERR_AUTH_FAILED);
    EXPECT_TRUE(eki_test::queue_holds_only(caller)) << "aad dropped";
  }
}

} // namespace
// NOLINTEND(readability-function-cognitive-complexity)
