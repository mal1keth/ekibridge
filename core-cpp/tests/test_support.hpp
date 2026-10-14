// Helpers shared by the FFI tests (ffi_*_test.cpp).
//
// The FFI tests call the eki_* functions of <ekicore.h> exactly as a C caller would: raw pointers,
// explicit lengths, outputs pre-filled with 0xA5 so that "zero-filled on error" and "fully written
// on success" are both observable. Statuses are compared by name, so a failure prints
// "EKI_ERR_UNSUPPORTED" rather than a bare integer.

#pragma once

#include <gtest/gtest.h>

#include <ekicore.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace eki_test {

// Byte every output buffer is pre-filled with before a call.
inline constexpr std::uint8_t kFill = 0xA5;

// The library's EKI_WITH_* options are private compile definitions of the `ekicore` target, so this
// test binary cannot see them. These mirror the CMake defaults (PKCS#11 on, PQ off); a build with
// other options can override them by defining EKI_TEST_WITH_PKCS11 / EKI_TEST_WITH_PQ to 0 or 1.
#ifdef EKI_TEST_WITH_PKCS11
inline constexpr bool kWithPkcs11 = EKI_TEST_WITH_PKCS11 != 0;
#else
inline constexpr bool kWithPkcs11 = true;
#endif
#ifdef EKI_TEST_WITH_PQ
inline constexpr bool kWithPq = EKI_TEST_WITH_PQ != 0;
#else
inline constexpr bool kWithPq = false;
#endif

// Name of a status ("EKI_OK", ...), for readable EXPECT_EQ output.
inline std::string_view name(eki_status status) {
  return eki_status_name(static_cast<std::int32_t>(status));
}

// Decodes a hex string; ASCII whitespace is ignored. Aborts on malformed input (a test bug).
inline std::vector<std::uint8_t> hex(std::string_view text) {
  const auto nibble = [](char c) -> unsigned {
    if (c >= '0' && c <= '9') {
      return static_cast<unsigned>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
      return static_cast<unsigned>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
      return static_cast<unsigned>(c - 'A' + 10);
    }
    std::abort();
  };
  std::vector<std::uint8_t> out;
  std::optional<unsigned> high;
  for (const char c : text) {
    if (c == ' ' || c == '\n' || c == '\t' || c == '\r') {
      continue;
    }
    const unsigned value = nibble(c);
    if (high) {
      out.push_back(static_cast<std::uint8_t>((*high << 4U) | value));
      high.reset();
    } else {
      high = value;
    }
  }
  if (high) {
    std::abort();
  }
  return out;
}

// Decodes a hex string into a fixed-size array. Aborts if the length differs (a test bug).
template <std::size_t N> std::array<std::uint8_t, N> hex_array(std::string_view text) {
  const std::vector<std::uint8_t> bytes = hex(text);
  if (bytes.size() != N) {
    std::abort();
  }
  std::array<std::uint8_t, N> out{};
  std::ranges::copy(bytes, out.begin());
  return out;
}

// An output buffer of n bytes, every byte 0xA5.
inline std::vector<std::uint8_t> prefill(std::size_t n) {
  // (n, v) constructor, not the {n, v} initializer list.
  return std::vector<std::uint8_t>(n, kFill); // NOLINT(modernize-return-braced-init-list)
}

// A fixed-size output buffer, every byte 0xA5.
template <std::size_t N> std::array<std::uint8_t, N> prefilled() {
  std::array<std::uint8_t, N> out{};
  out.fill(kFill);
  return out;
}

// EXPECT_TRUE(all_zero(buf)): every byte is zero (the "outputs on error" rule).
inline testing::AssertionResult all_zero(std::span<const std::uint8_t> buf) {
  const auto it = std::ranges::find_if(buf, [](std::uint8_t b) { return b != 0; });
  if (it == buf.end()) {
    return testing::AssertionSuccess();
  }
  return testing::AssertionFailure() << "output not zero-filled: byte " << (it - buf.begin())
                                     << " of " << buf.size() << " is " << int{*it};
}

// EXPECT_TRUE(untouched(buf)): every byte still holds the pre-fill value.
inline testing::AssertionResult untouched(std::span<const std::uint8_t> buf) {
  const auto it = std::ranges::find_if(buf, [](std::uint8_t b) { return b != kFill; });
  if (it == buf.end()) {
    return testing::AssertionSuccess();
  }
  return testing::AssertionFailure() << "output was written: byte " << (it - buf.begin()) << " of "
                                     << buf.size() << " is " << int{*it};
}

// Bytes of a string literal (without its NUL), as the message arguments of the ABI.
inline std::span<const std::uint8_t> bytes(std::string_view text) {
  return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

// ---------------------------------------------------------------------------------------------
// Key store helpers
// ---------------------------------------------------------------------------------------------

// A label of exactly n printable bytes ('a'..'z' repeating); c_str() adds the NUL.
inline std::string label_of_len(std::size_t n) {
  std::string out;
  out.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    out.push_back(static_cast<char>('a' + static_cast<char>(i % 26)));
  }
  return out;
}

// An id with every byte set to `byte` (caller-chosen ids for eki_ks_unwrap).
inline eki_key_id fixed_id(std::uint8_t byte) {
  eki_key_id id{};
  std::ranges::fill(id.bytes, byte);
  return id;
}

// An id no store has generated (generated ids are random; this one is fixed).
inline eki_key_id unknown_id() {
  return fixed_id(0x5A);
}

inline eki_key_id prefilled_id() {
  return fixed_id(kFill);
}

inline bool same_id(const eki_key_id& a, const eki_key_id& b) {
  return std::ranges::equal(a.bytes, b.bytes);
}

inline eki_key_info prefilled_info() {
  eki_key_info info{};
  info.alg = static_cast<eki_key_alg>(0xA5A5A5A5U);
  std::ranges::fill(info.label, static_cast<char>(kFill));
  return info;
}

inline std::span<const std::uint8_t> id_bytes(const eki_key_id& id) {
  return {std::begin(id.bytes), std::end(id.bytes)};
}

inline std::span<const std::uint8_t> label_bytes(const eki_key_info& info) {
  return {reinterpret_cast<const std::uint8_t*>(std::begin(info.label)), sizeof(info.label)};
}

// The fields of a key info are zero (padding bytes are unspecified, §4.2).
inline testing::AssertionResult info_zero(const eki_key_info& info) {
  if (info.alg != 0) {
    return testing::AssertionFailure() << "info_out.alg not zeroed: " << info.alg;
  }
  return all_zero(label_bytes(info));
}

// The key info names `alg` and `text`, NUL-padded through byte 64.
inline testing::AssertionResult info_is(const eki_key_info& info, eki_key_alg alg,
                                        std::string_view text) {
  if (info.alg != alg) {
    return testing::AssertionFailure() << "info_out.alg is " << info.alg << ", expected " << alg;
  }
  const std::span<const std::uint8_t> label = label_bytes(info);
  if (!std::equal(text.begin(), text.end(), label.begin(),
                  [](char c, std::uint8_t b) { return static_cast<std::uint8_t>(c) == b; })) {
    return testing::AssertionFailure() << "info_out.label differs from \"" << text << "\"";
  }
  return all_zero(label.subspan(text.size()));
}

inline eki_ks_config software_config() {
  return eki_ks_config{
      .backend = EKI_KS_SOFTWARE,
      .pkcs11_module_path = nullptr,
      .pkcs11_token_label = nullptr,
      .pkcs11_user_pin = nullptr,
  };
}

// Result of an eki_ks_open call with *out pre-set to a non-NULL sentinel.
struct Opened {
  eki_status status;
  bool out_is_null;
  eki_ks* handle; // closed by the caller when status is EKI_OK
};

inline Opened try_open(const eki_ks_config* config) {
  // A non-NULL sentinel; never dereferenced or closed unless the call succeeded.
  static char sentinel = 0;
  auto* handle = reinterpret_cast<eki_ks*>(&sentinel);
  const eki_status status = eki_ks_open(config, &handle);
  return Opened{.status = status, .out_is_null = handle == nullptr, .handle = handle};
}

// eki_ks_open fails with `expected` and leaves *out NULL (a stray handle is closed).
inline testing::AssertionResult open_fails(const eki_ks_config& config, eki_status expected) {
  const Opened opened = try_open(&config);
  if (opened.status == EKI_OK && !opened.out_is_null) {
    eki_ks_close(opened.handle);
  }
  if (opened.status != expected) {
    return testing::AssertionFailure()
           << "eki_ks_open returned " << name(opened.status) << ", expected " << name(expected);
  }
  if (!opened.out_is_null) {
    return testing::AssertionFailure() << "*out is not NULL after a failed eki_ks_open";
  }
  return testing::AssertionSuccess();
}

// An open key store. Keys created through it are destroyed and the handle is closed on
// destruction, including after a failed assertion, so a PKCS#11 token is left as it was found.
class Store {
public:
  Store() = default;
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;
  Store(Store&&) = delete;
  Store& operator=(Store&&) = delete;
  ~Store() {
    if (ks_ != nullptr) {
      for (const eki_key_id& id : created_) {
        static_cast<void>(eki_ks_destroy(ks_, &id));
      }
      eki_ks_close(ks_);
    }
  }

  // ASSERT_TRUE(store.open(config)).
  testing::AssertionResult open(const eki_ks_config& config) {
    const Opened opened = try_open(&config);
    if (opened.status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_open returned " << name(opened.status);
    }
    if (opened.out_is_null) {
      return testing::AssertionFailure() << "eki_ks_open returned EKI_OK and a NULL handle";
    }
    ks_ = opened.handle;
    return testing::AssertionSuccess();
  }

  [[nodiscard]] eki_ks* get() const {
    return ks_;
  }

  // ASSERT_TRUE(store.generate(alg, "label", id)); remembers the key for cleanup.
  testing::AssertionResult generate(eki_key_alg alg, const std::string& label, eki_key_id& id) {
    id = prefilled_id();
    const eki_status status = eki_ks_generate(ks_, alg, label.c_str(), &id);
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_generate returned " << name(status);
    }
    track(id);
    return testing::AssertionSuccess();
  }

  // ASSERT_TRUE(store.unwrap(kek, blob, alg, "label", id)); remembers the key for cleanup.
  testing::AssertionResult unwrap(const eki_key_id& kek, std::span<const std::uint8_t> blob,
                                  eki_key_alg alg, const std::string& label, const eki_key_id& id) {
    const eki_status status =
        eki_ks_unwrap(ks_, &kek, blob.data(), blob.size(), alg, label.c_str(), &id);
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_unwrap returned " << name(status);
    }
    track(id);
    return testing::AssertionSuccess();
  }

  // ASSERT_TRUE(store.info(id, info)).
  testing::AssertionResult info(const eki_key_id& id, eki_key_info& info) const {
    info = prefilled_info();
    const eki_status status = eki_ks_get_info(ks_, &id, &info);
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_get_info returned " << name(status);
    }
    return testing::AssertionSuccess();
  }

  // ASSERT_TRUE(store.hmac(id, msg, out)).
  testing::AssertionResult hmac(const eki_key_id& id, std::span<const std::uint8_t> msg,
                                std::array<std::uint8_t, 32>& out) const {
    out = prefilled<32>();
    const eki_status status = eki_ks_hmac_sha256(ks_, &id, msg.data(), msg.size(), out.data());
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_hmac_sha256 returned " << name(status);
    }
    return testing::AssertionSuccess();
  }

  // ASSERT_TRUE(store.public_key(id, out)).
  testing::AssertionResult public_key(const eki_key_id& id,
                                      std::array<std::uint8_t, 65>& out) const {
    out = prefilled<65>();
    const eki_status status = eki_ks_get_public_key(ks_, &id, out.data());
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_get_public_key returned " << name(status);
    }
    return testing::AssertionSuccess();
  }

  // ASSERT_TRUE(store.sign(id, msg, sig)).
  testing::AssertionResult sign(const eki_key_id& id, std::span<const std::uint8_t> msg,
                                std::array<std::uint8_t, 64>& sig) const {
    sig = prefilled<64>();
    const eki_status status = eki_ks_sign(ks_, &id, msg.data(), msg.size(), sig.data());
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_sign returned " << name(status);
    }
    return testing::AssertionSuccess();
  }

  // ASSERT_TRUE(store.wrap(kek, key, blob)).
  testing::AssertionResult wrap(const eki_key_id& kek, const eki_key_id& key,
                                std::array<std::uint8_t, 40>& blob) const {
    blob = prefilled<40>();
    const eki_status status = eki_ks_wrap(ks_, &kek, &key, blob.data());
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_wrap returned " << name(status);
    }
    return testing::AssertionSuccess();
  }

  // ASSERT_TRUE(store.destroy(id)); forgets the key.
  testing::AssertionResult destroy(const eki_key_id& id) {
    const eki_status status = eki_ks_destroy(ks_, &id);
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_destroy returned " << name(status);
    }
    forget(id);
    return testing::AssertionSuccess();
  }

  void track(const eki_key_id& id) {
    created_.push_back(id);
  }

  void forget(const eki_key_id& id) {
    std::erase_if(created_, [&id](const eki_key_id& k) { return same_id(k, id); });
  }

private:
  eki_ks* ks_ = nullptr;
  std::vector<eki_key_id> created_;
};

// The last error message of a handle (NULL allowed), read through a 512-byte buffer. Checks
// that the returned length matches the NUL-terminated text.
inline std::optional<std::string> last_error(const eki_ks* ks) {
  std::array<char, 512> buf{};
  buf.fill(static_cast<char>(kFill));
  const std::size_t n = eki_ks_last_error_message(ks, buf.data(), buf.size());
  auto* const nul = std::ranges::find(buf, '\0');
  if (nul == buf.end()) {
    ADD_FAILURE() << "last error message is not NUL-terminated";
    return std::nullopt;
  }
  const auto written = static_cast<std::size_t>(nul - buf.begin());
  EXPECT_EQ(std::min(n, buf.size() - 1), written) << "returned length matches the written text";
  return std::string(buf.begin(), nul);
}

// ---------------------------------------------------------------------------------------------
// Key store scenarios shared by the software and PKCS#11 suites (plan §4.2, §4.4). Each takes an
// open Store; backend-specific rows live in the test files. Mirrors core-rs/tests/common/ks.rs.
// ---------------------------------------------------------------------------------------------

// The scenarios are long row tables; their complexity is the macros, not branching logic.
// NOLINTBEGIN(readability-function-cognitive-complexity)
namespace scenarios {

using Mac = std::array<std::uint8_t, 32>;
using PublicKey = std::array<std::uint8_t, 65>;
using Signature = std::array<std::uint8_t, 64>;
using Blob = std::array<std::uint8_t, 40>;

inline eki_status verify(const PublicKey& pk, std::span<const std::uint8_t> msg,
                         const Signature& sig) {
  return eki_ecdsa_p256_verify(pk.data(), msg.data(), msg.size(), sig.data());
}

// Generate one key of each algorithm, read it back, use it, destroy it.
inline void lifecycle(Store& store) {
  eki_key_id aes{};
  eki_key_id mac{};
  eki_key_id mac2{};
  eki_key_id ec{};
  ASSERT_TRUE(store.generate(EKI_KEY_AES_256, "eki-test aes", aes));
  ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac 2", mac2));
  ASSERT_TRUE(store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa", ec));
  EXPECT_FALSE(same_id(aes, mac) || same_id(mac, ec) || same_id(aes, ec)) << "ids are distinct";

  eki_key_info info{};
  ASSERT_TRUE(store.info(aes, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_AES_256, "eki-test aes"));
  ASSERT_TRUE(store.info(mac, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_HMAC_SHA256, "eki-test hmac"));
  ASSERT_TRUE(store.info(ec, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_ECDSA_P256, "eki-test ecdsa"));

  // HMAC is deterministic per key and differs between keys.
  Mac t1{};
  Mac t2{};
  ASSERT_TRUE(store.hmac(mac, bytes("message"), t1));
  ASSERT_TRUE(store.hmac(mac, bytes("message"), t2));
  EXPECT_EQ(t1, t2);
  ASSERT_TRUE(store.hmac(mac, bytes("message!"), t2));
  EXPECT_NE(t1, t2);
  ASSERT_TRUE(store.hmac(mac2, bytes("message"), t2));
  EXPECT_NE(t1, t2);

  // Sign, then verify with the stateless function (never compare signature bytes, plan §2).
  PublicKey pk{};
  PublicKey pk2{};
  ASSERT_TRUE(store.public_key(ec, pk));
  EXPECT_EQ(pk.at(0), 0x04) << "SEC1 uncompressed";
  ASSERT_TRUE(store.public_key(ec, pk2));
  EXPECT_EQ(pk, pk2) << "public key is stable";
  Signature sig{};
  ASSERT_TRUE(store.sign(ec, bytes("message"), sig));
  EXPECT_EQ(name(verify(pk, bytes("message"), sig)), name(EKI_OK));
  EXPECT_EQ(name(verify(pk, bytes("other"), sig)), name(EKI_ERR_AUTH_FAILED));
  ASSERT_TRUE(store.sign(ec, bytes("message"), sig));
  EXPECT_EQ(name(verify(pk, bytes("message"), sig)), name(EKI_OK));

  for (const eki_key_id& id : {aes, mac, mac2, ec}) {
    ASSERT_TRUE(store.destroy(id));
    eki_key_info gone = prefilled_info();
    EXPECT_EQ(name(eki_ks_get_info(store.get(), &id, &gone)), name(EKI_ERR_KEY_NOT_FOUND));
    EXPECT_TRUE(info_zero(gone));
  }
}

// Wrap an HMAC key and an AES key, unwrap them under new ids, and check the copies behave like
// the originals.
inline void wrap_unwrap_round_trip(Store& store) {
  eki_key_id kek{};
  eki_key_id mac{};
  eki_key_id aes{};
  ASSERT_TRUE(store.generate(EKI_KEY_AES_256, "eki-test kek", kek));
  ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  ASSERT_TRUE(store.generate(EKI_KEY_AES_256, "eki-test aes", aes));

  Blob blob{};
  Blob again{};
  ASSERT_TRUE(store.wrap(kek, mac, blob));
  ASSERT_TRUE(store.wrap(kek, mac, again));
  EXPECT_EQ(blob, again) << "RFC 3394 wrapping is deterministic";

  const eki_key_id copy = fixed_id(0x11);
  ASSERT_TRUE(store.unwrap(kek, blob, EKI_KEY_HMAC_SHA256, "eki-test hmac copy", copy));
  eki_key_info info{};
  ASSERT_TRUE(store.info(copy, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_HMAC_SHA256, "eki-test hmac copy"));
  Mac a{};
  Mac b{};
  ASSERT_TRUE(store.hmac(copy, bytes("message"), a));
  ASSERT_TRUE(store.hmac(mac, bytes("message"), b));
  EXPECT_EQ(a, b);
  ASSERT_TRUE(store.hmac(copy, {}, a));
  ASSERT_TRUE(store.hmac(mac, {}, b));
  EXPECT_EQ(a, b);

  // An unwrapped AES key wraps exactly like the original.
  Blob aes_blob{};
  ASSERT_TRUE(store.wrap(kek, aes, aes_blob));
  const eki_key_id aes_copy = fixed_id(0x12);
  ASSERT_TRUE(store.unwrap(kek, aes_blob, EKI_KEY_AES_256, "eki-test aes copy", aes_copy));
  ASSERT_TRUE(store.info(aes_copy, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_AES_256, "eki-test aes copy"));
  ASSERT_TRUE(store.wrap(aes, mac, blob));
  ASSERT_TRUE(store.wrap(aes_copy, mac, again));
  EXPECT_EQ(blob, again);

  // Self-wrap is allowed (§4.4: kek_id == key_id (AES) → OK).
  ASSERT_TRUE(store.wrap(kek, kek, blob));

  // Destroying the copy leaves the original.
  ASSERT_TRUE(store.destroy(copy));
  ASSERT_TRUE(store.info(mac, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_HMAC_SHA256, "eki-test hmac"));
}

// §4.4 ks_generate rows and the label rules of §4.2.
inline void generate_rows(Store& store) {
  eki_ks* ks = store.get();
  for (const eki_key_alg alg : {0, 4, -1, INT32_MIN, INT32_MAX}) {
    eki_key_id id = prefilled_id();
    EXPECT_EQ(name(eki_ks_generate(ks, alg, "eki-test", &id)), name(EKI_ERR_INVALID_ARGUMENT))
        << "alg " << alg;
    EXPECT_TRUE(all_zero(id_bytes(id)));
  }

  const std::string long_label = label_of_len(65);
  const std::array<std::string, 7> bad_labels{
      std::string{},
      long_label,
      std::string{"eki\x01test"},
      std::string{"\x1f"},
      std::string{"eki\x7f"},
      std::string{"eki\x80"},
      std::string{"\xff"},
  };
  // 65 non-NUL bytes in an allocation of exactly 65: rejected after reading at most 65 bytes.
  std::array<char, 65> unterminated{};
  unterminated.fill('x');
  for (const eki_key_alg alg : {EKI_KEY_AES_256, EKI_KEY_HMAC_SHA256, EKI_KEY_ECDSA_P256}) {
    for (const std::string& bad : bad_labels) {
      eki_key_id id = prefilled_id();
      EXPECT_EQ(name(eki_ks_generate(ks, alg, bad.c_str(), &id)), name(EKI_ERR_INVALID_ARGUMENT))
          << "alg " << alg << " label of " << bad.size() << " bytes";
      EXPECT_TRUE(all_zero(id_bytes(id)));
    }
    eki_key_id id = prefilled_id();
    EXPECT_EQ(name(eki_ks_generate(ks, alg, unterminated.data(), &id)),
              name(EKI_ERR_INVALID_ARGUMENT))
        << "alg " << alg << " unterminated label";
    EXPECT_TRUE(all_zero(id_bytes(id)));
  }

  // Boundary labels that are valid: 1 byte, 64 bytes, the printable extremes.
  for (const std::string& text : {
           std::string{" "},
           std::string{"~"},
           std::string{" !\"#$%&'()*+,-./0123456789:;<=>?@AZ[\\]^_`az{|}~"},
           label_of_len(64),
       }) {
    eki_key_id id{};
    ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, text, id));
    eki_key_info info{};
    ASSERT_TRUE(store.info(id, info));
    EXPECT_TRUE(info_is(info, EKI_KEY_HMAC_SHA256, text));
  }

  // Labels need not be unique.
  eki_key_id a{};
  eki_key_id b{};
  ASSERT_TRUE(store.generate(EKI_KEY_AES_256, "eki-test same", a));
  ASSERT_TRUE(store.generate(EKI_KEY_AES_256, "eki-test same", b));
  EXPECT_FALSE(same_id(a, b));
}

// NULL rows of ks_generate, including NULL taking precedence over selector and label checks.
inline void generate_null_rows(Store& store) {
  eki_ks* ks = store.get();
  eki_key_id id = prefilled_id();
  EXPECT_EQ(name(eki_ks_generate(nullptr, EKI_KEY_AES_256, "eki-test", &id)),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(id_bytes(id)));
  id = prefilled_id();
  EXPECT_EQ(name(eki_ks_generate(ks, EKI_KEY_AES_256, nullptr, &id)), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(id_bytes(id)));
  EXPECT_EQ(name(eki_ks_generate(ks, EKI_KEY_AES_256, "eki-test", nullptr)),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_EQ(name(eki_ks_generate(nullptr, 0, "", nullptr)), name(EKI_ERR_NULL_POINTER));
  id = prefilled_id();
  EXPECT_EQ(name(eki_ks_generate(ks, 0, nullptr, &id)), name(EKI_ERR_NULL_POINTER));
  id = prefilled_id();
  EXPECT_EQ(name(eki_ks_generate(ks, 0, "", &id)), name(EKI_ERR_INVALID_ARGUMENT));
}

// §4.4 rows for get_info, destroy, get_public_key, sign and ks_hmac.
inline void lookup_rows(Store& store) {
  eki_ks* ks = store.get();
  const eki_key_id unknown = unknown_id();
  const auto m = bytes("m");
  eki_key_id aes{};
  eki_key_id mac{};
  eki_key_id ec{};
  eki_key_id doomed{};
  ASSERT_TRUE(store.generate(EKI_KEY_AES_256, "eki-test aes", aes));
  ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  ASSERT_TRUE(store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa", ec));
  ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, "eki-test doomed", doomed));

  // get_info / destroy: unknown id; destroy twice.
  eki_key_info info = prefilled_info();
  EXPECT_EQ(name(eki_ks_get_info(ks, &unknown, &info)), name(EKI_ERR_KEY_NOT_FOUND));
  EXPECT_TRUE(info_zero(info));
  EXPECT_EQ(name(eki_ks_destroy(ks, &unknown)), name(EKI_ERR_KEY_NOT_FOUND));
  ASSERT_TRUE(store.destroy(doomed));
  EXPECT_EQ(name(eki_ks_destroy(ks, &doomed)), name(EKI_ERR_KEY_NOT_FOUND)) << "destroy twice";
  Mac out = prefilled<32>();
  EXPECT_EQ(name(eki_ks_hmac_sha256(ks, &doomed, m.data(), m.size(), out.data())),
            name(EKI_ERR_KEY_NOT_FOUND));
  EXPECT_TRUE(all_zero(out));

  // get_public_key / sign: missing → KEY_NOT_FOUND; not ECDSA → WRONG_KEY_TYPE.
  const std::array<std::pair<eki_key_id, eki_status>, 3> ec_rows{
      {
          {unknown, EKI_ERR_KEY_NOT_FOUND},
          {aes, EKI_ERR_WRONG_KEY_TYPE},
          {mac, EKI_ERR_WRONG_KEY_TYPE},
      },
  };
  for (const auto& [id, expected] : ec_rows) {
    PublicKey pk = prefilled<65>();
    EXPECT_EQ(name(eki_ks_get_public_key(ks, &id, pk.data())), name(expected)) << "get_public_key";
    EXPECT_TRUE(all_zero(pk));
    Signature sig = prefilled<64>();
    EXPECT_EQ(name(eki_ks_sign(ks, &id, m.data(), m.size(), sig.data())), name(expected)) << "sign";
    EXPECT_TRUE(all_zero(sig));
  }

  // ks_hmac: missing → KEY_NOT_FOUND; not HMAC → WRONG_KEY_TYPE.
  const std::array<std::pair<eki_key_id, eki_status>, 3> mac_rows{
      {
          {unknown, EKI_ERR_KEY_NOT_FOUND},
          {ec, EKI_ERR_WRONG_KEY_TYPE},
          {aes, EKI_ERR_WRONG_KEY_TYPE},
      },
  };
  for (const auto& [id, expected] : mac_rows) {
    out = prefilled<32>();
    EXPECT_EQ(name(eki_ks_hmac_sha256(ks, &id, m.data(), m.size(), out.data())), name(expected));
    EXPECT_TRUE(all_zero(out));
  }

  // Empty messages are fine for ks_hmac and ks_sign, with NULL or non-NULL pointers.
  Mac tag{};
  ASSERT_TRUE(store.hmac(mac, {}, tag));
  out = prefilled<32>();
  EXPECT_EQ(name(eki_ks_hmac_sha256(ks, &mac, nullptr, 0, out.data())), name(EKI_OK));
  EXPECT_EQ(out, tag);
  PublicKey pk{};
  ASSERT_TRUE(store.public_key(ec, pk));
  Signature sig = prefilled<64>();
  EXPECT_EQ(name(eki_ks_sign(ks, &ec, nullptr, 0, sig.data())), name(EKI_OK));
  EXPECT_EQ(name(verify(pk, {}, sig)), name(EKI_OK));
  ASSERT_TRUE(store.sign(ec, m.subspan(0, 0), sig));
  EXPECT_EQ(name(verify(pk, {}, sig)), name(EKI_OK));
}

// NULL rows of every per-key function; NULL takes precedence over store state.
inline void lookup_null_rows(Store& store) {
  eki_ks* ks = store.get();
  const eki_key_id unknown = unknown_id();
  const auto m = bytes("m");
  eki_key_id mac{};
  eki_key_id ec{};
  ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  ASSERT_TRUE(store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa", ec));

  eki_key_info info = prefilled_info();
  EXPECT_EQ(name(eki_ks_get_info(nullptr, &mac, &info)), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(info_zero(info));
  info = prefilled_info();
  EXPECT_EQ(name(eki_ks_get_info(ks, nullptr, &info)), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(info_zero(info));
  EXPECT_EQ(name(eki_ks_get_info(ks, &unknown, nullptr)), name(EKI_ERR_NULL_POINTER));

  EXPECT_EQ(name(eki_ks_destroy(nullptr, &mac)), name(EKI_ERR_NULL_POINTER));
  EXPECT_EQ(name(eki_ks_destroy(ks, nullptr)), name(EKI_ERR_NULL_POINTER));

  PublicKey pk = prefilled<65>();
  EXPECT_EQ(name(eki_ks_get_public_key(nullptr, &ec, pk.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(pk));
  pk = prefilled<65>();
  EXPECT_EQ(name(eki_ks_get_public_key(ks, nullptr, pk.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(pk));
  EXPECT_EQ(name(eki_ks_get_public_key(ks, &mac, nullptr)), name(EKI_ERR_NULL_POINTER))
      << "before type";

  Signature sig = prefilled<64>();
  EXPECT_EQ(name(eki_ks_sign(nullptr, &ec, m.data(), m.size(), sig.data())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(sig));
  sig = prefilled<64>();
  EXPECT_EQ(name(eki_ks_sign(ks, nullptr, m.data(), m.size(), sig.data())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(sig));
  sig = prefilled<64>();
  EXPECT_EQ(name(eki_ks_sign(ks, &ec, nullptr, 1, sig.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(sig));
  EXPECT_EQ(name(eki_ks_sign(ks, &unknown, m.data(), m.size(), nullptr)),
            name(EKI_ERR_NULL_POINTER));

  Mac out = prefilled<32>();
  EXPECT_EQ(name(eki_ks_hmac_sha256(nullptr, &mac, m.data(), m.size(), out.data())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(out));
  out = prefilled<32>();
  EXPECT_EQ(name(eki_ks_hmac_sha256(ks, nullptr, m.data(), m.size(), out.data())),
            name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(out));
  out = prefilled<32>();
  EXPECT_EQ(name(eki_ks_hmac_sha256(ks, &mac, nullptr, 5, out.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(out));
  EXPECT_EQ(name(eki_ks_hmac_sha256(ks, &ec, m.data(), m.size(), nullptr)),
            name(EKI_ERR_NULL_POINTER))
      << "before type";
}

// §4.4 ks_wrap rows, including the multi-fault rows that pin the check order
// (kek exists → key exists → kek is AES → key is AES or HMAC).
inline void wrap_rows(Store& store) {
  eki_ks* ks = store.get();
  const eki_key_id unknown = unknown_id();
  eki_key_id kek{};
  eki_key_id mac{};
  eki_key_id ec{};
  ASSERT_TRUE(store.generate(EKI_KEY_AES_256, "eki-test kek", kek));
  ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  ASSERT_TRUE(store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa", ec));

  struct Row {
    const char* what;
    eki_key_id kek_id;
    eki_key_id key_id;
    eki_status expected;
  };
  const std::array<Row, 9> rows{
      {
          {
              .what = "kek is HMAC, key missing",
              .kek_id = mac,
              .key_id = unknown,
              .expected = EKI_ERR_KEY_NOT_FOUND,
          },
          {
              .what = "kek is HMAC, key exists",
              .kek_id = mac,
              .key_id = kek,
              .expected = EKI_ERR_WRONG_KEY_TYPE,
          },
          {
              .what = "kek is ECDSA, key exists",
              .kek_id = ec,
              .key_id = mac,
              .expected = EKI_ERR_WRONG_KEY_TYPE,
          },
          {.what = "key is ECDSA", .kek_id = kek, .key_id = ec, .expected = EKI_ERR_WRONG_KEY_TYPE},
          {
              .what = "kek missing",
              .kek_id = unknown,
              .key_id = mac,
              .expected = EKI_ERR_KEY_NOT_FOUND,
          },
          {
              .what = "kek missing, key is ECDSA",
              .kek_id = unknown,
              .key_id = ec,
              .expected = EKI_ERR_KEY_NOT_FOUND,
          },
          {
              .what = "kek missing, key missing",
              .kek_id = unknown,
              .key_id = unknown,
              .expected = EKI_ERR_KEY_NOT_FOUND,
          },
          {
              .what = "key missing",
              .kek_id = kek,
              .key_id = unknown,
              .expected = EKI_ERR_KEY_NOT_FOUND,
          },
          {
              .what = "kek is HMAC, key is ECDSA",
              .kek_id = mac,
              .key_id = ec,
              .expected = EKI_ERR_WRONG_KEY_TYPE,
          },
      },
  };
  for (const Row& row : rows) {
    Blob out = prefilled<40>();
    EXPECT_EQ(name(eki_ks_wrap(ks, &row.kek_id, &row.key_id, out.data())), name(row.expected))
        << row.what;
    EXPECT_TRUE(all_zero(out)) << row.what;
  }

  Blob out = prefilled<40>();
  EXPECT_EQ(name(eki_ks_wrap(ks, &kek, &kek, out.data())), name(EKI_OK)) << "self-wrap";

  // NULL rows, and NULL before store state.
  out = prefilled<40>();
  EXPECT_EQ(name(eki_ks_wrap(nullptr, &kek, &mac, out.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(out));
  out = prefilled<40>();
  EXPECT_EQ(name(eki_ks_wrap(ks, nullptr, &mac, out.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(out));
  out = prefilled<40>();
  EXPECT_EQ(name(eki_ks_wrap(ks, &kek, nullptr, out.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(out));
  EXPECT_EQ(name(eki_ks_wrap(ks, &unknown, &unknown, nullptr)), name(EKI_ERR_NULL_POINTER));
}

// §4.4 ks_unwrap rows, including the multi-fault rows that pin the check order
// (alg → blob_len → not ECDSA → label → kek exists → kek is AES → id free → integrity).
inline void unwrap_rows(Store& store) {
  eki_ks* ks = store.get();
  const eki_key_id unknown = unknown_id();
  eki_key_id kek{};
  eki_key_id mac{};
  eki_key_id ec{};
  ASSERT_TRUE(store.generate(EKI_KEY_AES_256, "eki-test kek", kek));
  ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  ASSERT_TRUE(store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa", ec));
  Blob blob{};
  ASSERT_TRUE(store.wrap(kek, mac, blob));
  Blob flipped = blob;
  flipped.at(20) = static_cast<std::uint8_t>(flipped.at(20) ^ 0x01U);
  const eki_key_id fresh = fixed_id(0x21);
  const std::string good = "eki-test unwrapped";
  const std::string long_label = label_of_len(65);
  std::array<char, 65> unterminated{};
  unterminated.fill('x');
  const std::array<std::uint8_t, 41> blob41{};

  struct InvalidRow {
    const char* what;
    const std::uint8_t* blob;
    std::size_t blob_len;
    eki_key_alg alg;
    const char* label;
    eki_key_id id;
  };
  const std::array<InvalidRow, 12> invalid{
      {
          {
              .what = "blob_len 39",
              .blob = blob.data(),
              .blob_len = 39,
              .alg = EKI_KEY_HMAC_SHA256,
              .label = good.c_str(),
              .id = fresh,
          },
          {
              .what = "blob_len 41",
              .blob = blob41.data(),
              .blob_len = 41,
              .alg = EKI_KEY_HMAC_SHA256,
              .label = good.c_str(),
              .id = fresh,
          },
          {
              .what = "blob NULL, blob_len 0",
              .blob = nullptr,
              .blob_len = 0,
              .alg = EKI_KEY_HMAC_SHA256,
              .label = good.c_str(),
              .id = fresh,
          },
          {
              .what = "alg ECDSA_P256",
              .blob = blob.data(),
              .blob_len = 40,
              .alg = EKI_KEY_ECDSA_P256,
              .label = good.c_str(),
              .id = fresh,
          },
          {
              .what = "alg 0",
              .blob = blob.data(),
              .blob_len = 40,
              .alg = 0,
              .label = good.c_str(),
              .id = fresh,
          },
          {
              .what = "alg 4",
              .blob = blob.data(),
              .blob_len = 40,
              .alg = 4,
              .label = good.c_str(),
              .id = fresh,
          },
          {
              .what = "label empty",
              .blob = blob.data(),
              .blob_len = 40,
              .alg = EKI_KEY_HMAC_SHA256,
              .label = "",
              .id = fresh,
          },
          {
              .what = "label 65 bytes",
              .blob = blob.data(),
              .blob_len = 40,
              .alg = EKI_KEY_HMAC_SHA256,
              .label = long_label.c_str(),
              .id = fresh,
          },
          {
              .what = "label 0x01",
              .blob = blob.data(),
              .blob_len = 40,
              .alg = EKI_KEY_HMAC_SHA256,
              .label = "eki\x01",
              .id = fresh,
          },
          {
              .what = "label unterminated",
              .blob = blob.data(),
              .blob_len = 40,
              .alg = EKI_KEY_HMAC_SHA256,
              .label = unterminated.data(),
              .id = fresh,
          },
          // Format checks come before store state: the id is taken, still INVALID_ARGUMENT.
          {
              .what = "blob_len 39, id taken",
              .blob = blob.data(),
              .blob_len = 39,
              .alg = EKI_KEY_HMAC_SHA256,
              .label = good.c_str(),
              .id = ec,
          },
          {
              .what = "alg ECDSA_P256, id taken",
              .blob = blob.data(),
              .blob_len = 40,
              .alg = EKI_KEY_ECDSA_P256,
              .label = good.c_str(),
              .id = kek,
          },
      },
  };
  for (const InvalidRow& row : invalid) {
    EXPECT_EQ(name(eki_ks_unwrap(ks, &kek, row.blob, row.blob_len, row.alg, row.label, &row.id)),
              name(EKI_ERR_INVALID_ARGUMENT))
        << row.what;
    // Format checks also precede the kek lookup.
    EXPECT_EQ(
        name(eki_ks_unwrap(ks, &unknown, row.blob, row.blob_len, row.alg, row.label, &row.id)),
        name(EKI_ERR_INVALID_ARGUMENT))
        << row.what << ", kek missing";
  }

  struct StateRow {
    const char* what;
    eki_key_id kek_id;
    const Blob* blob;
    eki_key_id id;
    eki_status expected;
  };
  const std::array<StateRow, 10> state{
      {
          {
              .what = "kek missing",
              .kek_id = unknown,
              .blob = &blob,
              .id = fresh,
              .expected = EKI_ERR_KEY_NOT_FOUND,
          },
          {
              .what = "kek missing, id taken",
              .kek_id = unknown,
              .blob = &blob,
              .id = ec,
              .expected = EKI_ERR_KEY_NOT_FOUND,
          },
          {
              .what = "kek is HMAC",
              .kek_id = mac,
              .blob = &blob,
              .id = fresh,
              .expected = EKI_ERR_WRONG_KEY_TYPE,
          },
          {
              .what = "kek is ECDSA",
              .kek_id = ec,
              .blob = &blob,
              .id = fresh,
              .expected = EKI_ERR_WRONG_KEY_TYPE,
          },
          {
              .what = "kek is HMAC, id taken",
              .kek_id = mac,
              .blob = &blob,
              .id = ec,
              .expected = EKI_ERR_WRONG_KEY_TYPE,
          },
          {
              .what = "kek is HMAC, blob flipped",
              .kek_id = mac,
              .blob = &flipped,
              .id = fresh,
              .expected = EKI_ERR_WRONG_KEY_TYPE,
          },
          {
              .what = "id used by an EC key pair",
              .kek_id = kek,
              .blob = &blob,
              .id = ec,
              .expected = EKI_ERR_KEY_EXISTS,
          },
          {
              .what = "id used by the kek",
              .kek_id = kek,
              .blob = &blob,
              .id = kek,
              .expected = EKI_ERR_KEY_EXISTS,
          },
          {
              .what = "id taken, blob flipped",
              .kek_id = kek,
              .blob = &flipped,
              .id = mac,
              .expected = EKI_ERR_KEY_EXISTS,
          },
          {
              .what = "blob byte flipped",
              .kek_id = kek,
              .blob = &flipped,
              .id = fresh,
              .expected = EKI_ERR_AUTH_FAILED,
          },
      },
  };
  for (const StateRow& row : state) {
    EXPECT_EQ(name(eki_ks_unwrap(ks, &row.kek_id, row.blob->data(), row.blob->size(),
                                 EKI_KEY_HMAC_SHA256, good.c_str(), &row.id)),
              name(row.expected))
        << row.what;
  }
  // A failed unwrap creates nothing, and the keys whose ids were offered are unchanged.
  eki_key_info info = prefilled_info();
  EXPECT_EQ(name(eki_ks_get_info(ks, &fresh, &info)), name(EKI_ERR_KEY_NOT_FOUND));
  ASSERT_TRUE(store.info(ec, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_ECDSA_P256, "eki-test ecdsa"));
  ASSERT_TRUE(store.info(kek, info));
  EXPECT_TRUE(info_is(info, EKI_KEY_AES_256, "eki-test kek"));

  // Every blob byte is covered by the integrity check.
  for (std::size_t index = 0; index < blob.size(); ++index) {
    Blob bad = blob;
    bad.at(index) = static_cast<std::uint8_t>(bad.at(index) ^ 0x80U);
    EXPECT_EQ(name(eki_ks_unwrap(ks, &kek, bad.data(), bad.size(), EKI_KEY_HMAC_SHA256,
                                 good.c_str(), &fresh)),
              name(EKI_ERR_AUTH_FAILED))
        << "byte " << index;
  }

  // NULL rows, and NULL before everything else.
  const eki_key_alg hmac = EKI_KEY_HMAC_SHA256;
  EXPECT_EQ(name(eki_ks_unwrap(nullptr, &kek, blob.data(), 40, hmac, good.c_str(), &fresh)),
            name(EKI_ERR_NULL_POINTER))
      << "ks";
  EXPECT_EQ(name(eki_ks_unwrap(ks, nullptr, blob.data(), 40, hmac, good.c_str(), &fresh)),
            name(EKI_ERR_NULL_POINTER))
      << "kek_id";
  EXPECT_EQ(name(eki_ks_unwrap(ks, &kek, nullptr, 40, hmac, good.c_str(), &fresh)),
            name(EKI_ERR_NULL_POINTER))
      << "blob";
  EXPECT_EQ(name(eki_ks_unwrap(ks, &kek, blob.data(), 40, hmac, nullptr, &fresh)),
            name(EKI_ERR_NULL_POINTER))
      << "label";
  EXPECT_EQ(name(eki_ks_unwrap(ks, &kek, blob.data(), 40, hmac, good.c_str(), nullptr)),
            name(EKI_ERR_NULL_POINTER))
      << "id";
  EXPECT_EQ(name(eki_ks_unwrap(ks, &kek, nullptr, 39, hmac, good.c_str(), &fresh)),
            name(EKI_ERR_NULL_POINTER))
      << "blob NULL with blob_len 39";
  EXPECT_EQ(name(eki_ks_unwrap(ks, &kek, blob.data(), 40, 0, nullptr, &fresh)),
            name(EKI_ERR_NULL_POINTER))
      << "label NULL, alg 0";

  // The original blob still unwraps after all of the above.
  ASSERT_TRUE(store.unwrap(kek, blob, EKI_KEY_HMAC_SHA256, good, fresh));
  Mac a{};
  Mac b{};
  ASSERT_TRUE(store.hmac(fresh, bytes("m"), a));
  ASSERT_TRUE(store.hmac(mac, bytes("m"), b));
  EXPECT_EQ(a, b);
}

// eki_ks_last_error_message conventions (§4.2 "Last error").
inline void last_error_rows(Store& store) {
  eki_ks* ks = store.get();
  const auto as_bytes = [](const auto& buf) {
    return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(buf.data()),
                                         buf.size());
  };

  // NULL handle: "" if there is room, return 0.
  std::array<char, 8> buf{};
  buf.fill(static_cast<char>(kFill));
  EXPECT_EQ(eki_ks_last_error_message(nullptr, buf.data(), buf.size()), 0U);
  EXPECT_EQ(buf.at(0), '\0') << "NUL written";
  EXPECT_TRUE(untouched(as_bytes(buf).subspan(1)));
  buf.fill(static_cast<char>(kFill));
  EXPECT_EQ(eki_ks_last_error_message(nullptr, buf.data(), 0), 0U);
  EXPECT_TRUE(untouched(as_bytes(buf)));
  EXPECT_EQ(eki_ks_last_error_message(nullptr, nullptr, 0), 0U);
  EXPECT_EQ(eki_ks_last_error_message(nullptr, nullptr, 8), 0U) << "buf NULL is buf_len 0";

  // A successful call leaves "".
  eki_key_id mac{};
  ASSERT_TRUE(store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac", mac));
  EXPECT_EQ(last_error(ks), std::optional<std::string>{""});

  // A failure may leave text; whatever it is, the snprintf convention holds.
  const eki_key_id unknown = unknown_id();
  EXPECT_EQ(name(eki_ks_destroy(ks, &unknown)), name(EKI_ERR_KEY_NOT_FOUND));
  const std::optional<std::string> message = last_error(ks);
  ASSERT_TRUE(message.has_value());
  const std::string full = message.value_or(std::string{});
  const std::size_t n = full.size();
  EXPECT_EQ(eki_ks_last_error_message(ks, nullptr, 0), n) << "buf NULL returns the full length";
  EXPECT_EQ(eki_ks_last_error_message(ks, nullptr, 64), n) << "buf NULL is buf_len 0";
  std::array<char, 4> small{};
  small.fill(static_cast<char>(kFill));
  EXPECT_EQ(eki_ks_last_error_message(ks, small.data(), 0), n);
  EXPECT_TRUE(untouched(as_bytes(small)));
  small.fill(static_cast<char>(kFill));
  EXPECT_EQ(eki_ks_last_error_message(ks, small.data(), 1), n);
  EXPECT_EQ(small.at(0), '\0') << "buf_len 1 writes only the NUL";
  small.fill(static_cast<char>(kFill));
  EXPECT_EQ(eki_ks_last_error_message(ks, small.data(), small.size()), n);
  const std::size_t written = std::min<std::size_t>(n, 3);
  EXPECT_EQ(std::string(small.data(), written), full.substr(0, written)) << "truncated prefix";
  EXPECT_EQ(small.at(written), '\0') << "NUL after the truncated prefix";

  // The next call resets the message on entry.
  eki_key_info info{};
  ASSERT_TRUE(store.info(mac, info));
  EXPECT_EQ(last_error(ks), std::optional<std::string>{""}) << "reset by a successful call";
  EXPECT_EQ(eki_ks_last_error_message(ks, nullptr, 0), 0U);
}

} // namespace scenarios
// NOLINTEND(readability-function-cognitive-complexity)

} // namespace eki_test
