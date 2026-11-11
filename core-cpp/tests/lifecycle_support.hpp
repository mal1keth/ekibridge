// Helpers and scenarios shared by the ABI version 2 tests (ffi_lifecycle_test.cpp,
// ffi_audit_test.cpp, ffi_lifecycle_pkcs11_test.cpp): opening handles with eki_ks_open_v2, keys in
// each lifecycle state, approvers in a separate software store, temporary log files, and the
// rows of docs/ffi-contract.md ("Key states", "Opening a store with ABI 2", "Dual control",
// "Per-function contract") that hold for every backend. Each scenario takes the version 1
// configuration of the backend under test.

#pragma once

#include "test_support.hpp"

#include <gtest/gtest.h>

#include <ekicore.h>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace eki_test::lifecycle {

using Request = std::array<std::uint8_t, EKI_DESTROY_REQUEST_LEN>;
using PublicKey = std::array<std::uint8_t, EKI_P256_PUBLIC_KEY_LEN>;
using Signature = std::array<std::uint8_t, EKI_P256_SIGNATURE_LEN>;
using Tag = std::array<std::uint8_t, EKI_HMAC_SHA256_LEN>;
using Blob = std::array<std::uint8_t, EKI_WRAPPED_KEY_LEN>;
using Head = std::array<std::uint8_t, EKI_AUDIT_HASH_LEN>;

inline constexpr std::uint32_t kFillU32 = 0xA5A5A5A5U;
inline constexpr std::uint64_t kFillU64 = 0xA5A5A5A5A5A5A5A5U;

// The state names, for readable failure output.
inline std::string_view state_name(eki_key_state state) {
  switch (state) {
  case EKI_KEY_STATE_ACTIVE:
    return "ACTIVE";
  case EKI_KEY_STATE_RETIRED:
    return "RETIRED";
  case EKI_KEY_STATE_REVOKED:
    return "REVOKED";
  default:
    return "(not a state)";
  }
}

inline constexpr std::array<eki_key_state, 3> kStates{
    EKI_KEY_STATE_ACTIVE,
    EKI_KEY_STATE_RETIRED,
    EKI_KEY_STATE_REVOKED,
};

// The version 2 configuration of a backend, with an optional log and approvers.
inline eki_ks_config_v2 widen(const eki_ks_config& base, const char* log = nullptr,
                              const std::uint8_t* approver_keys = nullptr,
                              std::size_t approver_count = 0) {
  return eki_ks_config_v2{
      .backend = base.backend,
      .pkcs11_module_path = base.pkcs11_module_path,
      .pkcs11_token_label = base.pkcs11_token_label,
      .pkcs11_user_pin = base.pkcs11_user_pin,
      .audit_log_path = log,
      .approver_public_keys = approver_keys,
      .approver_count = approver_count,
  };
}

// Result of an eki_ks_open_v2 call with *out pre-set to a non-NULL sentinel.
inline Opened try_open_v2(const eki_ks_config_v2* config) {
  static char sentinel = 0;
  auto* handle = reinterpret_cast<eki_ks*>(&sentinel);
  const eki_status status = eki_ks_open_v2(config, &handle);
  return Opened{.status = status, .out_is_null = handle == nullptr, .handle = handle};
}

// eki_ks_open_v2 fails with `expected` and leaves *out NULL (a stray handle is closed).
inline testing::AssertionResult open_v2_fails(const eki_ks_config_v2& config, eki_status expected) {
  const Opened opened = try_open_v2(&config);
  if (opened.status == EKI_OK && !opened.out_is_null) {
    eki_ks_close(opened.handle);
  }
  if (opened.status != expected) {
    return testing::AssertionFailure()
           << "eki_ks_open_v2 returned " << name(opened.status) << ", expected " << name(expected);
  }
  if (!opened.out_is_null) {
    return testing::AssertionFailure() << "*out is not NULL after a failed eki_ks_open_v2";
  }
  return testing::AssertionSuccess();
}

// eki_ks_open_v2 succeeds; the handle is closed again.
inline testing::AssertionResult open_v2_succeeds(const eki_ks_config_v2& config) {
  const Opened opened = try_open_v2(&config);
  if (opened.status != EKI_OK) {
    return testing::AssertionFailure() << "eki_ks_open_v2 returned " << name(opened.status);
  }
  if (opened.out_is_null) {
    return testing::AssertionFailure() << "eki_ks_open_v2 returned EKI_OK and a NULL handle";
  }
  eki_ks_close(opened.handle);
  return testing::AssertionSuccess();
}

// The 68-byte message an approver signs ("Dual control" in docs/ffi-contract.md).
inline std::vector<std::uint8_t> approval_message(const Request& request, const eki_key_id& id) {
  constexpr std::string_view domain = "ekibridge-destroy-v1";
  std::vector<std::uint8_t> message(domain.begin(), domain.end());
  message.insert(message.end(), request.begin(), request.end());
  message.insert(message.end(), std::begin(id.bytes), std::end(id.bytes));
  return message;
}

// Approver keys: ECDSA P-256 keys in a separate software store, as an approver would hold them
// outside the store under dual control.
class Approvers {
public:
  explicit Approvers(std::size_t count) {
    const eki_ks_config config = software_config();
    if (eki_ks_open(&config, &ks_) != EKI_OK) {
      ADD_FAILURE() << "opening the approvers' store failed";
      return;
    }
    for (std::size_t i = 0; i < count; ++i) {
      eki_key_id id = prefilled_id();
      PublicKey key = prefilled<EKI_P256_PUBLIC_KEY_LEN>();
      if (eki_ks_generate(ks_, EKI_KEY_ECDSA_P256, "approver", &id) != EKI_OK ||
          eki_ks_get_public_key(ks_, &id, key.data()) != EKI_OK) {
        ADD_FAILURE() << "making approver key " << i << " failed";
        return;
      }
      ids_.push_back(id);
      keys_.insert(keys_.end(), key.begin(), key.end());
    }
  }
  Approvers(const Approvers&) = delete;
  Approvers& operator=(const Approvers&) = delete;
  Approvers(Approvers&&) = delete;
  Approvers& operator=(Approvers&&) = delete;
  ~Approvers() {
    eki_ks_close(ks_);
  }

  // Every public key, back to back, as eki_ks_config_v2 takes them.
  [[nodiscard]] const std::uint8_t* keys() const {
    return keys_.data();
  }
  [[nodiscard]] std::size_t count() const {
    return ids_.size();
  }
  [[nodiscard]] PublicKey key(std::size_t i) const {
    PublicKey key{};
    std::ranges::copy(std::span{keys_}.subspan(i * key.size(), key.size()), key.begin());
    return key;
  }

  // Approver i's signature over the approval of request for id.
  [[nodiscard]] Signature sign(std::size_t i, const Request& request, const eki_key_id& id) const {
    const std::vector<std::uint8_t> message = approval_message(request, id);
    Signature sig = prefilled<EKI_P256_SIGNATURE_LEN>();
    const eki_status status =
        eki_ks_sign(ks_, &ids_.at(i), message.data(), message.size(), sig.data());
    EXPECT_EQ(name(status), name(EKI_OK)) << "approver " << i << " signs";
    return sig;
  }

private:
  eki_ks* ks_ = nullptr;
  std::vector<eki_key_id> ids_;
  std::vector<std::uint8_t> keys_;
};

// A handle opened with eki_ks_open_v2. Every key made through it is destroyed after the handle
// is closed, through a plain handle on the same backend, because a handle with approvers cannot
// destroy; on a token that leaves the token as it was found.
class Handle {
public:
  explicit Handle(const eki_ks_config& base) : base_(base) {}
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&&) = delete;
  Handle& operator=(Handle&&) = delete;
  ~Handle() {
    close();
    if (created_.empty()) {
      return;
    }
    eki_ks* cleaner = nullptr;
    if (eki_ks_open(&base_, &cleaner) != EKI_OK) {
      return;
    }
    for (const eki_key_id& id : created_) {
      static_cast<void>(eki_ks_destroy(cleaner, &id));
    }
    eki_ks_close(cleaner);
  }

  // ASSERT_TRUE(handle.open(widen(base, ...))).
  testing::AssertionResult open(const eki_ks_config_v2& config) {
    const Opened opened = try_open_v2(&config);
    if (opened.status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_open_v2 returned " << name(opened.status);
    }
    if (opened.out_is_null) {
      return testing::AssertionFailure() << "eki_ks_open_v2 returned EKI_OK and a NULL handle";
    }
    ks_ = opened.handle;
    return testing::AssertionSuccess();
  }

  // Closes the handle now (writing its close record); keys are destroyed later.
  void close() {
    if (ks_ != nullptr) {
      eki_ks_close(ks_);
      ks_ = nullptr;
    }
  }

  [[nodiscard]] eki_ks* get() const {
    return ks_;
  }

  // ASSERT_TRUE(handle.generate(alg, "label", id)).
  testing::AssertionResult generate(eki_key_alg alg, const std::string& label, eki_key_id& id) {
    id = prefilled_id();
    const eki_status status = eki_ks_generate(ks_, alg, label.c_str(), &id);
    if (status != EKI_OK) {
      return testing::AssertionFailure() << "eki_ks_generate returned " << name(status);
    }
    track(id);
    return testing::AssertionSuccess();
  }

  // eki_ks_rotate; the new key is remembered when the call succeeds.
  eki_status rotate(const eki_key_id& old_id, eki_key_id& new_id) {
    new_id = prefilled_id();
    const eki_status status = eki_ks_rotate(ks_, &old_id, &new_id);
    if (status == EKI_OK) {
      track(new_id);
    }
    return status;
  }

  // The state get_info_v2 reports, or 0 when it fails.
  [[nodiscard]] eki_key_state state(const eki_key_id& id) const {
    eki_key_info_v2 info{};
    if (eki_ks_get_info_v2(ks_, &id, &info) != EKI_OK) {
      return 0;
    }
    return info.state;
  }

  // ASSERT_TRUE(handle.put_in(id, state)): rotates the key to make it RETIRED, revokes it to make
  // it REVOKED; an ACTIVE key stays as it is.
  testing::AssertionResult put_in(const eki_key_id& id, eki_key_state wanted) {
    eki_status status = EKI_OK;
    if (wanted == EKI_KEY_STATE_RETIRED) {
      eki_key_id replacement{};
      status = rotate(id, replacement);
    } else if (wanted == EKI_KEY_STATE_REVOKED) {
      status = eki_ks_revoke(ks_, &id);
    }
    if (status != EKI_OK) {
      return testing::AssertionFailure()
             << "moving the key to " << state_name(wanted) << " returned " << name(status);
    }
    if (state(id) != wanted) {
      return testing::AssertionFailure()
             << "the key is " << state_name(state(id)) << ", not " << state_name(wanted);
    }
    return testing::AssertionSuccess();
  }

  void track(const eki_key_id& id) {
    created_.push_back(id);
  }

private:
  eki_ks_config base_;
  eki_ks* ks_ = nullptr;
  std::vector<eki_key_id> created_;
};

// A directory removed with its content at the end of the test.
class TempDir {
public:
  TempDir() {
    std::string pattern = (std::filesystem::temp_directory_path() / "eki-abi2-XXXXXX").string();
    if (mkdtemp(pattern.data()) == nullptr) {
      ADD_FAILURE() << "mkdtemp failed";
    }
    path_ = pattern;
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  TempDir(TempDir&&) = delete;
  TempDir& operator=(TempDir&&) = delete;
  ~TempDir() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  [[nodiscard]] std::string file(std::string_view file_name) const {
    return (path_ / file_name).string();
  }
  [[nodiscard]] const std::filesystem::path& path() const {
    return path_;
  }

private:
  std::filesystem::path path_;
};

inline std::string read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

inline void write_file(const std::string& path, std::string_view content) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

inline bool file_exists(const std::string& path) {
  struct stat info{};
  return ::stat(path.c_str(), &info) == 0;
}

// eki_ks_audit_head of a handle with a log; the seq of the last record, or nullopt on failure.
inline std::optional<std::uint64_t> head_seq(eki_ks* ks) {
  Head hash{};
  std::uint64_t seq = 0;
  if (eki_ks_audit_head(ks, hash.data(), &seq) != EKI_OK) {
    return std::nullopt;
  }
  return seq;
}

// A point that is not on P-256: x = 1, y = 1.
inline PublicKey off_curve_key() {
  PublicKey key{};
  key.front() = 0x04;
  key.at(32) = 1;
  key.back() = 1;
  return key;
}

// Whether every byte is zero, as a plain bool for EXPECT_EQ.
inline bool zero(std::span<const std::uint8_t> buf) {
  return std::ranges::all_of(buf, [](std::uint8_t b) { return b == 0; });
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage): keeps the failing call's line in the output
#define EKI_EXPECT_STATUS(call, expected) EXPECT_EQ(name(call), name(expected))

// ---------------------------------------------------------------------------------------------
// Scenarios shared by the software and PKCS#11 suites.
// ---------------------------------------------------------------------------------------------

// The rows are long tables; their complexity is the macros, not branching logic.
// NOLINTBEGIN(readability-function-cognitive-complexity)

// The state table ("Key states" in docs/ffi-contract.md): every operation on a key in each state.
inline void state_table(const eki_ks_config& base) {
  for (const eki_key_state state : kStates) {
    SCOPED_TRACE(state_name(state));
    const bool active = state == EKI_KEY_STATE_ACTIVE;
    const bool not_revoked = state != EKI_KEY_STATE_REVOKED;
    Handle h(base);
    ASSERT_TRUE(h.open(widen(base)));
    eki_ks* ks = h.get();
    eki_key_id kek{};
    eki_key_id aes{};
    eki_key_id mac{};
    eki_key_id ec{};
    eki_key_id fresh_kek{};
    eki_key_id fresh_aes{};
    ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "state kek", kek));
    ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "state aes", aes));
    ASSERT_TRUE(h.generate(EKI_KEY_HMAC_SHA256, "state hmac", mac));
    ASSERT_TRUE(h.generate(EKI_KEY_ECDSA_P256, "state ecdsa", ec));
    ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "fresh kek", fresh_kek));
    ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "fresh aes", fresh_aes));
    const std::span<const std::uint8_t> msg = bytes("state table");
    Tag tag{};
    Blob blob{};
    ASSERT_EQ(name(eki_ks_hmac_sha256(ks, &mac, msg.data(), msg.size(), tag.data())), name(EKI_OK));
    ASSERT_EQ(name(eki_ks_wrap(ks, &kek, &mac, blob.data())), name(EKI_OK));
    for (const eki_key_id& id : {kek, aes, mac, ec}) {
      ASSERT_TRUE(h.put_in(id, state));
    }

    // get_info and get_info_v2: every state.
    eki_key_info info = prefilled_info();
    EKI_EXPECT_STATUS(eki_ks_get_info(ks, &ec, &info), EKI_OK);
    EXPECT_TRUE(info_is(info, EKI_KEY_ECDSA_P256, "state ecdsa"));
    EXPECT_EQ(state_name(h.state(mac)), state_name(state));

    // get_public_key: ACTIVE, RETIRED.
    PublicKey pk = prefilled<EKI_P256_PUBLIC_KEY_LEN>();
    EKI_EXPECT_STATUS(eki_ks_get_public_key(ks, &ec, pk.data()),
                      not_revoked ? EKI_OK : EKI_ERR_KEY_STATE);
    EXPECT_EQ(zero(pk), !not_revoked);

    // sign: ACTIVE only.
    Signature sig = prefilled<EKI_P256_SIGNATURE_LEN>();
    EKI_EXPECT_STATUS(eki_ks_sign(ks, &ec, msg.data(), msg.size(), sig.data()),
                      active ? EKI_OK : EKI_ERR_KEY_STATE);
    EXPECT_EQ(zero(sig), !active);

    // hmac_sha256: ACTIVE only.
    Tag out = prefilled<EKI_HMAC_SHA256_LEN>();
    EKI_EXPECT_STATUS(eki_ks_hmac_sha256(ks, &mac, msg.data(), msg.size(), out.data()),
                      active ? EKI_OK : EKI_ERR_KEY_STATE);
    EXPECT_EQ(zero(out), !active);

    // hmac_sha256_verify: ACTIVE, RETIRED.
    EKI_EXPECT_STATUS(
        eki_ks_hmac_sha256_verify(ks, &mac, msg.data(), msg.size(), tag.data(), tag.size()),
        not_revoked ? EKI_OK : EKI_ERR_KEY_STATE);

    // wrap as the kek: ACTIVE only.
    Blob wrapped = prefilled<EKI_WRAPPED_KEY_LEN>();
    EKI_EXPECT_STATUS(eki_ks_wrap(ks, &kek, &fresh_aes, wrapped.data()),
                      active ? EKI_OK : EKI_ERR_KEY_STATE);
    EXPECT_EQ(zero(wrapped), !active);

    // wrap as the key being wrapped: ACTIVE, RETIRED; AES and HMAC keys alike.
    for (const eki_key_id& key : {aes, mac}) {
      wrapped = prefilled<EKI_WRAPPED_KEY_LEN>();
      EKI_EXPECT_STATUS(eki_ks_wrap(ks, &fresh_kek, &key, wrapped.data()),
                        not_revoked ? EKI_OK : EKI_ERR_KEY_STATE);
      EXPECT_EQ(zero(wrapped), !not_revoked);
    }

    // unwrap as the kek: ACTIVE, RETIRED. The unwrapped key is ACTIVE.
    const eki_key_id copy = fixed_id(static_cast<std::uint8_t>(0x60 + state));
    const eki_status unwrapped =
        eki_ks_unwrap(ks, &kek, blob.data(), blob.size(), EKI_KEY_HMAC_SHA256, "copy", &copy);
    EKI_EXPECT_STATUS(unwrapped, not_revoked ? EKI_OK : EKI_ERR_KEY_STATE);
    if (unwrapped == EKI_OK) {
      h.track(copy);
      EXPECT_EQ(state_name(h.state(copy)), state_name(EKI_KEY_STATE_ACTIVE));
    }

    // rotate as the old key: ACTIVE only, any key type.
    for (const eki_key_id& id : {aes, mac, ec}) {
      eki_key_id new_id{};
      EKI_EXPECT_STATUS(h.rotate(id, new_id), active ? EKI_OK : EKI_ERR_KEY_STATE);
      EXPECT_EQ(zero(id_bytes(new_id)), !active);
    }

    // revoke and destroy: every state.
    EKI_EXPECT_STATUS(eki_ks_revoke(ks, &ec), EKI_OK);
    EXPECT_EQ(state_name(h.state(ec)), state_name(EKI_KEY_STATE_REVOKED));
    EKI_EXPECT_STATUS(eki_ks_destroy(ks, &ec), EKI_OK);
    EKI_EXPECT_STATUS(eki_ks_get_info(ks, &ec, &info), EKI_ERR_KEY_NOT_FOUND);
  }
}

// The state check comes after the existence and type checks of the same key and before every
// later check ("Key states" in docs/ffi-contract.md).
inline void check_order(const eki_ks_config& base) {
  Handle h(base);
  ASSERT_TRUE(h.open(widen(base)));
  eki_ks* ks = h.get();
  const eki_key_id missing = unknown_id();
  eki_key_id mac{};
  eki_key_id revoked_mac{};
  eki_key_id revoked_aes{};
  eki_key_id retired_kek{};
  eki_key_id revoked_kek{};
  eki_key_id ec{};
  ASSERT_TRUE(h.generate(EKI_KEY_HMAC_SHA256, "order hmac", mac));
  ASSERT_TRUE(h.generate(EKI_KEY_HMAC_SHA256, "order revoked hmac", revoked_mac));
  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "order revoked aes", revoked_aes));
  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "order retired kek", retired_kek));
  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "order revoked kek", revoked_kek));
  ASSERT_TRUE(h.generate(EKI_KEY_ECDSA_P256, "order ecdsa", ec));
  const std::span<const std::uint8_t> msg = bytes("order");
  Tag tag{};
  Blob blob{};
  ASSERT_EQ(name(eki_ks_hmac_sha256(ks, &mac, msg.data(), msg.size(), tag.data())), name(EKI_OK));
  ASSERT_EQ(name(eki_ks_wrap(ks, &revoked_kek, &mac, blob.data())), name(EKI_OK));
  ASSERT_TRUE(h.put_in(revoked_mac, EKI_KEY_STATE_REVOKED));
  ASSERT_TRUE(h.put_in(revoked_aes, EKI_KEY_STATE_REVOKED));
  ASSERT_TRUE(h.put_in(retired_kek, EKI_KEY_STATE_RETIRED));
  ASSERT_TRUE(h.put_in(revoked_kek, EKI_KEY_STATE_REVOKED));

  // sign, hmac, get_public_key: missing, wrong type, state.
  Signature sig{};
  Tag out{};
  PublicKey pk{};
  EKI_EXPECT_STATUS(eki_ks_sign(ks, &missing, msg.data(), msg.size(), sig.data()),
                    EKI_ERR_KEY_NOT_FOUND);
  EKI_EXPECT_STATUS(eki_ks_sign(ks, &revoked_mac, msg.data(), msg.size(), sig.data()),
                    EKI_ERR_WRONG_KEY_TYPE);
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256(ks, &revoked_aes, msg.data(), msg.size(), out.data()),
                    EKI_ERR_WRONG_KEY_TYPE);
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256(ks, &revoked_mac, msg.data(), msg.size(), out.data()),
                    EKI_ERR_KEY_STATE);
  EKI_EXPECT_STATUS(eki_ks_get_public_key(ks, &revoked_mac, pk.data()), EKI_ERR_WRONG_KEY_TYPE);

  // hmac_sha256_verify: tag_len 32 (before existence), missing, not HMAC, state, comparison.
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256_verify(ks, &missing, msg.data(), msg.size(), tag.data(), 31),
                    EKI_ERR_INVALID_ARGUMENT);
  EKI_EXPECT_STATUS(
      eki_ks_hmac_sha256_verify(ks, &revoked_mac, msg.data(), msg.size(), tag.data(), 33),
      EKI_ERR_INVALID_ARGUMENT);
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256_verify(ks, &mac, msg.data(), msg.size(), nullptr, 0),
                    EKI_ERR_INVALID_ARGUMENT);
  EKI_EXPECT_STATUS(
      eki_ks_hmac_sha256_verify(ks, &missing, msg.data(), msg.size(), tag.data(), tag.size()),
      EKI_ERR_KEY_NOT_FOUND);
  EKI_EXPECT_STATUS(
      eki_ks_hmac_sha256_verify(ks, &revoked_aes, msg.data(), msg.size(), tag.data(), tag.size()),
      EKI_ERR_WRONG_KEY_TYPE);
  Tag wrong = tag;
  wrong.back() ^= 1U;
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256_verify(ks, &revoked_mac, msg.data(), msg.size(),
                                              wrong.data(), wrong.size()),
                    EKI_ERR_KEY_STATE);
  EKI_EXPECT_STATUS(
      eki_ks_hmac_sha256_verify(ks, &mac, msg.data(), msg.size(), wrong.data(), wrong.size()),
      EKI_ERR_AUTH_FAILED);
  EKI_EXPECT_STATUS(
      eki_ks_hmac_sha256_verify(ks, &mac, msg.data(), msg.size(), tag.data(), tag.size()), EKI_OK);
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256_verify(ks, &mac, nullptr, 0, tag.data(), tag.size()),
                    EKI_ERR_AUTH_FAILED);

  // wrap: kek exists, key exists, kek AES, key AES or HMAC, kek state, key state.
  Blob wrapped{};
  EKI_EXPECT_STATUS(eki_ks_wrap(ks, &missing, &revoked_mac, wrapped.data()), EKI_ERR_KEY_NOT_FOUND);
  EKI_EXPECT_STATUS(eki_ks_wrap(ks, &revoked_kek, &missing, wrapped.data()), EKI_ERR_KEY_NOT_FOUND);
  EKI_EXPECT_STATUS(eki_ks_wrap(ks, &revoked_kek, &ec, wrapped.data()), EKI_ERR_WRONG_KEY_TYPE);
  EKI_EXPECT_STATUS(eki_ks_wrap(ks, &revoked_mac, &mac, wrapped.data()), EKI_ERR_WRONG_KEY_TYPE);
  EKI_EXPECT_STATUS(eki_ks_wrap(ks, &retired_kek, &revoked_mac, wrapped.data()), EKI_ERR_KEY_STATE);
  EKI_EXPECT_STATUS(eki_ks_wrap(ks, &revoked_kek, &mac, wrapped.data()), EKI_ERR_KEY_STATE);

  // unwrap: formats first, then kek exists, kek AES, kek state, id free, integrity.
  const eki_key_id fresh = fixed_id(0x71);
  Blob bad = blob;
  bad.front() ^= 1U;
  EKI_EXPECT_STATUS(
      eki_ks_unwrap(ks, &revoked_kek, blob.data(), blob.size(), EKI_KEY_HMAC_SHA256, "", &fresh),
      EKI_ERR_INVALID_ARGUMENT);
  EKI_EXPECT_STATUS(
      eki_ks_unwrap(ks, &revoked_mac, blob.data(), blob.size(), EKI_KEY_HMAC_SHA256, "x", &fresh),
      EKI_ERR_WRONG_KEY_TYPE);
  EKI_EXPECT_STATUS(
      eki_ks_unwrap(ks, &revoked_kek, blob.data(), blob.size(), EKI_KEY_HMAC_SHA256, "x", &mac),
      EKI_ERR_KEY_STATE);
  EKI_EXPECT_STATUS(
      eki_ks_unwrap(ks, &revoked_kek, bad.data(), bad.size(), EKI_KEY_HMAC_SHA256, "x", &fresh),
      EKI_ERR_KEY_STATE);
  EKI_EXPECT_STATUS(
      eki_ks_unwrap(ks, &retired_kek, bad.data(), bad.size(), EKI_KEY_HMAC_SHA256, "x", &mac),
      EKI_ERR_KEY_EXISTS);
  EKI_EXPECT_STATUS(
      eki_ks_unwrap(ks, &retired_kek, bad.data(), bad.size(), EKI_KEY_HMAC_SHA256, "x", &fresh),
      EKI_ERR_AUTH_FAILED);

  // rotate: missing; RETIRED and REVOKED; the new key matches the old one's algorithm and label.
  eki_key_id new_id{};
  EKI_EXPECT_STATUS(h.rotate(missing, new_id), EKI_ERR_KEY_NOT_FOUND);
  EXPECT_TRUE(all_zero(id_bytes(new_id)));
  EKI_EXPECT_STATUS(h.rotate(retired_kek, new_id), EKI_ERR_KEY_STATE);
  EXPECT_TRUE(all_zero(id_bytes(new_id)));
  EKI_EXPECT_STATUS(h.rotate(revoked_kek, new_id), EKI_ERR_KEY_STATE);
  EKI_EXPECT_STATUS(h.rotate(mac, new_id), EKI_OK);
  EXPECT_FALSE(same_id(new_id, mac));
  eki_key_info_v2 info{};
  EKI_EXPECT_STATUS(eki_ks_get_info_v2(ks, &new_id, &info), EKI_OK);
  EXPECT_EQ(info.alg, EKI_KEY_HMAC_SHA256);
  EXPECT_EQ(state_name(info.state), state_name(EKI_KEY_STATE_ACTIVE));
  EXPECT_EQ(std::string_view{std::data(info.label)}, "order hmac");
  EXPECT_EQ(state_name(h.state(mac)), state_name(EKI_KEY_STATE_RETIRED));
  // Fresh key material: the new key's tag differs, the old key still verifies its own.
  Tag new_tag{};
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256(ks, &new_id, msg.data(), msg.size(), new_tag.data()),
                    EKI_OK);
  EXPECT_NE(new_tag, tag);
  EKI_EXPECT_STATUS(
      eki_ks_hmac_sha256_verify(ks, &mac, msg.data(), msg.size(), tag.data(), tag.size()), EKI_OK);

  // revoke: missing; from RETIRED; REVOKED again is OK and changes nothing.
  EKI_EXPECT_STATUS(eki_ks_revoke(ks, &missing), EKI_ERR_KEY_NOT_FOUND);
  EKI_EXPECT_STATUS(eki_ks_revoke(ks, &mac), EKI_OK);
  EXPECT_EQ(state_name(h.state(mac)), state_name(EKI_KEY_STATE_REVOKED));
  EKI_EXPECT_STATUS(eki_ks_revoke(ks, &mac), EKI_OK);
  EXPECT_EQ(state_name(h.state(mac)), state_name(EKI_KEY_STATE_REVOKED));
}

// get_info_v2: algorithm, state and the label NUL-padded through byte 64; zero on failure.
inline void info_v2_rows(const eki_ks_config& base) {
  Handle h(base);
  ASSERT_TRUE(h.open(widen(base)));
  eki_ks* ks = h.get();
  eki_key_id id{};
  const std::string label = label_of_len(EKI_LABEL_MAX_LEN);
  ASSERT_TRUE(h.generate(EKI_KEY_ECDSA_P256, label, id));
  eki_key_info_v2 info{};
  std::ranges::fill(info.label, static_cast<char>(kFill));
  info.alg = static_cast<eki_key_alg>(kFillU32);
  info.state = static_cast<eki_key_state>(kFillU32);
  EKI_EXPECT_STATUS(eki_ks_get_info_v2(ks, &id, &info), EKI_OK);
  EXPECT_EQ(info.alg, EKI_KEY_ECDSA_P256);
  EXPECT_EQ(state_name(info.state), state_name(EKI_KEY_STATE_ACTIVE));
  EXPECT_EQ(std::string_view(std::data(info.label), label.size()), label);
  EXPECT_EQ(info.label[EKI_LABEL_MAX_LEN], '\0');

  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "a", id));
  std::ranges::fill(info.label, static_cast<char>(kFill));
  EKI_EXPECT_STATUS(eki_ks_get_info_v2(ks, &id, &info), EKI_OK);
  EXPECT_EQ(info.alg, EKI_KEY_AES_256);
  EXPECT_TRUE(
      std::ranges::all_of(std::span{info.label}.subspan(1), [](char c) { return c == '\0'; }));

  const eki_key_id missing = unknown_id();
  std::array<std::uint8_t, sizeof(eki_key_info_v2)> raw{};
  raw.fill(kFill);
  auto* out = reinterpret_cast<eki_key_info_v2*>(raw.data());
  EKI_EXPECT_STATUS(eki_ks_get_info_v2(ks, &missing, out), EKI_ERR_KEY_NOT_FOUND);
  EXPECT_TRUE(all_zero(raw)) << "the whole struct, padding included";
}

// Dual control on a handle with approvers, and the two functions on a handle without them ("Dual
// control" in docs/ffi-contract.md).
inline void dual_control(const eki_ks_config& base) {
  const Approvers approvers(3);
  const Approvers outsider(1);
  Handle h(base);
  ASSERT_TRUE(h.open(widen(base, nullptr, approvers.keys(), approvers.count())));
  eki_ks* ks = h.get();
  eki_key_id key{};
  eki_key_id other{};
  ASSERT_TRUE(h.generate(EKI_KEY_HMAC_SHA256, "dual", key));
  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "dual other", other));
  const eki_key_id missing = unknown_id();

  // destroy: missing → KEY_NOT_FOUND; existing → APPROVAL_REQUIRED, nothing changes.
  EKI_EXPECT_STATUS(eki_ks_destroy(ks, &missing), EKI_ERR_KEY_NOT_FOUND);
  EKI_EXPECT_STATUS(eki_ks_destroy(ks, &key), EKI_ERR_APPROVAL_REQUIRED);
  EXPECT_EQ(state_name(h.state(key)), state_name(EKI_KEY_STATE_ACTIVE));

  // destroy_request: missing key.
  Request request = prefilled<EKI_DESTROY_REQUEST_LEN>();
  EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, &missing, request.data()), EKI_ERR_KEY_NOT_FOUND);
  EXPECT_TRUE(all_zero(request));

  Request first = prefilled<EKI_DESTROY_REQUEST_LEN>();
  EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, &key, first.data()), EKI_OK);
  EXPECT_FALSE(untouched(first));

  // destroy_approve: key format before the request lookup, then the request, then the approver,
  // then the signature.
  const Signature sig0 = approvers.sign(0, first, key);
  std::uint32_t remaining = kFillU32;
  const PublicKey bad_key = off_curve_key();
  const Request unknown{};
  EKI_EXPECT_STATUS(
      eki_ks_destroy_approve(ks, unknown.data(), bad_key.data(), sig0.data(), &remaining),
      EKI_ERR_INVALID_ARGUMENT);
  EXPECT_EQ(remaining, 0U);
  remaining = kFillU32;
  PublicKey compressed = approvers.key(0);
  compressed.front() = 0x02;
  EKI_EXPECT_STATUS(
      eki_ks_destroy_approve(ks, first.data(), compressed.data(), sig0.data(), &remaining),
      EKI_ERR_INVALID_ARGUMENT);
  EKI_EXPECT_STATUS(
      eki_ks_destroy_approve(ks, unknown.data(), approvers.key(0).data(), sig0.data(), &remaining),
      EKI_ERR_KEY_NOT_FOUND);
  EXPECT_EQ(remaining, 0U);
  const Signature outsider_sig = outsider.sign(0, first, key);
  remaining = kFillU32;
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, first.data(), outsider.key(0).data(),
                                           outsider_sig.data(), &remaining),
                    EKI_ERR_AUTH_FAILED);
  EXPECT_EQ(remaining, 0U);
  // Approver 1's key with approver 0's signature; a signature over another key id.
  EKI_EXPECT_STATUS(
      eki_ks_destroy_approve(ks, first.data(), approvers.key(1).data(), sig0.data(), &remaining),
      EKI_ERR_AUTH_FAILED);
  const Signature wrong_id = approvers.sign(0, first, other);
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, first.data(), approvers.key(0).data(),
                                           wrong_id.data(), &remaining),
                    EKI_ERR_AUTH_FAILED);

  // A valid approval; the same approver again changes nothing.
  remaining = kFillU32;
  EKI_EXPECT_STATUS(
      eki_ks_destroy_approve(ks, first.data(), approvers.key(0).data(), sig0.data(), &remaining),
      EKI_OK);
  EXPECT_EQ(remaining, 1U);
  remaining = kFillU32;
  EKI_EXPECT_STATUS(
      eki_ks_destroy_approve(ks, first.data(), approvers.key(0).data(), sig0.data(), &remaining),
      EKI_OK);
  EXPECT_EQ(remaining, 1U);

  // A new request replaces the old one and drops its approvals.
  Request second = prefilled<EKI_DESTROY_REQUEST_LEN>();
  EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, &key, second.data()), EKI_OK);
  EXPECT_NE(first, second);
  const Signature old_sig1 = approvers.sign(1, first, key);
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, first.data(), approvers.key(1).data(),
                                           old_sig1.data(), &remaining),
                    EKI_ERR_KEY_NOT_FOUND);
  // A signature over the old request does not approve the new one.
  EKI_EXPECT_STATUS(
      eki_ks_destroy_approve(ks, second.data(), approvers.key(0).data(), sig0.data(), &remaining),
      EKI_ERR_AUTH_FAILED);
  remaining = kFillU32;
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, second.data(), approvers.key(2).data(),
                                           approvers.sign(2, second, key).data(), &remaining),
                    EKI_OK);
  EXPECT_EQ(remaining, 1U);
  EXPECT_EQ(state_name(h.state(key)), state_name(EKI_KEY_STATE_ACTIVE));

  // The second distinct approver destroys the key and removes the request.
  remaining = kFillU32;
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, second.data(), approvers.key(0).data(),
                                           approvers.sign(0, second, key).data(), &remaining),
                    EKI_OK);
  EXPECT_EQ(remaining, 0U);
  eki_key_info info{};
  EKI_EXPECT_STATUS(eki_ks_get_info(ks, &key, &info), EKI_ERR_KEY_NOT_FOUND);
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, second.data(), approvers.key(1).data(),
                                           approvers.sign(1, second, key).data(), &remaining),
                    EKI_ERR_KEY_NOT_FOUND);

  // destroy_request and destroy_approve work in every state.
  for (const eki_key_state state : {EKI_KEY_STATE_RETIRED, EKI_KEY_STATE_REVOKED}) {
    SCOPED_TRACE(state_name(state));
    eki_key_id id{};
    ASSERT_TRUE(h.generate(EKI_KEY_ECDSA_P256, "dual state", id));
    ASSERT_TRUE(h.put_in(id, state));
    Request r{};
    EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, &id, r.data()), EKI_OK);
    EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, r.data(), approvers.key(1).data(),
                                             approvers.sign(1, r, id).data(), &remaining),
                      EKI_OK);
    EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, r.data(), approvers.key(2).data(),
                                             approvers.sign(2, r, id).data(), &remaining),
                      EKI_OK);
    EXPECT_EQ(remaining, 0U);
    EKI_EXPECT_STATUS(eki_ks_get_info(ks, &id, &info), EKI_ERR_KEY_NOT_FOUND);
  }

  // Requests live in the handle: a new handle with the same approvers knows none of them.
  Request pending{};
  EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, &other, pending.data()), EKI_OK);
  Handle again(base);
  ASSERT_TRUE(again.open(widen(base, nullptr, approvers.keys(), approvers.count())));
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(again.get(), pending.data(), approvers.key(0).data(),
                                           approvers.sign(0, pending, other).data(), &remaining),
                    EKI_ERR_KEY_NOT_FOUND);
}

// Without approvers, destroy_request and destroy_approve are UNSUPPORTED before any other check
// ("Validation order", step 2); destroy works as in ABI 1.
inline void no_approvers(const eki_ks_config& base) {
  const Approvers approvers(2);
  Handle h(base);
  ASSERT_TRUE(h.open(widen(base)));
  eki_ks* ks = h.get();
  const eki_key_id missing = unknown_id();
  Request request = prefilled<EKI_DESTROY_REQUEST_LEN>();
  EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, &missing, request.data()), EKI_ERR_UNSUPPORTED);
  EXPECT_TRUE(all_zero(request));
  eki_key_id key{};
  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "single", key));
  request = prefilled<EKI_DESTROY_REQUEST_LEN>();
  EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, &key, request.data()), EKI_ERR_UNSUPPORTED);
  EXPECT_TRUE(all_zero(request));
  const PublicKey bad_key = off_curve_key();
  const Signature sig{};
  std::uint32_t remaining = kFillU32;
  EKI_EXPECT_STATUS(
      eki_ks_destroy_approve(ks, request.data(), bad_key.data(), sig.data(), &remaining),
      EKI_ERR_UNSUPPORTED);
  EXPECT_EQ(remaining, 0U);
  EKI_EXPECT_STATUS(eki_ks_destroy(ks, &key), EKI_OK);
}

// The configuration rows of "Opening a store with ABI 2" (docs/ffi-contract.md) that hold for
// every backend.
inline void open_v2_rows(const eki_ks_config& base) {
  const Approvers approvers(EKI_APPROVERS_MAX + 1);
  const TempDir dir;
  const std::string log = dir.file("open.log");
  const std::uint8_t* keys = approvers.keys();

  EXPECT_TRUE(open_v2_succeeds(widen(base)));
  eki_ks_config_v2 bad_selector = widen(base);
  bad_selector.backend = 99;
  EXPECT_TRUE(open_v2_fails(bad_selector, EKI_ERR_INVALID_ARGUMENT));

  // audit_log_path: "" and 4097 bytes are INVALID; 4096 bytes that cannot be created is BACKEND.
  EXPECT_TRUE(open_v2_fails(widen(base, ""), EKI_ERR_INVALID_ARGUMENT));
  const std::string too_long = "/" + std::string(EKI_AUDIT_PATH_MAX_LEN, 'a');
  EXPECT_TRUE(open_v2_fails(widen(base, too_long.c_str()), EKI_ERR_INVALID_ARGUMENT));
  const std::string longest =
      "/nonexistent-eki-dir/" + std::string(EKI_AUDIT_PATH_MAX_LEN - 21, 'a');
  ASSERT_EQ(longest.size(), EKI_AUDIT_PATH_MAX_LEN);
  EXPECT_TRUE(open_v2_fails(widen(base, longest.c_str()), EKI_ERR_BACKEND));
  EXPECT_TRUE(open_v2_fails(widen(base, dir.path().c_str()), EKI_ERR_BACKEND));

  // approver_count and approver_public_keys.
  for (const std::size_t count : {std::size_t{1}, std::size_t{EKI_APPROVERS_MAX + 1}}) {
    EXPECT_TRUE(open_v2_fails(widen(base, nullptr, keys, count), EKI_ERR_INVALID_ARGUMENT))
        << count;
    EXPECT_TRUE(open_v2_fails(widen(base, nullptr, nullptr, count), EKI_ERR_NULL_POINTER)) << count;
  }
  EXPECT_TRUE(open_v2_fails(widen(base, nullptr, nullptr, 2), EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(open_v2_succeeds(widen(base, nullptr, keys, 0)));
  EXPECT_TRUE(open_v2_succeeds(widen(base, nullptr, keys, 2)));
  EXPECT_TRUE(open_v2_succeeds(widen(base, nullptr, keys, EKI_APPROVERS_MAX)));
  constexpr std::size_t key_len = EKI_P256_PUBLIC_KEY_LEN;
  std::vector<std::uint8_t> duplicate(keys, keys + (3 * key_len));
  std::copy_n(keys, key_len, duplicate.begin() + static_cast<std::ptrdiff_t>(2 * key_len));
  EXPECT_TRUE(open_v2_fails(widen(base, nullptr, duplicate.data(), 3), EKI_ERR_INVALID_ARGUMENT));
  std::vector<std::uint8_t> off_curve(keys, keys + (2 * key_len));
  const PublicKey bad = off_curve_key();
  std::ranges::copy(bad, off_curve.begin() + static_cast<std::ptrdiff_t>(key_len));
  EXPECT_TRUE(open_v2_fails(widen(base, nullptr, off_curve.data(), 2), EKI_ERR_INVALID_ARGUMENT));

  // NULL checks of every field before any format check: a NULL key list wins over a malformed
  // path; a malformed path and a malformed count are INVALID together.
  EXPECT_TRUE(open_v2_fails(widen(base, "", nullptr, 2), EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(open_v2_fails(widen(base, "", keys, 1), EKI_ERR_INVALID_ARGUMENT));
  // A format failure leaves no file behind.
  EXPECT_TRUE(open_v2_fails(widen(base, log.c_str(), keys, 1), EKI_ERR_INVALID_ARGUMENT));
  EXPECT_FALSE(file_exists(log));

  // NULL config, NULL out.
  EKI_EXPECT_STATUS(eki_ks_open_v2(nullptr, nullptr), EKI_ERR_NULL_POINTER);
  const Opened opened = try_open_v2(nullptr);
  EKI_EXPECT_STATUS(opened.status, EKI_ERR_NULL_POINTER);
  EXPECT_TRUE(opened.out_is_null);
  const eki_ks_config_v2 config = widen(base);
  EKI_EXPECT_STATUS(eki_ks_open_v2(&config, nullptr), EKI_ERR_NULL_POINTER);
}

// The NULL rows of the store functions ABI version 2 adds: every pointer parameter NULL in turn,
// outputs zero-filled, the last-error text reset.
inline void null_rows(const eki_ks_config& base) {
  Handle h(base);
  ASSERT_TRUE(h.open(widen(base)));
  eki_ks* ks = h.get();
  eki_key_id id{};
  ASSERT_TRUE(h.generate(EKI_KEY_HMAC_SHA256, "null rows", id));
  const std::span<const std::uint8_t> msg = bytes("m");
  const Tag tag{};

  eki_key_info_v2 info{};
  EKI_EXPECT_STATUS(eki_ks_get_info_v2(nullptr, &id, &info), EKI_ERR_NULL_POINTER);
  EKI_EXPECT_STATUS(eki_ks_get_info_v2(ks, nullptr, &info), EKI_ERR_NULL_POINTER);
  EKI_EXPECT_STATUS(eki_ks_get_info_v2(ks, &id, nullptr), EKI_ERR_NULL_POINTER);

  eki_key_id new_id = prefilled_id();
  EKI_EXPECT_STATUS(eki_ks_rotate(nullptr, &id, &new_id), EKI_ERR_NULL_POINTER);
  EXPECT_TRUE(all_zero(id_bytes(new_id)));
  new_id = prefilled_id();
  EKI_EXPECT_STATUS(eki_ks_rotate(ks, nullptr, &new_id), EKI_ERR_NULL_POINTER);
  EXPECT_TRUE(all_zero(id_bytes(new_id)));
  EKI_EXPECT_STATUS(eki_ks_rotate(ks, &id, nullptr), EKI_ERR_NULL_POINTER);

  EKI_EXPECT_STATUS(eki_ks_revoke(nullptr, &id), EKI_ERR_NULL_POINTER);
  EKI_EXPECT_STATUS(eki_ks_revoke(ks, nullptr), EKI_ERR_NULL_POINTER);

  EKI_EXPECT_STATUS(
      eki_ks_hmac_sha256_verify(nullptr, &id, msg.data(), msg.size(), tag.data(), tag.size()),
      EKI_ERR_NULL_POINTER);
  EKI_EXPECT_STATUS(
      eki_ks_hmac_sha256_verify(ks, nullptr, msg.data(), msg.size(), tag.data(), tag.size()),
      EKI_ERR_NULL_POINTER);
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256_verify(ks, &id, nullptr, 1, tag.data(), tag.size()),
                    EKI_ERR_NULL_POINTER);
  EKI_EXPECT_STATUS(eki_ks_hmac_sha256_verify(ks, &id, msg.data(), msg.size(), nullptr, tag.size()),
                    EKI_ERR_NULL_POINTER);

  Request request = prefilled<EKI_DESTROY_REQUEST_LEN>();
  EKI_EXPECT_STATUS(eki_ks_destroy_request(nullptr, &id, request.data()), EKI_ERR_NULL_POINTER);
  EXPECT_TRUE(all_zero(request));
  request = prefilled<EKI_DESTROY_REQUEST_LEN>();
  EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, nullptr, request.data()), EKI_ERR_NULL_POINTER);
  EXPECT_TRUE(all_zero(request));
  EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, &id, nullptr), EKI_ERR_NULL_POINTER);

  const PublicKey key{};
  const Signature sig{};
  std::uint32_t remaining = kFillU32;
  EKI_EXPECT_STATUS(
      eki_ks_destroy_approve(nullptr, request.data(), key.data(), sig.data(), &remaining),
      EKI_ERR_NULL_POINTER);
  EXPECT_EQ(remaining, 0U);
  for (int which = 0; which < 3; ++which) {
    remaining = kFillU32;
    EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, which == 0 ? nullptr : request.data(),
                                             which == 1 ? nullptr : key.data(),
                                             which == 2 ? nullptr : sig.data(), &remaining),
                      EKI_ERR_NULL_POINTER)
        << "parameter " << which;
    EXPECT_EQ(remaining, 0U);
  }
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, request.data(), key.data(), sig.data(), nullptr),
                    EKI_ERR_NULL_POINTER);

  Head hash = prefilled<EKI_AUDIT_HASH_LEN>();
  std::uint64_t seq = kFillU64;
  EKI_EXPECT_STATUS(eki_ks_audit_head(nullptr, hash.data(), &seq), EKI_ERR_NULL_POINTER);
  EXPECT_TRUE(all_zero(hash));
  EXPECT_EQ(seq, 0U);
  hash = prefilled<EKI_AUDIT_HASH_LEN>();
  seq = kFillU64;
  EKI_EXPECT_STATUS(eki_ks_audit_head(ks, nullptr, &seq), EKI_ERR_NULL_POINTER);
  EXPECT_EQ(seq, 0U);
  EKI_EXPECT_STATUS(eki_ks_audit_head(ks, hash.data(), nullptr), EKI_ERR_NULL_POINTER);
  EXPECT_TRUE(all_zero(hash));

  std::uint64_t records = kFillU64;
  EKI_EXPECT_STATUS(eki_audit_verify(nullptr, nullptr, &records), EKI_ERR_NULL_POINTER);
  EXPECT_EQ(records, 0U);
  EKI_EXPECT_STATUS(eki_audit_verify("x", nullptr, nullptr), EKI_ERR_NULL_POINTER);
}

// NOLINTEND(readability-function-cognitive-complexity)

} // namespace eki_test::lifecycle
