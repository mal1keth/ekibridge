// Input decoding, buffers and checks shared by the libFuzzer targets of libekicore.
//
// Every target calls the C ABI as a hostile C caller could: pointers into exactly sized heap
// buffers (so AddressSanitizer reports an access one byte past the end), NULL wherever the input
// asks for it, lengths within and beyond the documented caps, any selector value.
//
// Input layout. Input reads the layout that core-rs/fuzz/src/lib.rs reads, so one seed file means
// the same calls to both libraries and one generator (core-rs/fuzz/examples/seeds.rs) writes both
// corpora. Integers are little-endian; a fixed-size array is its bytes; a byte string is a 2-byte
// little-endian length followed by that many bytes. A field cut short by the end of the input
// reads as zero bytes (integers, arrays) or is shortened (byte strings), so every input decodes.
// The composite fields below (InBuf, read_capped_len, read_label, read_key_ref, read_audit_path,
// Config) say which bytes they consume.
//
// Audit logs are written to the system temporary directory under names that carry the target and
// the process id (Scratch). A configuration's PKCS#11 module path names a file that does not
// exist, so no token is ever opened.

#pragma once

#include <openssl/evp.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <new>
#include <optional>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "ekicore.h"

namespace ekifuzz {

// The library's options, forwarded as 0 or 1 by core-cpp/fuzz/CMakeLists.txt.
inline constexpr bool kWithPkcs11 = EKI_FUZZ_WITH_PKCS11 != 0;
inline constexpr bool kWithPq = EKI_FUZZ_WITH_PQ != 0;

using bytes = std::span<const uint8_t>;

// Reports a property that does not hold and aborts, so libFuzzer records a crash with the
// message and the line of the check.
inline void require(bool property, std::string_view what,
                    std::source_location where = std::source_location::current()) {
  if (!property) {
    std::fprintf(stderr, "property failed at %s:%u: %.*s\n", where.file_name(),
                 static_cast<unsigned>(where.line()), static_cast<int>(what.size()), what.data());
    std::abort();
  }
}

// Aborts unless a call returned the one status the contract gives for its arguments.
inline void expect_status(int32_t got, int32_t want, std::string_view function,
                          std::source_location where = std::source_location::current()) {
  if (got != want) {
    std::fprintf(stderr, "%.*s returned %d, expected %d\n", static_cast<int>(function.size()),
                 function.data(), got, want);
  }
  require(got == want, function, where);
}

// Aborts unless a call returned one of the statuses the contract allows for its arguments.
inline void expect_one_of(int32_t got, std::span<const int32_t> allowed, std::string_view function,
                          std::source_location where = std::source_location::current()) {
  const bool found = std::find(allowed.begin(), allowed.end(), got) != allowed.end();
  if (!found) {
    std::fprintf(stderr, "%.*s returned %d, which the contract does not allow here\n",
                 static_cast<int>(function.size()), function.data(), got);
  }
  require(found, function, where);
}

// The byte every output is filled with before a call, so that both a missing zero-fill and a
// write to an output that must stay untouched are visible.
inline constexpr uint8_t kFill = 0xA5;

// A heap allocation of exactly size() bytes, so AddressSanitizer reports a read or write one byte
// past the end. data() is never NULL, also for size 0, which makes the NULL flags the only source
// of NULL pointers.
class Buffer {
public:
  explicit Buffer(size_t size = 0, uint8_t fill = 0)
      : data_(std::make_unique<uint8_t[]>(size)), size_(size) {
    std::fill_n(data_.get(), size_, fill);
  }

  explicit Buffer(bytes from) : Buffer(from.size()) {
    std::copy(from.begin(), from.end(), data_.get());
  }

  [[nodiscard]] uint8_t* data() {
    return data_.get();
  }
  [[nodiscard]] const uint8_t* data() const {
    return data_.get();
  }
  [[nodiscard]] size_t size() const {
    return size_;
  }
  [[nodiscard]] bytes span() const {
    return {data_.get(), size_};
  }

  [[nodiscard]] bool all(uint8_t value) const {
    return std::all_of(data_.get(), data_.get() + size_, [value](uint8_t b) { return b == value; });
  }

  [[nodiscard]] bool equals(bytes other) const {
    return std::equal(data_.get(), data_.get() + size_, other.begin(), other.end());
  }

private:
  std::unique_ptr<uint8_t[]> data_;
  size_t size_;
};

// from cut or padded with pad to exactly len bytes, in an exact allocation.
inline Buffer exact(bytes from, size_t len, uint8_t pad) {
  Buffer out(len, pad);
  std::copy_n(from.begin(), std::min(len, from.size()), out.data());
  return out;
}

// Reads typed fields from the front of a libFuzzer input.
class Input {
public:
  Input(const uint8_t* data, size_t size) : rest_(data, size) {}

  [[nodiscard]] bool empty() const {
    return rest_.empty();
  }

  uint8_t u8() {
    if (rest_.empty()) {
      return 0;
    }
    const uint8_t value = rest_.front();
    rest_ = rest_.subspan(1);
    return value;
  }

  bool boolean() {
    return (u8() & 1U) != 0;
  }

  uint16_t u16() {
    const auto lo = static_cast<uint16_t>(u8());
    const auto hi = static_cast<uint16_t>(u8());
    return static_cast<uint16_t>(lo | static_cast<uint16_t>(hi << 8U));
  }

  int32_t i32() {
    uint32_t value = 0;
    for (unsigned shift = 0; shift < 32; shift += 8) {
      value |= static_cast<uint32_t>(u8()) << shift;
    }
    return static_cast<int32_t>(value);
  }

  template <size_t N> std::array<uint8_t, N> array() {
    std::array<uint8_t, N> out{};
    for (auto& b : out) {
      b = u8();
    }
    return out;
  }

  // A byte string: a u16 length, then that many bytes (fewer at the end).
  Buffer bytes() {
    const size_t len = std::min<size_t>(u16(), rest_.size());
    Buffer out(rest_.first(len));
    rest_ = rest_.subspan(len);
    return out;
  }

  // Every byte that is left.
  Buffer rest() {
    Buffer out(rest_);
    rest_ = {};
    return out;
  }

private:
  std::span<const uint8_t> rest_;
};

// A caller-supplied input buffer: a boolean (pass NULL), then a byte string. The length argument
// is the buffer's length either way: the contract defines both NULL with length 0 (an empty
// buffer) and NULL with a non-zero length (EKI_ERR_NULL_POINTER).
struct InBuf {
  bool null = false;
  Buffer bytes;

  static InBuf read(Input& in) {
    const bool null = in.boolean();
    return InBuf{null, in.bytes()};
  }

  [[nodiscard]] const uint8_t* ptr() const {
    return null ? nullptr : bytes.data();
  }
  [[nodiscard]] size_t len() const {
    return bytes.size();
  }
  // Whether (ptr, len) breaks the pointer rule: NULL with a non-zero length.
  [[nodiscard]] bool null_with(size_t len) const {
    return null && len > 0;
  }
};

// The length argument for a parameter with a documented maximum: one byte whose low two bits
// choose the real length (0, 1), cap + 1 (2) or SIZE_MAX (3). Above the cap the call must fail
// without touching the buffer, which stays at its real, smaller size.
inline size_t read_capped_len(Input& in, size_t actual, size_t cap) {
  switch (in.u8() & 3U) {
  case 2:
    return cap + 1;
  case 3:
    return SIZE_MAX;
  default:
    return actual;
  }
}

// A key id argument: one byte whose low two bits choose NULL (0), 16 raw bytes that follow (1),
// or (2, 3) one of `known` picked by the next byte (an all-zero id when `known` is empty).
inline std::optional<eki_key_id> read_key_ref(Input& in, const std::vector<eki_key_id>& known) {
  switch (in.u8() & 3U) {
  case 0:
    return std::nullopt;
  case 1: {
    eki_key_id id{};
    const auto raw = in.array<EKI_KEY_ID_LEN>();
    std::copy(raw.begin(), raw.end(), std::begin(id.bytes));
    return id;
  }
  default: {
    const size_t pick = in.u8();
    return known.empty() ? eki_key_id{} : known[pick % known.size()];
  }
  }
}

inline const eki_key_id* id_ptr(const std::optional<eki_key_id>& id) {
  return id ? &*id : nullptr;
}

// A string argument: NULL, a NUL-terminated string, or bytes without a terminator.
class Text {
public:
  static Text null() {
    return Text{true, Buffer(0)};
  }
  static Text terminated(std::string_view text) {
    Buffer b(text.size() + 1, 0);
    std::copy(text.begin(), text.end(), b.data());
    return Text{false, std::move(b)};
  }
  static Text terminated(bytes text) {
    return terminated(std::string_view{reinterpret_cast<const char*>(text.data()), text.size()});
  }
  // Exactly these bytes, with no terminator added.
  static Text unterminated(Buffer b) {
    return Text{false, std::move(b)};
  }

  [[nodiscard]] const char* ptr() const {
    return null_ ? nullptr : reinterpret_cast<const char*>(bytes_.data());
  }
  [[nodiscard]] bool is_null() const {
    return null_;
  }
  // The text the library reads with a bound of `scan` bytes: up to the first NUL, at most scan
  // bytes. std::nullopt for NULL.
  [[nodiscard]] std::optional<bytes> seen(size_t scan) const {
    if (null_) {
      return std::nullopt;
    }
    const bytes all = bytes_.span().first(std::min(scan, bytes_.size()));
    const auto nul = std::find(all.begin(), all.end(), uint8_t{0});
    return all.first(static_cast<size_t>(nul - all.begin()));
  }

private:
  Text(bool is_null, Buffer b) : null_(is_null), bytes_(std::move(b)) {}
  bool null_;
  Buffer bytes_;
};

inline bool same(std::optional<bytes> a, std::string_view b) {
  return a && std::equal(a->begin(), a->end(), b.begin(), b.end(),
                         [](uint8_t x, char y) { return x == static_cast<uint8_t>(y); });
}

// Longest label the targets pass before its NUL; longer than EKI_LABEL_MAX_LEN (64).
inline constexpr size_t kLabelFuzzMax = 80;

// A label argument: one byte modulo 3 chooses NULL (0), a byte string cut to kLabelFuzzMax with a
// NUL appended (1), or a byte string padded with 'a' or cut to exactly 65 bytes and passed
// without a NUL (2), the largest unterminated label the contract allows.
inline Text read_label(Input& in) {
  switch (in.u8() % 3U) {
  case 0:
    return Text::null();
  case 1: {
    const Buffer b = in.bytes();
    return Text::terminated(b.span().first(std::min(b.size(), kLabelFuzzMax)));
  }
  default:
    return Text::unterminated(exact(in.bytes().span(), EKI_LABEL_MAX_LEN + 1, 'a'));
  }
}

// Whether the library must accept the label (the bytes before its NUL): 1 to 64 bytes, each in
// 0x20..=0x7E.
inline bool label_is_valid(bytes label) {
  return !label.empty() && label.size() <= EKI_LABEL_MAX_LEN &&
         std::all_of(label.begin(), label.end(), [](uint8_t b) { return b >= 0x20 && b <= 0x7E; });
}

// The scratch paths of one target in this process.
struct Scratch {
  std::string log;     // the audit log a run may create; removed by reset()
  std::string dir;     // the temporary directory: exists and is not a regular file
  std::string missing; // a file in a directory that does not exist

  explicit Scratch(std::string_view target) {
    std::error_code error;
    std::filesystem::path base = std::filesystem::temp_directory_path(error);
    if (error) {
      base = "/tmp";
    }
    const std::string stem =
        "ekibridge-fuzz-" + std::string(target) + "-" + std::to_string(::getpid());
    log = (base / (stem + ".log")).string();
    missing = (base / (stem + ".d") / "audit.log").string();
    dir = base.string();
    // temp_directory_path keeps a trailing separator from TMPDIR; the library is given the path
    // as it is, which names the same directory.
  }

  void reset() const {
    std::error_code ignored;
    std::filesystem::remove(log, ignored);
  }

  [[nodiscard]] bool log_exists() const {
    std::error_code ignored;
    return std::filesystem::is_regular_file(log, ignored);
  }
};

// An audit log path argument: one byte modulo 6 chooses NULL (0), the run's log file (1), the
// empty string (2), 4097 bytes with no NUL, one more than the longest path (3), the temporary
// directory (4) or a file in a directory that does not exist (5).
inline Text read_audit_path(Input& in, const Scratch& scratch) {
  switch (in.u8() % 6U) {
  case 0:
    return Text::null();
  case 1:
    return Text::terminated(scratch.log);
  case 2:
    return Text::terminated(std::string_view{});
  case 3:
    return Text::unterminated(Buffer(EKI_AUDIT_PATH_MAX_LEN + 1, 'a'));
  case 4:
    return Text::terminated(scratch.dir);
  default:
    return Text::terminated(scratch.missing);
  }
}

// What the contract requires of a non-NULL output after a failed call.
enum class OnError { zero, untouched };

// The state of one output after a call.
struct Seen {
  bool null;
  OnError on_error;
  std::vector<uint8_t> bytes;
};

// A byte output, exactly allocated and pre-filled with kFill.
class OutBuf {
public:
  OutBuf(bool is_null, size_t len, OnError rule = OnError::zero)
      : null_(is_null), rule_(rule), bytes_(len, kFill) {}

  [[nodiscard]] uint8_t* ptr() {
    return null_ ? nullptr : bytes_.data();
  }
  [[nodiscard]] bool is_null() const {
    return null_;
  }
  [[nodiscard]] bytes span() const {
    return bytes_.span();
  }
  [[nodiscard]] Seen seen() const {
    return {null_, rule_, {bytes_.span().begin(), bytes_.span().end()}};
  }

private:
  bool null_;
  OnError rule_;
  Buffer bytes_;
};

// An output of n bytes for a parameter with maximum max, passed with length argument len: left
// untouched on failure when len is above max, zero-filled otherwise.
inline OutBuf sized_out(bool is_null, size_t n, size_t len, size_t max) {
  return {is_null, n, len > max ? OnError::untouched : OnError::zero};
}

// A struct or integer output (eki_key_id *, eki_key_info *, eki_ks **, uint64_t *, ...) in a
// heap allocation of exactly its size and alignment, pre-filled with kFill, so its bytes, padding
// included, can be checked after a failed call.
template <typename T> class Slot {
public:
  explicit Slot(bool is_null)
      : null_(is_null),
        raw_(static_cast<uint8_t*>(::operator new(sizeof(T), std::align_val_t{alignof(T)}))) {
    std::fill_n(raw_, sizeof(T), kFill);
  }
  Slot(const Slot&) = delete;
  Slot& operator=(const Slot&) = delete;
  Slot(Slot&&) = delete;
  Slot& operator=(Slot&&) = delete;
  ~Slot() {
    ::operator delete(raw_, std::align_val_t{alignof(T)});
  }

  [[nodiscard]] T* ptr() {
    return null_ ? nullptr : reinterpret_cast<T*>(raw_);
  }
  [[nodiscard]] bool is_null() const {
    return null_;
  }
  [[nodiscard]] T get() const {
    T value;
    std::memcpy(static_cast<void*>(&value), raw_, sizeof(T));
    return value;
  }
  [[nodiscard]] Seen seen() const {
    return {null_, OnError::zero, {raw_, raw_ + sizeof(T)}};
  }

private:
  bool null_;
  uint8_t* raw_;
};

// One finished call and what the contract says about it.
struct Call {
  const char* function;
  int32_t status;
  bool null_param = false; // a pointer parameter broke the pointer rule
  bool null_field = false; // a configuration field the contract checks for NULL was NULL
  bool over_cap = false;   // a length argument was above its parameter's maximum
  std::vector<Seen> outputs{};

  // Aborts unless the call kept the contract: a defined status other than EKI_ERR_INTERNAL; a NULL
  // pointer parameter gives EKI_ERR_NULL_POINTER, which has no other cause than a NULL parameter or
  // configuration field; a length above its maximum gives EKI_ERR_INVALID_ARGUMENT unless a
  // pointer was NULL; after a failure every non-NULL output is zero-filled, or untouched when its
  // length was above the maximum.
  void check(std::source_location where = std::source_location::current()) const {
    if (status < EKI_OK || status > EKI_ERR_APPROVAL_REQUIRED || status == EKI_ERR_INTERNAL ||
        (null_param && status != EKI_ERR_NULL_POINTER) ||
        (status == EKI_ERR_NULL_POINTER && !null_param && !null_field) ||
        (over_cap && !null_param && status != EKI_ERR_INVALID_ARGUMENT)) {
      std::fprintf(stderr, "%s returned %d (NULL parameter %d, NULL field %d, over cap %d)\n",
                   function, status, null_param, null_field, over_cap);
      require(false, function, where);
    }
    if (status == EKI_OK) {
      return;
    }
    for (size_t index = 0; index < outputs.size(); ++index) {
      const Seen& out = outputs[index];
      const uint8_t want = out.on_error == OnError::zero ? 0 : kFill;
      if (!out.null && !std::all_of(out.bytes.begin(), out.bytes.end(),
                                    [want](uint8_t b) { return b == want; })) {
        std::fprintf(stderr, "%s returned %d but output #%zu is not %s\n", function, status, index,
                     out.on_error == OnError::zero ? "zero-filled" : "untouched");
        require(false, function, where);
      }
    }
  }
};

// An open key store handle, closed on every path out of a target.
class Store {
public:
  explicit Store(eki_ks* handle) : ks_(handle) {
    require(handle != nullptr, "a store opened with EKI_OK has a handle");
  }
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;
  Store(Store&& other) noexcept : ks_(std::exchange(other.ks_, nullptr)) {}
  Store& operator=(Store&&) = delete;
  ~Store() {
    eki_ks_close(ks_);
  }

  static Store software() {
    eki_ks_config config{};
    config.backend = EKI_KS_SOFTWARE;
    eki_ks* handle = nullptr;
    require(eki_ks_open(&config, &handle) == EKI_OK, "opening a software store");
    return Store(handle);
  }

  [[nodiscard]] eki_ks* get() const {
    return ks_;
  }

  [[nodiscard]] eki_key_id generate(eki_key_alg alg, const char* label) const {
    eki_key_id id{};
    std::fill(std::begin(id.bytes), std::end(id.bytes), kFill);
    require(eki_ks_generate(ks_, alg, label, &id) == EKI_OK, "eki_ks_generate in an open store");
    return id;
  }

private:
  eki_ks* ks_;
};

inline constexpr size_t kApproverPool = 4;
inline constexpr std::string_view kApprovalDomain = "ekibridge-destroy-v1";

using PublicKey = std::array<uint8_t, EKI_P256_PUBLIC_KEY_LEN>;
using Signature = std::array<uint8_t, EKI_P256_SIGNATURE_LEN>;
using Request = std::array<uint8_t, EKI_DESTROY_REQUEST_LEN>;

// ECDSA P-256 keys in a software store of their own, for dual control: their public keys go into
// a configuration, their signatures approve destroy requests. Made on first use.
class Approvers {
public:
  PublicKey public_key(uint8_t index) {
    return pool()[index % kApproverPool].second;
  }

  Signature approve(uint8_t index, const Request& request, const eki_key_id& id) {
    const eki_key_id signer = pool()[index % kApproverPool].first;
    std::vector<uint8_t> message(kApprovalDomain.begin(), kApprovalDomain.end());
    message.insert(message.end(), request.begin(), request.end());
    message.insert(message.end(), std::begin(id.bytes), std::end(id.bytes));
    Signature sig{};
    require(eki_ks_sign(store_->get(), &signer, message.data(), message.size(), sig.data()) ==
                EKI_OK,
            "an approver failed to sign");
    return sig;
  }

private:
  std::vector<std::pair<eki_key_id, PublicKey>>& pool() {
    if (!store_) {
      store_.emplace(Store::software());
      for (size_t i = 0; i < kApproverPool; ++i) {
        const eki_key_id id = store_->generate(EKI_KEY_ECDSA_P256, "approver");
        PublicKey pk{};
        require(eki_ks_get_public_key(store_->get(), &id, pk.data()) == EKI_OK,
                "reading an approver's public key");
        keys_.emplace_back(id, pk);
      }
    }
    return keys_;
  }

  std::optional<Store> store_;
  std::vector<std::pair<eki_key_id, PublicKey>> keys_;
};

// A PKCS#11 module path that names no file: a configuration that reaches the module load fails
// there (EKI_ERR_BACKEND) and no token is opened.
inline constexpr const char* kNoModule = "/nonexistent/ekibridge-fuzz/no-pkcs11-module.so";
inline constexpr size_t kTokenLabelFuzzMax = 40;
inline constexpr size_t kPinFuzzMax = 300;
inline constexpr size_t kTokenLabelMax = 32;
inline constexpr size_t kPinMax = 255;

// A store configuration, owning every buffer its pointers point into.
//
// Bytes read: backend (i32); one byte of flags for the PKCS#11 fields (bit 0: the module path is
// kNoModule, bit 1: the token label is given, bit 2: the PIN is given); the token label (byte
// string cut to kTokenLabelFuzzMax, NUL appended); the PIN (the same, kPinFuzzMax); the audit log
// path (read_audit_path); the approver count (one byte: 255 is SIZE_MAX, any other value modulo
// 12); the approver keys source (one byte modulo 3: NULL; raw bytes, resized to count * 65 when
// the count is valid; or Approvers keys, one index byte per key, for a valid count) and their
// bytes.
class Config {
public:
  static Config read(Input& in, const Scratch& scratch, Approvers& approvers) {
    Config c;
    c.backend_ = in.i32();
    const uint8_t flags = in.u8();
    const Buffer label = in.bytes();
    const Buffer pin = in.bytes();
    c.module_given_ = (flags & 1U) != 0;
    c.token_label_ =
        (flags & 2U) != 0
            ? Text::terminated(label.span().first(std::min(label.size(), kTokenLabelFuzzMax)))
            : Text::null();
    c.pin_ = (flags & 4U) != 0
                 ? Text::terminated(pin.span().first(std::min(pin.size(), kPinFuzzMax)))
                 : Text::null();
    c.audit_ = read_audit_path(in, scratch);
    const uint8_t count = in.u8();
    c.approver_count_ = count == 255 ? SIZE_MAX : count % 12U;
    const bool valid_count = c.approver_count_ >= 2 && c.approver_count_ <= EKI_APPROVERS_MAX;
    const uint8_t source = in.u8() % 3U;
    if (source == 1) {
      const Buffer raw = in.bytes();
      c.approver_keys_ = valid_count
                             ? exact(raw.span(), c.approver_count_ * EKI_P256_PUBLIC_KEY_LEN, 0)
                             : Buffer(raw.span());
    } else if (source == 2) {
      const size_t n = valid_count ? c.approver_count_ : 1;
      Buffer keys(n * EKI_P256_PUBLIC_KEY_LEN);
      std::vector<size_t> picks;
      for (size_t i = 0; i < n; ++i) {
        const uint8_t pick = in.u8();
        picks.push_back(pick % kApproverPool);
        const PublicKey pk = approvers.public_key(pick);
        std::copy(pk.begin(), pk.end(), keys.data() + i * EKI_P256_PUBLIC_KEY_LEN);
      }
      c.approver_keys_ = std::move(keys);
      c.approvers_generated_ = true;
      for (size_t i = 1; i < picks.size(); ++i) {
        c.approvers_repeat_ |=
            std::find(picks.begin(), picks.begin() + static_cast<std::ptrdiff_t>(i), picks[i]) !=
            picks.begin() + static_cast<std::ptrdiff_t>(i);
      }
    }
    return c;
  }

  // The software backend with nothing else.
  static Config software() {
    return Config{};
  }

  void set_audit_log(const Scratch& scratch) {
    audit_ = Text::terminated(scratch.log);
  }

  [[nodiscard]] eki_ks_config v1() const {
    eki_ks_config c{};
    c.backend = backend_;
    c.pkcs11_module_path = module_given_ ? kNoModule : nullptr;
    c.pkcs11_token_label = token_label_.ptr();
    c.pkcs11_user_pin = pin_.ptr();
    return c;
  }

  [[nodiscard]] eki_ks_config_v2 v2() const {
    const eki_ks_config one = v1();
    eki_ks_config_v2 c{};
    c.backend = one.backend;
    c.pkcs11_module_path = one.pkcs11_module_path;
    c.pkcs11_token_label = one.pkcs11_token_label;
    c.pkcs11_user_pin = one.pkcs11_user_pin;
    c.audit_log_path = audit_.ptr();
    c.approver_public_keys = approver_keys_ ? approver_keys_->data() : nullptr;
    c.approver_count = approver_count_;
    return c;
  }

  // Whether a field that eki_ks_open checks for NULL is NULL.
  [[nodiscard]] bool null_field_v1() const {
    return backend_ == EKI_KS_PKCS11 && kWithPkcs11 &&
           (!module_given_ || token_label_.is_null() || pin_.is_null());
  }
  // Whether a field that eki_ks_open_v2 checks for NULL is NULL.
  [[nodiscard]] bool null_field_v2() const {
    return null_field_v1() || (approver_count_ != 0 && !approver_keys_);
  }
  [[nodiscard]] bool has_approvers() const {
    return approver_count_ != 0;
  }
  [[nodiscard]] bool has_audit_log() const {
    return !audit_.is_null();
  }

  // The statuses eki_ks_open (v2 false) or eki_ks_open_v2 may return for this configuration when
  // config and out are not NULL, step by step in the contract's order: the backend selector; every
  // NULL field; the token label, the PIN, the audit path, the approver count and the approver
  // keys; opening the backend (a module that does not exist fails); opening the log (log_locked:
  // another handle holds the run's log). Raw approver keys may or may not be valid points, so for
  // them both outcomes are allowed.
  [[nodiscard]] std::vector<int32_t> expected_open(bool v2, const Scratch& scratch,
                                                   bool log_locked) const {
    const bool pkcs11 = backend_ == EKI_KS_PKCS11;
    if (backend_ != EKI_KS_SOFTWARE && !pkcs11) {
      return {EKI_ERR_INVALID_ARGUMENT};
    }
    if (pkcs11 && !kWithPkcs11) {
      return {EKI_ERR_UNSUPPORTED};
    }
    if (v2 ? null_field_v2() : null_field_v1()) {
      return {EKI_ERR_NULL_POINTER};
    }
    const auto printable = [](uint8_t b) { return b >= 0x20 && b <= 0x7E; };
    if (pkcs11) {
      const bytes label = token_label_.seen(kTokenLabelMax + 1).value_or(bytes{});
      const bytes pin = pin_.seen(kPinMax + 1).value_or(bytes{});
      if (label.empty() || label.size() > kTokenLabelMax ||
          !std::all_of(label.begin(), label.end(), printable) || pin.empty() ||
          pin.size() > kPinMax) {
        return {EKI_ERR_INVALID_ARGUMENT};
      }
    }
    std::vector<int32_t> allowed;
    if (v2) {
      const auto path = audit_.seen(EKI_AUDIT_PATH_MAX_LEN + 1);
      if (path && (path->empty() || path->size() > EKI_AUDIT_PATH_MAX_LEN)) {
        return {EKI_ERR_INVALID_ARGUMENT};
      }
      if (approver_count_ != 0 && (approver_count_ < 2 || approver_count_ > EKI_APPROVERS_MAX)) {
        return {EKI_ERR_INVALID_ARGUMENT};
      }
      if (approver_count_ != 0) {
        if (!approvers_generated_) {
          allowed.push_back(EKI_ERR_INVALID_ARGUMENT);
        } else if (approvers_repeat_) {
          return {EKI_ERR_INVALID_ARGUMENT};
        }
      }
    }
    if (pkcs11) {
      allowed.push_back(EKI_ERR_BACKEND);
      return allowed;
    }
    bool log_fails = false;
    if (v2 && !audit_.is_null()) {
      log_fails = same(audit_.seen(EKI_AUDIT_PATH_MAX_LEN + 1), scratch.log) ? log_locked : true;
    }
    allowed.push_back(log_fails ? EKI_ERR_BACKEND : EKI_OK);
    return allowed;
  }

private:
  Config() = default;

  int32_t backend_ = EKI_KS_SOFTWARE;
  bool module_given_ = false;
  Text token_label_ = Text::null();
  Text pin_ = Text::null();
  Text audit_ = Text::null();
  size_t approver_count_ = 0;
  std::optional<Buffer> approver_keys_;
  bool approvers_generated_ = false;
  bool approvers_repeat_ = false;
};

inline bool contains(const std::vector<int32_t>& allowed, int32_t status) {
  return std::find(allowed.begin(), allowed.end(), status) != allowed.end();
}

// The fourteen op names of an audit record.
inline constexpr std::array<std::string_view, 14> kAuditOps = {
    "open",    "close",           "generate",        "unwrap", "rotate", "revoke",
    "destroy", "destroy_request", "destroy_approve", "sign",   "hmac",   "hmac_verify",
    "wrap",    "get_public_key"};

using Digest = std::array<uint8_t, EKI_AUDIT_HASH_LEN>;

// The end of a valid audit log: its number of records and the hash of the last one.
struct AuditHead {
  uint64_t records = 0;
  Digest hash{};
};

namespace audit_detail {

inline std::string lower_hex(bytes b) {
  static constexpr std::string_view digits = "0123456789abcdef";
  std::string out;
  for (const uint8_t byte : b) {
    out += digits[byte >> 4U];
    out += digits[byte & 0x0FU];
  }
  return out;
}

// Whether text is YYYY-MM-DDTHH:MM:SSZ naming a real UTC second from 1970 on.
inline bool time_is_valid(std::string_view text) {
  static constexpr std::string_view shape = "dddd-dd-ddTdd:dd:ddZ";
  if (text.size() != shape.size()) {
    return false;
  }
  for (size_t i = 0; i < shape.size(); ++i) {
    const bool ok = shape[i] == 'd' ? (text[i] >= '0' && text[i] <= '9') : text[i] == shape[i];
    if (!ok) {
      return false;
    }
  }
  const auto num = [text](size_t from, size_t len) {
    unsigned n = 0;
    for (size_t i = from; i < from + len; ++i) {
      n = n * 10 + static_cast<unsigned>(text[i] - '0');
    }
    return n;
  };
  const unsigned year = num(0, 4);
  const unsigned month = num(5, 2);
  const unsigned day = num(8, 2);
  const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
  static constexpr std::array<unsigned, 12> days = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (month < 1 || month > 12) {
    return false;
  }
  const unsigned month_days = days[month - 1] + (month == 2 && leap ? 1U : 0U);
  return year >= 1970 && day >= 1 && day <= month_days && num(11, 2) < 24 && num(14, 2) < 60 &&
         num(17, 2) < 60;
}

// text before the first `byte`, and the rest after it.
inline std::optional<std::pair<std::string_view, std::string_view>> split(std::string_view text,
                                                                          char byte) {
  const size_t at = text.find(byte);
  if (at == std::string_view::npos) {
    return std::nullopt;
  }
  return std::pair{text.substr(0, at), text.substr(at + 1)};
}

inline bool strip(std::string_view& text, std::string_view prefix) {
  if (!text.starts_with(prefix)) {
    return false;
  }
  text.remove_prefix(prefix.size());
  return true;
}

inline bool key_ok(std::string_view k) {
  return k.empty() ||
         (k.size() == 32 && k.find_first_not_of("0123456789abcdef") == std::string_view::npos);
}

} // namespace audit_detail

// An independent strict reading of an audit log, written from the ABI 2 contract (section 5 and
// amendments 6, 12 and 15) rather than from either library: the head of the log if every line is
// exactly a record that continues the chain, std::nullopt otherwise.
inline std::optional<AuditHead> audit_rebuild(bytes log) {
  using namespace audit_detail;
  AuditHead head;
  if (log.empty()) {
    return head;
  }
  std::string_view body{reinterpret_cast<const char*>(log.data()), log.size()};
  if (!body.ends_with('\n')) {
    return std::nullopt;
  }
  body.remove_suffix(1);
  size_t start = 0;
  while (start <= body.size()) {
    const size_t end = std::min(body.find('\n', start), body.size());
    const std::string_view line = body.substr(start, end - start);
    start = end + 1;
    std::string_view rest = line;
    std::string_view seq, time, op, key, key2, status, prev, hash;
    const auto field = [&rest](std::string_view& out, char until) {
      const auto parts = split(rest, until);
      if (!parts) {
        return false;
      }
      out = parts->first;
      rest = parts->second;
      return true;
    };
    if (!strip(rest, "{\"seq\":") || !field(seq, ',') || !strip(rest, "\"time\":\"") ||
        !field(time, '"') || !strip(rest, ",\"op\":\"") || !field(op, '"') ||
        !strip(rest, ",\"key\":\"") || !field(key, '"') || !strip(rest, ",\"key2\":\"") ||
        !field(key2, '"') || !strip(rest, ",\"status\":") || !field(status, ',') ||
        !strip(rest, "\"prev\":\"") || !field(prev, '"') || !strip(rest, ",\"hash\":\"") ||
        !field(hash, '"')) {
      return std::nullopt;
    }
    bool status_ok = false;
    for (int s = 0; s <= EKI_ERR_APPROVAL_REQUIRED; ++s) {
      status_ok |= status == std::to_string(s);
    }
    const size_t covered =
        line.size() - rest.size() - hash.size() - std::string_view(",\"hash\":\"\"").size();
    Digest digest{};
    unsigned int digest_len = 0;
    require(EVP_Digest(line.data(), covered, digest.data(), &digest_len, EVP_sha256(), nullptr) ==
                1,
            "SHA-256");
    const bool valid =
        rest == "}" && seq == std::to_string(head.records + 1) && time_is_valid(time) &&
        std::find(kAuditOps.begin(), kAuditOps.end(), op) != kAuditOps.end() && key_ok(key) &&
        key_ok(key2) && status_ok && prev == lower_hex(head.hash) && hash == lower_hex(digest);
    if (!valid) {
      return std::nullopt;
    }
    head.records += 1;
    head.hash = digest;
  }
  return head;
}

} // namespace ekifuzz
