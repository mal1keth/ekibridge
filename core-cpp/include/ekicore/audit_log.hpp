#pragma once

// The audit log of a key store handle (ABI 2 contract section 5): a text file with one record per
// call, each line chained to the previous one by SHA-256. The format is byte-exact so that either
// library can verify, and continue, a log the other wrote:
//
//   {"seq":1,"time":"2026-11-11T09:30:00Z","op":"generate","key":"<32 hex>","key2":"",
//    "status":0,"prev":"<64 hex>","hash":"<64 hex>"}
//
// on one line, ended by '\n'. hash is SHA-256 over the line up to and including the closing quote
// of prev; prev is the previous record's hash, 64 zeros for the first.
//
// Records are formatted into a fixed buffer and matched against the grammar directly: no
// allocation while writing or verifying, and a hostile file is read one bounded line at a time.

#include <ekicore.h>
#include <ekicore/keystore.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace ekicore::keystore {

namespace audit {

using digest = std::array<std::uint8_t, EKI_AUDIT_HASH_LEN>;

// The longest line a verifier accepts, its '\n' included. A record this library writes is at most
// 333 bytes.
inline constexpr std::size_t max_line_len = 512;

// The op values of section 5, in its order.
enum class op : std::uint8_t {
  open,
  close,
  generate,
  unwrap,
  rotate,
  revoke,
  destroy,
  destroy_request,
  destroy_approve,
  sign,
  hmac,
  hmac_verify,
  wrap,
  get_public_key,
};

// The fields of a record that the call decides: everything except seq, time, prev and hash. An
// empty key or key2 is written as "".
struct entry {
  op operation = op::open;
  std::optional<key_id> key;
  std::optional<key_id> key2;
  eki_status status = EKI_OK;
};

// The end of a chain that passed verification, or of the chain a writer has written so far.
struct chain_end {
  // The number of records, which is also the seq of the last one.
  std::uint64_t records = 0;
  // The hash of the last record; 32 zero bytes when there is none.
  digest head{};
  // The length of the file in bytes.
  std::uint64_t size = 0;
};

// Verifies the file at path (NUL-terminated, already length-checked) under every rule of
// eki_audit_verify: EKI_OK with end filled in, EKI_ERR_AUTH_FAILED for any deviation from the
// format or the chain, EKI_ERR_BACKEND when the file cannot be opened or read or is not a regular
// file.
[[nodiscard]] eki_status verify_path(const char* path, chain_end& end);

// An open file descriptor, closed on destruction.
class file_descriptor {
public:
  file_descriptor() = default;
  explicit file_descriptor(int fd) noexcept : fd_(fd) {}
  file_descriptor(const file_descriptor&) = delete;
  file_descriptor& operator=(const file_descriptor&) = delete;
  file_descriptor(file_descriptor&& other) noexcept;
  file_descriptor& operator=(file_descriptor&& other) noexcept;
  ~file_descriptor();

  [[nodiscard]] int get() const noexcept {
    return fd_;
  }
  [[nodiscard]] bool valid() const noexcept {
    return fd_ >= 0;
  }

private:
  int fd_ = -1;
};

} // namespace audit

// The writer: the log file of one handle, open for append and locked for the handle's life.
class audit_log {
public:
  audit_log(audit::file_descriptor fd, const audit::chain_end& end) noexcept;
  audit_log(const audit_log&) = delete;
  audit_log(audit_log&&) = delete;
  audit_log& operator=(const audit_log&) = delete;
  audit_log& operator=(audit_log&&) = delete;
  // Closing the descriptor releases the lock.
  ~audit_log() = default;

  // Opens path for append, creating it with mode 0600 when missing; takes an exclusive,
  // non-blocking flock (per open file, so a second handle in the same process is refused too);
  // and verifies the existing content through the locked descriptor. Status EKI_OK and out set;
  // EKI_ERR_AUTH_FAILED when the content fails verification (the file is not written); or
  // EKI_ERR_BACKEND for an I/O or locking failure. out stays empty on failure.
  [[nodiscard]] static outcome open(const std::string& path, std::unique_ptr<audit_log>& out);

  // Appends the next record: seq one past the last, time now (UTC), prev the last hash. The line
  // goes out with one write and is flushed with fsync before this returns. On failure the file is
  // cut back to its previous length so that the chain stays intact, the head is unchanged and the
  // status is EKI_ERR_BACKEND with a reason. If the file cannot be cut back, the log is damaged
  // and every later append fails.
  [[nodiscard]] outcome append(const audit::entry& entry);

  // The last record written or verified.
  [[nodiscard]] const audit::chain_end& end() const noexcept {
    return end_;
  }

private:
  // Cuts the file back to the length of the committed chain after a failed append.
  void roll_back() noexcept;

  audit::file_descriptor fd_;
  audit::chain_end end_;
  bool damaged_ = false;
};

} // namespace ekicore::keystore
