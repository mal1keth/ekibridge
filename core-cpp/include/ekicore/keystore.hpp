#pragma once

// The key store behind the eki_ks_* functions, in three layers:
//
// 1. The handle, struct eki_ks (the opaque type of the public header): a mutex, the last-error
//    text, one backend, and optionally an audit log and the approvers of dual control. The mutex
//    serialises every operation on the handle; the extern "C" entry points take it before they
//    call layer 2.
// 2. The store logic (src/keystore/store.cpp, src/keystore/lifecycle.cpp), shared by every
//    backend: everything the ABI contract fixes independently of where keys live. It resets the
//    last-error text, validates selectors and labels, runs the per-function state checks in
//    contract order (existence before type before key state, and so on), chooses the status,
//    records a message for every backend failure and writes the audit record of every call.
// 3. The backend (class backend below): only what differs between places where keys can live.
//    The software backend (src/keystore/software.cpp) keeps keys in memory; a PKCS#11 backend
//    keeps them in a token. A backend is called only after layer 2 has checked everything the
//    contract lets it check, so its preconditions are stated per operation.
//
// The interface never asks a backend for key bytes: a token may refuse to export them, so wrap
// and unwrap are backend operations, and an unwrapped key is created where it will live.

#include <ekicore.h>
#include <ekicore/primitives.hpp>
#include <ekicore/secret_buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace ekicore::keystore {

// A key id: 16 bytes, made by the library in generate and chosen by the caller in unwrap.
using key_id = std::array<std::uint8_t, EKI_KEY_ID_LEN>;

[[nodiscard]] inline key_id to_key_id(const eki_key_id& id) noexcept {
  return std::to_array(id.bytes);
}

// A key algorithm that passed the selector check. The values are the ABI's.
enum class key_alg : std::uint8_t {
  aes_256 = EKI_KEY_AES_256,
  hmac_sha256 = EKI_KEY_HMAC_SHA256,
  ecdsa_p256 = EKI_KEY_ECDSA_P256,
};

// The algorithm for an ABI selector, or nullopt for an unknown one.
[[nodiscard]] std::optional<key_alg> parse_key_alg(eki_key_alg alg) noexcept;

[[nodiscard]] constexpr eki_key_alg to_abi(key_alg alg) noexcept {
  return static_cast<eki_key_alg>(alg);
}

// A label that passed the contract's format check: 1 to 64 bytes, each in 0x20..0x7E. The only
// ways to make one are parse() and from_bytes(), which apply the same rule, so a backend never
// receives an unchecked label and never reports one. Stored inline, so copying one allocates
// nothing.
class key_label {
public:
  // Reads the NUL-terminated text at most EKI_LABEL_MAX_LEN + 1 bytes far and returns the label,
  // or nullopt when the text is empty, longer than EKI_LABEL_MAX_LEN bytes, unterminated within
  // that bound, or holds a byte outside 0x20..0x7E. text must not be NULL.
  [[nodiscard]] static std::optional<key_label> parse(const char* text) noexcept;

  // The label made of exactly these bytes (no NUL), as a backend reads it back from storage (a
  // token's CKA_LABEL), or nullopt when they break the rule above.
  [[nodiscard]] static std::optional<key_label> from_bytes(std::span<const char> text) noexcept;

  [[nodiscard]] std::string_view view() const noexcept {
    return {text_.data(), size_};
  }

private:
  key_label() = default;

  std::array<char, EKI_LABEL_MAX_LEN> text_{};
  std::size_t size_ = 0;
};

// The lifecycle state of a key (docs/ffi-contract.md, "Key states"). The values are the ABI's. A
// key is active when created; rotate makes the old key retired; revoke makes a key revoked.
enum class key_state : std::uint8_t {
  active = EKI_KEY_STATE_ACTIVE,
  retired = EKI_KEY_STATE_RETIRED,
  revoked = EKI_KEY_STATE_REVOKED,
};

[[nodiscard]] constexpr eki_key_state to_abi(key_state state) noexcept {
  return static_cast<eki_key_state>(state);
}

// What get_info and get_info_v2 report, and what layer 2 needs to know about a key before it uses
// it.
struct key_info {
  key_info(key_alg info_alg, const key_label& info_label, key_state info_state) noexcept
      : alg(info_alg), label(info_label), state(info_state) {}

  key_alg alg;
  key_label label;
  key_state state;
};

// What a backend's find reports about an id. exists: some object carries the id. info: the key's
// algorithm, label and state, set exactly when the objects carrying the id form one of the
// library's key shapes with a valid label and, on a token, usage attributes that spell a state. An
// object that exists without info (a PKCS#11 object another program created: a certificate, a key
// of another type, a label that breaks the rule) still takes the id: unwrap answers KEY_EXISTS and
// destroy removes it, while an operation that needs the algorithm or the label answers
// EKI_ERR_BACKEND.
struct key_lookup {
  bool exists = false;
  std::optional<key_info> info;
};

// The result of a backend operation. status is EKI_OK, or the status of the failure: normally
// EKI_ERR_BACKEND, EKI_ERR_AUTH_FAILED from unwrap when the blob fails the integrity check, and
// EKI_ERR_INTERNAL when a stated precondition did not hold. detail is the text for the handle's
// last-error message; for EKI_ERR_BACKEND it names the operation and the underlying error (the
// OpenSSL error string or the CKR_* name).
struct outcome {
  eki_status status = EKI_OK;
  std::string detail;
};

// An EKI_ERR_BACKEND outcome for an OpenSSL call that failed: detail is "<operation> failed: "
// followed by the newest entry on this thread's OpenSSL error queue, which the failing call left
// there. Nothing is removed from the queue. Allocates, so it may throw std::bad_alloc.
[[nodiscard]] outcome openssl_failure(std::string_view operation);

// Where keys live. Layer 2 calls these only with the handle's lock held, so a backend sees one
// call at a time. The operations are not const: a backend may hold mutable session state (a
// PKCS#11 session), and the lock already gives each call exclusive access. Operations may throw
// (allocation); the FFI barrier turns an exception into EKI_ERR_INTERNAL.
class backend {
public:
  backend(const backend&) = delete;
  backend(backend&&) = delete;
  backend& operator=(const backend&) = delete;
  backend& operator=(backend&&) = delete;
  // Destroying the backend wipes the secrets it holds in memory (software) or closes its session
  // (PKCS#11); it must not throw.
  virtual ~backend() = default;

  // Reports whether any object, of any class, carries id, and if so what key it is (key_lookup).
  [[nodiscard]] virtual outcome find(const key_id& id, key_lookup& found) = 0;

  // Creates a new key of alg under id. Precondition: no object carries id. On failure nothing is
  // created and existing keys are unchanged.
  [[nodiscard]] virtual outcome create(key_alg alg, const key_label& label, const key_id& id) = 0;

  // Writes the SEC1 uncompressed public key (0x04 || X || Y) of the key pair id into out65.
  // Precondition: id names an ECDSA P-256 key; out65 has 65 bytes.
  [[nodiscard]] virtual outcome public_key(const key_id& id, mut_bytes out65) = 0;

  // Signs SHA-256(msg) with the key pair id and writes r || s, 32 bytes each, into sig64. msg may
  // be empty with a null data(). Precondition: id names an ECDSA P-256 key; sig64 has 64 bytes.
  [[nodiscard]] virtual outcome sign(const key_id& id, bytes msg, mut_bytes sig64) = 0;

  // Writes HMAC-SHA256(key id, msg) into out32. msg may be empty with a null data().
  // Precondition: id names an HMAC-SHA256 key; out32 has 32 bytes.
  [[nodiscard]] virtual outcome hmac_sha256(const key_id& id, bytes msg, mut_bytes out32) = 0;

  // Wraps the secret key `key` under `kek` with RFC 3394 AES Key Wrap into out40. kek and key may
  // be the same id. Precondition: kek names an AES-256 key, key an AES-256 or HMAC-SHA256 key;
  // out40 has 40 bytes.
  [[nodiscard]] virtual outcome wrap(const key_id& kek, const key_id& key, mut_bytes out40) = 0;

  // Unwraps blob40 under kek and stores the 32-byte result as a new key of alg under id.
  // EKI_ERR_AUTH_FAILED when the blob fails the RFC 3394 integrity check. On any failure nothing
  // is created and existing keys are unchanged. Precondition: kek names an AES-256 key; blob40
  // has 40 bytes; alg is AES-256 or HMAC-SHA256; no object carries id.
  [[nodiscard]] virtual outcome unwrap(const key_id& kek, bytes blob40, key_alg alg,
                                       const key_label& label, const key_id& id) = 0;

  // Removes every object that carries id; for the software backend that wipes the key material.
  // Precondition: some object carries id (it need not be a key the library can represent).
  [[nodiscard]] virtual outcome destroy(const key_id& id) = 0;

  // Moves the key id forward to the state `state`: a field of the stored key (software) or the
  // usage attributes of the token objects (PKCS#11). Never makes a key more usable: a state
  // earlier than the key's leaves it unchanged, and on a token only attributes are cleared, the
  // "protect" group (FALSE from RETIRED on) before the "recover" group. Precondition: id names a
  // key of the library.
  [[nodiscard]] virtual outcome set_state(const key_id& id, key_state state) = 0;

  // Compares tag32 with HMAC-SHA256(key id, msg) in constant time: EKI_OK on a match,
  // EKI_ERR_AUTH_FAILED on a mismatch. msg may be empty with a null data(). Precondition: id names
  // an HMAC-SHA256 key; tag32 has 32 bytes.
  [[nodiscard]] virtual outcome hmac_sha256_verify(const key_id& id, bytes msg, bytes tag32) = 0;

protected:
  backend() = default;
};

// The software backend (src/keystore/software.cpp): an in-memory map for the handle's lifetime.
[[nodiscard]] std::unique_ptr<backend> make_software_backend();

// The longest token label (CK_TOKEN_INFO.label holds 32 bytes, blank-padded) and the longest PIN
// that eki_ks_open accepts.
inline constexpr std::size_t pkcs11_token_label_max_len = 32;
inline constexpr std::size_t pkcs11_user_pin_max_len = 255;

// The configuration of a PKCS#11 store once layer 2 has checked it: copies of the caller's
// strings, so that the library keeps no caller pointer. The PIN lives in a secret_buffer, which
// wipes it when the configuration is destroyed.
struct pkcs11_config {
  std::string module_path;
  std::string token_label; // 1..=pkcs11_token_label_max_len printable bytes
  secret_buffer user_pin;  // 1..=pkcs11_user_pin_max_len bytes
};

// The PKCS#11 backend (src/keystore/pkcs11.cpp, compiled when EKI_WITH_PKCS11 is on): loads the
// module, finds the token, opens a session and logs in. Every failure is EKI_ERR_BACKEND and
// leaves out empty. config is taken by value, so the PIN copy is wiped as soon as this returns,
// that is, right after the login.
[[nodiscard]] outcome make_pkcs11_backend(pkcs11_config config, std::unique_ptr<backend>& out);

// The audit log of a handle (ekicore/audit_log.hpp) and its approvers with their pending destroy
// requests (ekicore/dual_control.hpp). Declared here only: the handle owns them through pointers
// and its destructor is defined where they are complete.
class audit_log;
class dual_control;

} // namespace ekicore::keystore

// The handle. Allocated by eki_ks_open or eki_ks_open_v2, freed by eki_ks_close, which must not
// race with any other call on the same handle.
struct eki_ks {
  eki_ks(std::unique_ptr<ekicore::keystore::backend> store_backend,
         std::unique_ptr<ekicore::keystore::audit_log> store_log,
         std::unique_ptr<ekicore::keystore::dual_control> store_approvers) noexcept;
  eki_ks(const eki_ks&) = delete;
  eki_ks(eki_ks&&) = delete;
  eki_ks& operator=(const eki_ks&) = delete;
  eki_ks& operator=(eki_ks&&) = delete;
  // Closes the backend and the log file; writes nothing (the close record is written by
  // ekicore::keystore::close).
  ~eki_ks();

  // Serialises every operation on the handle, including eki_ks_last_error_message, which takes a
  // const handle: hence mutable.
  mutable std::mutex mutex;
  // The message of the most recent operation on the handle; guarded by mutex.
  std::string last_error;
  // Where the keys live; guarded by mutex. Never null.
  std::unique_ptr<ekicore::keystore::backend> backend;
  // The audit log; null for a handle without one. Guarded by mutex.
  std::unique_ptr<ekicore::keystore::audit_log> log;
  // The approvers and pending destroy requests; null for a handle without approvers (single
  // control). Guarded by mutex.
  std::unique_ptr<ekicore::keystore::dual_control> approvers;
};

namespace ekicore::keystore {

// Layer 2. Except for open, open_v2, close, audit_verify and copy_message, each function is called
// with ks.mutex held and after the entry point has checked every pointer parameter; each resets
// ks.last_error first.

// eki_ks_open: open_v2 with no audit log and no approvers.
[[nodiscard]] eki_status open(const eki_ks_config& config, eki_ks*& out);

// Checks the configuration (selector, then the NULL checks of the fields, then their formats, in
// field order), opens the backend, then the audit log, creates the handle and writes its "open"
// record. out is written only on success; on failure everything opened is closed again.
[[nodiscard]] eki_status open_v2(const eki_ks_config_v2& config, eki_ks*& out);

// eki_ks_close: writes the "close" record when the handle has an audit log (a failure cannot be
// reported and is ignored), then destroys the handle. Accepts NULL.
void close(eki_ks* ks) noexcept;

// Copies text into buf under the snprintf convention: at most buf.size() - 1 bytes and a NUL,
// nothing when buf is empty. Returns text.size().
std::size_t copy_message(std::string_view text, std::span<char> buf) noexcept;

// A call on ks whose other pointer parameter is NULL: the call still counts as an operation on
// ks, so its last-error text is reset. Returns EKI_ERR_NULL_POINTER.
[[nodiscard]] eki_status null_pointer(eki_ks& ks) noexcept;

[[nodiscard]] eki_status generate(eki_ks& ks, eki_key_alg alg, const char* label,
                                  eki_key_id& id_out);
[[nodiscard]] eki_status get_info(eki_ks& ks, const key_id& id, eki_key_info& info_out);
[[nodiscard]] eki_status get_public_key(eki_ks& ks, const key_id& id, mut_bytes out65);
[[nodiscard]] eki_status sign(eki_ks& ks, const key_id& id, bytes msg, mut_bytes sig64);
[[nodiscard]] eki_status hmac_sha256(eki_ks& ks, const key_id& id, bytes msg, mut_bytes out32);
[[nodiscard]] eki_status wrap(eki_ks& ks, const key_id& kek, const key_id& key, mut_bytes out40);
[[nodiscard]] eki_status unwrap(eki_ks& ks, const key_id& kek, bytes blob, eki_key_alg alg,
                                const char* label, const key_id& id);
[[nodiscard]] eki_status destroy(eki_ks& ks, const key_id& id);

// ABI version 2 (src/keystore/lifecycle.cpp).
[[nodiscard]] eki_status get_info_v2(eki_ks& ks, const key_id& id, eki_key_info_v2& info_out);
[[nodiscard]] eki_status rotate(eki_ks& ks, const key_id& old_id, eki_key_id& new_id_out);
[[nodiscard]] eki_status revoke(eki_ks& ks, const key_id& id);
[[nodiscard]] eki_status hmac_sha256_verify(eki_ks& ks, const key_id& id, bytes msg, bytes tag);
[[nodiscard]] eki_status destroy_request(eki_ks& ks, const key_id& id, mut_bytes request_out);
[[nodiscard]] eki_status destroy_approve(eki_ks& ks, bytes request, bytes approver_public_key,
                                         bytes sig, std::uint32_t& remaining_out);
[[nodiscard]] eki_status audit_head(eki_ks& ks, mut_bytes hash_out, std::uint64_t& seq_out);

// eki_audit_verify, stateless: the path check (1..=EKI_AUDIT_PATH_MAX_LEN bytes, read no further
// than one byte past the maximum), then the file. expected_head is empty for NULL, else 32 bytes.
[[nodiscard]] eki_status audit_verify(const char* path, bytes expected_head,
                                      std::uint64_t& records_out);

} // namespace ekicore::keystore
