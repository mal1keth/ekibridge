// Layer 2 of the key store: the logic that every backend shares. Each operation follows the
// per-function sequence of the ABI contract (plan 4.2, ABI 2 contract section 3): selector and
// format checks first, then the store state checks in their fixed order (existence, type, key
// state), and only then the backend operation. Statuses that follow from caller input or store
// state are decided here and never by a backend. Every logged operation runs in run_logged, which
// writes its audit record and undoes its changes when it does not succeed (finish below).
//
// This file holds the shared pieces and the ABI version 1 operations; open.cpp opens and closes
// handles, lifecycle.cpp holds the operations ABI version 2 adds.

#include "store_internal.hpp"

#include <ekicore/audit_log.hpp>
#include <ekicore/dual_control.hpp>
#include <ekicore/keystore.hpp>
#include <ekicore/openssl_raii.hpp>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

eki_ks::eki_ks(std::unique_ptr<ekicore::keystore::backend> store_backend,
               std::unique_ptr<ekicore::keystore::audit_log> store_log,
               std::unique_ptr<ekicore::keystore::dual_control> store_approvers) noexcept
    : backend(std::move(store_backend)), log(std::move(store_log)),
      approvers(std::move(store_approvers)) {}

eki_ks::~eki_ks() = default;

namespace ekicore::keystore {

std::optional<key_alg> parse_key_alg(eki_key_alg alg) noexcept {
  switch (alg) {
  case EKI_KEY_AES_256:
    return key_alg::aes_256;
  case EKI_KEY_HMAC_SHA256:
    return key_alg::hmac_sha256;
  case EKI_KEY_ECDSA_P256:
    return key_alg::ecdsa_p256;
  default:
    return std::nullopt;
  }
}

std::optional<key_label> key_label::parse(const char* text) noexcept {
  const std::optional<std::size_t> len = detail::bounded_length(text, EKI_LABEL_MAX_LEN);
  if (!len.has_value()) {
    return std::nullopt;
  }
  return from_bytes({text, *len});
}

std::optional<key_label> key_label::from_bytes(std::span<const char> text) noexcept {
  if (text.empty() || text.size() > EKI_LABEL_MAX_LEN || !detail::printable(text)) {
    return std::nullopt;
  }
  key_label label;
  std::ranges::copy(text, label.text_.begin());
  label.size_ = text.size();
  return label;
}

outcome openssl_failure(std::string_view operation) {
  outcome result{.status = EKI_ERR_BACKEND, .detail = std::string{operation}};
  result.detail += " failed: ";
  const unsigned long code = ERR_peek_last_error();
  if (code == 0) {
    result.detail += "no OpenSSL error queued";
    return result;
  }
  std::array<char, 256> line{};
  ERR_error_string_n(code, line.data(), line.size());
  result.detail += line.data();
  return result;
}

std::size_t copy_message(std::string_view text, std::span<char> buf) noexcept {
  if (!buf.empty()) {
    const std::size_t written = std::min(text.size(), buf.size() - 1);
    std::copy_n(text.begin(), written, buf.begin());
    buf.subspan(written).front() = '\0';
  }
  return text.size();
}

eki_status null_pointer(eki_ks& ks) noexcept {
  ks.last_error.clear();
  return EKI_ERR_NULL_POINTER;
}

namespace detail {

std::optional<std::size_t> bounded_length(const char* text, std::size_t max_len) noexcept {
  for (std::size_t len = 0; len <= max_len; ++len) {
    if (text[len] == '\0') {
      return len;
    }
  }
  return std::nullopt;
}

// The comparison is on the byte value, so it holds whether char is signed or not.
bool printable(std::span<const char> text) noexcept {
  return std::ranges::all_of(text, [](char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte >= 0x20 && byte <= 0x7E;
  });
}

eki_status record(eki_ks& ks, outcome result) {
  if (result.status == EKI_ERR_BACKEND && result.detail.empty()) {
    result.detail = "key store backend failed without a reason";
  }
  if (result.status != EKI_OK) {
    ks.last_error = std::move(result.detail);
  }
  return result.status;
}

eki_status id_taken(eki_ks& ks, const key_id& id, bool& exists) {
  key_lookup found;
  const eki_status status = record(ks, ks.backend->find(id, found));
  exists = found.exists;
  return status;
}

std::optional<key_info> find_existing(eki_ks& ks, const key_id& id, eki_status& status) {
  key_lookup found;
  status = record(ks, ks.backend->find(id, found));
  if (status != EKI_OK) {
    return std::nullopt;
  }
  if (!found.exists) {
    status = EKI_ERR_KEY_NOT_FOUND;
  } else if (!found.info.has_value()) {
    status = record(ks, outcome{
                            .status = EKI_ERR_BACKEND,
                            .detail = "the objects that carry this key id are not a key of a "
                                      "type, label and state this library can use",
                        });
  }
  return found.info;
}

eki_status require_state(key_state state, key_use use) noexcept {
  switch (state) {
  case key_state::active:
    return EKI_OK;
  case key_state::retired:
    return use == key_use::recover ? EKI_OK : EKI_ERR_KEY_STATE;
  case key_state::revoked:
    break;
  }
  return EKI_ERR_KEY_STATE;
}

eki_status require_key(eki_ks& ks, const key_id& id, key_alg wanted, key_use use) {
  eki_status status = EKI_OK;
  const std::optional<key_info> found = find_existing(ks, id, status);
  if (!found.has_value()) {
    return status;
  }
  if (found->alg != wanted) {
    return EKI_ERR_WRONG_KEY_TYPE;
  }
  return require_state(found->state, use);
}

eki_status new_key_id(eki_ks& ks, key_id& id) {
  if (RAND_bytes(id.data(), static_cast<int>(id.size())) != 1) {
    return record(ks, openssl_failure("RAND_bytes for a key id"));
  }
  bool taken = false;
  const eki_status status = id_taken(ks, id, taken);
  if (status != EKI_OK) {
    return status;
  }
  if (taken) {
    return record(
        ks, outcome{.status = EKI_ERR_BACKEND, .detail = "the random key id is already in use"});
  }
  return EKI_OK;
}

namespace {

// Appends "; <what>" to text.
void append_clause(std::string& text, std::string_view what) {
  text += text.empty() ? "" : "; ";
  text += what;
}

// Undoes the changes registered in current, most recent first: the pending request is put back,
// the created key is destroyed again. A state change and a destroy cannot be undone and are named
// as such. Returns what was done, as text for the last-error message, and sets failed when an
// undo step failed.
std::string undo(eki_ks& ks, const call& current, bool& failed) {
  std::string done;
  failed = false;
  if (current.request.has_value() && ks.approvers) {
    ks.approvers->restore(current.request->id, current.request->before);
    append_clause(done, "the pending destroy request was put back");
  }
  if (current.changed.has_value()) {
    append_clause(done, current.changed->after == key_state::retired
                            ? "the key stays RETIRED, which cannot be undone"
                            : "the key stays REVOKED, which cannot be undone");
  }
  if (current.created.has_value()) {
    const outcome destroyed = ks.backend->destroy(*current.created);
    failed = failed || destroyed.status != EKI_OK;
    append_clause(done, destroyed.status == EKI_OK
                            ? "the key this call created was destroyed again"
                            : "destroying the key this call created failed: " + destroyed.detail);
  }
  if (current.destroyed) {
    append_clause(done, "the key was destroyed, which cannot be undone");
  }
  return done;
}

// Undoes the changes of an operation that failed. Its own last-error text stays; a failed undo
// step makes the call a backend failure and adds its reason.
eki_status undo_failed_call(eki_ks& ks, const call& current, eki_status status) {
  bool failed = false;
  const std::string done = undo(ks, current, failed);
  if (!failed) {
    return status;
  }
  append_clause(ks.last_error, done);
  return EKI_ERR_BACKEND;
}

} // namespace

eki_status finish(eki_ks& ks, call& current, eki_status status) {
  if (status != EKI_OK) {
    status = undo_failed_call(ks, current, status);
  }
  if (!ks.log) {
    return status;
  }
  current.record.status = status;
  const outcome written = ks.log->append(current.record);
  if (written.status == EKI_OK) {
    return status;
  }
  std::string text = "the audit record could not be written: " + written.detail;
  if (status == EKI_OK) {
    bool failed = false;
    append_clause(text, undo(ks, current, failed));
  }
  ks.last_error = std::move(text);
  return EKI_ERR_BACKEND;
}

} // namespace detail

namespace {

using detail::call;
using detail::find_existing;
using detail::id_taken;
using detail::key_use;
using detail::new_key_id;
using detail::record;
using detail::require_key;
using detail::require_state;
using detail::run;
using detail::run_logged;

// Whether a key of this algorithm can be wrapped: the 32-byte secrets can, a key pair cannot.
bool is_wrappable(key_alg alg) noexcept {
  return alg == key_alg::aes_256 || alg == key_alg::hmac_sha256;
}

// Fills info_out: the algorithm, and the label NUL-padded through byte 64.
void write_info(const key_info& info, eki_key_info& info_out) noexcept {
  info_out.alg = to_abi(info.alg);
  const std::span<char> label{info_out.label};
  std::ranges::fill(label, '\0');
  std::ranges::copy(info.label.view(), label.begin());
}

} // namespace

// Audit record: key is the new id, or empty when no key was created.
eki_status generate(eki_ks& ks, eki_key_alg alg, const char* label, eki_key_id& id_out) {
  return run_logged(ks, audit::op::generate, [&](call& current) {
    const std::optional<key_alg> parsed_alg = parse_key_alg(alg);
    if (!parsed_alg.has_value()) {
      return EKI_ERR_INVALID_ARGUMENT;
    }
    const std::optional<key_label> parsed_label = key_label::parse(label);
    if (!parsed_label.has_value()) {
      return EKI_ERR_INVALID_ARGUMENT;
    }
    key_id id{};
    eki_status status = new_key_id(ks, id);
    if (status != EKI_OK) {
      return status;
    }
    status = record(ks, ks.backend->create(*parsed_alg, *parsed_label, id));
    if (status != EKI_OK) {
      return status;
    }
    current.created = id;
    current.record.key = id;
    std::ranges::copy(id, std::begin(id_out.bytes));
    return EKI_OK;
  });
}

eki_status get_info(eki_ks& ks, const key_id& id, eki_key_info& info_out) {
  return run(ks, [&] {
    eki_status status = EKI_OK;
    const std::optional<key_info> found = find_existing(ks, id, status);
    if (!found.has_value()) {
      return status;
    }
    write_info(*found, info_out);
    return EKI_OK;
  });
}

// Contract order: exists, is ECDSA P-256, not REVOKED.
eki_status get_public_key(eki_ks& ks, const key_id& id, mut_bytes out65) {
  return run_logged(ks, audit::op::get_public_key, [&](call& current) {
    current.record.key = id;
    const eki_status status = require_key(ks, id, key_alg::ecdsa_p256, key_use::recover);
    if (status != EKI_OK) {
      return status;
    }
    return record(ks, ks.backend->public_key(id, out65));
  });
}

// Contract order: exists, is ECDSA P-256, ACTIVE.
eki_status sign(eki_ks& ks, const key_id& id, bytes msg, mut_bytes sig64) {
  return run_logged(ks, audit::op::sign, [&](call& current) {
    current.record.key = id;
    const eki_status status = require_key(ks, id, key_alg::ecdsa_p256, key_use::protect);
    if (status != EKI_OK) {
      return status;
    }
    return record(ks, ks.backend->sign(id, msg, sig64));
  });
}

// Contract order: exists, is HMAC-SHA256, ACTIVE.
eki_status hmac_sha256(eki_ks& ks, const key_id& id, bytes msg, mut_bytes out32) {
  return run_logged(ks, audit::op::hmac, [&](call& current) {
    current.record.key = id;
    const eki_status status = require_key(ks, id, key_alg::hmac_sha256, key_use::protect);
    if (status != EKI_OK) {
      return status;
    }
    return record(ks, ks.backend->hmac_sha256(id, msg, out32));
  });
}

// Contract order: kek exists, key exists, kek is AES-256, key is AES-256 or HMAC-SHA256, kek
// ACTIVE, key not REVOKED. Audit record: key is the key wrapped, key2 the kek.
eki_status wrap(eki_ks& ks, const key_id& kek, const key_id& key, mut_bytes out40) {
  return run_logged(ks, audit::op::wrap, [&](call& current) {
    current.record.key = key;
    current.record.key2 = kek;
    eki_status status = EKI_OK;
    const std::optional<key_info> kek_found = find_existing(ks, kek, status);
    if (!kek_found.has_value()) {
      return status;
    }
    const std::optional<key_info> key_found = find_existing(ks, key, status);
    if (!key_found.has_value()) {
      return status;
    }
    if (kek_found->alg != key_alg::aes_256 || !is_wrappable(key_found->alg)) {
      return EKI_ERR_WRONG_KEY_TYPE;
    }
    status = require_state(kek_found->state, key_use::protect);
    if (status != EKI_OK) {
      return status;
    }
    status = require_state(key_found->state, key_use::recover);
    if (status != EKI_OK) {
      return status;
    }
    return record(ks, ks.backend->wrap(kek, key, out40));
  });
}

// Contract order: alg known, blob_len 40, alg not ECDSA, label format; kek exists, kek is
// AES-256, kek not REVOKED, id free; then the integrity check, which the backend performs. Audit
// record: key is the id given, key2 the kek, whatever the outcome.
eki_status unwrap(eki_ks& ks, const key_id& kek, bytes blob, eki_key_alg alg, const char* label,
                  const key_id& id) {
  return run_logged(ks, audit::op::unwrap, [&](call& current) {
    current.record.key = id;
    current.record.key2 = kek;
    const std::optional<key_alg> parsed_alg = parse_key_alg(alg);
    if (!parsed_alg.has_value()) {
      return EKI_ERR_INVALID_ARGUMENT;
    }
    if (blob.size() != EKI_WRAPPED_KEY_LEN) {
      return EKI_ERR_INVALID_ARGUMENT;
    }
    if (!is_wrappable(*parsed_alg)) {
      return EKI_ERR_INVALID_ARGUMENT;
    }
    const std::optional<key_label> parsed_label = key_label::parse(label);
    if (!parsed_label.has_value()) {
      return EKI_ERR_INVALID_ARGUMENT;
    }
    eki_status status = require_key(ks, kek, key_alg::aes_256, key_use::recover);
    if (status != EKI_OK) {
      return status;
    }
    bool taken = false;
    status = id_taken(ks, id, taken);
    if (status != EKI_OK) {
      return status;
    }
    if (taken) {
      return EKI_ERR_KEY_EXISTS;
    }
    status = record(ks, ks.backend->unwrap(kek, blob, *parsed_alg, *parsed_label, id));
    if (status == EKI_OK) {
      current.created = id;
    }
    return status;
  });
}

// Any object that carries the id can be destroyed, a foreign one included (plan 4.3). A handle
// with approvers destroys only through destroy_approve: an existing key is APPROVAL_REQUIRED.
eki_status destroy(eki_ks& ks, const key_id& id) {
  return run_logged(ks, audit::op::destroy, [&](call& current) {
    current.record.key = id;
    bool exists = false;
    eki_status status = id_taken(ks, id, exists);
    if (status != EKI_OK) {
      return status;
    }
    if (!exists) {
      return EKI_ERR_KEY_NOT_FOUND;
    }
    if (ks.approvers) {
      return EKI_ERR_APPROVAL_REQUIRED;
    }
    status = record(ks, ks.backend->destroy(id));
    current.destroyed = status == EKI_OK;
    return status;
  });
}

} // namespace ekicore::keystore
