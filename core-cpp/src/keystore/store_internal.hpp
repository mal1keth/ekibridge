#pragma once

// The pieces of layer 2 that its source files share (store.cpp, open.cpp, lifecycle.cpp): the
// frame every operation runs in, which writes its audit record and undoes its changes when it does
// not succeed, and the store-state checks in their contract order.

#include <ekicore/audit_log.hpp>
#include <ekicore/dual_control.hpp>
#include <ekicore/keystore.hpp>
#include <ekicore/openssl_raii.hpp>

#include <cstddef>
#include <optional>
#include <span>

namespace ekicore::keystore::detail {

// The length of the NUL-terminated text, found by reading at most max_len + 1 bytes, or nullopt
// when no NUL is among them (the text is longer than max_len).
[[nodiscard]] std::optional<std::size_t> bounded_length(const char* text,
                                                        std::size_t max_len) noexcept;

// Whether every byte is printable ASCII (0x20..0x7E).
[[nodiscard]] bool printable(std::span<const char> text) noexcept;

// The status of a backend outcome. A failure's detail becomes the last-error text; an
// EKI_ERR_BACKEND failure always leaves text, even from a backend that gave none.
eki_status record(eki_ks& ks, outcome result);

// Whether some object carries id (EKI_OK with exists set), or the backend's failure.
eki_status id_taken(eki_ks& ks, const key_id& id, bool& exists);

// The existence check: the objects that carry id, whether or not they are a key the library can
// describe. When there are none the result is nullopt and status is EKI_ERR_KEY_NOT_FOUND, or the
// backend's failure. An operation that takes two ids checks both before it describes either
// (plan 4.2), so that a foreign object never hides a missing key.
std::optional<key_lookup> find_object(eki_ks& ks, const key_id& id, eki_status& status);

// The key that existing objects are. A foreign object (plan 4.3) gives nullopt with status
// EKI_ERR_BACKEND and a last-error text.
std::optional<key_info> describe(eki_ks& ks, const key_lookup& found, eki_status& status);

// find_object, then describe: the key that id names, KEY_NOT_FOUND before a foreign object.
std::optional<key_info> find_existing(eki_ks& ks, const key_id& id, eki_status& status);

// What an operation does with a key, as the state table of ABI 2 contract section 3 sorts them:
// protect something new (sign, hmac, wrap as the kek, rotate as the old key: ACTIVE only), or
// check or recover what the key protected before (get_public_key, hmac_verify, wrap as the key
// being wrapped, unwrap as the kek: ACTIVE or RETIRED).
enum class key_use : std::uint8_t { protect, recover };

// EKI_OK when a key in state may be used this way, else EKI_ERR_KEY_STATE.
[[nodiscard]] eki_status require_state(key_state state, key_use use) noexcept;

// The key id exists, has algorithm `wanted`, and its state permits `use`: KEY_NOT_FOUND, then
// WRONG_KEY_TYPE, then KEY_STATE.
eki_status require_key(eki_ks& ks, const key_id& id, key_alg wanted, key_use use);

// A fresh id for a new key: 16 bytes from OpenSSL's RNG. An id that some key already carries
// would mean a broken RNG; it is reported as a backend failure rather than overwriting the key.
eki_status new_key_id(eki_ks& ks, key_id& id);

// One call as the audit log sees it, and the changes it made that must be undone if it does not
// succeed. An operation fills the record's ids as it establishes them and registers each change
// right before it makes it. Every member is trivially copyable, so registering never allocates.
struct call {
  explicit call(audit::op operation) noexcept {
    record.operation = operation;
  }

  struct state_change {
    key_id id{};
    key_state after = key_state::active;
  };
  struct request_change {
    key_id id{};
    std::optional<dual_control::pending> before;
  };

  // op, key and key2 of the audit record; its status is the call's final status.
  audit::entry record;
  // A key the call created: destroyed again.
  std::optional<key_id> created;
  // A key state the call changed or began to change. No state leads back to an earlier one, so
  // the change stays; a failure to log it says so.
  std::optional<state_change> changed;
  // A pending destroy request the call replaced or approved: put back.
  std::optional<request_change> request;
  // A key the call destroyed. Cannot be undone; a failure to log it says so.
  bool destroyed = false;
};

// Ends a call: when status is not EKI_OK, undoes the registered changes; then writes the audit
// record with the final status. When the record cannot be written the changes of a call that
// succeeded are undone too and the status is EKI_ERR_BACKEND. Returns the call's status.
eki_status finish(eki_ks& ks, call& current, eki_status status);

// The frame of an operation that is not logged (get_info, get_info_v2, audit_head): the
// last-error text is reset on entry, and the entries that the operation pushes onto OpenSSL's
// error queue are confined to it as for a primitive (kept for EKI_ERR_BACKEND, whose reason they
// carry, removed otherwise). The caller's entries are never touched.
template <typename Operation> eki_status run(eki_ks& ks, const Operation& operation) {
  ks.last_error.clear();
  ossl::error_scope errors;
  return errors.settle(operation());
}

// The frame of every logged operation: as run, and the operation receives the call it fills in.
// An exception from the operation ends it with EKI_ERR_INTERNAL, which is logged like any other
// status after the changes made so far are undone.
template <typename Operation>
eki_status run_logged(eki_ks& ks, audit::op operation, const Operation& body) {
  ks.last_error.clear();
  ossl::error_scope errors;
  call current{operation};
  eki_status status = EKI_ERR_INTERNAL;
  try {
    status = body(current);
  } catch (...) {
    status = EKI_ERR_INTERNAL;
  }
  return errors.settle(finish(ks, current, status));
}

} // namespace ekicore::keystore::detail
