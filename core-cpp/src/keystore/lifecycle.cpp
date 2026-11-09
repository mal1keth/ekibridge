// The store operations that ABI version 2 adds (ABI 2 contract sections 3, 5 and 6): key lifecycle,
// the audit head and verifier, and dual control of destroy. Each operation follows its contract
// sequence top to bottom; the frame (store_internal.hpp) writes the audit record and undoes the
// registered changes when the call does not succeed.

#include "store_internal.hpp"

#include <ekicore/audit_log.hpp>
#include <ekicore/dual_control.hpp>
#include <ekicore/keystore.hpp>
#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <span>

namespace ekicore::keystore {

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

// Moves the key change.id forward to change.after. The change is registered before the backend
// makes it, so that a failure to log the call names it even when it stopped halfway on a token.
// It is never set back: no state leads to an earlier one.
eki_status change_state(eki_ks& ks, call& current, const call::state_change& change) {
  current.changed = change;
  return record(ks, ks.backend->set_state(change.id, change.after));
}

// Fills info_out: the algorithm, the state, and the label NUL-padded through byte 64.
void write_info_v2(const key_info& info, eki_key_info_v2& info_out) noexcept {
  info_out.alg = to_abi(info.alg);
  info_out.state = to_abi(info.state);
  const std::span<char> label{info_out.label};
  std::ranges::fill(label, '\0');
  std::ranges::copy(info.label.view(), label.begin());
}

// The approvals a pending request still needs.
std::uint32_t remaining_for(const dual_control::pending& request) noexcept {
  return dual_control::approvals_needed -
         std::min(request.approvals(), dual_control::approvals_needed);
}

// The approval that completes a request: the key is destroyed and the request removed. A key that
// no longer exists is KEY_NOT_FOUND, and the request is removed all the same (section 6).
eki_status complete_destroy(eki_ks& ks, call& current, const key_id& id,
                            std::uint32_t& remaining_out) {
  bool exists = false;
  eki_status status = id_taken(ks, id, exists);
  if (status != EKI_OK) {
    return status;
  }
  if (!exists) {
    ks.approvers->remove(id);
    return EKI_ERR_KEY_NOT_FOUND;
  }
  status = record(ks, ks.backend->destroy(id));
  if (status != EKI_OK) {
    return status;
  }
  current.destroyed = true;
  ks.approvers->remove(id);
  remaining_out = 0;
  return EKI_OK;
}

} // namespace

eki_status get_info_v2(eki_ks& ks, const key_id& id, eki_key_info_v2& info_out) {
  return run(ks, [&] {
    eki_status status = EKI_OK;
    const std::optional<key_info> found = find_existing(ks, id, status);
    if (!found.has_value()) {
      return status;
    }
    write_info_v2(*found, info_out);
    return EKI_OK;
  });
}

// Contract order: old exists, old ACTIVE, a fresh id, the new key (old algorithm and label), then
// the old key RETIRED. A failure after the new key exists destroys it again (frame), also when
// the record of a rotate that retired the old key cannot be written; the old key then stays
// RETIRED. Audit record: key is the old id, key2 the new id once the call has succeeded.
eki_status rotate(eki_ks& ks, const key_id& old_id, eki_key_id& new_id_out) {
  return run_logged(ks, audit::op::rotate, [&](call& current) {
    current.record.key = old_id;
    eki_status status = EKI_OK;
    const std::optional<key_info> old_key = find_existing(ks, old_id, status);
    if (!old_key.has_value()) {
      return status;
    }
    status = require_state(old_key->state, key_use::protect);
    if (status != EKI_OK) {
      return status;
    }
    key_id new_id{};
    status = new_key_id(ks, new_id);
    if (status != EKI_OK) {
      return status;
    }
    status = record(ks, ks.backend->create(old_key->alg, old_key->label, new_id));
    if (status != EKI_OK) {
      return status;
    }
    current.created = new_id;
    status = change_state(ks, current, {.id = old_id, .after = key_state::retired});
    if (status != EKI_OK) {
      return status;
    }
    current.record.key2 = new_id;
    std::ranges::copy(new_id, std::begin(new_id_out.bytes));
    return EKI_OK;
  });
}

// Contract order: exists (a foreign PKCS#11 object has no state: EKI_ERR_BACKEND), then REVOKED.
// A key that is REVOKED already stays as it is: the backend is not called. A revoke whose record
// cannot be written is EKI_ERR_BACKEND and the key stays REVOKED.
eki_status revoke(eki_ks& ks, const key_id& id) {
  return run_logged(ks, audit::op::revoke, [&](call& current) {
    current.record.key = id;
    eki_status status = EKI_OK;
    const std::optional<key_info> found = find_existing(ks, id, status);
    if (!found.has_value()) {
      return status;
    }
    if (found->state == key_state::revoked) {
      return EKI_OK;
    }
    return change_state(ks, current, {.id = id, .after = key_state::revoked});
  });
}

// Contract order: tag_len 32 (a format check, before the key is looked up), exists, is
// HMAC-SHA256, not REVOKED, then the constant-time comparison, which the backend performs.
eki_status hmac_sha256_verify(eki_ks& ks, const key_id& id, bytes msg, bytes tag) {
  return run_logged(ks, audit::op::hmac_verify, [&](call& current) {
    current.record.key = id;
    if (tag.size() != EKI_HMAC_SHA256_LEN) {
      return EKI_ERR_INVALID_ARGUMENT;
    }
    const eki_status status = require_key(ks, id, key_alg::hmac_sha256, key_use::recover);
    if (status != EKI_OK) {
      return status;
    }
    return record(ks, ks.backend->hmac_sha256_verify(id, msg, tag));
  });
}

// Contract order: the handle has approvers (amendment 8: before any store check), the key exists,
// then 32 fresh random bytes replace any earlier request for the key and its approvals
// (amendment 7).
eki_status destroy_request(eki_ks& ks, const key_id& id, mut_bytes request_out) {
  return run_logged(ks, audit::op::destroy_request, [&](call& current) {
    current.record.key = id;
    if (!ks.approvers) {
      return EKI_ERR_UNSUPPORTED;
    }
    bool exists = false;
    const eki_status status = id_taken(ks, id, exists);
    if (status != EKI_OK) {
      return status;
    }
    if (!exists) {
      return EKI_ERR_KEY_NOT_FOUND;
    }
    dual_control::pending request{};
    if (RAND_bytes(request.value.data(), static_cast<int>(request.value.size())) != 1) {
      return record(ks, openssl_failure("RAND_bytes for a destroy request"));
    }
    if (ks.approvers->in_use(request.value)) {
      return record(ks, outcome{
                            .status = EKI_ERR_BACKEND,
                            .detail = "the random destroy request is already in use",
                        });
    }
    current.request = call::request_change{.id = id, .before = ks.approvers->pending_for(id)};
    ks.approvers->set(id, request);
    std::ranges::copy(request.value, request_out.begin());
    return EKI_OK;
  });
}

// Contract order: the handle has approvers (amendment 8), the approver key is a valid point
// (amendment 9), a pending request has these bytes, the key is one of the approvers, the
// signature verifies over the approval message. Then the approval is recorded; the second
// distinct approval destroys the key. Audit record: key is the id the request names, empty when
// no request matched.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): the order is the C ABI's
eki_status destroy_approve(eki_ks& ks, bytes request, bytes approver_public_key, bytes sig,
                           std::uint32_t& remaining_out) {
  return run_logged(ks, audit::op::destroy_approve, [&](call& current) {
    if (!ks.approvers) {
      return EKI_ERR_UNSUPPORTED;
    }
    eki_status status = check_public_key(approver_public_key);
    if (status == EKI_ERR_BACKEND) {
      return record(ks, openssl_failure("parsing the approver public key"));
    }
    if (status != EKI_OK) {
      return status;
    }
    const auto found = ks.approvers->find(request);
    if (!found.has_value()) {
      return EKI_ERR_KEY_NOT_FOUND;
    }
    const key_id id = found->first;
    dual_control::pending pending = found->second;
    current.record.key = id;
    const std::optional<std::size_t> approver = ks.approvers->approver_index(approver_public_key);
    if (!approver.has_value()) {
      return EKI_ERR_AUTH_FAILED;
    }
    status = ecdsa_p256_verify(approver_public_key, approval_message(pending.value, id), sig);
    if (status == EKI_ERR_BACKEND) {
      return record(ks, openssl_failure("ECDSA verification of an approval"));
    }
    if (status != EKI_OK) {
      return status;
    }
    if (pending.has_approval_of(*approver)) {
      remaining_out = remaining_for(pending);
      return EKI_OK;
    }
    pending.approve(*approver);
    if (pending.approvals() >= dual_control::approvals_needed) {
      return complete_destroy(ks, current, id, remaining_out);
    }
    current.request = call::request_change{.id = id, .before = found->second};
    ks.approvers->set(id, pending);
    remaining_out = remaining_for(pending);
    return EKI_OK;
  });
}

eki_status audit_head(eki_ks& ks, mut_bytes hash_out, std::uint64_t& seq_out) {
  return run(ks, [&] {
    if (!ks.log) {
      return EKI_ERR_UNSUPPORTED;
    }
    std::ranges::copy(ks.log->end().head, hash_out.begin());
    seq_out = ks.log->end().records;
    return EKI_OK;
  });
}

eki_status audit_verify(const char* path, bytes expected_head, std::uint64_t& records_out) {
  ossl::error_scope errors;
  const std::optional<std::size_t> len = detail::bounded_length(path, EKI_AUDIT_PATH_MAX_LEN);
  if (!len.has_value() || *len == 0) {
    return errors.settle(EKI_ERR_INVALID_ARGUMENT);
  }
  audit::chain_end end;
  const eki_status status = audit::verify_path(path, end);
  if (status != EKI_OK) {
    return errors.settle(status);
  }
  if (!expected_head.empty() && !std::ranges::equal(expected_head, end.head)) {
    return errors.settle(EKI_ERR_AUTH_FAILED);
  }
  records_out = end.records;
  return errors.settle(EKI_OK);
}

} // namespace ekicore::keystore
