// Opening and closing a key store handle (ABI 2 contract section 4). eki_ks_open and eki_ks_open_v2
// share one path: open builds the version 2 configuration with no audit log and no approvers and
// hands it to open_v2. The checks run in contract order: the backend selector; the NULL checks of
// the fields in field order; the formats of the fields in field order; then the backend is opened,
// and the audit log last. Failures before the handle exists are reported as a status only: there
// is no handle to carry a message.

#include "store_internal.hpp"

#include <ekicore/audit_log.hpp>
#include <ekicore/dual_control.hpp>
#include <ekicore/keystore.hpp>
#include <ekicore/openssl_raii.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace ekicore::keystore {

namespace {

using detail::bounded_length;
using detail::printable;

#ifdef EKI_WITH_PKCS11
constexpr bool pkcs11_compiled_in = true;
#else
constexpr bool pkcs11_compiled_in = false;
#endif

// Step 2: the backend selector. EKI_KS_PKCS11 in a build without EKI_WITH_PKCS11 names a backend
// that is not compiled in, which is EKI_ERR_UNSUPPORTED before any field is looked at.
eki_status check_selector(eki_ks_backend selector) noexcept {
  if (selector == EKI_KS_SOFTWARE) {
    return EKI_OK;
  }
  if (selector == EKI_KS_PKCS11) {
    return pkcs11_compiled_in ? EKI_OK : EKI_ERR_UNSUPPORTED;
  }
  return EKI_ERR_INVALID_ARGUMENT;
}

// The approver keys as one span of approver_count * 65 bytes. Called only once the pointer is
// known to be non-NULL and the count to be at most EKI_APPROVERS_MAX.
bytes approver_bytes(const eki_ks_config_v2& config) noexcept {
  return {config.approver_public_keys, config.approver_count * EKI_P256_PUBLIC_KEY_LEN};
}

// Step 1 for the fields: every NULL check, in field order, before any format check. The PKCS#11
// fields count only for that backend; the approver keys only when approver_count is not 0, whatever
// the count (amendment 1).
bool fields_present(const eki_ks_config_v2& config) noexcept {
  if (config.backend == EKI_KS_PKCS11 &&
      (config.pkcs11_module_path == nullptr || config.pkcs11_token_label == nullptr ||
       config.pkcs11_user_pin == nullptr)) {
    return false;
  }
  return config.approver_count == 0 || config.approver_public_keys != nullptr;
}

// The token label: 1..=32 printable bytes, read no further than one byte past the maximum.
std::optional<std::size_t> token_label_length(const char* label) noexcept {
  const std::optional<std::size_t> len = bounded_length(label, pkcs11_token_label_max_len);
  if (!len.has_value() || *len == 0 || !printable({label, *len})) {
    return std::nullopt;
  }
  return len;
}

// The PIN: 1..=255 bytes of any value.
std::optional<std::size_t> user_pin_length(const char* pin) noexcept {
  const std::optional<std::size_t> len = bounded_length(pin, pkcs11_user_pin_max_len);
  if (!len.has_value() || *len == 0) {
    return std::nullopt;
  }
  return len;
}

// The audit log path: 1..=EKI_AUDIT_PATH_MAX_LEN bytes.
std::optional<std::size_t> audit_path_length(const char* path) noexcept {
  const std::optional<std::size_t> len = bounded_length(path, EKI_AUDIT_PATH_MAX_LEN);
  if (!len.has_value() || *len == 0) {
    return std::nullopt;
  }
  return len;
}

// The approver keys: each a valid SEC1 uncompressed P-256 point, no two equal. EKI_ERR_BACKEND
// when OpenSSL fails while parsing one.
eki_status check_approver_keys(bytes keys) noexcept {
  for (std::size_t first = 0; first < keys.size(); first += EKI_P256_PUBLIC_KEY_LEN) {
    const bytes key = keys.subspan(first, EKI_P256_PUBLIC_KEY_LEN);
    const eki_status status = check_public_key(key);
    if (status != EKI_OK) {
      return status;
    }
    for (std::size_t earlier = 0; earlier < first; earlier += EKI_P256_PUBLIC_KEY_LEN) {
      if (std::ranges::equal(keys.subspan(earlier, EKI_P256_PUBLIC_KEY_LEN), key)) {
        return EKI_ERR_INVALID_ARGUMENT;
      }
    }
  }
  return EKI_OK;
}

// Step 3 for the fields, in field order: token label, PIN (PKCS#11 only), audit log path,
// approver_count, approver keys.
eki_status check_formats(const eki_ks_config_v2& config) noexcept {
  if (config.backend == EKI_KS_PKCS11 &&
      (!token_label_length(config.pkcs11_token_label).has_value() ||
       !user_pin_length(config.pkcs11_user_pin).has_value())) {
    return EKI_ERR_INVALID_ARGUMENT;
  }
  if (config.audit_log_path != nullptr && !audit_path_length(config.audit_log_path).has_value()) {
    return EKI_ERR_INVALID_ARGUMENT;
  }
  if (config.approver_count == 0) {
    return EKI_OK;
  }
  if (config.approver_count < dual_control::approvals_needed ||
      config.approver_count > EKI_APPROVERS_MAX) {
    return EKI_ERR_INVALID_ARGUMENT;
  }
  return check_approver_keys(approver_bytes(config));
}

// Opens the backend the checked configuration names. Every failure is EKI_ERR_BACKEND.
eki_status open_backend(const eki_ks_config_v2& config, std::unique_ptr<backend>& out) {
  if (config.backend == EKI_KS_SOFTWARE) {
    // The software backend ignores the PKCS#11 fields of the configuration.
    out = make_software_backend();
    return EKI_OK;
  }
#ifdef EKI_WITH_PKCS11
  // The library keeps no caller pointer: the strings are copied, the PIN into a secret_buffer.
  const std::size_t pin_len = user_pin_length(config.pkcs11_user_pin).value_or(0);
  pkcs11_config copied{
      .module_path = config.pkcs11_module_path,
      .token_label = config.pkcs11_token_label,
      .user_pin = secret_buffer::copy_of(
          bytes{reinterpret_cast<const std::uint8_t*>(config.pkcs11_user_pin), pin_len}),
  };
  return make_pkcs11_backend(std::move(copied), out).status;
#else
  return EKI_ERR_UNSUPPORTED;
#endif
}

// Opens the audit log, when the configuration names one: EKI_ERR_AUTH_FAILED for an existing log
// that fails verification, EKI_ERR_BACKEND for any I/O or locking failure.
eki_status open_log(const eki_ks_config_v2& config, std::unique_ptr<audit_log>& out) {
  if (config.audit_log_path == nullptr) {
    return EKI_OK;
  }
  return audit_log::open(config.audit_log_path, out).status;
}

// The approvers of a configuration with approver_count != 0, copied into the handle.
std::unique_ptr<dual_control> make_approvers(const eki_ks_config_v2& config) {
  if (config.approver_count == 0) {
    return nullptr;
  }
  const bytes keys = approver_bytes(config);
  std::vector<dual_control::public_key> copied(config.approver_count);
  std::size_t offset = 0;
  for (dual_control::public_key& key : copied) {
    std::ranges::copy(keys.subspan(offset, EKI_P256_PUBLIC_KEY_LEN), key.begin());
    offset += EKI_P256_PUBLIC_KEY_LEN;
  }
  return std::make_unique<dual_control>(std::move(copied));
}

// Writes the first record of a new handle. Its status is always EKI_OK: a handle whose open
// record cannot be written is not returned.
eki_status write_open_record(eki_ks& ks) {
  if (!ks.log) {
    return EKI_OK;
  }
  const outcome written = ks.log->append(audit::entry{
      .operation = audit::op::open,
      .key = std::nullopt,
      .key2 = std::nullopt,
      .status = EKI_OK,
  });
  return written.status == EKI_OK ? EKI_OK : EKI_ERR_BACKEND;
}

// Steps 4 and later, once the configuration has passed every check: the backend, then the audit
// log, then the handle with its "open" record. Whatever was opened is closed again on failure,
// when the unique_ptrs go out of scope.
eki_status open_checked(const eki_ks_config_v2& config, eki_ks*& out) {
  std::unique_ptr<backend> store_backend;
  eki_status status = open_backend(config, store_backend);
  if (status != EKI_OK) {
    return status;
  }
  std::unique_ptr<audit_log> store_log;
  status = open_log(config, store_log);
  if (status != EKI_OK) {
    return status;
  }
  auto handle = std::make_unique<eki_ks>(std::move(store_backend), std::move(store_log),
                                         make_approvers(config));
  status = write_open_record(*handle);
  if (status != EKI_OK) {
    return status;
  }
  out = handle.release();
  return EKI_OK;
}

} // namespace

eki_status open(const eki_ks_config& config, eki_ks*& out) {
  const eki_ks_config_v2 widened{
      .backend = config.backend,
      .pkcs11_module_path = config.pkcs11_module_path,
      .pkcs11_token_label = config.pkcs11_token_label,
      .pkcs11_user_pin = config.pkcs11_user_pin,
      .audit_log_path = nullptr,
      .approver_public_keys = nullptr,
      .approver_count = 0,
  };
  return open_v2(widened, out);
}

eki_status open_v2(const eki_ks_config_v2& config, eki_ks*& out) {
  // A module that uses the same libcrypto as this library may push entries onto the caller's
  // error queue while it initialises and logs in; they are confined to this call.
  ossl::error_scope errors;
  eki_status status = check_selector(config.backend);
  if (status != EKI_OK) {
    return errors.settle(status);
  }
  if (!fields_present(config)) {
    return errors.settle(EKI_ERR_NULL_POINTER);
  }
  status = check_formats(config);
  if (status != EKI_OK) {
    return errors.settle(status);
  }
  return errors.settle(open_checked(config, out));
}

void close(eki_ks* ks) noexcept {
  const std::unique_ptr<eki_ks> owned{ks};
  if (!owned || !owned->log) {
    return;
  }
  // A close record that cannot be written cannot be reported either: close returns nothing. The
  // log then ends without it, which a reader sees. The scope is never settled with
  // EKI_ERR_BACKEND, so whatever OpenSSL queued while writing is removed again.
  const ossl::error_scope errors;
  bool written = false;
  try {
    const audit::entry record{
        .operation = audit::op::close,
        .key = std::nullopt,
        .key2 = std::nullopt,
        .status = EKI_OK,
    };
    written = owned->log->append(record).status == EKI_OK;
  } catch (...) {
    written = false;
  }
  static_cast<void>(written);
}

} // namespace ekicore::keystore
