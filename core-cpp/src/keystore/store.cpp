// Layer 2 of the key store: the logic that every backend shares. Each operation follows the
// per-function sequence of the ABI contract (plan 4.2): selector and format checks first, then
// the store state checks in their fixed order, and only then the backend operation. Statuses that
// follow from caller input or store state are decided here and never by a backend.

#include <ekicore/keystore.hpp>
#include <ekicore/openssl_raii.hpp>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

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
  // The loop reads text[0] to text[EKI_LABEL_MAX_LEN] at most: 65 bytes, the contract's bound.
  // The comparison is on the byte value, so it holds whether char is signed or not.
  std::size_t len = 0;
  while (len <= EKI_LABEL_MAX_LEN && text[len] != '\0') {
    const auto byte = static_cast<unsigned char>(text[len]);
    if (byte < 0x20 || byte > 0x7E) {
      return std::nullopt;
    }
    ++len;
  }
  if (len == 0 || len > EKI_LABEL_MAX_LEN) {
    return std::nullopt;
  }
  key_label label;
  std::copy_n(text, len, label.text_.begin());
  label.size_ = len;
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

namespace {

// The frame of every store operation: the last-error text is reset on entry, and the entries
// that the operation pushes onto OpenSSL's error queue are confined to it as for a primitive
// (kept for EKI_ERR_BACKEND, whose reason they carry, removed otherwise). The caller's entries
// are never touched.
template <typename Operation> eki_status run(eki_ks& ks, const Operation& operation) {
  ks.last_error.clear();
  ossl::error_scope errors;
  return errors.settle(operation());
}

// The status of a backend outcome. A failure's detail becomes the last-error text; an
// EKI_ERR_BACKEND failure always leaves text, even from a backend that gave none.
eki_status record(eki_ks& ks, outcome result) {
  if (result.status == EKI_ERR_BACKEND && result.detail.empty()) {
    result.detail = "key store backend failed without a reason";
  }
  if (result.status != EKI_OK) {
    ks.last_error = std::move(result.detail);
  }
  return result.status;
}

// The key that id names. When there is none the result is nullopt and status says why:
// EKI_ERR_KEY_NOT_FOUND when no object carries id, or the backend's failure.
std::optional<key_info> find_existing(eki_ks& ks, const key_id& id, eki_status& status) {
  std::optional<key_info> found;
  status = record(ks, ks.backend->find(id, found));
  if (status != EKI_OK) {
    return std::nullopt;
  }
  if (!found.has_value()) {
    status = EKI_ERR_KEY_NOT_FOUND;
  }
  return found;
}

// The key id exists and has algorithm `wanted`: KEY_NOT_FOUND, then WRONG_KEY_TYPE.
eki_status require_key(eki_ks& ks, const key_id& id, key_alg wanted) {
  eki_status status = EKI_OK;
  const std::optional<key_info> found = find_existing(ks, id, status);
  if (!found.has_value()) {
    return status;
  }
  return found->alg == wanted ? EKI_OK : EKI_ERR_WRONG_KEY_TYPE;
}

// Whether a key of this algorithm can be wrapped: the 32-byte secrets can, a key pair cannot.
bool is_wrappable(key_alg alg) noexcept {
  return alg == key_alg::aes_256 || alg == key_alg::hmac_sha256;
}

// A fresh id for generate: 16 bytes from OpenSSL's RNG. An id that some key already carries
// would mean a broken RNG; it is reported as a backend failure rather than overwriting the key.
eki_status new_key_id(eki_ks& ks, key_id& id) {
  if (RAND_bytes(id.data(), static_cast<int>(id.size())) != 1) {
    return record(ks, openssl_failure("RAND_bytes for a key id"));
  }
  std::optional<key_info> found;
  const eki_status status = record(ks, ks.backend->find(id, found));
  if (status != EKI_OK) {
    return status;
  }
  if (found.has_value()) {
    return record(
        ks, outcome{.status = EKI_ERR_BACKEND, .detail = "the random key id is already in use"});
  }
  return EKI_OK;
}

// Fills info_out: the algorithm, and the label NUL-padded through byte 64.
void write_info(const key_info& info, eki_key_info& info_out) noexcept {
  info_out.alg = to_abi(info.alg);
  const std::span<char> label{info_out.label};
  std::ranges::fill(label, '\0');
  std::ranges::copy(info.label.view(), label.begin());
}

} // namespace

eki_status open(const eki_ks_config& config, eki_ks*& out) {
  std::unique_ptr<backend> store_backend;
  switch (config.backend) {
  case EKI_KS_SOFTWARE:
    // The software backend ignores the PKCS#11 fields of the configuration.
    store_backend = make_software_backend();
    break;
  case EKI_KS_PKCS11:
    // PKCS#11 BACKEND: constructed here once it exists, after the checks of its configuration
    // fields (NULL checks in field order, then the token label and PIN formats). Until then the
    // selector is answered as for a backend that is not compiled in (validation step 2),
    // whatever EKI_WITH_PKCS11 says.
    return EKI_ERR_UNSUPPORTED;
  default:
    return EKI_ERR_INVALID_ARGUMENT;
  }
  auto handle = std::make_unique<eki_ks>(std::move(store_backend));
  out = handle.release();
  return EKI_OK;
}

eki_status generate(eki_ks& ks, eki_key_alg alg, const char* label, eki_key_id& id_out) {
  return run(ks, [&] {
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
    if (status == EKI_OK) {
      std::ranges::copy(id, std::begin(id_out.bytes));
    }
    return status;
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

eki_status get_public_key(eki_ks& ks, const key_id& id, mut_bytes out65) {
  return run(ks, [&] {
    const eki_status status = require_key(ks, id, key_alg::ecdsa_p256);
    if (status != EKI_OK) {
      return status;
    }
    return record(ks, ks.backend->public_key(id, out65));
  });
}

eki_status sign(eki_ks& ks, const key_id& id, bytes msg, mut_bytes sig64) {
  return run(ks, [&] {
    const eki_status status = require_key(ks, id, key_alg::ecdsa_p256);
    if (status != EKI_OK) {
      return status;
    }
    return record(ks, ks.backend->sign(id, msg, sig64));
  });
}

eki_status hmac_sha256(eki_ks& ks, const key_id& id, bytes msg, mut_bytes out32) {
  return run(ks, [&] {
    const eki_status status = require_key(ks, id, key_alg::hmac_sha256);
    if (status != EKI_OK) {
      return status;
    }
    return record(ks, ks.backend->hmac_sha256(id, msg, out32));
  });
}

// Contract order: kek exists, key exists, kek is AES-256, key is AES-256 or HMAC-SHA256.
eki_status wrap(eki_ks& ks, const key_id& kek, const key_id& key, mut_bytes out40) {
  return run(ks, [&] {
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
    return record(ks, ks.backend->wrap(kek, key, out40));
  });
}

// Contract order: alg known, blob_len 40, alg not ECDSA, label format; kek exists, kek is
// AES-256, id free; then the integrity check, which the backend performs.
eki_status unwrap(eki_ks& ks, const key_id& kek, bytes blob, eki_key_alg alg, const char* label,
                  const key_id& id) {
  return run(ks, [&] {
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
    eki_status status = require_key(ks, kek, key_alg::aes_256);
    if (status != EKI_OK) {
      return status;
    }
    std::optional<key_info> taken;
    status = record(ks, ks.backend->find(id, taken));
    if (status != EKI_OK) {
      return status;
    }
    if (taken.has_value()) {
      return EKI_ERR_KEY_EXISTS;
    }
    return record(ks, ks.backend->unwrap(kek, blob, *parsed_alg, *parsed_label, id));
  });
}

eki_status destroy(eki_ks& ks, const key_id& id) {
  return run(ks, [&] {
    eki_status status = EKI_OK;
    if (!find_existing(ks, id, status).has_value()) {
      return status;
    }
    return record(ks, ks.backend->destroy(id));
  });
}

} // namespace ekicore::keystore
