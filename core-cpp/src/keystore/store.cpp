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
#include <cstddef>
#include <cstdint>
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

namespace {

// The length of the NUL-terminated text, found by reading at most max_len + 1 bytes, or nullopt
// when no NUL is among them (the text is longer than max_len).
std::optional<std::size_t> bounded_length(const char* text, std::size_t max_len) noexcept {
  for (std::size_t len = 0; len <= max_len; ++len) {
    if (text[len] == '\0') {
      return len;
    }
  }
  return std::nullopt;
}

// Whether every byte is printable ASCII (0x20..0x7E). The comparison is on the byte value, so it
// holds whether char is signed or not.
bool printable(std::span<const char> text) noexcept {
  return std::ranges::all_of(text, [](char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte >= 0x20 && byte <= 0x7E;
  });
}

} // namespace

std::optional<key_label> key_label::parse(const char* text) noexcept {
  const std::optional<std::size_t> len = bounded_length(text, EKI_LABEL_MAX_LEN);
  if (!len.has_value()) {
    return std::nullopt;
  }
  return from_bytes({text, *len});
}

std::optional<key_label> key_label::from_bytes(std::span<const char> text) noexcept {
  if (text.empty() || text.size() > EKI_LABEL_MAX_LEN || !printable(text)) {
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

// Whether some object carries id (EKI_OK with exists set), or the backend's failure.
eki_status id_taken(eki_ks& ks, const key_id& id, bool& exists) {
  key_lookup found;
  const eki_status status = record(ks, ks.backend->find(id, found));
  exists = found.exists;
  return status;
}

// The key that id names. When there is none the result is nullopt and status says why:
// EKI_ERR_KEY_NOT_FOUND when no object carries id; EKI_ERR_BACKEND when the objects that carry it
// are not a key the library can represent (a foreign object, plan 4.3); or the backend's failure.
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
                                      "type and label this library can use",
                        });
  }
  return found.info;
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

// The PKCS#11 part of eki_ks_open, after the selector check: validation steps 2 and 3 for the
// configuration fields, then the backend. Without EKI_WITH_PKCS11 the selector names a backend
// that is not compiled in, which step 2 answers with EKI_ERR_UNSUPPORTED before any field is
// looked at. With it, the three fields are checked for NULL in field order before any format
// check, so a NULL field wins over a malformed other field; then the token label (1..=32
// printable bytes) and the PIN (1..=255 bytes), each read no further than one byte past its
// maximum. Every failure after that is EKI_ERR_BACKEND, reported as a status only: there is no
// handle to carry a message.
eki_status open_pkcs11([[maybe_unused]] const eki_ks_config& config,
                       [[maybe_unused]] std::unique_ptr<backend>& out) {
#ifdef EKI_WITH_PKCS11
  if (config.pkcs11_module_path == nullptr || config.pkcs11_token_label == nullptr ||
      config.pkcs11_user_pin == nullptr) {
    return EKI_ERR_NULL_POINTER;
  }
  const std::optional<std::size_t> label_len =
      bounded_length(config.pkcs11_token_label, pkcs11_token_label_max_len);
  if (!label_len.has_value() || *label_len == 0 ||
      !printable({config.pkcs11_token_label, *label_len})) {
    return EKI_ERR_INVALID_ARGUMENT;
  }
  const std::optional<std::size_t> pin_len =
      bounded_length(config.pkcs11_user_pin, pkcs11_user_pin_max_len);
  if (!pin_len.has_value() || *pin_len == 0) {
    return EKI_ERR_INVALID_ARGUMENT;
  }
  // The library keeps no caller pointer: the strings are copied, the PIN into a secret_buffer.
  pkcs11_config copied{
      .module_path = config.pkcs11_module_path,
      .token_label = std::string{config.pkcs11_token_label, *label_len},
      .user_pin = secret_buffer::copy_of(
          bytes{reinterpret_cast<const std::uint8_t*>(config.pkcs11_user_pin), *pin_len}),
  };
  return make_pkcs11_backend(std::move(copied), out).status;
#else
  return EKI_ERR_UNSUPPORTED;
#endif
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
  case EKI_KS_PKCS11: {
    // A module that uses the same libcrypto as this library may push entries onto the caller's
    // error queue while it initialises and logs in; they are confined to this call.
    ossl::error_scope errors;
    const eki_status status = errors.settle(open_pkcs11(config, store_backend));
    if (status != EKI_OK) {
      return status;
    }
    break;
  }
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
    bool taken = false;
    status = id_taken(ks, id, taken);
    if (status != EKI_OK) {
      return status;
    }
    if (taken) {
      return EKI_ERR_KEY_EXISTS;
    }
    return record(ks, ks.backend->unwrap(kek, blob, *parsed_alg, *parsed_label, id));
  });
}

eki_status destroy(eki_ks& ks, const key_id& id) {
  return run(ks, [&] {
    // Any object that carries the id can be destroyed, a foreign one included (plan 4.3).
    bool exists = false;
    const eki_status status = id_taken(ks, id, exists);
    if (status != EKI_OK) {
      return status;
    }
    if (!exists) {
      return EKI_ERR_KEY_NOT_FOUND;
    }
    return record(ks, ks.backend->destroy(id));
  });
}

} // namespace ekicore::keystore
