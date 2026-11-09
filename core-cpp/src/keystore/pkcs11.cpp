// The PKCS#11 backend of the key store (plan 4.3): keys are token objects, reached through one
// read-write session per handle on a module that pkcs11_module.cpp loads and initialises.
//
// Objects follow the plan's mapping table, so that both ekicore libraries can use keys the other
// created in the same token. A key is the set of objects that carry its CKA_ID: one secret key
// object (AES-256, HMAC-SHA256) or a private and a public key object (ECDSA P-256). Objects that
// carry an id but form none of these shapes, or whose CKA_LABEL is not a valid label, were made by
// another program; they still take the id (plan 4.3, amended).
//
// The lifecycle state of a key is the set of its usage attributes (ABI 2 contract section 3): the
// token itself refuses what the state forbids, and every library and process that uses the token
// sees the same state. A combination of usage attributes that spells no state makes the objects
// foreign like a broken shape.
//
// Every operation looks its objects up again by id: object handles are not kept between calls,
// since another session or process may destroy or replace the objects in between.

#include "pkcs11_module.hpp"

#include <ekicore/keystore.hpp>
#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>
#include <ekicore/secret_buffer.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <bit>
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

using pkcs11::failure;
using pkcs11::module_lease;

constexpr std::size_t secret_key_len = 32;

// CKA_EC_PARAMS of P-256: the DER encoding of the named-curve OID 1.2.840.10045.3.1.7.
constexpr std::array<CK_BYTE, 10> p256_params{
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
};

// CKA_EC_POINT of a P-256 public key: a DER OCTET STRING (tag 0x04, length 65) around the SEC1
// uncompressed point, which starts with 0x04. The point follows the first two bytes.
constexpr std::array<CK_BYTE, 3> ec_point_header{0x04, 0x41, 0x04};
constexpr std::size_t ec_point_der_len = 2;
constexpr std::size_t ec_point_len = ec_point_der_len + EKI_P256_PUBLIC_KEY_LEN;

// The attribute values that templates point at. PKCS#11 types every template value as a
// non-const pointer, but the module only reads through it (see attribute()).
constexpr CK_BBOOL yes = CK_TRUE;
constexpr CK_BBOOL no = CK_FALSE;
constexpr CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
constexpr CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;
constexpr CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;
constexpr CK_KEY_TYPE aes_key_type = CKK_AES;
constexpr CK_KEY_TYPE generic_secret_key_type = CKK_GENERIC_SECRET;
constexpr CK_KEY_TYPE ec_key_type = CKK_EC;
constexpr CK_ULONG secret_value_len = secret_key_len;

// A template entry pointing at size bytes at value. The module reads an input template and never
// writes through it, so a pointer to const data is passed as the non-const pointer PKCS#11
// declares.
CK_ATTRIBUTE attribute(CK_ATTRIBUTE_TYPE type, const void* value, std::size_t size) noexcept {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): input template, read-only for the module
  return CK_ATTRIBUTE{.type = type, .pValue = const_cast<void*>(value), .ulValueLen = size};
}

template <typename Value>
CK_ATTRIBUTE attribute(CK_ATTRIBUTE_TYPE type, const Value& value) noexcept {
  return attribute(type, &value, sizeof value);
}

// The data pointer for an input buffer. PKCS#11 declares input data as non-const although the
// module never writes through it. SoftHSM2 answers CKR_ARGUMENTS_BAD for a NULL data pointer even
// with length 0, so an empty input points at a dummy byte instead (plan 4.3, "empty data").
CK_BYTE_PTR input(bytes data) noexcept {
  static constexpr CK_BYTE empty_input = 0;
  const CK_BYTE* pointer = data.empty() ? &empty_input : data.data();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): input data, read-only for the module
  return const_cast<CK_BYTE_PTR>(pointer);
}

CK_MECHANISM mechanism(CK_MECHANISM_TYPE type) noexcept {
  return CK_MECHANISM{.mechanism = type, .pParameter = nullptr, .ulParameterLen = 0};
}

// The usage and protection attributes of a secret key of alg, from the plan's table; generate and
// unwrap give a key the same ones.
std::vector<CK_ATTRIBUTE> secret_key_usage(key_alg alg) {
  if (alg == key_alg::aes_256) {
    return {
        attribute(CKA_SENSITIVE, yes), attribute(CKA_EXTRACTABLE, yes), attribute(CKA_WRAP, yes),
        attribute(CKA_UNWRAP, yes),    attribute(CKA_ENCRYPT, yes),     attribute(CKA_DECRYPT, yes),
    };
  }
  return {
      attribute(CKA_SIGN, yes),
      attribute(CKA_VERIFY, yes),
      attribute(CKA_SENSITIVE, yes),
      attribute(CKA_EXTRACTABLE, yes),
  };
}

// The template of a new secret key of alg (AES-256 or HMAC-SHA256): class, key type, the common
// attributes, then the usage attributes of its row. CKA_VALUE_LEN is not part of it: generate adds
// it, unwrap must not (SoftHSM2 rejects it there, the length comes from the blob).
std::vector<CK_ATTRIBUTE> secret_key_template(key_alg alg, const key_label& label,
                                              const key_id& id) {
  std::vector<CK_ATTRIBUTE> attributes{
      attribute(CKA_CLASS, secret_key_class),
      attribute(CKA_KEY_TYPE, alg == key_alg::aes_256 ? aes_key_type : generic_secret_key_type),
      attribute(CKA_TOKEN, yes),
      attribute(CKA_PRIVATE, yes),
      attribute(CKA_ID, id.data(), id.size()),
      attribute(CKA_LABEL, label.view().data(), label.view().size()),
  };
  const std::vector<CK_ATTRIBUTE> usage = secret_key_usage(alg);
  attributes.insert(attributes.end(), usage.begin(), usage.end());
  return attributes;
}

// One usage attribute of the state table (ABI 2 contract section 3): the object it sits on and its
// value in each state, in the order ACTIVE, RETIRED, REVOKED.
struct usage_flag {
  // On the public key of a key pair; otherwise on the secret key or the private key.
  bool on_public_key;
  CK_ATTRIBUTE_TYPE type;
  std::array<CK_BBOOL, 3> values;
};

constexpr std::array<usage_flag, 4> aes_flags{
    usage_flag{.on_public_key = false, .type = CKA_WRAP, .values = {yes, no, no}},
    usage_flag{.on_public_key = false, .type = CKA_ENCRYPT, .values = {yes, no, no}},
    usage_flag{.on_public_key = false, .type = CKA_UNWRAP, .values = {yes, yes, no}},
    usage_flag{.on_public_key = false, .type = CKA_DECRYPT, .values = {yes, yes, no}},
};
constexpr std::array<usage_flag, 2> hmac_flags{
    usage_flag{.on_public_key = false, .type = CKA_SIGN, .values = {yes, no, no}},
    usage_flag{.on_public_key = false, .type = CKA_VERIFY, .values = {yes, yes, no}},
};
constexpr std::array<usage_flag, 2> ecdsa_flags{
    usage_flag{.on_public_key = false, .type = CKA_SIGN, .values = {yes, no, no}},
    usage_flag{.on_public_key = true, .type = CKA_VERIFY, .values = {yes, yes, no}},
};

constexpr std::array<key_state, 3> all_states{
    key_state::active,
    key_state::retired,
    key_state::revoked,
};

// The usage attributes that spell the state of a key of alg.
std::span<const usage_flag> usage_flags(key_alg alg) noexcept {
  switch (alg) {
  case key_alg::aes_256:
    return aes_flags;
  case key_alg::hmac_sha256:
    return hmac_flags;
  case key_alg::ecdsa_p256:
    break;
  }
  return ecdsa_flags;
}

// The column of state in usage_flag::values.
std::size_t state_column(key_state state) noexcept {
  return static_cast<std::size_t>(state) - static_cast<std::size_t>(key_state::active);
}

// A read-write session, closed on destruction. Closing never logs out: login state belongs to the
// whole application, and C_Logout would log out every other handle on the token (plan 4.3).
class session {
public:
  session() = default;
  session(CK_FUNCTION_LIST* functions, CK_SESSION_HANDLE handle) noexcept
      : functions_(functions), handle_(handle) {}
  session(const session&) = delete;
  session& operator=(const session&) = delete;
  session(session&& other) noexcept
      : functions_(std::exchange(other.functions_, nullptr)),
        handle_(std::exchange(other.handle_, CK_INVALID_HANDLE)) {}
  session& operator=(session&& other) noexcept {
    if (this != &other) {
      close();
      functions_ = std::exchange(other.functions_, nullptr);
      handle_ = std::exchange(other.handle_, CK_INVALID_HANDLE);
    }
    return *this;
  }
  ~session() {
    close();
  }

  [[nodiscard]] CK_SESSION_HANDLE handle() const noexcept {
    return handle_;
  }

private:
  void close() noexcept {
    if (functions_ != nullptr && handle_ != CK_INVALID_HANDLE) {
      // A session that cannot be closed is left to C_Finalize or process exit.
      static_cast<void>(functions_->C_CloseSession(handle_));
    }
    functions_ = nullptr;
    handle_ = CK_INVALID_HANDLE;
  }

  CK_FUNCTION_LIST* functions_ = nullptr;
  CK_SESSION_HANDLE handle_ = CK_INVALID_HANDLE;
};

// An active C_FindObjectsInit search, finished on destruction unless finish() was called, so that
// a failing step or a throwing allocation does not leave the session unable to search again.
class search_guard {
public:
  search_guard(CK_FUNCTION_LIST* functions, CK_SESSION_HANDLE session) noexcept
      : functions_(functions), session_(session) {}
  search_guard(const search_guard&) = delete;
  search_guard(search_guard&&) = delete;
  search_guard& operator=(const search_guard&) = delete;
  search_guard& operator=(search_guard&&) = delete;
  ~search_guard() {
    if (active_) {
      static_cast<void>(functions_->C_FindObjectsFinal(session_));
    }
  }

  // Finishes the search and returns what C_FindObjectsFinal returned.
  CK_RV finish() noexcept {
    active_ = false;
    return functions_->C_FindObjectsFinal(session_);
  }

private:
  CK_FUNCTION_LIST* functions_;
  CK_SESSION_HANDLE session_;
  bool active_ = true;
};

// The objects that carry one id, as find, the operations and destroy need them.
struct located {
  // Every object that carries the id, of any class.
  std::vector<CK_OBJECT_HANDLE> objects;
  // Set when the objects form one of the library's key shapes with a valid label, whatever their
  // usage attributes.
  std::optional<key_alg> shape;
  // Set when, in addition, the usage attributes spell a state.
  std::optional<key_info> info;
  // The secret key, or the private key of a key pair; valid when shape is set.
  CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
  // The public key of a key pair; valid when shape is ECDSA P-256.
  CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
};

// What one object is, as far as the shapes care.
struct object_kind {
  CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
  std::optional<CK_OBJECT_CLASS> object_class;
  std::optional<CK_KEY_TYPE> key_type;
};

class pkcs11_backend final : public backend {
public:
  pkcs11_backend(module_lease lease, session opened) noexcept
      : lease_(std::move(lease)), session_(std::move(opened)) {}
  pkcs11_backend(const pkcs11_backend&) = delete;
  pkcs11_backend(pkcs11_backend&&) = delete;
  pkcs11_backend& operator=(const pkcs11_backend&) = delete;
  pkcs11_backend& operator=(pkcs11_backend&&) = delete;
  // The session closes before the lease is released, so C_Finalize, when it comes, finds no
  // session of this handle open. Both happen inside an error scope: eki_ks_close has none, and a
  // module that uses the same libcrypto as this library may push entries onto the caller's error
  // queue while it closes or finalises.
  ~pkcs11_backend() override {
    const ossl::error_scope errors;
    session_ = session{};
    lease_ = module_lease{};
  }

  outcome find(const key_id& id, key_lookup& found) override {
    found = key_lookup{};
    located objects;
    outcome result = locate(id, objects);
    if (result.status != EKI_OK) {
      return result;
    }
    found.exists = !objects.objects.empty();
    found.info = objects.info;
    return {};
  }

  outcome create(key_alg alg, const key_label& label, const key_id& id) override {
    if (alg == key_alg::ecdsa_p256) {
      return create_key_pair(label, id);
    }
    std::vector<CK_ATTRIBUTE> attributes = secret_key_template(alg, label, id);
    attributes.push_back(attribute(CKA_VALUE_LEN, secret_value_len));
    CK_MECHANISM generate =
        mechanism(alg == key_alg::aes_256 ? CKM_AES_KEY_GEN : CKM_GENERIC_SECRET_KEY_GEN);
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    const CK_RV rv = functions()->C_GenerateKey(session_.handle(), &generate, attributes.data(),
                                                attributes.size(), &key);
    return rv == CKR_OK ? outcome{} : failure("C_GenerateKey", rv);
  }

  outcome public_key(const key_id& id, mut_bytes out65) override {
    located objects;
    outcome result = locate_key(id, key_alg::ecdsa_p256, objects);
    if (result.status != EKI_OK) {
      return result;
    }
    std::array<CK_BYTE, ec_point_len> point{};
    std::optional<std::size_t> point_len;
    result = read_attribute(objects.public_key, CKA_EC_POINT, point, point_len);
    if (result.status != EKI_OK) {
      return result;
    }
    const std::span<const CK_BYTE> value{point};
    if (point_len != ec_point_len ||
        !std::ranges::equal(value.first(ec_point_header.size()), ec_point_header)) {
      return outcome{
          .status = EKI_ERR_BACKEND,
          .detail = "CKA_EC_POINT of the public key is not a DER OCTET STRING holding "
                    "an uncompressed P-256 point",
      };
    }
    std::ranges::copy(value.subspan(ec_point_der_len), out65.begin());
    return {};
  }

  outcome sign(const key_id& id, bytes msg, mut_bytes sig64) override {
    located objects;
    outcome result = locate_key(id, key_alg::ecdsa_p256, objects);
    if (result.status != EKI_OK) {
      return result;
    }
    // CKM_ECDSA signs a digest that the caller computes (plan 4.3, "sign").
    std::array<CK_BYTE, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    if (EVP_Digest(msg.data(), msg.size(), digest.data(), &digest_len, EVP_sha256(), nullptr) !=
        1) {
      return openssl_failure("EVP_Digest SHA-256");
    }
    return sign_with(objects.key, CKM_ECDSA, bytes{digest}.first(digest_len), sig64);
  }

  outcome hmac_sha256(const key_id& id, bytes msg, mut_bytes out32) override {
    located objects;
    outcome result = locate_key(id, key_alg::hmac_sha256, objects);
    if (result.status != EKI_OK) {
      return result;
    }
    return sign_with(objects.key, CKM_SHA256_HMAC, msg, out32);
  }

  outcome wrap(const key_id& kek, const key_id& key, mut_bytes out40) override {
    located wrapping;
    outcome result = locate_key(kek, key_alg::aes_256, wrapping);
    if (result.status != EKI_OK) {
      return result;
    }
    located wrapped;
    result = locate(key, wrapped);
    if (result.status != EKI_OK) {
      return result;
    }
    if (!wrapped.info.has_value() || wrapped.info->alg == key_alg::ecdsa_p256) {
      return precondition_broken();
    }
    CK_MECHANISM key_wrap = mechanism(CKM_AES_KEY_WRAP);
    CK_ULONG written = out40.size();
    const CK_RV rv = functions()->C_WrapKey(session_.handle(), &key_wrap, wrapping.key, wrapped.key,
                                            out40.data(), &written);
    if (rv != CKR_OK) {
      return failure("C_WrapKey", rv);
    }
    // A 32-byte key wraps to 40 bytes; another length means a key of another size that carries a
    // type the library maps to a 32-byte key.
    if (written != out40.size()) {
      return outcome{
          .status = EKI_ERR_BACKEND,
          .detail = "C_WrapKey produced " + std::to_string(written) +
                    " bytes instead of 40: the key is not 32 bytes long",
      };
    }
    return {};
  }

  outcome unwrap(const key_id& kek, bytes blob40, key_alg alg, const key_label& label,
                 const key_id& id) override {
    located wrapping;
    outcome result = locate_key(kek, key_alg::aes_256, wrapping);
    if (result.status != EKI_OK) {
      return result;
    }
    std::vector<CK_ATTRIBUTE> attributes = secret_key_template(alg, label, id);
    CK_MECHANISM key_wrap = mechanism(CKM_AES_KEY_WRAP);
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    const CK_RV rv =
        functions()->C_UnwrapKey(session_.handle(), &key_wrap, wrapping.key, input(blob40),
                                 blob40.size(), attributes.data(), attributes.size(), &key);
    if (rv != CKR_OK) {
      // Every failure here counts as a failed integrity check (plan 4.3, return-code mapping):
      // SoftHSM2 reports a wrong RFC 3394 check value as CKR_GENERAL_ERROR, which cannot be told
      // apart from other causes. Layer 2 has checked everything else by now.
      outcome rejected = failure("C_UnwrapKey", rv);
      rejected.status = EKI_ERR_AUTH_FAILED;
      return rejected;
    }
    return {};
  }

  outcome destroy(const key_id& id) override {
    located objects;
    outcome result = locate(id, objects);
    if (result.status != EKI_OK) {
      return result;
    }
    if (objects.objects.empty()) {
      return precondition_broken();
    }
    for (const CK_OBJECT_HANDLE object : objects.objects) {
      const CK_RV rv = functions()->C_DestroyObject(session_.handle(), object);
      if (rv != CKR_OK) {
        return failure("C_DestroyObject", rv);
      }
    }
    return {};
  }

  // Only clears attributes, never sets one: the token itself lets a cleared usage attribute be
  // set back to TRUE (SoftHSM2 2.7.0), so this is what keeps a key from moving back. The
  // "protect" group (the attributes FALSE from RETIRED on) is cleared first, then the "recover"
  // group; within a group the secret or private key before the public key. A change that stops
  // halfway thus leaves the key RETIRED or foreign, never more usable than before.
  outcome set_state(const key_id& id, key_state state) override {
    located objects;
    outcome result = locate(id, objects);
    if (result.status != EKI_OK) {
      return result;
    }
    if (!objects.shape.has_value()) {
      return precondition_broken();
    }
    const std::span<const usage_flag> flags = usage_flags(*objects.shape);
    for (const bool protect_group : {true, false}) {
      for (const bool on_public_key : {false, true}) {
        const CK_OBJECT_HANDLE object = on_public_key ? objects.public_key : objects.key;
        const flag_selection selection{
            .protect_group = protect_group,
            .on_public_key = on_public_key,
            .state = state,
        };
        result = clear_flags(object, flags, selection);
        if (result.status != EKI_OK) {
          return result;
        }
      }
    }
    return {};
  }

  // C_Verify ends the operation whatever it returns, CKR_SIGNATURE_INVALID and
  // CKR_SIGNATURE_LEN_RANGE included (checked on SoftHSM2 2.7.0).
  outcome hmac_sha256_verify(const key_id& id, bytes msg, bytes tag32) override {
    located objects;
    outcome result = locate_key(id, key_alg::hmac_sha256, objects);
    if (result.status != EKI_OK) {
      return result;
    }
    CK_MECHANISM verify_mechanism = mechanism(CKM_SHA256_HMAC);
    CK_RV rv = functions()->C_VerifyInit(session_.handle(), &verify_mechanism, objects.key);
    if (rv != CKR_OK) {
      return failure("C_VerifyInit", rv);
    }
    rv = functions()->C_Verify(session_.handle(), input(msg), msg.size(), input(tag32),
                               tag32.size());
    if (rv == CKR_SIGNATURE_INVALID || rv == CKR_SIGNATURE_LEN_RANGE) {
      return outcome{.status = EKI_ERR_AUTH_FAILED, .detail = {}};
    }
    return rv == CKR_OK ? outcome{} : failure("C_Verify", rv);
  }

private:
  [[nodiscard]] CK_FUNCTION_LIST* functions() const noexcept {
    return lease_.functions();
  }

  // Layer 2 checked the key before the call, but the token is shared: another session or process
  // may have changed it since. That is a backend condition, not an internal error.
  static outcome precondition_broken() {
    return outcome{
        .status = EKI_ERR_BACKEND,
        .detail = "the token's objects for this key id changed during the operation",
    };
  }

  outcome create_key_pair(const key_label& label, const key_id& id) {
    std::array public_template{
        attribute(CKA_CLASS, public_key_class),
        attribute(CKA_KEY_TYPE, ec_key_type),
        attribute(CKA_TOKEN, yes),
        attribute(CKA_PRIVATE, no),
        attribute(CKA_ID, id.data(), id.size()),
        attribute(CKA_LABEL, label.view().data(), label.view().size()),
        attribute(CKA_EC_PARAMS, p256_params),
        attribute(CKA_VERIFY, yes),
    };
    std::array private_template{
        attribute(CKA_CLASS, private_key_class),
        attribute(CKA_KEY_TYPE, ec_key_type),
        attribute(CKA_TOKEN, yes),
        attribute(CKA_PRIVATE, yes),
        attribute(CKA_ID, id.data(), id.size()),
        attribute(CKA_LABEL, label.view().data(), label.view().size()),
        attribute(CKA_SIGN, yes),
        attribute(CKA_SENSITIVE, yes),
        attribute(CKA_EXTRACTABLE, no),
    };
    CK_MECHANISM generate = mechanism(CKM_EC_KEY_PAIR_GEN);
    CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;
    const CK_RV rv = functions()->C_GenerateKeyPair(
        session_.handle(), &generate, public_template.data(), public_template.size(),
        private_template.data(), private_template.size(), &public_key, &private_key);
    return rv == CKR_OK ? outcome{} : failure("C_GenerateKeyPair", rv);
  }

  // A single-part C_Sign with mechanism type under key: data in, exactly out.size() bytes out.
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters): PKCS#11 types are all CK_ULONG
  outcome sign_with(CK_OBJECT_HANDLE key, CK_MECHANISM_TYPE type, bytes data, mut_bytes out) {
    CK_MECHANISM sign_mechanism = mechanism(type);
    CK_RV rv = functions()->C_SignInit(session_.handle(), &sign_mechanism, key);
    if (rv != CKR_OK) {
      return failure("C_SignInit", rv);
    }
    // C_Sign ends the operation whatever it returns, except for CKR_BUFFER_TOO_SMALL, which
    // cannot happen: out has room for the mechanism's full output.
    CK_ULONG written = out.size();
    rv = functions()->C_Sign(session_.handle(), input(data), data.size(), out.data(), &written);
    if (rv != CKR_OK) {
      return failure("C_Sign", rv);
    }
    if (written != out.size()) {
      return outcome{
          .status = EKI_ERR_BACKEND,
          .detail = "C_Sign produced " + std::to_string(written) + " bytes instead of " +
                    std::to_string(out.size()),
      };
    }
    return {};
  }

  // locate(), then the requirement that layer 2 has already checked: the key exists and is alg.
  outcome locate_key(const key_id& id, key_alg alg, located& objects) {
    outcome result = locate(id, objects);
    if (result.status != EKI_OK) {
      return result;
    }
    if (!objects.info.has_value() || objects.info->alg != alg) {
      return precondition_broken();
    }
    return {};
  }

  // Finds every object that carries id and works out whether they form a key of the library.
  outcome locate(const key_id& id, located& objects) {
    objects = located{};
    outcome result = find_objects(id, objects.objects);
    if (result.status != EKI_OK) {
      return result;
    }
    std::vector<object_kind> kinds;
    kinds.reserve(objects.objects.size());
    for (const CK_OBJECT_HANDLE object : objects.objects) {
      object_kind kind{.handle = object, .object_class = std::nullopt, .key_type = std::nullopt};
      result = read_kind(object, kind);
      if (result.status != EKI_OK) {
        return result;
      }
      kinds.push_back(kind);
    }
    std::optional<key_alg> alg;
    result = classify(objects, kinds, alg);
    if (result.status != EKI_OK || !alg.has_value()) {
      return result;
    }
    std::optional<key_label> label;
    result = read_label(objects.key, label);
    if (result.status != EKI_OK || !label.has_value()) {
      return result;
    }
    objects.shape = *alg;
    std::optional<key_state> state;
    result = read_state(objects, *alg, state);
    if (result.status != EKI_OK || !state.has_value()) {
      return result;
    }
    objects.info.emplace(*alg, *label, *state);
    return {};
  }

  // The state that the usage attributes of the located key spell, or nullopt when an attribute is
  // missing or the combination is none of the table's rows. A CK_BBOOL other than CK_FALSE counts
  // as TRUE.
  outcome read_state(const located& objects, key_alg alg, std::optional<key_state>& state) {
    state.reset();
    const std::span<const usage_flag> flags = usage_flags(alg);
    std::array<bool, aes_flags.size()> values{};
    auto* value_out = values.begin();
    for (const usage_flag& flag : flags) {
      std::optional<bool> value;
      outcome result =
          read_flag(flag.on_public_key ? objects.public_key : objects.key, flag.type, value);
      if (result.status != EKI_OK || !value.has_value()) {
        return result;
      }
      *value_out++ = *value;
    }
    const std::span<const bool> read{values.begin(), flags.size()};
    for (const key_state candidate : all_states) {
      const std::size_t column = state_column(candidate);
      const bool matches =
          std::ranges::equal(flags, read, [column](const usage_flag& flag, bool value) {
            return value == (flag.values.at(column) != CK_FALSE);
          });
      if (matches) {
        state = candidate;
        return {};
      }
    }
    return {};
  }

  // Reads a CK_BBOOL attribute; nullopt as for read_attribute, and also when the value is not one
  // byte long.
  outcome read_flag(CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type, std::optional<bool>& value) {
    value.reset();
    std::array<CK_BYTE, sizeof(CK_BBOOL)> raw{};
    std::optional<std::size_t> length;
    outcome read = read_attribute(object, type, raw, length);
    if (read.status == EKI_OK && length == raw.size()) {
      value = raw.front() != CK_FALSE;
    }
    return read;
  }

  // Which usage attributes one C_SetAttributeValue call clears.
  struct flag_selection {
    // The "protect" group (FALSE from RETIRED on), or the "recover" group (FALSE in REVOKED).
    bool protect_group;
    // The attributes on the public key of a key pair, or those on the other object.
    bool on_public_key;
    // The state whose FALSE attributes are cleared.
    key_state state;
  };

  // Sets to CK_FALSE, with one C_SetAttributeValue call, the selected attributes that are FALSE in
  // the selected state. Nothing is called when there are none.
  outcome clear_flags(CK_OBJECT_HANDLE object, std::span<const usage_flag> flags,
                      const flag_selection& selection) {
    const std::size_t column = state_column(selection.state);
    const std::size_t retired = state_column(key_state::retired);
    std::vector<CK_ATTRIBUTE> attributes;
    for (const usage_flag& flag : flags) {
      const bool in_protect_group = flag.values.at(retired) == CK_FALSE;
      if (in_protect_group == selection.protect_group &&
          flag.on_public_key == selection.on_public_key && flag.values.at(column) == CK_FALSE) {
        attributes.push_back(attribute(flag.type, flag.values.at(column)));
      }
    }
    if (attributes.empty()) {
      return {};
    }
    const CK_RV rv = functions()->C_SetAttributeValue(session_.handle(), object, attributes.data(),
                                                      attributes.size());
    return rv == CKR_OK ? outcome{} : failure("C_SetAttributeValue", rv);
  }

  // The shapes the library creates: one secret key of type AES or GENERIC_SECRET, or one private
  // and one public key of type EC on P-256. alg stays empty for anything else. CKA_VALUE_LEN is
  // never read (plan 4.3, "get_info").
  outcome classify(located& objects, std::span<const object_kind> kinds,
                   std::optional<key_alg>& alg) {
    alg.reset();
    if (kinds.size() == 1 && kinds.front().object_class == CKO_SECRET_KEY) {
      if (kinds.front().key_type == CKK_AES) {
        alg = key_alg::aes_256;
      } else if (kinds.front().key_type == CKK_GENERIC_SECRET) {
        alg = key_alg::hmac_sha256;
      }
      objects.key = kinds.front().handle;
      return {};
    }
    if (kinds.size() != 2) {
      return {};
    }
    for (const object_kind& kind : kinds) {
      if (kind.key_type != CKK_EC) {
        return {};
      }
      if (kind.object_class == CKO_PRIVATE_KEY) {
        objects.key = kind.handle;
      } else if (kind.object_class == CKO_PUBLIC_KEY) {
        objects.public_key = kind.handle;
      }
    }
    if (objects.key == CK_INVALID_HANDLE || objects.public_key == CK_INVALID_HANDLE) {
      return {};
    }
    for (const CK_OBJECT_HANDLE half : {objects.key, objects.public_key}) {
      bool on_p256 = false;
      outcome result = is_p256(half, on_p256);
      if (result.status != EKI_OK || !on_p256) {
        return result;
      }
    }
    alg = key_alg::ecdsa_p256;
    return {};
  }

  // C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal on CKA_ID. The search is always
  // finished, also when a step fails or allocation throws, so that the session can search again.
  outcome find_objects(const key_id& id, std::vector<CK_OBJECT_HANDLE>& found) {
    found.clear();
    std::array search{attribute(CKA_ID, id.data(), id.size())};
    CK_RV rv = functions()->C_FindObjectsInit(session_.handle(), search.data(), search.size());
    if (rv != CKR_OK) {
      return failure("C_FindObjectsInit", rv);
    }
    search_guard guard{functions(), session_.handle()};
    std::array<CK_OBJECT_HANDLE, 16> batch{};
    while (true) {
      CK_ULONG count = 0;
      rv = functions()->C_FindObjects(session_.handle(), batch.data(), batch.size(), &count);
      if (rv != CKR_OK) {
        return failure("C_FindObjects", rv);
      }
      if (count == 0) {
        break;
      }
      const auto returned = std::span{batch}.first(std::min<std::size_t>(count, batch.size()));
      found.insert(found.end(), returned.begin(), returned.end());
    }
    rv = guard.finish();
    return rv == CKR_OK ? outcome{} : failure("C_FindObjectsFinal", rv);
  }

  // Reads one attribute of object into buffer. length is its size, or nullopt when the object has
  // no such attribute, keeps it secret, or holds a value longer than buffer: the codes PKCS#11
  // gives for these (CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_SENSITIVE, CKR_BUFFER_TOO_SMALL)
  // describe the object, not a failure.
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters): PKCS#11 types are all CK_ULONG
  outcome read_attribute(CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type, std::span<CK_BYTE> buffer,
                         std::optional<std::size_t>& length) {
    length.reset();
    CK_ATTRIBUTE value{.type = type, .pValue = buffer.data(), .ulValueLen = buffer.size()};
    const CK_RV rv = functions()->C_GetAttributeValue(session_.handle(), object, &value, 1);
    if (rv == CKR_ATTRIBUTE_TYPE_INVALID || rv == CKR_ATTRIBUTE_SENSITIVE ||
        rv == CKR_BUFFER_TOO_SMALL) {
      return {};
    }
    if (rv != CKR_OK) {
      return failure("C_GetAttributeValue", rv);
    }
    if (value.ulValueLen != CK_UNAVAILABLE_INFORMATION && value.ulValueLen <= buffer.size()) {
      length = value.ulValueLen;
    }
    return {};
  }

  // Reads a CK_ULONG attribute (CKA_CLASS, CKA_KEY_TYPE); nullopt as for read_attribute, and also
  // when the value does not have the size of a CK_ULONG.
  outcome read_ulong(CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
                     std::optional<CK_ULONG>& result) {
    result.reset();
    std::array<CK_BYTE, sizeof(CK_ULONG)> raw{};
    std::optional<std::size_t> length;
    outcome read = read_attribute(object, type, raw, length);
    if (read.status == EKI_OK && length == raw.size()) {
      result = std::bit_cast<CK_ULONG>(raw);
    }
    return read;
  }

  outcome read_kind(CK_OBJECT_HANDLE object, object_kind& kind) {
    outcome result = read_ulong(object, CKA_CLASS, kind.object_class);
    if (result.status != EKI_OK) {
      return result;
    }
    if (kind.object_class == CKO_SECRET_KEY || kind.object_class == CKO_PRIVATE_KEY ||
        kind.object_class == CKO_PUBLIC_KEY) {
      result = read_ulong(object, CKA_KEY_TYPE, kind.key_type);
    }
    return result;
  }

  // Whether CKA_EC_PARAMS of object names P-256 by its OID.
  outcome is_p256(CK_OBJECT_HANDLE object, bool& on_p256) {
    std::array<CK_BYTE, p256_params.size()> params{};
    std::optional<std::size_t> length;
    outcome result = read_attribute(object, CKA_EC_PARAMS, params, length);
    on_p256 = result.status == EKI_OK && length == params.size() &&
              std::ranges::equal(params, p256_params);
    return result;
  }

  // The label of object, or nullopt when CKA_LABEL is missing or is not a valid label.
  outcome read_label(CK_OBJECT_HANDLE object, std::optional<key_label>& label) {
    label.reset();
    std::array<CK_BYTE, EKI_LABEL_MAX_LEN> raw{};
    std::optional<std::size_t> length;
    outcome result = read_attribute(object, CKA_LABEL, raw, length);
    if (result.status == EKI_OK && length.has_value()) {
      std::array<char, EKI_LABEL_MAX_LEN> text{};
      std::ranges::transform(raw, text.begin(),
                             [](CK_BYTE byte) { return static_cast<char>(byte); });
      label = key_label::from_bytes(std::span<const char>{text}.first(*length));
    }
    return result;
  }

  module_lease lease_;
  session session_;
};

// The slot whose token label, blank-padded to 32 bytes, equals label. Slots whose token cannot be
// read (removed meanwhile, not recognised) are passed over.
outcome find_slot(CK_FUNCTION_LIST* functions, const std::string& label, CK_SLOT_ID& slot) {
  std::array<CK_UTF8CHAR, pkcs11_token_label_max_len> wanted{};
  std::ranges::fill(wanted, static_cast<CK_UTF8CHAR>(' '));
  std::ranges::transform(label, wanted.begin(), [](char c) { return static_cast<CK_UTF8CHAR>(c); });

  std::vector<CK_SLOT_ID> slots;
  CK_RV rv = CKR_BUFFER_TOO_SMALL;
  // The slot count may grow between the two calls; the module then answers CKR_BUFFER_TOO_SMALL.
  while (rv == CKR_BUFFER_TOO_SMALL) {
    CK_ULONG count = 0;
    rv = functions->C_GetSlotList(CK_TRUE, nullptr, &count);
    if (rv != CKR_OK) {
      return failure("C_GetSlotList", rv);
    }
    slots.resize(count);
    rv = functions->C_GetSlotList(CK_TRUE, slots.data(), &count);
    slots.resize(std::min<std::size_t>(count, slots.size()));
  }
  if (rv != CKR_OK) {
    return failure("C_GetSlotList", rv);
  }
  for (const CK_SLOT_ID candidate : slots) {
    CK_TOKEN_INFO info{};
    if (functions->C_GetTokenInfo(candidate, &info) == CKR_OK &&
        std::ranges::equal(info.label, wanted)) {
      slot = candidate;
      return {};
    }
  }
  return outcome{.status = EKI_ERR_BACKEND, .detail = "no token with label \"" + label + "\""};
}

} // namespace

outcome make_pkcs11_backend(pkcs11_config config, std::unique_ptr<backend>& out) {
  out.reset();
  // The lease is declared before the session, so on every failure path the session closes first
  // and C_Finalize (when this was the last lease) finds it closed.
  module_lease lease;
  outcome result = module_lease::acquire(config.module_path, lease);
  if (result.status != EKI_OK) {
    return result;
  }
  CK_FUNCTION_LIST* functions = lease.functions();
  CK_SLOT_ID slot = 0;
  result = find_slot(functions, config.token_label, slot);
  if (result.status != EKI_OK) {
    return result;
  }
  CK_SESSION_HANDLE handle = CK_INVALID_HANDLE;
  CK_RV rv = functions->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                      &handle);
  if (rv != CKR_OK) {
    return failure("C_OpenSession", rv);
  }
  session opened{functions, handle};
  {
    // The PIN leaves the configuration here and is wiped when this block ends, right after login.
    secret_buffer pin = std::move(config.user_pin);
    rv = functions->C_Login(handle, CKU_USER, pin.data(), pin.size());
  }
  // Login state belongs to the application: while another handle is logged in to the token, the
  // module answers CKR_USER_ALREADY_LOGGED_IN whatever the PIN (plan 4.3).
  if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
    return failure("C_Login", rv);
  }
  out = std::make_unique<pkcs11_backend>(std::move(lease), std::move(opened));
  return {};
}

} // namespace ekicore::keystore
