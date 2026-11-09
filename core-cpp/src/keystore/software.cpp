// The software backend of the key store: keys live in memory, in a map owned by the handle, and
// disappear with it. Secret keys (AES-256, HMAC-SHA256) are 32 bytes in a secret_buffer; an ECDSA
// P-256 key pair is an OpenSSL EVP_PKEY. The lifecycle state of a key is a field of its entry.

#include <ekicore/keystore.hpp>
#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>
#include <ekicore/secret_buffer.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>

namespace ekicore::keystore {
namespace {

constexpr std::size_t secret_key_len = 32;
constexpr std::size_t scalar_len = EKI_P256_SIGNATURE_LEN / 2;

// Largest DER encoding of a P-256 ECDSA-Sig-Value: SEQUENCE header (2) plus two INTEGERs of at
// most 33 content bytes each (a leading zero when the top bit is set) with 2-byte headers.
constexpr std::size_t max_der_len = 2 + (2 * (2 + scalar_len + 1));

// The key material of one entry: the 32 secret bytes of an AES-256 or HMAC-SHA256 key, or an
// ECDSA P-256 key pair. For the key pair OpenSSL holds the private scalar inside the EVP_PKEY, in
// memory that OpenSSL allocates and this library does not lock; EVP_PKEY_free clears the scalar
// before freeing it.
using material = std::variant<secret_buffer, ossl::pkey>;

struct software_key {
  key_alg alg;
  key_label label;
  material key;
  key_state state = key_state::active;
};

// Draws a new 32-byte secret straight into its secret_buffer. RAND_priv_bytes is OpenSSL's RNG
// for private values: the same generator as RAND_bytes, with a separate instance, so key ids and
// key material never come from the same stream.
outcome new_secret(secret_buffer& secret) {
  secret = secret_buffer(secret_key_len);
  if (RAND_priv_bytes(secret.data(), static_cast<int>(secret.size())) != 1) {
    return openssl_failure("RAND_priv_bytes for a secret key");
  }
  return {};
}

// Generates a P-256 key pair.
outcome new_key_pair(ossl::pkey& key_pair) {
  const ossl::pkey_ctx ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
  EVP_PKEY* raw = nullptr;
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
      EVP_PKEY_CTX_set_group_name(ctx.get(), "P-256") != 1 ||
      EVP_PKEY_generate(ctx.get(), &raw) != 1) {
    return openssl_failure("P-256 key generation");
  }
  key_pair.reset(raw);
  return {};
}

// Signs SHA-256(msg) with key_pair and leaves the DER signature in der; der_len is its length.
outcome sign_der(EVP_PKEY* key_pair, bytes msg, std::array<std::uint8_t, max_der_len>& der,
                 std::size_t& der_len) {
  const ossl::md_ctx ctx{EVP_MD_CTX_new()};
  if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key_pair) != 1) {
    return openssl_failure("ECDSA signing setup");
  }
  // An empty message may come with a null data(); OpenSSL gets a valid pointer regardless.
  static constexpr std::uint8_t empty = 0;
  const std::uint8_t* msg_data = msg.empty() ? &empty : msg.data();
  der_len = der.size();
  if (EVP_DigestSign(ctx.get(), der.data(), &der_len, msg_data, msg.size()) != 1) {
    return openssl_failure("ECDSA signing");
  }
  return {};
}

// Converts a DER ECDSA-Sig-Value into fixed-width r || s, each left-padded to 32 bytes.
outcome der_to_fixed(bytes der, mut_bytes sig64) {
  const std::uint8_t* cursor = der.data();
  const ossl::ecdsa_sig sig{d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(der.size()))};
  if (!sig) {
    return openssl_failure("decoding the DER signature");
  }
  const BIGNUM* r = nullptr;
  const BIGNUM* s = nullptr;
  ECDSA_SIG_get0(sig.get(), &r, &s);
  const int pad = static_cast<int>(scalar_len);
  if (BN_bn2binpad(r, sig64.first(scalar_len).data(), pad) != pad ||
      BN_bn2binpad(s, sig64.subspan(scalar_len).data(), pad) != pad) {
    return openssl_failure("encoding r || s");
  }
  return {};
}

// An outcome for a primitive's status; what was attempted names the OpenSSL failure.
outcome from_primitive(eki_status status, std::string_view what) {
  if (status == EKI_ERR_BACKEND) {
    return openssl_failure(what);
  }
  return {.status = status, .detail = {}};
}

// A broken precondition: layer 2 checked the key's existence and type under the same lock.
outcome precondition_failed() {
  return {.status = EKI_ERR_INTERNAL, .detail = "key store precondition violated"};
}

class software_backend final : public backend {
public:
  // Every entry is a key the library created, so an id that exists always has its info.
  outcome find(const key_id& id, key_lookup& found) override {
    const auto entry = keys_.find(id);
    found = key_lookup{};
    if (entry != keys_.end()) {
      found.exists = true;
      found.info.emplace(entry->second.alg, entry->second.label, entry->second.state);
    }
    return {};
  }

  outcome create(key_alg alg, const key_label& label, const key_id& id) override {
    material key;
    outcome result;
    if (alg == key_alg::ecdsa_p256) {
      result = new_key_pair(key.emplace<ossl::pkey>());
    } else {
      result = new_secret(key.emplace<secret_buffer>());
    }
    if (result.status != EKI_OK) {
      return result;
    }
    return insert(id, software_key{.alg = alg, .label = label, .key = std::move(key)});
  }

  outcome public_key(const key_id& id, mut_bytes out65) override {
    const EVP_PKEY* key_pair = key_pair_of(id);
    if (key_pair == nullptr) {
      return precondition_failed();
    }
    // A key generated by OpenSSL encodes its point uncompressed unless told otherwise.
    std::size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(key_pair, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, out65.data(),
                                        out65.size(), &len) != 1 ||
        len != EKI_P256_PUBLIC_KEY_LEN || out65.front() != 0x04) {
      return openssl_failure("reading the public key");
    }
    return {};
  }

  outcome sign(const key_id& id, bytes msg, mut_bytes sig64) override {
    EVP_PKEY* key_pair = key_pair_of(id);
    if (key_pair == nullptr) {
      return precondition_failed();
    }
    std::array<std::uint8_t, max_der_len> der{};
    std::size_t der_len = 0;
    outcome result = sign_der(key_pair, msg, der, der_len);
    if (result.status != EKI_OK) {
      return result;
    }
    return der_to_fixed(bytes{der}.first(der_len), sig64);
  }

  outcome hmac_sha256(const key_id& id, bytes msg, mut_bytes out32) override {
    const secret_buffer* key = secret_of(id);
    if (key == nullptr) {
      return precondition_failed();
    }
    return from_primitive(ekicore::hmac_sha256(key->span(), msg, out32), "HMAC-SHA256");
  }

  outcome wrap(const key_id& kek, const key_id& key, mut_bytes out40) override {
    const secret_buffer* kek_secret = secret_of(kek);
    const secret_buffer* key_secret = secret_of(key);
    if (kek_secret == nullptr || key_secret == nullptr) {
      return precondition_failed();
    }
    return from_primitive(aes_256_key_wrap(kek_secret->span(), key_secret->span(), out40),
                          "AES key wrap");
  }

  outcome unwrap(const key_id& kek, bytes blob40, key_alg alg, const key_label& label,
                 const key_id& id) override {
    const secret_buffer* kek_secret = secret_of(kek);
    if (kek_secret == nullptr) {
      return precondition_failed();
    }
    secret_buffer secret(secret_key_len);
    outcome result = from_primitive(aes_256_key_unwrap(kek_secret->span(), blob40, secret.span()),
                                    "AES key unwrap");
    if (result.status != EKI_OK) {
      return result;
    }
    return insert(id, software_key{.alg = alg, .label = label, .key = std::move(secret)});
  }

  outcome destroy(const key_id& id) override {
    // Erasing the entry destroys its material: the secret_buffer wipes its bytes, the EVP_PKEY
    // is freed by OpenSSL, which clears the private scalar.
    if (keys_.erase(id) == 0) {
      return precondition_failed();
    }
    return {};
  }

  outcome set_state(const key_id& id, key_state state) override {
    const auto entry = keys_.find(id);
    if (entry == keys_.end()) {
      return precondition_failed();
    }
    // Forward only: a state earlier than the key's leaves it as it is.
    entry->second.state = std::max(entry->second.state, state);
    return {};
  }

  outcome hmac_sha256_verify(const key_id& id, bytes msg, bytes tag32) override {
    const secret_buffer* key = secret_of(id);
    if (key == nullptr) {
      return precondition_failed();
    }
    return from_primitive(ekicore::hmac_sha256_verify(key->span(), msg, tag32),
                          "HMAC-SHA256 verification");
  }

private:
  // Adds a fully built entry: the only step of create and unwrap that changes the map. try_emplace
  // either inserts or, when the node allocation throws, leaves the map as it was; moving the entry
  // into the node cannot throw. An id already in use is a broken precondition and the entry is
  // dropped (and wiped) without touching the existing key.
  outcome insert(const key_id& id, software_key entry) {
    if (!keys_.try_emplace(id, std::move(entry)).second) {
      return precondition_failed();
    }
    return {};
  }

  // The secret bytes of id, or nullptr when id names no secret key.
  [[nodiscard]] const secret_buffer* secret_of(const key_id& id) const {
    const auto entry = keys_.find(id);
    return entry == keys_.end() ? nullptr : std::get_if<secret_buffer>(&entry->second.key);
  }

  // The key pair of id, or nullptr when id names no key pair.
  [[nodiscard]] EVP_PKEY* key_pair_of(const key_id& id) const {
    const auto entry = keys_.find(id);
    if (entry == keys_.end()) {
      return nullptr;
    }
    const ossl::pkey* key_pair = std::get_if<ossl::pkey>(&entry->second.key);
    return key_pair == nullptr ? nullptr : key_pair->get();
  }

  // Ordered by the id bytes (std::array's lexicographic comparison). A tree rather than a hash
  // table: callers choose ids in unwrap, and a tree costs O(log n) per lookup whatever the ids
  // are, with no hash function to choose or defend. Ids are not secret, so the comparison need
  // not be constant time.
  std::map<key_id, software_key> keys_;
};

} // namespace

std::unique_ptr<backend> make_software_backend() {
  return std::make_unique<software_backend>();
}

} // namespace ekicore::keystore
