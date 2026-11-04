// Hybrid key encapsulation: X25519 and ML-KEM-768 over OpenSSL 3.5's EVP_PKEY interface, with the
// two shared secrets combined by HKDF-SHA256.
//
// Layouts (fixed-width halves, the X25519 part always first):
//   pk = X25519 public key (32) || ML-KEM-768 encapsulation key (1184)
//   sk = X25519 secret key (32) || ML-KEM-768 seed d || z (64)
//   ct = X25519 ephemeral public key (32) || ML-KEM-768 ciphertext (1088)
//   ss = HKDF-SHA256(ikm = ss_x25519 || ss_mlkem, salt = empty,
//                    info = "ekibridge-hybrid-x25519-mlkem768-v1" || ct || pk, L = 32)
//
// sk is 96 random bytes and nothing else: any 32 bytes are a valid X25519 secret (OpenSSL stores
// them as given and clamps when it uses them) and any 64 bytes are a valid ML-KEM seed. The
// expanded ML-KEM key and both public keys are rebuilt from sk whenever they are needed, so pk is
// a pure function of sk and decapsulation can feed the combiner with it.
//
// Statuses. A size that is not the contract's is INVALID_ARGUMENT, and so is input that the
// provider refuses: a peer X25519 point whose Diffie-Hellman result is all zero (OpenSSL's derive
// fails for it) and an ML-KEM encapsulation key that fails the FIPS 203 modulus check on import.
// A failure of OpenSSL itself (fetch, allocation, random numbers) is BACKEND, and only then do its
// error queue entries stay for the caller (ossl::error_scope). Decapsulating any ciphertext of the
// right size succeeds: ML-KEM's implicit rejection returns an unrelated secret for a bad one.
//
// Secrets. sk and ss live in the caller's buffers and are wiped on failure. The ephemeral X25519
// secret and the two shared secrets, the only others, live in stack arrays that are wiped on every
// way out of the function (wiped_array); the EVP_PKEY objects that OpenSSL builds from key bytes
// are released at the end of each call.
//
// Without EKI_WITH_PQ the three functions are still defined and answer EKI_ERR_UNSUPPORTED; only
// the bodies differ, never the declarations.

#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

// The signatures follow the ABI (sk then ct, ct then ss), so adjacent byte spans are inherent to
// the API rather than a design choice.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
namespace ekicore {
namespace {

#ifdef EKI_WITH_PQ

constexpr std::size_t x25519_len = 32;
constexpr std::size_t mlkem_seed_len = 64;
constexpr std::size_t mlkem_ek_len = 1184;
constexpr std::size_t mlkem_ct_len = 1088;
constexpr std::size_t mlkem_ss_len = 32;
constexpr std::size_t ikm_len = x25519_len + mlkem_ss_len;
static_assert(EKI_HYBRID_PK_LEN == x25519_len + mlkem_ek_len, "pk is X25519 key then ek");
static_assert(EKI_HYBRID_SK_LEN == x25519_len + mlkem_seed_len, "sk is X25519 key then seed");
static_assert(EKI_HYBRID_CT_LEN == x25519_len + mlkem_ct_len, "ct is ephemeral key then ML-KEM ct");

constexpr const char* mlkem_name = "ML-KEM-768";
constexpr auto combiner_label = [] {
  constexpr std::string_view text = "ekibridge-hybrid-x25519-mlkem768-v1";
  std::array<std::uint8_t, text.size()> label{};
  std::ranges::transform(text, label.begin(), [](char c) { return static_cast<std::uint8_t>(c); });
  return label;
}();
constexpr std::size_t info_len = combiner_label.size() + EKI_HYBRID_CT_LEN + EKI_HYBRID_PK_LEN;

// Stack storage for secret bytes. The bytes are overwritten when the object goes out of scope, so
// every way out of the function that owns it, early returns included, wipes them. The primitives
// are noexcept and allocate nothing, which rules out secret_buffer (it maps and locks pages and
// throws std::bad_alloc); the values kept here live for one call and are 32 or 64 bytes.
template <std::size_t Size> class wiped_array {
public:
  wiped_array() = default;
  wiped_array(const wiped_array&) = delete;
  wiped_array(wiped_array&&) = delete;
  wiped_array& operator=(const wiped_array&) = delete;
  wiped_array& operator=(wiped_array&&) = delete;
  ~wiped_array() {
    ossl::cleanse(bytes_);
  }

  [[nodiscard]] mut_bytes span() noexcept {
    return bytes_;
  }

private:
  std::array<std::uint8_t, Size> bytes_{};
};

// The X25519 half and the ML-KEM half of a pk, sk or ct.
template <typename Byte> std::span<Byte> x25519_part(std::span<Byte> whole) noexcept {
  return whole.first(x25519_len);
}
template <typename Byte> std::span<Byte> mlkem_part(std::span<Byte> whole) noexcept {
  return whole.subspan(x25519_len);
}

// An OSSL_PARAM for a read-only octet string. OSSL_PARAM has no const variant; OpenSSL only reads
// input parameters, so casting the const away is sound.
OSSL_PARAM octets(const char* name, bytes value) noexcept {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
  return OSSL_PARAM_construct_octet_string(name, const_cast<std::uint8_t*>(value.data()),
                                           value.size());
}

// Whether the newest entry on this thread's error queue is the provider's report of this reason.
// A failed EVP call returns only a failure code; the reason on the queue is what separates input
// that the provider refused from a fault of the backend (an allocation, a missing algorithm), and
// the two get different statuses.
bool provider_reported(int reason) noexcept {
  const unsigned long entry = ERR_peek_last_error();
  return ERR_GET_LIB(entry) == ERR_LIB_PROV && ERR_GET_REASON(entry) == reason;
}

// X25519 ------------------------------------------------------------------------------------

// OpenSSL keeps raw private bytes as given (it does not clamp them on import) and derives the
// public key and the shared secret from the clamped scalar, as RFC 7748 prescribes.
ossl::pkey x25519_private(bytes secret) noexcept {
  return ossl::pkey{
      EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, secret.data(), secret.size())};
}

// Any 32 bytes load as a public key: OpenSSL does not validate the point at import.
ossl::pkey x25519_public(bytes point) noexcept {
  return ossl::pkey{
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, point.data(), point.size())};
}

// Writes the public key of secret (32 bytes) into point (32 bytes).
bool x25519_public_of(bytes secret, mut_bytes point) noexcept {
  const ossl::pkey key = x25519_private(secret);
  std::size_t len = point.size();
  return key && EVP_PKEY_get_raw_public_key(key.get(), point.data(), &len) == 1 &&
         len == x25519_len;
}

// Writes X25519(secret, peer) into shared (32 bytes). OpenSSL's derive fails when the result is
// all zero, which is what a peer point of small order produces; that is the one failure that the
// peer's bytes cause, and it is reported as INVALID_ARGUMENT. Any other failure is the backend's.
eki_status x25519_agree(bytes secret, bytes peer, mut_bytes shared) noexcept {
  const ossl::pkey own = x25519_private(secret);
  const ossl::pkey other = x25519_public(peer);
  if (!own || !other) {
    return EKI_ERR_BACKEND;
  }
  const ossl::pkey_ctx ctx{EVP_PKEY_CTX_new(own.get(), nullptr)};
  if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
      EVP_PKEY_derive_set_peer(ctx.get(), other.get()) != 1) {
    return EKI_ERR_BACKEND;
  }
  std::size_t len = shared.size();
  if (EVP_PKEY_derive(ctx.get(), shared.data(), &len) != 1) {
    return provider_reported(PROV_R_FAILED_DURING_DERIVATION) ? EKI_ERR_INVALID_ARGUMENT
                                                              : EKI_ERR_BACKEND;
  }
  return len == x25519_len ? EKI_OK : EKI_ERR_BACKEND;
}

// ML-KEM-768 --------------------------------------------------------------------------------

// The key pair that a 64-byte seed d || z generates. A seed is not accepted as a raw private key
// (that form is the 2400-byte FIPS 203 dk), so it goes in as the key generation parameter that
// OpenSSL documents for a pre-determined seed.
ossl::pkey mlkem_from_seed(bytes seed) noexcept {
  const ossl::pkey_ctx ctx{EVP_PKEY_CTX_new_from_name(nullptr, mlkem_name, nullptr)};
  const std::array<OSSL_PARAM, 2> params{
      octets(OSSL_PKEY_PARAM_ML_KEM_SEED, seed),
      OSSL_PARAM_construct_end(),
  };
  EVP_PKEY* raw = nullptr;
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
      EVP_PKEY_CTX_set_params(ctx.get(), params.data()) != 1 ||
      EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
    return nullptr;
  }
  return ossl::pkey{raw};
}

// Writes the encapsulation key of key (1184 bytes) into ek.
bool mlkem_encapsulation_key(const EVP_PKEY* key, mut_bytes ek) noexcept {
  std::size_t len = ek.size();
  return EVP_PKEY_get_raw_public_key(key, ek.data(), &len) == 1 && len == mlkem_ek_len;
}

// The outcome of an import that can fail for a reason the caller caused or for an internal one.
struct key_result {
  ossl::pkey key;
  eki_status status;
};

// Imports an encapsulation key of the right length. The provider decodes it and applies the FIPS
// 203 modulus check (every 12-bit coefficient must be below q = 3329); a key that fails is
// reported as an invalid key, which is INVALID_ARGUMENT. Any other failure is the backend's.
key_result mlkem_import_encapsulation_key(bytes ek) noexcept {
  const ossl::pkey_ctx ctx{EVP_PKEY_CTX_new_from_name(nullptr, mlkem_name, nullptr)};
  // EVP_PKEY_fromdata takes the parameter array as mutable, although it only reads it.
  std::array<OSSL_PARAM, 2> params{
      octets(OSSL_PKEY_PARAM_PUB_KEY, ek),
      OSSL_PARAM_construct_end(),
  };
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) {
    return {.key = nullptr, .status = EKI_ERR_BACKEND};
  }
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.data()) != 1) {
    const eki_status status =
        provider_reported(PROV_R_INVALID_KEY) ? EKI_ERR_INVALID_ARGUMENT : EKI_ERR_BACKEND;
    return {.key = nullptr, .status = status};
  }
  return {.key = ossl::pkey{raw}, .status = EKI_OK};
}

// Encapsulates to key: ciphertext (1088 bytes) and shared secret (32 bytes). The randomness comes
// from OpenSSL's DRBG; the provider's "ikme" parameter that fixes it is meant for tests only and
// is not used.
bool mlkem_encapsulate(EVP_PKEY* key, mut_bytes ct, mut_bytes ss) noexcept {
  const ossl::pkey_ctx ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr)};
  std::size_t ct_len = ct.size();
  std::size_t ss_len = ss.size();
  return ctx && EVP_PKEY_encapsulate_init(ctx.get(), nullptr) == 1 &&
         EVP_PKEY_encapsulate(ctx.get(), ct.data(), &ct_len, ss.data(), &ss_len) == 1 &&
         ct_len == mlkem_ct_len && ss_len == mlkem_ss_len;
}

// Decapsulates ct (1088 bytes) into ss (32 bytes). FIPS 203 implicit rejection: a ciphertext that
// was not made for key still gives a success and an unrelated secret, so a failure here is never
// the ciphertext's fault.
bool mlkem_decapsulate(EVP_PKEY* key, bytes ct, mut_bytes ss) noexcept {
  const ossl::pkey_ctx ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr)};
  std::size_t ss_len = ss.size();
  return ctx && EVP_PKEY_decapsulate_init(ctx.get(), nullptr) == 1 &&
         EVP_PKEY_decapsulate(ctx.get(), ss.data(), &ss_len, ct.data(), ct.size()) == 1 &&
         ss_len == mlkem_ss_len;
}

// The hybrid public key of sk: the X25519 public key of its first 32 bytes, then the encapsulation
// key of mlkem, which is the key that the seed in the last 64 bytes generates.
bool rebuild_public_key(bytes sk, const EVP_PKEY* mlkem, mut_bytes pk) noexcept {
  return x25519_public_of(x25519_part(sk), x25519_part(pk)) &&
         mlkem_encapsulation_key(mlkem, mlkem_part(pk));
}

// Combiner ----------------------------------------------------------------------------------

// ss = HKDF-SHA256(ikm, no salt, label || ct || pk), where ikm is ss_x25519 || ss_mlkem. Binding
// ct and pk into the output ties the secret to this exchange whatever either half does with its
// own inputs: the X25519 part ignores the top bit of the ephemeral key, and implicit rejection
// hands back some secret for any ML-KEM ciphertext.
eki_status combine(bytes ikm, bytes ct, bytes pk, mut_bytes ss) noexcept {
  std::array<std::uint8_t, info_len> info{};
  mut_bytes rest{info};
  const auto append = [&rest](bytes part) {
    std::ranges::copy(part, rest.begin());
    rest = rest.subspan(part.size());
  };
  append(combiner_label);
  append(ct);
  append(pk);
  return hkdf_sha256(ikm, {}, info, ss);
}

// The three operations --------------------------------------------------------------------

eki_status keygen(mut_bytes pk, mut_bytes sk) noexcept {
  if (pk.size() != EKI_HYBRID_PK_LEN || sk.size() != EKI_HYBRID_SK_LEN) {
    return EKI_ERR_INVALID_ARGUMENT;
  }
  // The secret is drawn straight into the caller's buffer; no second copy is made here.
  if (RAND_priv_bytes(sk.data(), static_cast<int>(sk.size())) != 1) {
    return EKI_ERR_BACKEND;
  }
  const ossl::pkey mlkem = mlkem_from_seed(mlkem_part(sk));
  if (!mlkem || !rebuild_public_key(sk, mlkem.get(), pk)) {
    return EKI_ERR_BACKEND;
  }
  return EKI_OK;
}

eki_status encap(bytes pk, mut_bytes ct, mut_bytes ss) noexcept {
  if (pk.size() != EKI_HYBRID_PK_LEN || ct.size() != EKI_HYBRID_CT_LEN ||
      ss.size() != EKI_HYBRID_SS_LEN) {
    return EKI_ERR_INVALID_ARGUMENT;
  }
  // The key is checked before any random bytes are drawn: a refused input is reported as such even
  // when the generator would also fail.
  const key_result imported = mlkem_import_encapsulation_key(mlkem_part(pk));
  if (imported.status != EKI_OK) {
    return imported.status;
  }
  wiped_array<x25519_len> ephemeral;
  wiped_array<ikm_len> ikm;
  if (RAND_priv_bytes(ephemeral.span().data(), static_cast<int>(x25519_len)) != 1 ||
      !x25519_public_of(ephemeral.span(), x25519_part(ct))) {
    return EKI_ERR_BACKEND;
  }
  const eki_status agreed =
      x25519_agree(ephemeral.span(), x25519_part(pk), x25519_part(ikm.span()));
  if (agreed != EKI_OK) {
    return agreed;
  }
  if (!mlkem_encapsulate(imported.key.get(), mlkem_part(ct), mlkem_part(ikm.span()))) {
    return EKI_ERR_BACKEND;
  }
  return combine(ikm.span(), ct, pk, ss);
}

eki_status decap(bytes sk, bytes ct, mut_bytes ss) noexcept {
  if (sk.size() != EKI_HYBRID_SK_LEN || ct.size() != EKI_HYBRID_CT_LEN ||
      ss.size() != EKI_HYBRID_SS_LEN) {
    return EKI_ERR_INVALID_ARGUMENT;
  }
  const ossl::pkey mlkem = mlkem_from_seed(mlkem_part(sk));
  std::array<std::uint8_t, EKI_HYBRID_PK_LEN> pk{};
  if (!mlkem || !rebuild_public_key(sk, mlkem.get(), pk)) {
    return EKI_ERR_BACKEND;
  }
  wiped_array<ikm_len> ikm;
  const eki_status agreed = x25519_agree(x25519_part(sk), x25519_part(ct), x25519_part(ikm.span()));
  if (agreed != EKI_OK) {
    return agreed;
  }
  if (!mlkem_decapsulate(mlkem.get(), mlkem_part(ct), mlkem_part(ikm.span()))) {
    return EKI_ERR_BACKEND;
  }
  return combine(ikm.span(), ct, pk, ss);
}

#else // !EKI_WITH_PQ

// The contract answers a function that is not compiled in before it looks at any length, so these
// ignore their arguments.
eki_status keygen([[maybe_unused]] mut_bytes pk, [[maybe_unused]] mut_bytes sk) noexcept {
  return EKI_ERR_UNSUPPORTED;
}

eki_status encap([[maybe_unused]] bytes pk, [[maybe_unused]] mut_bytes ct,
                 [[maybe_unused]] mut_bytes ss) noexcept {
  return EKI_ERR_UNSUPPORTED;
}

eki_status decap([[maybe_unused]] bytes sk, [[maybe_unused]] bytes ct,
                 [[maybe_unused]] mut_bytes ss) noexcept {
  return EKI_ERR_UNSUPPORTED;
}

#endif

// Zero-fills out when it has the size the contract gives it; a span of any other size is not
// touched, since nothing says that the caller's buffer is that large.
void wipe_output(mut_bytes out, std::size_t size) noexcept {
  if (out.size() == size) {
    ossl::cleanse(out);
  }
}

} // namespace

eki_status hybrid_kem_keygen(mut_bytes pk, mut_bytes sk) noexcept {
  ossl::error_scope errors;
  const eki_status status = keygen(pk, sk);
  if (status != EKI_OK) {
    wipe_output(pk, EKI_HYBRID_PK_LEN);
    wipe_output(sk, EKI_HYBRID_SK_LEN);
  }
  return errors.settle(status);
}

eki_status hybrid_kem_encap(bytes pk, mut_bytes ct, mut_bytes ss) noexcept {
  ossl::error_scope errors;
  const eki_status status = encap(pk, ct, ss);
  if (status != EKI_OK) {
    wipe_output(ct, EKI_HYBRID_CT_LEN);
    wipe_output(ss, EKI_HYBRID_SS_LEN);
  }
  return errors.settle(status);
}

eki_status hybrid_kem_decap(bytes sk, bytes ct, mut_bytes ss) noexcept {
  ossl::error_scope errors;
  const eki_status status = decap(sk, ct, ss);
  if (status != EKI_OK) {
    wipe_output(ss, EKI_HYBRID_SS_LEN);
  }
  return errors.settle(status);
}

} // namespace ekicore
// NOLINTEND(bugprone-easily-swappable-parameters)
