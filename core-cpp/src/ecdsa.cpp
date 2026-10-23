// ECDSA P-256 / SHA-256 signature verification over OpenSSL's EVP_PKEY interface.

#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace ekicore {
namespace {

constexpr std::size_t scalar_len = EKI_P256_SIGNATURE_LEN / 2;

// Largest DER encoding of a P-256 ECDSA-Sig-Value: SEQUENCE header (2) plus two INTEGERs of at
// most 33 content bytes each (a leading zero when the top bit is set) with 2-byte headers.
constexpr std::size_t max_der_len = 2 + (2 * (2 + scalar_len + 1));

// The outcome of a step that can fail for a reason the caller caused or for an internal one.
struct key_result {
  ossl::pkey key;
  eki_status status;
};

// Imports a SEC1 uncompressed point as a P-256 public key and runs OpenSSL's public key check.
// A point that does not parse or is not on the curve gives EKI_ERR_INVALID_ARGUMENT.
key_result import_public_key(bytes public_key65) noexcept {
  const ossl::param_bld bld{OSSL_PARAM_BLD_new()};
  if (!bld ||
      OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) !=
          1 ||
      OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, public_key65.data(),
                                       public_key65.size()) != 1) {
    return {.key = nullptr, .status = EKI_ERR_BACKEND};
  }
  const ossl::params params{OSSL_PARAM_BLD_to_param(bld.get())};
  const ossl::pkey_ctx import_ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
  if (!params || !import_ctx || EVP_PKEY_fromdata_init(import_ctx.get()) != 1) {
    return {.key = nullptr, .status = EKI_ERR_BACKEND};
  }

  // EVP_PKEY_fromdata decodes the point and rejects coordinates >= p and points off the curve.
  // It cannot tell us whether a failure was the input's fault or an allocation failure; the input
  // is by far the likelier cause, so every failure here counts as INVALID_ARGUMENT.
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_fromdata(import_ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) != 1) {
    return {.key = nullptr, .status = EKI_ERR_INVALID_ARGUMENT};
  }
  ossl::pkey key{raw};

  const ossl::pkey_ctx check_ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr)};
  if (!check_ctx) {
    return {.key = nullptr, .status = EKI_ERR_BACKEND};
  }
  if (EVP_PKEY_public_check(check_ctx.get()) != 1) {
    return {.key = nullptr, .status = EKI_ERR_INVALID_ARGUMENT};
  }
  return {.key = std::move(key), .status = EKI_OK};
}

// DER-encodes r || s into der after checking 1 <= r, s < n. Returns the encoded length, 0 when
// r or s is out of range, or -1 on an internal failure.
int encode_signature(bytes sig64, std::array<std::uint8_t, max_der_len>& der) noexcept {
  const ossl::ec_group group{EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)};
  const BIGNUM* order = group ? EC_GROUP_get0_order(group.get()) : nullptr;
  ossl::bignum r{BN_bin2bn(sig64.data(), static_cast<int>(scalar_len), nullptr)};
  ossl::bignum s{
      BN_bin2bn(sig64.subspan(scalar_len).data(), static_cast<int>(scalar_len), nullptr)};
  if (order == nullptr || !r || !s) {
    return -1;
  }
  if (BN_is_zero(r.get()) != 0 || BN_is_zero(s.get()) != 0 || BN_cmp(r.get(), order) >= 0 ||
      BN_cmp(s.get(), order) >= 0) {
    return 0;
  }

  const ossl::ecdsa_sig sig{ECDSA_SIG_new()};
  if (!sig) {
    return -1;
  }
  // On success ECDSA_SIG_set0 takes ownership of both numbers; on failure they stay ours.
  BIGNUM* const raw_r = r.release();
  BIGNUM* const raw_s = s.release();
  if (ECDSA_SIG_set0(sig.get(), raw_r, raw_s) != 1) {
    BN_clear_free(raw_r);
    BN_clear_free(raw_s);
    return -1;
  }

  const int der_len = i2d_ECDSA_SIG(sig.get(), nullptr);
  if (der_len <= 0 || static_cast<std::size_t>(der_len) > der.size()) {
    return -1;
  }
  std::uint8_t* cursor = der.data();
  return i2d_ECDSA_SIG(sig.get(), &cursor) == der_len ? der_len : -1;
}

// The whole verification; ecdsa_p256_verify wraps it in an error_scope. The OpenSSL entries left
// by the INVALID_ARGUMENT and AUTH_FAILED returns are removed there.
eki_status verify(bytes public_key65, bytes msg, bytes sig64) noexcept {
  if (public_key65.size() != EKI_P256_PUBLIC_KEY_LEN || sig64.size() != EKI_P256_SIGNATURE_LEN ||
      public_key65.front() != 0x04) {
    return EKI_ERR_INVALID_ARGUMENT;
  }
  const key_result imported = import_public_key(public_key65);
  if (imported.status != EKI_OK) {
    return imported.status;
  }

  std::array<std::uint8_t, max_der_len> der{};
  const int der_len = encode_signature(sig64, der);
  if (der_len < 0) {
    return EKI_ERR_BACKEND;
  }
  if (der_len == 0) {
    return EKI_ERR_AUTH_FAILED;
  }

  const ossl::md_ctx ctx{EVP_MD_CTX_new()};
  if (!ctx ||
      EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, imported.key.get()) != 1) {
    return EKI_ERR_BACKEND;
  }
  // An empty message may come with a null data(); hand OpenSSL a valid pointer regardless.
  static constexpr std::uint8_t empty = 0;
  const std::uint8_t* msg_data = msg.empty() ? &empty : msg.data();
  if (EVP_DigestVerify(ctx.get(), der.data(), static_cast<std::size_t>(der_len), msg_data,
                       msg.size()) != 1) {
    return EKI_ERR_AUTH_FAILED;
  }
  return EKI_OK;
}

} // namespace

eki_status ecdsa_p256_verify(bytes public_key65, bytes msg, bytes sig64) noexcept {
  ossl::error_scope errors;
  return errors.settle(verify(public_key65, msg, sig64));
}

} // namespace ekicore
