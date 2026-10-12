// HMAC-SHA256 over OpenSSL's EVP_MAC interface.

#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace ekicore {
namespace {

// Computes the tag into out (exactly 32 bytes). key is non-empty. Does not zero out on failure.
eki_status compute(bytes key, bytes msg, mut_bytes out) noexcept {
  const ossl::mac mac{EVP_MAC_fetch(nullptr, "HMAC", nullptr)};
  if (!mac) {
    return EKI_ERR_BACKEND;
  }
  const ossl::mac_ctx ctx{EVP_MAC_CTX_new(mac.get())};
  if (!ctx) {
    return EKI_ERR_BACKEND;
  }

  // OSSL_PARAM wants a mutable buffer even for a value it only reads.
  std::array<char, sizeof("SHA256")> digest{"SHA256"};
  const std::array<OSSL_PARAM, 2> params{
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest.data(), 0),
      OSSL_PARAM_construct_end(),
  };
  if (EVP_MAC_init(ctx.get(), key.data(), key.size(), params.data()) != 1) {
    return EKI_ERR_BACKEND;
  }

  // EVP_MAC_update takes a size_t, but chunking keeps every update call within int range like the
  // rest of the library, and costs nothing for normal sizes.
  const bool updated = ossl::for_each_chunk(msg.size(), [&](std::size_t offset, std::size_t len) {
    return EVP_MAC_update(ctx.get(), msg.subspan(offset, len).data(), len) == 1;
  });
  if (!updated) {
    return EKI_ERR_BACKEND;
  }

  std::size_t out_len = 0;
  if (EVP_MAC_final(ctx.get(), out.data(), &out_len, out.size()) != 1 ||
      out_len != EKI_HMAC_SHA256_LEN) {
    return EKI_ERR_BACKEND;
  }
  return EKI_OK;
}

} // namespace

eki_status hmac_sha256(bytes key, bytes msg, mut_bytes out32) noexcept {
  const bool out_ok = out32.size() == EKI_HMAC_SHA256_LEN;
  eki_status status = EKI_OK;
  if (key.empty() || !out_ok) {
    status = EKI_ERR_INVALID_ARGUMENT;
  } else {
    status = compute(key, msg, out32);
  }
  if (status != EKI_OK && out_ok) {
    ossl::cleanse(out32);
  }
  return status;
}

// key, msg and tag are all byte strings; the order is fixed by the C ABI.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
eki_status hmac_sha256_verify(bytes key, bytes msg, bytes tag) noexcept {
  if (key.empty() || tag.size() != EKI_HMAC_SHA256_LEN) {
    return EKI_ERR_INVALID_ARGUMENT;
  }
  std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> expected{};
  eki_status status = compute(key, msg, expected);
  if (status == EKI_OK) {
    status = CRYPTO_memcmp(expected.data(), tag.data(), expected.size()) == 0 ? EKI_OK
                                                                              : EKI_ERR_AUTH_FAILED;
  }
  ossl::cleanse(expected);
  return status;
}

} // namespace ekicore
