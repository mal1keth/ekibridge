// HKDF-SHA256 (RFC 5869, extract then expand) over OpenSSL's EVP_KDF interface.

#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <array>
#include <cstddef>
#include <cstdint>

// ikm, salt and info are all byte strings by definition of HKDF.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
namespace ekicore {
namespace {

// An OSSL_PARAM for a read-only octet string. OSSL_PARAM has no const variant; OpenSSL only reads
// input parameters, so casting the const away is sound.
OSSL_PARAM octets(const char* name, bytes value) noexcept {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
  return OSSL_PARAM_construct_octet_string(name, const_cast<std::uint8_t*>(value.data()),
                                           value.size());
}

// Derives into okm (1..=8160 bytes). ikm is non-empty. Does not zero okm on failure.
eki_status derive(bytes ikm, bytes salt, bytes info, mut_bytes okm) noexcept {
  const ossl::kdf kdf{EVP_KDF_fetch(nullptr, "HKDF", nullptr)};
  if (!kdf) {
    return EKI_ERR_BACKEND;
  }
  const ossl::kdf_ctx ctx{EVP_KDF_CTX_new(kdf.get())};
  if (!ctx) {
    return EKI_ERR_BACKEND;
  }

  // OSSL_PARAM wants a mutable buffer even for a value it only reads.
  std::array<char, sizeof("SHA256")> digest{"SHA256"};
  // digest, key, optional salt, optional info, end marker. The default mode is extract-and-expand.
  // An absent salt is RFC 5869's default (HashLen zero bytes); an absent info is the empty string.
  std::array<OSSL_PARAM, 5> params{
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest.data(), 0),
      octets(OSSL_KDF_PARAM_KEY, ikm),
      OSSL_PARAM_construct_end(),
      OSSL_PARAM_construct_end(),
      OSSL_PARAM_construct_end(),
  };
  OSSL_PARAM* next = params.data() + 2;
  if (!salt.empty()) {
    *next++ = octets(OSSL_KDF_PARAM_SALT, salt);
  }
  if (!info.empty()) {
    *next = octets(OSSL_KDF_PARAM_INFO, info);
  }

  if (EVP_KDF_derive(ctx.get(), okm.data(), okm.size(), params.data()) != 1) {
    return EKI_ERR_BACKEND;
  }
  return EKI_OK;
}

} // namespace

eki_status hkdf_sha256(bytes ikm, bytes salt, bytes info, mut_bytes okm) noexcept {
  const bool okm_ok = !okm.empty() && okm.size() <= EKI_HKDF_MAX_OKM_LEN;
  eki_status status = EKI_OK;
  if (ikm.empty() || ikm.size() > EKI_HKDF_MAX_INPUT_LEN || salt.size() > EKI_HKDF_MAX_INPUT_LEN ||
      info.size() > EKI_HKDF_MAX_INPUT_LEN || !okm_ok) {
    status = EKI_ERR_INVALID_ARGUMENT;
  } else {
    status = derive(ikm, salt, info, okm);
  }
  if (status != EKI_OK && okm_ok) {
    ossl::cleanse(okm);
  }
  return status;
}

} // namespace ekicore
// NOLINTEND(bugprone-easily-swappable-parameters)
