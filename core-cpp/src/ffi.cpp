// The entry points of the C ABI other than the metadata functions, which live in version.cpp.
//
// The six stateless functions (HMAC, HMAC verify, HKDF, AEAD seal and open, ECDSA verify) are
// built the same way from ekicore/ffi_guard.hpp: the outputs to zero-fill on failure are
// described from the raw parameters, then the barrier runs the body, which checks every pointer
// parameter (validation step 1) and calls the primitive, which performs the selector and length
// checks itself. The barrier turns any exception into EKI_ERR_INTERNAL.
//
// The key store and hybrid KEM functions are still stubs that answer EKI_ERR_UNSUPPORTED without
// touching their arguments; they are implemented in lessons L6 (software key store), L7 (PKCS#11
// key store) and L9 (hybrid KEM).

// The public header comes first so that its EKI_API attribute reaches the definitions.
#include <ekicore.h>

#include <ekicore/ffi_guard.hpp>
#include <ekicore/primitives.hpp>

#include <array>

// The signatures are fixed by include/ekicore.h, so adjacent parameters of one type are not a
// choice.

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
extern "C" {

eki_status eki_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len,
                           uint8_t* out) {
  const std::array outputs{ekicore::fixed_output(out, EKI_HMAC_SHA256_LEN)};
  return ekicore::ffi_barrier(outputs, [&] {
    const auto key_span = ekicore::sized_span(key, key_len);
    const auto msg_span = ekicore::sized_span(msg, msg_len);
    const auto out_span = ekicore::fixed_span(out, EKI_HMAC_SHA256_LEN);
    if (!key_span || !msg_span || !out_span) {
      return EKI_ERR_NULL_POINTER;
    }
    return ekicore::hmac_sha256(*key_span, *msg_span, *out_span);
  });
}

// tag is sized by tag_len here, unlike the fixed 16-byte AEAD tag: tag_len 0 makes a NULL tag an
// empty span, which the primitive rejects as INVALID_ARGUMENT.
eki_status eki_hmac_sha256_verify(const uint8_t* key, size_t key_len, const uint8_t* msg,
                                  size_t msg_len, const uint8_t* tag, size_t tag_len) {
  return ekicore::ffi_barrier([&] {
    const auto key_span = ekicore::sized_span(key, key_len);
    const auto msg_span = ekicore::sized_span(msg, msg_len);
    const auto tag_span = ekicore::sized_span(tag, tag_len);
    if (!key_span || !msg_span || !tag_span) {
      return EKI_ERR_NULL_POINTER;
    }
    return ekicore::hmac_sha256_verify(*key_span, *msg_span, *tag_span);
  });
}

eki_status eki_hkdf_sha256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len,
                           const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
  const std::array outputs{ekicore::sized_output<EKI_HKDF_MAX_OKM_LEN>(okm, okm_len)};
  return ekicore::ffi_barrier(outputs, [&] {
    const auto ikm_span = ekicore::sized_span(ikm, ikm_len);
    const auto salt_span = ekicore::sized_span(salt, salt_len);
    const auto info_span = ekicore::sized_span(info, info_len);
    const auto okm_span = ekicore::sized_span(okm, okm_len);
    if (!ikm_span || !salt_span || !info_span || !okm_span) {
      return EKI_ERR_NULL_POINTER;
    }
    return ekicore::hkdf_sha256(*ikm_span, *salt_span, *info_span, *okm_span);
  });
}

eki_status eki_aead_seal(eki_aead_alg alg, const uint8_t* key, size_t key_len, const uint8_t* nonce,
                         size_t nonce_len, const uint8_t* aad, size_t aad_len, const uint8_t* pt,
                         size_t pt_len, uint8_t* ct_out, uint8_t* tag_out) {
  const std::array outputs{
      ekicore::sized_output<EKI_AEAD_MAX_LEN>(ct_out, pt_len),
      ekicore::fixed_output(tag_out, EKI_AEAD_TAG_LEN),
  };
  return ekicore::ffi_barrier(outputs, [&] {
    const auto key_span = ekicore::sized_span(key, key_len);
    const auto nonce_span = ekicore::sized_span(nonce, nonce_len);
    const auto aad_span = ekicore::sized_span(aad, aad_len);
    const auto pt_span = ekicore::sized_span(pt, pt_len);
    const auto ct_span = ekicore::sized_span(ct_out, pt_len);
    const auto tag_span = ekicore::fixed_span(tag_out, EKI_AEAD_TAG_LEN);
    if (!key_span || !nonce_span || !aad_span || !pt_span || !ct_span || !tag_span) {
      return EKI_ERR_NULL_POINTER;
    }
    return ekicore::aead_seal(alg, *key_span, *nonce_span, *aad_span, *pt_span, *ct_span,
                              *tag_span);
  });
}

eki_status eki_aead_open(eki_aead_alg alg, const uint8_t* key, size_t key_len, const uint8_t* nonce,
                         size_t nonce_len, const uint8_t* aad, size_t aad_len, const uint8_t* ct,
                         size_t ct_len, const uint8_t* tag, uint8_t* pt_out) {
  const std::array outputs{ekicore::sized_output<EKI_AEAD_MAX_LEN>(pt_out, ct_len)};
  return ekicore::ffi_barrier(outputs, [&] {
    const auto key_span = ekicore::sized_span(key, key_len);
    const auto nonce_span = ekicore::sized_span(nonce, nonce_len);
    const auto aad_span = ekicore::sized_span(aad, aad_len);
    const auto ct_span = ekicore::sized_span(ct, ct_len);
    const auto tag_span = ekicore::fixed_span(tag, EKI_AEAD_TAG_LEN);
    const auto pt_span = ekicore::sized_span(pt_out, ct_len);
    if (!key_span || !nonce_span || !aad_span || !ct_span || !tag_span || !pt_span) {
      return EKI_ERR_NULL_POINTER;
    }
    return ekicore::aead_open(alg, *key_span, *nonce_span, *aad_span, *ct_span, *tag_span,
                              *pt_span);
  });
}

eki_status eki_ecdsa_p256_verify(const uint8_t* public_key, const uint8_t* msg, size_t msg_len,
                                 const uint8_t* sig) {
  return ekicore::ffi_barrier([&] {
    const auto public_key_span = ekicore::fixed_span(public_key, EKI_P256_PUBLIC_KEY_LEN);
    const auto msg_span = ekicore::sized_span(msg, msg_len);
    const auto sig_span = ekicore::fixed_span(sig, EKI_P256_SIGNATURE_LEN);
    if (!public_key_span || !msg_span || !sig_span) {
      return EKI_ERR_NULL_POINTER;
    }
    return ekicore::ecdsa_p256_verify(*public_key_span, *msg_span, *sig_span);
  });
}

eki_status eki_ks_open([[maybe_unused]] const eki_ks_config* config,
                       [[maybe_unused]] eki_ks** out) {
  return EKI_ERR_UNSUPPORTED;
}

void eki_ks_close([[maybe_unused]] eki_ks* ks) {}

size_t eki_ks_last_error_message([[maybe_unused]] const eki_ks* ks, [[maybe_unused]] char* buf,
                                 [[maybe_unused]] size_t buf_len) {
  return 0;
}

eki_status eki_ks_generate([[maybe_unused]] eki_ks* ks, [[maybe_unused]] eki_key_alg alg,
                           [[maybe_unused]] const char* label,
                           [[maybe_unused]] eki_key_id* id_out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_ks_get_info([[maybe_unused]] eki_ks* ks, [[maybe_unused]] const eki_key_id* id,
                           [[maybe_unused]] eki_key_info* info_out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_ks_get_public_key([[maybe_unused]] eki_ks* ks, [[maybe_unused]] const eki_key_id* id,
                                 [[maybe_unused]] uint8_t* out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_ks_sign([[maybe_unused]] eki_ks* ks, [[maybe_unused]] const eki_key_id* id,
                       [[maybe_unused]] const uint8_t* msg, [[maybe_unused]] size_t msg_len,
                       [[maybe_unused]] uint8_t* sig_out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_ks_hmac_sha256([[maybe_unused]] eki_ks* ks, [[maybe_unused]] const eki_key_id* id,
                              [[maybe_unused]] const uint8_t* msg, [[maybe_unused]] size_t msg_len,
                              [[maybe_unused]] uint8_t* out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_ks_wrap([[maybe_unused]] eki_ks* ks, [[maybe_unused]] const eki_key_id* kek_id,
                       [[maybe_unused]] const eki_key_id* key_id, [[maybe_unused]] uint8_t* out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_ks_unwrap([[maybe_unused]] eki_ks* ks, [[maybe_unused]] const eki_key_id* kek_id,
                         [[maybe_unused]] const uint8_t* blob, [[maybe_unused]] size_t blob_len,
                         [[maybe_unused]] eki_key_alg alg, [[maybe_unused]] const char* label,
                         [[maybe_unused]] const eki_key_id* id) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_ks_destroy([[maybe_unused]] eki_ks* ks, [[maybe_unused]] const eki_key_id* id) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_hybrid_kem_keygen([[maybe_unused]] uint8_t* pk_out,
                                 [[maybe_unused]] uint8_t* sk_out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_hybrid_kem_encap([[maybe_unused]] const uint8_t* pk,
                                [[maybe_unused]] uint8_t* ct_out,
                                [[maybe_unused]] uint8_t* ss_out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_hybrid_kem_decap([[maybe_unused]] const uint8_t* sk,
                                [[maybe_unused]] const uint8_t* ct,
                                [[maybe_unused]] uint8_t* ss_out) {
  return EKI_ERR_UNSUPPORTED;
}

} // extern "C"
// NOLINTEND(bugprone-easily-swappable-parameters)
