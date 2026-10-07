// The remaining entry points of the C ABI. Every function is a stub that answers
// EKI_ERR_UNSUPPORTED without touching its arguments; the bodies are implemented in lessons
// L2 (stateless primitives and the exception barrier), L6 (software key store), L7 (PKCS#11
// key store) and L9 (hybrid KEM). The metadata functions live in version.cpp.
//
// No exceptions and no try blocks here yet: the barrier arrives with L2.

// The public header comes first so that its EKI_API attribute reaches the definitions.
#include <ekicore.h>

// The signatures are fixed by include/ekicore.h, so adjacent parameters of one type are not a
// choice.

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
extern "C" {

eki_status eki_hmac_sha256([[maybe_unused]] const uint8_t* key, [[maybe_unused]] size_t key_len,
                           [[maybe_unused]] const uint8_t* msg, [[maybe_unused]] size_t msg_len,
                           [[maybe_unused]] uint8_t* out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status
eki_hmac_sha256_verify([[maybe_unused]] const uint8_t* key, [[maybe_unused]] size_t key_len,
                       [[maybe_unused]] const uint8_t* msg, [[maybe_unused]] size_t msg_len,
                       [[maybe_unused]] const uint8_t* tag, [[maybe_unused]] size_t tag_len) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_hkdf_sha256([[maybe_unused]] const uint8_t* ikm, [[maybe_unused]] size_t ikm_len,
                           [[maybe_unused]] const uint8_t* salt, [[maybe_unused]] size_t salt_len,
                           [[maybe_unused]] const uint8_t* info, [[maybe_unused]] size_t info_len,
                           [[maybe_unused]] uint8_t* okm, [[maybe_unused]] size_t okm_len) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_aead_seal([[maybe_unused]] eki_aead_alg alg, [[maybe_unused]] const uint8_t* key,
                         [[maybe_unused]] size_t key_len, [[maybe_unused]] const uint8_t* nonce,
                         [[maybe_unused]] size_t nonce_len, [[maybe_unused]] const uint8_t* aad,
                         [[maybe_unused]] size_t aad_len, [[maybe_unused]] const uint8_t* pt,
                         [[maybe_unused]] size_t pt_len, [[maybe_unused]] uint8_t* ct_out,
                         [[maybe_unused]] uint8_t* tag_out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_aead_open([[maybe_unused]] eki_aead_alg alg, [[maybe_unused]] const uint8_t* key,
                         [[maybe_unused]] size_t key_len, [[maybe_unused]] const uint8_t* nonce,
                         [[maybe_unused]] size_t nonce_len, [[maybe_unused]] const uint8_t* aad,
                         [[maybe_unused]] size_t aad_len, [[maybe_unused]] const uint8_t* ct,
                         [[maybe_unused]] size_t ct_len, [[maybe_unused]] const uint8_t* tag,
                         [[maybe_unused]] uint8_t* pt_out) {
  return EKI_ERR_UNSUPPORTED;
}

eki_status eki_ecdsa_p256_verify([[maybe_unused]] const uint8_t* public_key,
                                 [[maybe_unused]] const uint8_t* msg,
                                 [[maybe_unused]] size_t msg_len,
                                 [[maybe_unused]] const uint8_t* sig) {
  return EKI_ERR_UNSUPPORTED;
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
