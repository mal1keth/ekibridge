// The entry points of the C ABI other than the metadata functions, which live in version.cpp.
//
// Every entry point that returns a status is built the same way from ekicore/ffi_guard.hpp: the
// outputs to zero-fill on failure are described from the raw parameters, then the barrier runs
// the body, which checks every pointer parameter in parameter order (validation step 1) and hands
// the call on. The barrier turns any exception into EKI_ERR_INTERNAL.
//
// The nine stateless functions (HMAC, HMAC verify, HKDF, AEAD seal and open, ECDSA verify, and the
// three hybrid KEM functions) hand the call to a primitive (ekicore/primitives.hpp), which performs
// the selector and length checks itself. The hybrid KEM primitives exist in every build and answer
// EKI_ERR_UNSUPPORTED when the library is built without EKI_WITH_PQ, so the entry points below are
// the same either way: the pointer checks come first, as validation step 1 requires.
//
// The key store functions hand the call to the store logic (ekicore/keystore.hpp) with the
// handle's mutex held; the store logic performs every later check. The mutex is taken right after
// the ks NULL check, so that a call with another NULL pointer still resets the handle's last-error
// text like every other call on it. eki_ks_last_error_message and eki_ks_close return no status
// and have no barrier: the first catches the one exception it can meet (taking the lock), the
// second cannot throw. eki_ks_open hands the configuration to the store logic, which checks the
// backend selector and, for EKI_KS_PKCS11, the configuration fields; when the library is built
// without EKI_WITH_PKCS11, EKI_KS_PKCS11 answers EKI_ERR_UNSUPPORTED.
//
// The nine functions ABI version 2 adds (key lifecycle, audit log, dual control of destroy, from
// eki_ks_open_v2 to eki_audit_verify) have the same shape but do nothing else yet: after the
// pointer checks they answer EKI_ERR_UNSUPPORTED, and the barrier zero-fills their outputs. The
// store functions among them take the handle's mutex and reset its last-error text first, as
// every store call does. eki_ks_open_v2 reads none of its configuration fields yet.

// The public header comes first so that its EKI_API attribute reaches the definitions.
#include <ekicore.h>

#include <ekicore/ffi_guard.hpp>
#include <ekicore/keystore.hpp>
#include <ekicore/primitives.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>

namespace {

// The bytes of an eki_key_id output that the barrier zero-fills on failure.
ekicore::mut_bytes id_output(eki_key_id* id) noexcept {
  return id == nullptr ? ekicore::mut_bytes{} : ekicore::mut_bytes{id->bytes};
}

// The bytes of an eki_key_info output that the barrier zero-fills on failure: the whole object,
// sizeof(eki_key_info) bytes, padding included.
ekicore::mut_bytes info_output(eki_key_info* info) noexcept {
  return info == nullptr ? ekicore::mut_bytes{}
                         : ekicore::mut_bytes{reinterpret_cast<std::uint8_t*>(info), sizeof(*info)};
}

// The bytes of an eki_key_info_v2, uint32_t or uint64_t output that the barrier zero-fills on
// failure: the whole object, sizeof(T) bytes, padding included.
template <typename T> ekicore::mut_bytes object_output(T* object) noexcept {
  return object == nullptr
             ? ekicore::mut_bytes{}
             : ekicore::mut_bytes{reinterpret_cast<std::uint8_t*>(object), sizeof(*object)};
}

// The end of an ABI version 2 store function whose pointers have been checked: the call counts as
// an operation on ks, so its last-error text is reset, and the operation is not implemented yet.
eki_status not_implemented(eki_ks& ks) noexcept {
  ks.last_error.clear();
  return EKI_ERR_UNSUPPORTED;
}

} // namespace

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

eki_status eki_ks_open(const eki_ks_config* config, eki_ks** out) {
  // *out is NULL on every failure, so it is cleared before anything can fail and written only
  // once the handle exists.
  if (out != nullptr) {
    *out = nullptr;
  }
  return ekicore::ffi_barrier([&] {
    if (config == nullptr || out == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    return ekicore::keystore::open(*config, *out);
  });
}

// No lock: the contract forbids racing close with any other call on the handle. Destroying the
// handle destroys its backend, which wipes every key it holds; nothing in that path throws.
void eki_ks_close(eki_ks* ks) {
  const std::unique_ptr<eki_ks> owned{ks};
}

size_t eki_ks_last_error_message(const eki_ks* ks, char* buf, size_t buf_len) {
  // buf NULL counts as buf_len 0.
  const std::span<char> out = buf == nullptr ? std::span<char>{} : std::span<char>{buf, buf_len};
  if (ks == nullptr) {
    return ekicore::keystore::copy_message("", out);
  }
  try {
    const std::scoped_lock lock{ks->mutex};
    return ekicore::keystore::copy_message(ks->last_error, out);
  } catch (...) {
    // Only taking the lock can throw; the message cannot be read then.
    return ekicore::keystore::copy_message("", out);
  }
}

eki_status eki_ks_generate(eki_ks* ks, eki_key_alg alg, const char* label, eki_key_id* id_out) {
  const std::array outputs{id_output(id_out)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    if (label == nullptr || id_out == nullptr) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return ekicore::keystore::generate(*ks, alg, label, *id_out);
  });
}

eki_status eki_ks_get_info(eki_ks* ks, const eki_key_id* id, eki_key_info* info_out) {
  const std::array outputs{info_output(info_out)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    if (id == nullptr || info_out == nullptr) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return ekicore::keystore::get_info(*ks, ekicore::keystore::to_key_id(*id), *info_out);
  });
}

eki_status eki_ks_get_public_key(eki_ks* ks, const eki_key_id* id, uint8_t* out) {
  const std::array outputs{ekicore::fixed_output(out, EKI_P256_PUBLIC_KEY_LEN)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    const auto out_span = ekicore::fixed_span(out, EKI_P256_PUBLIC_KEY_LEN);
    if (id == nullptr || !out_span) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return ekicore::keystore::get_public_key(*ks, ekicore::keystore::to_key_id(*id), *out_span);
  });
}

eki_status eki_ks_sign(eki_ks* ks, const eki_key_id* id, const uint8_t* msg, size_t msg_len,
                       uint8_t* sig_out) {
  const std::array outputs{ekicore::fixed_output(sig_out, EKI_P256_SIGNATURE_LEN)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    const auto msg_span = ekicore::sized_span(msg, msg_len);
    const auto sig_span = ekicore::fixed_span(sig_out, EKI_P256_SIGNATURE_LEN);
    if (id == nullptr || !msg_span || !sig_span) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return ekicore::keystore::sign(*ks, ekicore::keystore::to_key_id(*id), *msg_span, *sig_span);
  });
}

eki_status eki_ks_hmac_sha256(eki_ks* ks, const eki_key_id* id, const uint8_t* msg, size_t msg_len,
                              uint8_t* out) {
  const std::array outputs{ekicore::fixed_output(out, EKI_HMAC_SHA256_LEN)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    const auto msg_span = ekicore::sized_span(msg, msg_len);
    const auto out_span = ekicore::fixed_span(out, EKI_HMAC_SHA256_LEN);
    if (id == nullptr || !msg_span || !out_span) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return ekicore::keystore::hmac_sha256(*ks, ekicore::keystore::to_key_id(*id), *msg_span,
                                          *out_span);
  });
}

eki_status eki_ks_wrap(eki_ks* ks, const eki_key_id* kek_id, const eki_key_id* key_id,
                       uint8_t* out) {
  const std::array outputs{ekicore::fixed_output(out, EKI_WRAPPED_KEY_LEN)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    const auto out_span = ekicore::fixed_span(out, EKI_WRAPPED_KEY_LEN);
    if (kek_id == nullptr || key_id == nullptr || !out_span) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return ekicore::keystore::wrap(*ks, ekicore::keystore::to_key_id(*kek_id),
                                   ekicore::keystore::to_key_id(*key_id), *out_span);
  });
}

// blob is sized by blob_len like any input pair; layer 2 rejects every length but 40 before the
// blob is read.
eki_status eki_ks_unwrap(eki_ks* ks, const eki_key_id* kek_id, const uint8_t* blob, size_t blob_len,
                         eki_key_alg alg, const char* label, const eki_key_id* id) {
  return ekicore::ffi_barrier([&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    const auto blob_span = ekicore::sized_span(blob, blob_len);
    if (kek_id == nullptr || !blob_span || label == nullptr || id == nullptr) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return ekicore::keystore::unwrap(*ks, ekicore::keystore::to_key_id(*kek_id), *blob_span, alg,
                                     label, ekicore::keystore::to_key_id(*id));
  });
}

eki_status eki_ks_destroy(eki_ks* ks, const eki_key_id* id) {
  return ekicore::ffi_barrier([&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    if (id == nullptr) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return ekicore::keystore::destroy(*ks, ekicore::keystore::to_key_id(*id));
  });
}

eki_status eki_hybrid_kem_keygen(uint8_t* pk_out, uint8_t* sk_out) {
  const std::array outputs{
      ekicore::fixed_output(pk_out, EKI_HYBRID_PK_LEN),
      ekicore::fixed_output(sk_out, EKI_HYBRID_SK_LEN),
  };
  return ekicore::ffi_barrier(outputs, [&] {
    const auto pk_span = ekicore::fixed_span(pk_out, EKI_HYBRID_PK_LEN);
    const auto sk_span = ekicore::fixed_span(sk_out, EKI_HYBRID_SK_LEN);
    if (!pk_span || !sk_span) {
      return EKI_ERR_NULL_POINTER;
    }
    return ekicore::hybrid_kem_keygen(*pk_span, *sk_span);
  });
}

eki_status eki_hybrid_kem_encap(const uint8_t* pk, uint8_t* ct_out, uint8_t* ss_out) {
  const std::array outputs{
      ekicore::fixed_output(ct_out, EKI_HYBRID_CT_LEN),
      ekicore::fixed_output(ss_out, EKI_HYBRID_SS_LEN),
  };
  return ekicore::ffi_barrier(outputs, [&] {
    const auto pk_span = ekicore::fixed_span(pk, EKI_HYBRID_PK_LEN);
    const auto ct_span = ekicore::fixed_span(ct_out, EKI_HYBRID_CT_LEN);
    const auto ss_span = ekicore::fixed_span(ss_out, EKI_HYBRID_SS_LEN);
    if (!pk_span || !ct_span || !ss_span) {
      return EKI_ERR_NULL_POINTER;
    }
    return ekicore::hybrid_kem_encap(*pk_span, *ct_span, *ss_span);
  });
}

eki_status eki_hybrid_kem_decap(const uint8_t* sk, const uint8_t* ct, uint8_t* ss_out) {
  const std::array outputs{ekicore::fixed_output(ss_out, EKI_HYBRID_SS_LEN)};
  return ekicore::ffi_barrier(outputs, [&] {
    const auto sk_span = ekicore::fixed_span(sk, EKI_HYBRID_SK_LEN);
    const auto ct_span = ekicore::fixed_span(ct, EKI_HYBRID_CT_LEN);
    const auto ss_span = ekicore::fixed_span(ss_out, EKI_HYBRID_SS_LEN);
    if (!sk_span || !ct_span || !ss_span) {
      return EKI_ERR_NULL_POINTER;
    }
    return ekicore::hybrid_kem_decap(*sk_span, *ct_span, *ss_span);
  });
}

// ABI version 2: key lifecycle, audit log, dual control of destroy.

eki_status eki_ks_open_v2(const eki_ks_config_v2* config, eki_ks** out) {
  // *out is NULL on every failure, so it is cleared before anything can fail.
  if (out != nullptr) {
    *out = nullptr;
  }
  return ekicore::ffi_barrier([&] {
    if (config == nullptr || out == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    return EKI_ERR_UNSUPPORTED;
  });
}

eki_status eki_ks_get_info_v2(eki_ks* ks, const eki_key_id* id, eki_key_info_v2* info_out) {
  const std::array outputs{object_output(info_out)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    if (id == nullptr || info_out == nullptr) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return not_implemented(*ks);
  });
}

eki_status eki_ks_rotate(eki_ks* ks, const eki_key_id* old_id, eki_key_id* new_id_out) {
  const std::array outputs{id_output(new_id_out)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    if (old_id == nullptr || new_id_out == nullptr) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return not_implemented(*ks);
  });
}

eki_status eki_ks_revoke(eki_ks* ks, const eki_key_id* id) {
  return ekicore::ffi_barrier([&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    if (id == nullptr) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return not_implemented(*ks);
  });
}

// tag is sized by tag_len, as in eki_hmac_sha256_verify: tag_len 0 makes a NULL tag an empty span,
// which the store logic will reject as INVALID_ARGUMENT.
eki_status eki_ks_hmac_sha256_verify(eki_ks* ks, const eki_key_id* id, const uint8_t* msg,
                                     size_t msg_len, const uint8_t* tag, size_t tag_len) {
  return ekicore::ffi_barrier([&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    const auto msg_span = ekicore::sized_span(msg, msg_len);
    const auto tag_span = ekicore::sized_span(tag, tag_len);
    if (id == nullptr || !msg_span || !tag_span) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return not_implemented(*ks);
  });
}

eki_status eki_ks_destroy_request(eki_ks* ks, const eki_key_id* id, uint8_t* request_out) {
  const std::array outputs{ekicore::fixed_output(request_out, EKI_DESTROY_REQUEST_LEN)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    const auto request_span = ekicore::fixed_span(request_out, EKI_DESTROY_REQUEST_LEN);
    if (id == nullptr || !request_span) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return not_implemented(*ks);
  });
}

eki_status eki_ks_destroy_approve(eki_ks* ks, const uint8_t* request,
                                  const uint8_t* approver_public_key, const uint8_t* sig,
                                  uint32_t* remaining_out) {
  const std::array outputs{object_output(remaining_out)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    const auto request_span = ekicore::fixed_span(request, EKI_DESTROY_REQUEST_LEN);
    const auto key_span = ekicore::fixed_span(approver_public_key, EKI_P256_PUBLIC_KEY_LEN);
    const auto sig_span = ekicore::fixed_span(sig, EKI_P256_SIGNATURE_LEN);
    if (!request_span || !key_span || !sig_span || remaining_out == nullptr) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return not_implemented(*ks);
  });
}

eki_status eki_ks_audit_head(eki_ks* ks, uint8_t* hash_out, uint64_t* seq_out) {
  const std::array outputs{
      ekicore::fixed_output(hash_out, EKI_AUDIT_HASH_LEN),
      object_output(seq_out),
  };
  return ekicore::ffi_barrier(outputs, [&] {
    if (ks == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    const std::scoped_lock lock{ks->mutex};
    const auto hash_span = ekicore::fixed_span(hash_out, EKI_AUDIT_HASH_LEN);
    if (!hash_span || seq_out == nullptr) {
      return ekicore::keystore::null_pointer(*ks);
    }
    return not_implemented(*ks);
  });
}

// expected_head may be NULL (no head to compare with), so it takes no part in the NULL checks.
eki_status eki_audit_verify(const char* path, const uint8_t* expected_head, uint64_t* records_out) {
  const std::array outputs{object_output(records_out)};
  return ekicore::ffi_barrier(outputs, [&] {
    if (path == nullptr || records_out == nullptr) {
      return EKI_ERR_NULL_POINTER;
    }
    static_cast<void>(expected_head);
    return EKI_ERR_UNSUPPORTED;
  });
}

} // extern "C"
// NOLINTEND(bugprone-easily-swappable-parameters)
