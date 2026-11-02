// The entry points of the C ABI other than the metadata functions, which live in version.cpp.
//
// Every entry point that returns a status is built the same way from ekicore/ffi_guard.hpp: the
// outputs to zero-fill on failure are described from the raw parameters, then the barrier runs
// the body, which checks every pointer parameter in parameter order (validation step 1) and hands
// the call on. The barrier turns any exception into EKI_ERR_INTERNAL.
//
// The six stateless functions (HMAC, HMAC verify, HKDF, AEAD seal and open, ECDSA verify) hand
// the call to a primitive (ekicore/primitives.hpp), which performs the selector and length checks
// itself.
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
// The hybrid KEM functions are still stubs that answer EKI_ERR_UNSUPPORTED without touching their
// arguments.

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
