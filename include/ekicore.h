/*
 * ekicore C ABI shared by libekicore (C++) and libekicore_rs (Rust); generated from the Rust
 * declarations by cbindgen; do not edit by hand.
 */

#ifndef EKICORE_H
#define EKICORE_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(_WIN32)
#define EKI_API
#elif defined(__GNUC__) || defined(__clang__)
#define EKI_API __attribute__((visibility("default")))
#else
#define EKI_API
#endif

/**
 * ABI version implemented by both libraries. Bumped only for incompatible changes.
 */
#define EKI_ABI_VERSION 2

/**
 * Length in bytes of an HMAC-SHA256 tag.
 */
#define EKI_HMAC_SHA256_LEN 32

/**
 * Length in bytes of an AEAD key (AES-256-GCM and ChaCha20-Poly1305).
 */
#define EKI_AEAD_KEY_LEN 32

/**
 * Length in bytes of an AEAD nonce.
 */
#define EKI_AEAD_NONCE_LEN 12

/**
 * Length in bytes of an AEAD authentication tag.
 */
#define EKI_AEAD_TAG_LEN 16

/**
 * Largest plaintext or ciphertext length for both algorithms: 2^36 - 32 (the GCM limit).
 */
#define EKI_AEAD_MAX_LEN 68719476704ull

/**
 * Largest HKDF-SHA256 output length: 255 * 32.
 */
#define EKI_HKDF_MAX_OKM_LEN 8160

/**
 * Cap on the HKDF input lengths `ikm_len`, `salt_len` and `info_len` (OpenSSL `HKDF_MAXINFO`).
 */
#define EKI_HKDF_MAX_INPUT_LEN 32768

/**
 * Length in bytes of a key id.
 */
#define EKI_KEY_ID_LEN 16

/**
 * Largest key label length in bytes, excluding the terminating NUL.
 */
#define EKI_LABEL_MAX_LEN 64

/**
 * Length in bytes of a P-256 public key in SEC1 uncompressed form: `0x04 || X || Y`.
 */
#define EKI_P256_PUBLIC_KEY_LEN 65

/**
 * Length in bytes of an ECDSA P-256 signature: big-endian `r || s`, fixed width.
 */
#define EKI_P256_SIGNATURE_LEN 64

/**
 * Length in bytes of a wrapped key: the RFC 3394 output for a 32-byte key.
 */
#define EKI_WRAPPED_KEY_LEN 40

/**
 * Length in bytes of a hybrid KEM public key:
 * X25519 public key (32) || ML-KEM-768 encapsulation key (1184).
 */
#define EKI_HYBRID_PK_LEN 1216

/**
 * Length in bytes of a hybrid KEM secret key:
 * X25519 secret key (32) || ML-KEM-768 seed d || z (64).
 */
#define EKI_HYBRID_SK_LEN 96

/**
 * Length in bytes of a hybrid KEM ciphertext:
 * X25519 ephemeral public key (32) || ML-KEM-768 ciphertext (1088).
 */
#define EKI_HYBRID_CT_LEN 1120

/**
 * Length in bytes of a hybrid KEM shared secret.
 */
#define EKI_HYBRID_SS_LEN 32

/**
 * Length in bytes of an audit record hash: SHA-256.
 */
#define EKI_AUDIT_HASH_LEN 32

/**
 * Length in bytes of a destroy request made by `eki_ks_destroy_request`.
 */
#define EKI_DESTROY_REQUEST_LEN 32

/**
 * Largest number of approver keys in an `eki_ks_config_v2`.
 */
#define EKI_APPROVERS_MAX 8

/**
 * Largest audit log path length in bytes, excluding the terminating NUL.
 */
#define EKI_AUDIT_PATH_MAX_LEN 4096

/**
 * Result of every fallible call. Values are stable and only ever appended.
 */
enum eki_status
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : int32_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
  /**
   * The call succeeded.
   */
  EKI_OK = 0,
  /**
   * A required pointer argument was NULL.
   */
  EKI_ERR_NULL_POINTER = 1,
  /**
   * An argument had an invalid length, range, format or an unknown selector value.
   */
  EKI_ERR_INVALID_ARGUMENT = 2,
  /**
   * Reserved for future variable-length outputs.
   */
  EKI_ERR_BUFFER_TOO_SMALL = 3,
  /**
   * The selector or function is known but not compiled into this library.
   */
  EKI_ERR_UNSUPPORTED = 4,
  /**
   * Authentication failed: AEAD tag, HMAC verify, ECDSA verify or AES key wrap integrity.
   */
  EKI_ERR_AUTH_FAILED = 5,
  /**
   * No key with the given id exists in the store.
   */
  EKI_ERR_KEY_NOT_FOUND = 6,
  /**
   * A key with the given id already exists in the store.
   */
  EKI_ERR_KEY_EXISTS = 7,
  /**
   * The key exists but has the wrong algorithm for this operation.
   */
  EKI_ERR_WRONG_KEY_TYPE = 8,
  /**
   * Internal failure of OpenSSL or the PKCS#11 module; never caused by caller input.
   */
  EKI_ERR_BACKEND = 9,
  /**
   * A panic or exception was caught, or an internal invariant was violated.
   */
  EKI_ERR_INTERNAL = 10,
  /**
   * The key's state (retired or revoked) does not permit this operation.
   */
  EKI_ERR_KEY_STATE = 11,
  /**
   * The handle has dual control: destroying a key needs approvals
   * (`eki_ks_destroy_request`, `eki_ks_destroy_approve`).
   */
  EKI_ERR_APPROVAL_REQUIRED = 12,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum eki_status eki_status;
#else
typedef int32_t eki_status;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * Key store handle. Opaque and library-allocated; freed only by `eki_ks_close`.
 */
typedef struct eki_ks eki_ks;

/**
 * AEAD algorithm selector. Unknown values are answered with `EKI_ERR_INVALID_ARGUMENT`.
 */
typedef int32_t eki_aead_alg;

/**
 * Key store backend selector. Unknown values are answered with `EKI_ERR_INVALID_ARGUMENT`.
 */
typedef int32_t eki_ks_backend;

/**
 * Configuration for `eki_ks_open`. The library copies the strings and keeps no pointer.
 */
typedef struct eki_ks_config {
  /**
   * Which backend to open.
   */
  eki_ks_backend backend;
  /**
   * Path of the PKCS#11 module. PKCS#11 backend only.
   */
  const char *pkcs11_module_path;
  /**
   * Label of the PKCS#11 token, 1 to 32 printable bytes. PKCS#11 backend only.
   */
  const char *pkcs11_token_label;
  /**
   * User PIN, 1 to 255 bytes; copied into zeroizing storage. PKCS#11 backend only.
   */
  const char *pkcs11_user_pin;
} eki_ks_config;

/**
 * Key algorithm selector. Unknown values are answered with `EKI_ERR_INVALID_ARGUMENT`.
 */
typedef int32_t eki_key_alg;

/**
 * Identifier of a stored key: 16 random bytes made by the library at generation time.
 */
typedef struct eki_key_id {
  /**
   * The id bytes.
   */
  uint8_t bytes[16];
} eki_key_id;

/**
 * Public description of a stored key.
 */
typedef struct eki_key_info {
  /**
   * Algorithm of the key.
   */
  eki_key_alg alg;
  /**
   * Label, NUL-padded through byte 64.
   */
  char label[65];
} eki_key_info;

/**
 * Configuration for `eki_ks_open_v2`: the fields of `eki_ks_config`, an optional audit log and
 * optional approver keys for dual control of destroy. The library copies what it keeps and
 * keeps no pointer.
 */
typedef struct eki_ks_config_v2 {
  /**
   * Which backend to open.
   */
  eki_ks_backend backend;
  /**
   * Path of the PKCS#11 module. PKCS#11 backend only.
   */
  const char *pkcs11_module_path;
  /**
   * Label of the PKCS#11 token, 1 to 32 printable bytes. PKCS#11 backend only.
   */
  const char *pkcs11_token_label;
  /**
   * User PIN, 1 to 255 bytes; copied into zeroizing storage. PKCS#11 backend only.
   */
  const char *pkcs11_user_pin;
  /**
   * NULL for no audit log; otherwise the path of the audit log file, NUL-terminated, 1 to
   * `EKI_AUDIT_PATH_MAX_LEN` bytes.
   */
  const char *audit_log_path;
  /**
   * `approver_count` SEC1 uncompressed P-256 public keys of 65 bytes each, back to back.
   */
  const uint8_t *approver_public_keys;
  /**
   * 0 for single control; otherwise 2 to `EKI_APPROVERS_MAX` distinct approver keys, two of
   * which must approve every destroy.
   */
  size_t approver_count;
} eki_ks_config_v2;

/**
 * Lifecycle state of a stored key. The library writes only the three values below; a field
 * that was zero-filled because the call failed holds 0.
 */
typedef int32_t eki_key_state;

/**
 * Public description of a stored key, with its lifecycle state.
 */
typedef struct eki_key_info_v2 {
  /**
   * Algorithm of the key.
   */
  eki_key_alg alg;
  /**
   * Lifecycle state of the key.
   */
  eki_key_state state;
  /**
   * Label, NUL-padded through byte 64.
   */
  char label[65];
} eki_key_info_v2;

/**
 * AES-256-GCM.
 */
#define EKI_AEAD_AES_256_GCM 1

/**
 * ChaCha20-Poly1305 (RFC 8439).
 */
#define EKI_AEAD_CHACHA20_POLY1305 2

/**
 * 32-byte AES secret; usable as a key-encryption key; wrappable.
 */
#define EKI_KEY_AES_256 1

/**
 * 32-byte HMAC-SHA256 secret; used through `eki_ks_hmac_sha256`; wrappable.
 */
#define EKI_KEY_HMAC_SHA256 2

/**
 * ECDSA P-256 key pair; used through `eki_ks_sign` and `eki_ks_get_public_key`; not wrappable.
 */
#define EKI_KEY_ECDSA_P256 3

/**
 * In-memory software key store.
 */
#define EKI_KS_SOFTWARE 1

/**
 * Key store held in a PKCS#11 token.
 */
#define EKI_KS_PKCS11 2

/**
 * The key may be used for every operation its algorithm allows. Generated and unwrapped keys
 * start here.
 */
#define EKI_KEY_STATE_ACTIVE 1

/**
 * Replaced by `eki_ks_rotate`: the key may still verify an HMAC tag, give its public key,
 * unwrap and be wrapped, but may not sign, make an HMAC tag, wrap or be rotated again.
 */
#define EKI_KEY_STATE_RETIRED 2

/**
 * Revoked by `eki_ks_revoke`: the key may only be described, revoked again and destroyed.
 */
#define EKI_KEY_STATE_REVOKED 3

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Returns the ABI version this library implements (`EKI_ABI_VERSION`).
 */
EKI_API uint32_t eki_abi_version(void);

/**
 * Returns the implementation name and version, for example `ekicore-rs 0.1.0`.
 * The string has static storage and is never NULL.
 */
EKI_API const char *eki_version(void);

/**
 * Returns the identifier of a status value, for example `EKI_ERR_AUTH_FAILED`, or
 * `EKI_STATUS_UNKNOWN` for any other integer. The string has static storage and is never NULL.
 */
EKI_API const char *eki_status_name(int32_t status);

/**
 * Computes HMAC-SHA256 of `msg` under `key` and writes the 32-byte tag to `out`.
 * `key_len` must be non-zero.
 */
EKI_API
eki_status eki_hmac_sha256(const uint8_t *key,
                           size_t key_len,
                           const uint8_t *msg,
                           size_t msg_len,
                           uint8_t *out);

/**
 * Compares `tag`, which must be exactly 32 bytes, with HMAC-SHA256 of `msg` under `key` in
 * constant time. A mismatch returns `EKI_ERR_AUTH_FAILED`.
 */
EKI_API
eki_status eki_hmac_sha256_verify(const uint8_t *key,
                                  size_t key_len,
                                  const uint8_t *msg,
                                  size_t msg_len,
                                  const uint8_t *tag,
                                  size_t tag_len);

/**
 * Derives `okm_len` bytes (1 to 8160) with HKDF-SHA256 (RFC 5869). An empty `salt` selects the
 * RFC default salt.
 */
EKI_API
eki_status eki_hkdf_sha256(const uint8_t *ikm,
                           size_t ikm_len,
                           const uint8_t *salt,
                           size_t salt_len,
                           const uint8_t *info,
                           size_t info_len,
                           uint8_t *okm,
                           size_t okm_len);

/**
 * Encrypts `pt` into `ct_out` (`pt_len` bytes) and writes the 16-byte tag to `tag_out`.
 * `key_len` must be 32 and `nonce_len` 12.
 */
EKI_API
eki_status eki_aead_seal(eki_aead_alg alg,
                         const uint8_t *key,
                         size_t key_len,
                         const uint8_t *nonce,
                         size_t nonce_len,
                         const uint8_t *aad,
                         size_t aad_len,
                         const uint8_t *pt,
                         size_t pt_len,
                         uint8_t *ct_out,
                         uint8_t *tag_out);

/**
 * Verifies the 16-byte `tag` and decrypts `ct` into `pt_out` (`ct_len` bytes). On any failure
 * `pt_out` is zero-filled.
 */
EKI_API
eki_status eki_aead_open(eki_aead_alg alg,
                         const uint8_t *key,
                         size_t key_len,
                         const uint8_t *nonce,
                         size_t nonce_len,
                         const uint8_t *aad,
                         size_t aad_len,
                         const uint8_t *ct,
                         size_t ct_len,
                         const uint8_t *tag,
                         uint8_t *pt_out);

/**
 * Verifies a 64-byte `r || s` ECDSA P-256 signature over SHA-256 of `msg` against a 65-byte
 * SEC1 uncompressed public key.
 */
EKI_API
eki_status eki_ecdsa_p256_verify(const uint8_t *public_key,
                                 const uint8_t *msg,
                                 size_t msg_len,
                                 const uint8_t *sig);

/**
 * Opens a key store as described by `config` and stores the handle in `*out`.
 * `*out` is NULL on failure.
 */
EKI_API eki_status eki_ks_open(const struct eki_ks_config *config, struct eki_ks **out);

/**
 * Closes the store and frees the handle. Passing NULL is allowed.
 */
EKI_API void eki_ks_close(struct eki_ks *ks);

/**
 * Copies the most recent error message of the handle into `buf` with snprintf semantics and
 * returns its full length, excluding the NUL.
 */
EKI_API size_t eki_ks_last_error_message(const struct eki_ks *ks, char *buf, size_t buf_len);

/**
 * Generates a key of algorithm `alg` with a label of 1 to 64 printable bytes and returns its
 * new id in `id_out`.
 */
EKI_API
eki_status eki_ks_generate(struct eki_ks *ks,
                           eki_key_alg alg,
                           const char *label,
                           struct eki_key_id *id_out);

/**
 * Reports the algorithm and label of the key with the given id.
 */
EKI_API
eki_status eki_ks_get_info(struct eki_ks *ks,
                           const struct eki_key_id *id,
                           struct eki_key_info *info_out);

/**
 * Writes the 65-byte SEC1 uncompressed public key of an ECDSA P-256 key to `out`.
 */
EKI_API
eki_status eki_ks_get_public_key(struct eki_ks *ks,
                                 const struct eki_key_id *id,
                                 uint8_t *out);

/**
 * Signs SHA-256 of `msg` with an ECDSA P-256 key and writes the 64-byte `r || s` signature to
 * `sig_out`.
 */
EKI_API
eki_status eki_ks_sign(struct eki_ks *ks,
                       const struct eki_key_id *id,
                       const uint8_t *msg,
                       size_t msg_len,
                       uint8_t *sig_out);

/**
 * Computes HMAC-SHA256 of `msg` under a stored HMAC key and writes the 32-byte tag to `out`.
 */
EKI_API
eki_status eki_ks_hmac_sha256(struct eki_ks *ks,
                              const struct eki_key_id *id,
                              const uint8_t *msg,
                              size_t msg_len,
                              uint8_t *out);

/**
 * Wraps the AES or HMAC key `key_id` under the AES key `kek_id` (RFC 3394) and writes the
 * 40-byte blob to `out`.
 */
EKI_API
eki_status eki_ks_wrap(struct eki_ks *ks,
                       const struct eki_key_id *kek_id,
                       const struct eki_key_id *key_id,
                       uint8_t *out);

/**
 * Unwraps the 40-byte `blob` under the AES key `kek_id` and stores the result as a new key with
 * algorithm `alg`, label `label` and id `id`.
 */
EKI_API
eki_status eki_ks_unwrap(struct eki_ks *ks,
                         const struct eki_key_id *kek_id,
                         const uint8_t *blob,
                         size_t blob_len,
                         eki_key_alg alg,
                         const char *label,
                         const struct eki_key_id *id);

/**
 * Destroys the key with the given id, including both halves of a key pair.
 */
EKI_API eki_status eki_ks_destroy(struct eki_ks *ks, const struct eki_key_id *id);

/**
 * Generates a hybrid X25519 + ML-KEM-768 key pair. Returns `EKI_ERR_UNSUPPORTED` when the
 * library is built without hybrid support.
 */
EKI_API eki_status eki_hybrid_kem_keygen(uint8_t *pk_out, uint8_t *sk_out);

/**
 * Encapsulates a fresh shared secret to `pk`: writes the ciphertext to `ct_out` and the shared
 * secret to `ss_out`.
 */
EKI_API eki_status eki_hybrid_kem_encap(const uint8_t *pk, uint8_t *ct_out, uint8_t *ss_out);

/**
 * Recovers the shared secret from `ct` with the secret key `sk` and writes it to `ss_out`.
 */
EKI_API eki_status eki_hybrid_kem_decap(const uint8_t *sk, const uint8_t *ct, uint8_t *ss_out);

/**
 * Opens a key store as described by `config` and stores the handle in `*out`; `*out` is NULL on
 * failure. `eki_ks_open(config)` equals this function with no audit log and no approvers.
 *
 * After the backend selector, the fields are checked in field order: the PKCS#11 fields as in
 * `eki_ks_open` (PKCS#11 backend only), `audit_log_path` (NULL, or 1 to
 * `EKI_AUDIT_PATH_MAX_LEN` bytes), `approver_count` (0, or 2 to `EKI_APPROVERS_MAX`) and
 * `approver_public_keys` (non-NULL when `approver_count` is not 0; distinct, valid SEC1
 * uncompressed P-256 points). A NULL field is reported before any malformed field. The backend
 * is opened next, and the audit log last: an existing log that fails `eki_audit_verify` is
 * `EKI_ERR_AUTH_FAILED`; a log that cannot be opened, created or locked is `EKI_ERR_BACKEND`.
 * The log stays locked for the life of the handle, so a second handle on it fails to open.
 */
EKI_API eki_status eki_ks_open_v2(const struct eki_ks_config_v2 *config, struct eki_ks **out);

/**
 * Reports the algorithm, lifecycle state and label of the key with the given id. Works in every
 * state.
 */
EKI_API
eki_status eki_ks_get_info_v2(struct eki_ks *ks,
                              const struct eki_key_id *id,
                              struct eki_key_info_v2 *info_out);

/**
 * Replaces the ACTIVE key `old_id` with a new ACTIVE key of the same algorithm and label under a
 * fresh random id, written to `new_id_out`, and makes the old key RETIRED. A key that is not
 * ACTIVE is `EKI_ERR_KEY_STATE`.
 */
EKI_API
eki_status eki_ks_rotate(struct eki_ks *ks,
                         const struct eki_key_id *old_id,
                         struct eki_key_id *new_id_out);

/**
 * Makes the key REVOKED, from either other state. Revoking a REVOKED key succeeds and changes
 * nothing. No state leads back.
 */
EKI_API eki_status eki_ks_revoke(struct eki_ks *ks, const struct eki_key_id *id);

/**
 * Compares `tag`, which must be exactly 32 bytes, with HMAC-SHA256 of `msg` under a stored HMAC
 * key in constant time. A mismatch returns `EKI_ERR_AUTH_FAILED`. Allowed for ACTIVE and RETIRED
 * keys.
 */
EKI_API
eki_status eki_ks_hmac_sha256_verify(struct eki_ks *ks,
                                     const struct eki_key_id *id,
                                     const uint8_t *msg,
                                     size_t msg_len,
                                     const uint8_t *tag,
                                     size_t tag_len);

/**
 * Starts the destruction of a key on a handle with approvers: writes 32 fresh random bytes to
 * `request_out` and remembers them for this key, replacing an earlier request for it. Requests
 * live in the handle and vanish when it is closed. A handle without approvers returns
 * `EKI_ERR_UNSUPPORTED`.
 */
EKI_API
eki_status eki_ks_destroy_request(struct eki_ks *ks,
                                  const struct eki_key_id *id,
                                  uint8_t *request_out);

/**
 * Records the approval of a pending destroy request by one approver. `sig` is the 64-byte
 * `r || s` ECDSA P-256 signature over SHA-256 of the 20 ASCII bytes `ekibridge-destroy-v1`, the
 * 32 request bytes and the 16 bytes of the key id, made with the private key of
 * `approver_public_key`. `remaining_out` receives the number of approvals still needed; a second
 * approval by the same approver changes nothing. When two different approvers have approved, the
 * key is destroyed, the request is removed and `remaining_out` is 0.
 */
EKI_API
eki_status eki_ks_destroy_approve(struct eki_ks *ks,
                                  const uint8_t *request,
                                  const uint8_t *approver_public_key,
                                  const uint8_t *sig,
                                  uint32_t *remaining_out);

/**
 * Writes the hash and the sequence number of the last record of the handle's audit log to
 * `hash_out` (32 bytes) and `seq_out`. A handle without an audit log returns
 * `EKI_ERR_UNSUPPORTED`. Kept elsewhere, the hash lets `eki_audit_verify` detect a log whose
 * tail was cut off, which the chain alone cannot show.
 */
EKI_API eki_status eki_ks_audit_head(struct eki_ks *ks, uint8_t *hash_out, uint64_t *seq_out);

/**
 * Verifies the audit log at `path` (1 to `EKI_AUDIT_PATH_MAX_LEN` bytes) and writes its number
 * of records to `records_out`. Every line must be a well-formed record whose sequence number,
 * previous hash and hash continue the chain, and the file must end with a newline. When
 * `expected_head` (32 bytes) is not NULL, the hash of the last record must equal it (32 zero
 * bytes for an empty file). Any deviation is `EKI_ERR_AUTH_FAILED`; a file that cannot be
 * opened or read is `EKI_ERR_BACKEND`.
 */
EKI_API
eki_status eki_audit_verify(const char *path,
                            const uint8_t *expected_head,
                            uint64_t *records_out);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* EKICORE_H */
