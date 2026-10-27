#pragma once

// The stateless primitives of libekicore, implemented over OpenSSL 3 EVP. This is the internal C++
// API that the extern "C" layer (ffi.cpp) calls once it has validated the raw pointers.
//
// Contract shared by every function here:
// - Spans refer to valid memory. Turning (pointer, length) pairs into spans, and rejecting NULL
//   pointers, is the FFI layer's job; an empty span may have a null data().
// - Each function enforces the selector and length rules of the ABI contract itself and returns
//   the same status the C function would, so it is safe to call directly. Output spans whose size
//   does not match the input they belong to (out32 != 32, tag16 != 16, ct != pt, ...) give
//   EKI_ERR_INVALID_ARGUMENT.
// - On any status other than EKI_OK every output span is zero-filled, unless its size is outside
//   the valid range for it (then it is not touched).
// - Nothing throws and nothing is allocated on our side. OpenSSL fetch or allocation failures give
//   EKI_ERR_BACKEND and leave their reason on OpenSSL's per-thread error queue.
// - Inputs longer than INT_MAX are fed to the int-sized EVP update calls in chunks.

#include <ekicore.h>

#include <cstdint>
#include <span>

namespace ekicore {

using bytes = std::span<const std::uint8_t>;
using mut_bytes = std::span<std::uint8_t>;

// HMAC-SHA256 of msg under key into out32. key must not be empty.
[[nodiscard]] eki_status hmac_sha256(bytes key, bytes msg, mut_bytes out32) noexcept;

// Recomputes the tag and compares it with tag in constant time: EKI_ERR_AUTH_FAILED on mismatch.
// key must not be empty and tag must be 32 bytes.
[[nodiscard]] eki_status hmac_sha256_verify(bytes key, bytes msg, bytes tag) noexcept;

// RFC 5869 HKDF-SHA256 (extract then expand) into okm. Empty salt means the RFC's default salt.
// ikm: 1..=32768 bytes; salt, info: 0..=32768 bytes; okm: 1..=8160 bytes.
[[nodiscard]] eki_status hkdf_sha256(bytes ikm, bytes salt, bytes info, mut_bytes okm) noexcept;

// AEAD encryption with a detached 16-byte tag. alg is EKI_AEAD_AES_256_GCM or
// EKI_AEAD_CHACHA20_POLY1305; key is 32 bytes, nonce 12; pt and ct have equal sizes of at most
// EKI_AEAD_MAX_LEN bytes; aad and pt may be empty.
[[nodiscard]] eki_status aead_seal(eki_aead_alg alg, bytes key, bytes nonce, bytes aad, bytes pt,
                                   mut_bytes ct, mut_bytes tag16) noexcept;

// AEAD decryption and tag check, same sizes as aead_seal. On EKI_ERR_AUTH_FAILED (and on every
// other failure) pt is all zeros: OpenSSL writes plaintext before it checks the tag.
[[nodiscard]] eki_status aead_open(eki_aead_alg alg, bytes key, bytes nonce, bytes aad, bytes ct,
                                   bytes tag16, mut_bytes pt) noexcept;

// ECDSA P-256 / SHA-256 verification. public_key65 is SEC1 uncompressed (0x04 || X || Y) and must
// be a valid curve point (else EKI_ERR_INVALID_ARGUMENT); sig64 is big-endian r || s. r or s
// outside [1, n-1], or a signature that does not verify, gives EKI_ERR_AUTH_FAILED. High-s
// signatures are accepted.
[[nodiscard]] eki_status ecdsa_p256_verify(bytes public_key65, bytes msg, bytes sig64) noexcept;

// RFC 3394 AES Key Wrap of a 32-byte key under a 32-byte KEK, with the default initial value
// A6A6A6A6A6A6A6A6. The ABI exposes it only through stored keys (eki_ks_wrap, eki_ks_unwrap).
// kek32 and key32 are 32 bytes, out40 is 40; key32 and kek32 may be the same memory.
[[nodiscard]] eki_status aes_256_key_wrap(bytes kek32, bytes key32, mut_bytes out40) noexcept;

// The inverse of aes_256_key_wrap: unwraps blob40 into key32. EKI_ERR_AUTH_FAILED when the blob
// fails the integrity check (wrong KEK or altered blob). kek32 and key32 are 32 bytes, blob40 is
// 40. The key is written straight into key32, so a caller that keeps it passes the storage it
// will live in.
[[nodiscard]] eki_status aes_256_key_unwrap(bytes kek32, bytes blob40, mut_bytes key32) noexcept;

} // namespace ekicore
