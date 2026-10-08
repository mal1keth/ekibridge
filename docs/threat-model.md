# Threat model

Scope: the two ekicore libraries (`libekicore`, `libekicore_rs`) and the C ABI between them and their
callers, as specified in [ffi-contract.md](ffi-contract.md). The calling application, the operating
system and the hardware are out of scope except where noted.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Secret keys (AES-256, HMAC-SHA256) | software store memory; or inside the PKCS#11 token | confidentiality and integrity of everything they protect |
| ECDSA P-256 private keys | software store memory; or inside the token, non-extractable | signing authority |
| Caller-supplied keys for stateless calls | caller memory, copied into library intermediates during a call | as above, for the duration of the call |
| Plaintext | caller buffers; `pt_out` of `eki_aead_open` | confidentiality; unauthenticated plaintext must never be released |
| Wrapped key blobs | wherever the caller stores them | confidentiality of the wrapped key rests on the KEK |
| PKCS#11 user PIN | caller memory; a zeroising copy inside the library until login | access to every key in the token |
| Integrity of results | statuses and outputs | a wrong `EKI_OK` (a forged tag accepted) is worse than any crash |

## Trust boundaries

```
  untrusted inputs                 trusted code                           trusted, separately
 ┌───────────────┐  C ABI  ┌──────────────────────────────┐            ┌──────────────────────┐
 │    caller     │ ──────▶ │ libekicore    (C++)          │ ─────────▶ │ OpenSSL 3            │
 │ (application, │ status  │   or                         │            ├──────────────────────┤
 │  any language)│ ◀────── │ libekicore_rs (Rust)         │ ─────────▶ │ RustCrypto crates    │
 └───────────────┘         │                              │  PKCS#11   ├──────────────────────┤
                           │  stateless primitives        │ ─────────▶ │ PKCS#11 module       │
                           │  key store (software/PKCS#11)│            │  (SoftHSM2 in tests) │
                           └──────────────────────────────┘            └──────────┬───────────┘
                                                                                  │
                                                                       ┌──────────▼───────────┐
                                                                       │ token (keys at rest) │
                                                                       └──────────────────────┘
```

- **Caller → library.** Every pointer, length, selector, label and blob is untrusted. The library
  validates in a fixed order and answers with a status; it never trusts a length it has not checked
  and never reads beyond what the contract allows (labels: at most 65 bytes).
- **Library → crypto provider.** OpenSSL and RustCrypto are trusted to implement their algorithms
  correctly. The library is responsible for calling them correctly (lengths, tag handling, error
  checking) and for not leaking their failures as unauthenticated output.
- **Library → PKCS#11 module.** The module is trusted with key material but is shared, process-global
  state. Its return codes are mapped to statuses; its quirks are documented in
  [PKCS#11 specifics](#pkcs11-specifics).

## Attacker models

1. **Hostile caller inputs.** An attacker controls some or all arguments: NULL or dangling-looking
   pointers with zero lengths, huge lengths, unknown selector values, unterminated or non-printable
   labels, malformed public keys and signatures. Goal: memory corruption, a crash, undefined
   behaviour, or a status that differs between the two libraries.
2. **Tampered ciphertext and wrapped blobs.** An attacker modifies ciphertexts, tags, AAD, signatures
   or wrapped-key blobs in storage or transit. Goal: get modified data accepted, or learn something
   from plaintext released before authentication.
3. **Memory disclosure after use.** An attacker later reads process memory (core dump, swap, a
   separate memory-safety bug, a reused allocation). Goal: recover keys, PINs or plaintext that the
   library handled earlier.
4. **Wrong library loaded.** A deployment loads a different, older or substituted library at runtime
   (path mix-up during migration, a library built without a feature). Goal or accident: silently
   different behaviour.

## Mitigations

| Threat | Mechanism | Where tested |
|---|---|---|
| NULL / zero-length confusion | fixed rules: `n == 0` never dereferences, `n > 0 && p == NULL` → `EKI_ERR_NULL_POINTER`; Rust builds `&[]` instead of `from_raw_parts(NULL, 0)` | error-matrix rows in both unit suites and the conformance harness; `ffi_status` fuzz targets; Miri |
| Out-of-range lengths | explicit caps (`EKI_AEAD_MAX_LEN`, `EKI_HKDF_MAX_*`, exact key/nonce/tag/blob lengths) checked before any work; `EVP_*Update` calls split at `INT_MAX` | error matrix; differential tests with random lengths |
| Unknown selectors | selectors are `int32_t`, never a C enum, so every value is representable and rejected with a status | error matrix (`alg 0`, `alg 3`, `backend 99`) |
| Unterminated labels | bounded scan of at most 65 bytes | label bounded-scan unit test |
| Forged ciphertext or tag | AEAD tag verified by the provider; HMAC compared in constant time | vectors (RFC, Wycheproof); tag/AAD/truncation rows of the error matrix |
| Plaintext released before authentication | `pt_out` zero-filled on every failure (OpenSSL GCM writes plaintext before the tag check) | "AUTH_FAILED, `pt_out` all zero" rows |
| Forged signatures | full P-256 point validation; `r`, `s` range checks; provider verification | RFC 6979 and Wycheproof vectors |
| Tampered wrapped blobs | RFC 3394 integrity check | "blob byte flipped → AUTH_FAILED"; `unwrap_blob` fuzz targets |
| Leftover secrets in memory | `zeroize` / `secrecy` in Rust; `SecretBuffer` with `OPENSSL_cleanse` (and best-effort `mlock`) in C++; outputs zeroed on error; PIN copy zeroised after login | zeroisation unit tests |
| Panics or exceptions crossing into C | `catch_unwind` / `try { } catch (...)` in every exported function → `EKI_ERR_INTERNAL` | exception-barrier test via fault injection; poisoned-mutex recovery test |
| Undefined behaviour in the Rust boundary | `unsafe` confined to `ffi.rs`, each block with a SAFETY comment; `#![deny(unsafe_op_in_unsafe_fn)]` | Miri over `ekicore-rs`; clippy `undocumented_unsafe_blocks` |
| Memory errors in the C++ library | RAII for every OpenSSL handle; no raw owning pointers | ASan + UBSan build; libFuzzer targets |
| Divergence between the two libraries | one header, one contract, statuses compared as raw `int32_t` | conformance harness: vectors, differential runs, error matrix, cross-language round trips |
| Wrong library loaded | `eki_abi_version()` and `eki_version()` checked and logged at load; only `eki_*` symbols exported | `meta` conformance module; `scripts/check-exports.sh` |

## What the fuzzers cover and do not

TODO(L8): targets, corpora, run lengths, sanitizers in use, and the classes of bug they can and
cannot find. Results are logged in [findings.md](findings.md).

## PKCS#11 specifics

- **Initialisation is per process.** `C_Initialize` and `C_Finalize` act on the whole process, not on
  a session. Each library keeps one process-wide registry per module path (loaded module, function
  list, whether this library initialised it, number of open handles). `CKR_CRYPTOKI_ALREADY_INITIALIZED`
  is accepted and means someone else owns finalisation.
- **Login is per application.** `C_Login(CKU_USER)` logs in every session of the application;
  `CKR_USER_ALREADY_LOGGED_IN` is accepted. For the same reason `eki_ks_close` never calls `C_Logout`,
  which would log out every other open handle.
- **Finalize rule.** `eki_ks_close` closes its session and decrements the handle count; when the
  count reaches zero it calls `C_Finalize` only if this library performed `C_Initialize`.
- **Two libraries, one process.** If `libekicore` and `libekicore_rs` both hold PKCS#11 stores open
  at once, only one of them owns `C_Finalize` and the other can be left with a finalised module. Do
  not do this; the conformance suite opens them one after the other (the token persists on disk).
- **Return codes.** Zero objects found by `CKA_ID` → `EKI_ERR_KEY_NOT_FOUND`; any `C_UnwrapKey`
  failure after all argument checks passed → `EKI_ERR_AUTH_FAILED` (SoftHSM2 reports an AES-KW
  integrity failure as `CKR_GENERAL_ERROR`); everything else → `EKI_ERR_BACKEND` with the `CKR_*`
  name in the last-error message.
- **Test token.** The SoftHSM2 token used by the tests (`ekibridge`, user PIN `1234`, SO PIN
  `12345678`) is a throwaway created by `scripts/softhsm-init.sh` inside the checkout. Those values
  are test-only.

## Known limitations

- **Unauthenticated wrap metadata.** The wrapped blob is plain RFC 3394 output. The algorithm, label
  and id travel out of band and are not bound to it, so an attacker who can change the metadata can
  get an AES key unwrapped as an HMAC key (or the reverse) under a label of their choosing.
- **OpenSSL GCM writes plaintext before the tag check.** The C++ library zeroes `pt_out` on failure;
  a caller that ignores the status still sees only zeros, but the plaintext did exist in its buffer
  briefly.
- **The software store is not persistent.** Keys live in memory for the lifetime of the handle and
  are lost on close or crash.
- **The PIN is passed as a C string.** It sits in caller memory, outside the library's control,
  before and after `eki_ks_open`.
- **No side-channel testing.** Constant-time behaviour is inherited from OpenSSL and RustCrypto and is
  not measured here.
- **No multi-threaded fuzzing.** The fuzz targets are single-threaded; lock behaviour is covered by
  unit tests only.
