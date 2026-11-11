# Threat model

This document says what the two ekicore libraries, `libekicore` and `libekicore_rs`, protect,
against whom, by what mechanism, and what evidence there is that the mechanism works. It also
says what they do not protect. It is written for someone deciding whether the libraries can hold
keys in their process, and for a reviewer who wants to check each claim against the code.

The scope is the two libraries and the C ABI between them and their callers, as specified in the
[contract](ffi-contract.md) at ABI version 2. The calling application, the operating system, the
hardware, OpenSSL, the RustCrypto crates and the PKCS#11 module are outside the libraries; this
document says where the libraries depend on them.

Source references are to files in this repository. "Both" means the C++ library under `core-cpp/`
and the Rust library under `core-rs/`.

I develop and test on macOS (Apple silicon). On Linux the CI workflows build and test the
implementation on Ubuntu 24.04. By hand I have run only parts of it on Linux (Debian 13, x86-64):
the C++ tests built with GCC, the Miri selection and one fuzz target. The durability of the Linux
flush path has not been tested, and I have run the PKCS#11 backend by hand only against SoftHSM2
2.7.0 on macOS, not against the 2.6.1 that Ubuntu packages.

## What is protected

| Asset | Where it lives | Property the libraries aim for |
|---|---|---|
| Secret keys (AES-256, HMAC-SHA256) | software store memory, or inside the PKCS#11 token | not released through the ABI except wrapped under another key; wiped when destroyed or when the handle closes (software store) |
| ECDSA P-256 private keys | software store memory, or inside the token as a non-extractable object | never released; signing only while ACTIVE |
| Plaintexts | caller buffers; `pt_out` of `eki_aead_open` | never released unless the tag verified: `pt_out` is all zero after every failure |
| Integrity of results | statuses and outputs | a forged tag, signature or wrapped blob is never answered with `EKI_OK` |
| Audit log integrity | the log file named by `audit_log_path` | a change, insertion, removal or reordering of records is detected by `eki_audit_verify` and when a handle opens the log; a cut tail is detected when the head is kept elsewhere |
| The destroy decision | the handle's pending requests and approver keys | with dual control, a key is destroyed only after two different configured approvers signed the same fresh request for that key |
| Key lifecycle state | the handle (software) or the token's usage attributes (PKCS#11) | no call moves a key back from RETIRED or REVOKED |

The libraries do not protect the following.

- Memory the caller owns is the caller's to wipe: keys passed to stateless functions, plaintexts,
  shared secrets, the PIN and the configuration strings
  ([contract, secret handling](ffi-contract.md#secret-handling)).
- Nothing is confidential from the process itself. Code in the same process can read every key
  the software store holds.
- Availability is not protected. A caller can exhaust memory with keys, a full disk makes logged
  calls fail, and another process can hold the log lock.
- The metadata of a wrapped key (algorithm, label and id) travels outside the blob and is not
  authenticated (see [limits](#limits)).
- Key ids, labels, approver public keys, audit records and the audit head are not secret.

## Trust boundaries

```
  untrusted inputs                 the libraries                          trusted, separately
 ┌───────────────┐  C ABI  ┌──────────────────────────────┐            ┌──────────────────────┐
 │    caller     │ ──────▶ │ libekicore    (C++)          │ ─────────▶ │ OpenSSL 3            │
 │ (application, │ status  │   or                         │            ├──────────────────────┤
 │  any language)│ ◀────── │ libekicore_rs (Rust)         │ ─────────▶ │ RustCrypto crates    │
 └───────────────┘         │                              │  PKCS#11   ├──────────────────────┤
                           │  stateless primitives        │ ─────────▶ │ PKCS#11 module       │
 ┌───────────────┐         │  key store (software/PKCS#11)│            │  (SoftHSM2 in tests) │
 │ data from     │ via the │  audit log, dual control     │            └──────────┬───────────┘
 │ elsewhere:    │ caller  └──────────────┬───────────────┘                       │
 │ ciphertexts,  │                        │ file system                ┌──────────▼───────────┐
 │ signatures,   │                 ┌──────▼───────────────┐            │ token (keys at rest) │
 │ blobs, KEM ct │                 │ audit log file       │            └──────────────────────┘
 └───────────────┘                 └──────────────────────┘
```

The libraries guard three boundaries.

1. At the C ABI, every pointer, length, selector, label, configuration field, ciphertext,
   signature, blob, public key and KEM ciphertext is untrusted.
2. The PKCS#11 module and the token are trusted with key material. The objects in the token are
   shared with every program that has the user PIN, and may change between two calls.
3. The audit log on the file system is read back when a handle opens it and by
   `eki_audit_verify`. Its content is untrusted.

The cryptographic providers (OpenSSL, the RustCrypto crates) are trusted to implement their
algorithms correctly. The libraries are responsible for calling them correctly and for not releasing
their intermediate output.

## Adversaries

Four adversaries are in scope.

1. A hostile or buggy caller in the same process, acting only through the ABI. It passes NULL
   pointers with and without lengths, lengths above every cap, unknown selectors, unterminated or
   non-printable labels and malformed configurations, and it makes calls in any order on any
   handle state. It is after memory corruption, a crash, undefined behaviour, an unexpected
   `EKI_OK`, or a status that differs between the two libraries. The model does not cover a
   caller that passes a non-NULL pointer to fewer bytes than the length says, uses a freed
   handle, or closes a handle while another call on it is running. The contract makes those the
   caller's responsibility, and no library check can detect them.
2. A party that controls data the caller passes on: ciphertexts, tags, AAD, signatures, messages,
   wrapped-key blobs, hybrid KEM public keys and ciphertexts. It wants modified data accepted,
   plaintext released before authentication, or a crash of the process.
3. Another process with access to the token or the log file. With the token and the user PIN it
   can use, create, destroy and change keys; with write access to the log it can edit, truncate
   or replace it. It wants to hide or forge audit records, or to undo a key state change. The
   libraries detect edits to the log. They do not defend keys against a holder of the PIN (see
   [limits](#limits)).
4. Someone who later reads process memory or swap, through a core dump, a swap file or a
   memory-safety bug elsewhere in the process, and wants keys, PINs or plaintexts handled
   earlier. The libraries reduce what remains (wiping, and locked pages in C++); they do not
   prevent the read.

Out of scope are the operating system and anyone with its privileges; physical and hardware
attacks, including cache and power side channels; a malicious or faulty cryptographic provider or
PKCS#11 module; supply-chain attacks on dependencies (`cargo deny` checks advisories and licences,
which is not a defence against them); and timing attacks other than those listed under
[time that depends on data](#time-that-depends-on-data).

## Guarantees and mechanisms per boundary

### The C ABI

| Guarantee | Mechanism | Evidence |
|---|---|---|
| No access through NULL; a zero length never dereferences | `n > 0 && p == NULL` is `EKI_ERR_NULL_POINTER`; `n == 0` accepts any pointer; the Rust library builds `&[]` instead of calling `from_raw_parts` with NULL ([contract, pointer rules](ffi-contract.md#pointer-and-length-rules)) | error-matrix rows of both unit suites and the conformance harness; `ffi_status` fuzz targets (`Call::check`); Miri over the NULL-pointer tests |
| Nothing read or written beyond a checked length | every cap (`EKI_AEAD_MAX_LEN`, `EKI_HKDF_MAX_*`, exact key, nonce, tag, blob and KEM lengths, audit path 4096, approver count 8) is checked before a buffer is touched; labels are scanned for at most 65 bytes | length rows of the error matrix; the fuzz targets pass lengths of cap + 1 and `SIZE_MAX` with real, smaller buffers, under AddressSanitizer |
| A fixed, documented status for each kind of bad argument | one validation order in both libraries: NULL, selector, lengths and formats, store state, cryptography, backend ([contract, validation order](ffi-contract.md#validation-order)); selectors are `int32_t`, so every value is representable | conformance error matrix compares raw `int32_t` statuses; `ffi_status` checks that `EKI_ERR_NULL_POINTER` has no other cause and that over-cap lengths give `EKI_ERR_INVALID_ARGUMENT`; exact status oracles for `eki_ks_open`, `eki_ks_open_v2`, `eki_ks_generate`, `eki_ks_unwrap`, `eki_audit_verify` and `eki_hkdf_sha256` |
| No output after a failure | every output is zero-filled on any non-OK status, `EKI_ERR_UNSUPPORTED` included; a variable output whose length argument is above its maximum is left untouched ([contract, outputs on error](ffi-contract.md#outputs-on-error)). C++: `ffi_barrier` and `sized_output` in `core-cpp/include/ekicore/ffi_guard.hpp`; Rust: `OutputParam::zero` and `StructOut` in `core-rs/src/ffi.rs` (struct outputs are zeroed over their full size, padding included) | "outputs zero" rows of the unit suites; every fuzz target pre-fills outputs with `0xA5` and checks them after each failed call |
| No panic or exception crosses into C | Rust: `barrier` and `contain_panic` run each body under `catch_unwind` (`core-rs/src/ffi.rs`); C++: `ffi_barrier` wraps each body in `try { } catch (...)`; both return `EKI_ERR_INTERNAL` with outputs zeroed | barrier tests (`core-cpp/tests/ffi_guard_test.cpp`, the ffi unit tests in `core-rs/src/ffi.rs`); the fuzz targets fail on any `EKI_ERR_INTERNAL` |
| `unsafe` Rust confined and justified | `unsafe` only in `core-rs/src/ffi.rs`, each block with a SAFETY comment; `#![deny(unsafe_op_in_unsafe_fn)]` | clippy `undocumented_unsafe_blocks`; Miri over a selection of tests (see [testing evidence](#testing-evidence)) |
| Plaintext only after authentication | the tag is verified by the provider; OpenSSL GCM writes plaintext before the tag check, so the C++ library zeroes `pt_out` on failure | "AUTH_FAILED, `pt_out` all zero" rows; `aead_open` fuzz targets check `pt_out` after every failure and that a flipped tag bit is rejected |
| Forgeries rejected | AEAD tags by the provider; HMAC tags compared in constant time (`CRYPTO_memcmp` in `core-cpp/src/hmac.cpp`, `verify_slice` in `core-rs/src/hmac.rs`); ECDSA with full point validation and `r`, `s` range checks; RFC 3394 integrity check on unwrap; ML-KEM implicit rejection and an all-zero X25519 result rejected | RFC and Wycheproof vectors in `conformance/vectors/`; `ecdsa_sign_verify`, `unwrap_blob` and `hybrid_kem` fuzz targets |
| The handle enforces key state and dual control | state checks before every keyed operation ([contract, key states](ffi-contract.md#key-states)); with approvers, `eki_ks_destroy` returns `EKI_ERR_APPROVAL_REQUIRED` and a key is destroyed only after two different configured approvers signed `"ekibridge-destroy-v1" || request || id` ([contract, dual control](ffi-contract.md#dual-control)) | lifecycle and dual-control tests in `core-cpp/tests/ffi_lifecycle_test.cpp`, `core-rs/tests/ffi_lifecycle.rs`; conformance `ks_lifecycle`; `ffi_status` drives requests and approvals with generated and raw signatures |
| The library that was loaded is the one expected | `eki_abi_version()` and `eki_version()`; only `eki_*` symbols exported | conformance `meta`; `scripts/check-header.sh`, `scripts/check-exports.sh` |

### The PKCS#11 module

- Key values of the PKCS#11 backend are generated in the token with `CKA_SENSITIVE` TRUE (private
  EC keys also `CKA_EXTRACTABLE` FALSE) and never enter library memory
  ([contract, PKCS#11 object mapping](ffi-contract.md#pkcs11-object-mapping-and-lifecycle)).
- Objects are looked up again by `CKA_ID` for every operation; handles are not kept, because
  another session may change the token in between. An object of an unexpected shape is foreign:
  the library answers with a defined status and does not use it.
- Key state lives in usage attributes, so the token refuses what a state forbids. The library
  refuses first, which makes the token a second check.
- Return codes are mapped to statuses; a failing module call is `EKI_ERR_BACKEND` with the `CKR_*`
  name in the last-error message, with the exceptions listed under
  [PKCS#11 specifics](#pkcs11-specifics).

### The file system (audit log)

- Each record carries the SHA-256 of the previous one, so the records form a chain from the first
  record to the head ([contract, audit log](ffi-contract.md#audit-log)).
- `eki_audit_verify` and the open check rebuild the exact bytes every record must have from the
  fields a writer chooses and accept only those bytes. Lines are read with a bound of 512 bytes,
  so a file without newlines is not read into memory whole.
- Both libraries open the path with `O_NONBLOCK` and refuse anything that is not a regular file,
  judged on the open file (`core-cpp/src/keystore/audit_log.cpp`,
  `core-rs/src/keystore/audit.rs`). A FIFO or a device at the path fails the call without being
  read, and a FIFO does not make the call wait.
- With `expected_head`, the last hash must equal a head stored elsewhere, which detects a cut tail
  and a replaced chain.
- The writer holds an exclusive `flock` lock for the life of the handle, appends one record per
  logged call with a single `write`, and flushes it before the call returns. A record that cannot
  be written fails the call with `EKI_ERR_BACKEND` and is truncated away.

## PKCS#11 specifics

`C_Initialize` and `C_Finalize` act on the whole process, not on a session. Each library keeps
a process-wide registry keyed by module path. An entry holds the loaded module, its function
list, whether this library initialised it, and the number of open handles.
`CKR_CRYPTOKI_ALREADY_INITIALIZED` is accepted and means someone else owns finalisation.
`eki_ks_close` closes its session and decrements the handle count; when the count reaches zero it
calls `C_Finalize` only if this library performed `C_Initialize`.

`C_Login(CKU_USER)` logs in every session of the application, so `CKR_USER_ALREADY_LOGGED_IN` is
accepted. For the same reason `eki_ks_close` never calls `C_Logout`, which would log out every
other open handle.

If `libekicore` and `libekicore_rs` both hold PKCS#11 stores open at once, only one of them owns
`C_Finalize` and the other can be left with a finalised module. The conformance suite opens them
one after the other (the token persists on disk).

The module's return codes map to statuses as follows.

| The module's answer | Status |
|---|---|
| no object found by `CKA_ID` | `EKI_ERR_KEY_NOT_FOUND` |
| any `C_UnwrapKey` failure after all argument checks passed (SoftHSM2 reports an AES-KW integrity failure as `CKR_GENERAL_ERROR`) | `EKI_ERR_AUTH_FAILED` |
| `CKR_SIGNATURE_INVALID` or `CKR_SIGNATURE_LEN_RANGE` from the `C_Verify` of an HMAC tag | `EKI_ERR_AUTH_FAILED` |
| any other failure | `EKI_ERR_BACKEND`, with the `CKR_*` name in the last-error message |

The SoftHSM2 token the tests use (`ekibridge`, user PIN `1234`, SO PIN `12345678`) is a throwaway
that `scripts/softhsm-init.sh` creates inside the checkout. Those values are for tests only, and
the fuzz targets do not use the token.

## Time that depends on data

| Operation | Timing | Why that is acceptable, or not |
|---|---|---|
| HMAC tag comparison (stateless and software store) | constant time (see above) | the tag is the secret-dependent value an attacker would probe |
| AEAD tag comparison | constant time in OpenSSL and the RustCrypto AEAD crates (`core-rs/src/aead.rs`) | as above; inherited, not measured here |
| HMAC verification in a PKCS#11 token | performed by the token (`C_Verify`) | depends on the module |
| ECDSA verification | variable time in both (`core-rs/src/ecdsa.rs` says so) | public key, message and signature are public |
| ECDSA signing, key generation, AES, X25519, ML-KEM | as implemented by OpenSSL and the RustCrypto crates | inherited; no measurement in this repository |
| Hybrid KEM rejection paths | the all-zero X25519 check is constant time in Rust (`subtle`, `core-rs/src/pq.rs`); ML-KEM implicit rejection by the providers | inherited for ML-KEM |
| Key lookup by id and label checks | variable time (`std::map` in `core-cpp/src/keystore/software.cpp`, maps in Rust) | ids and labels are not secret |
| Pending destroy request lookup | constant time per request in C++ (`core-cpp/include/ekicore/dual_control.hpp`); a `BTreeMap` lookup in Rust (`core-rs/src/keystore/dual.rs`) | a request is not an authenticator: an approval also needs a configured approver's signature over it |
| Audit head comparison | a plain comparison (`core-rs/src/keystore/audit.rs`) | the head is public |

I have made no side-channel measurement. The table records what the source does.

## Testing evidence

| Kind | What it shows | What it cannot show |
|---|---|---|
| Unit and ABI tests (`core-cpp/tests/`, `core-rs/tests/`, unit tests in `core-rs/src/`) | each library does what the contract says for chosen inputs, error rows and state sequences, including fault injection for barriers and audit write failures | behaviour on inputs nobody chose; both libraries agreeing |
| Conformance harness (`conformance/`, modules in `conformance/ci-modules.txt`) | both libraries give the same raw statuses and outputs on RFC and Wycheproof vectors, the error matrix, differential runs with random inputs and cross-language round trips (a log or key written by one is read by the other) | that a behaviour both libraries share is right, except where a published vector fixes it |
| Fuzzing (below, [findings.md](findings.md)) | no crash, sanitizer report, contract violation encoded as a property, or disagreement with an independent oracle on the inputs the campaign reached | absence of bugs; anything the properties do not check; paths the inputs did not reach; PKCS#11, threads and timing |
| Sanitizers (`asan` and `fuzz` CMake presets; cargo-fuzz builds with AddressSanitizer, debug assertions and overflow checks) | memory errors and undefined behaviour on the paths that ran | paths that did not run; uninitialised reads (no MemorySanitizer build); leaks inside OpenSSL are not attributed |
| Miri (`.github/workflows/rust.yml`) | no undefined behaviour in the Rust pointer handling for the ffi unit tests and the NULL-pointer, length and format tests of the ABI test files, built without default features | the PKCS#11 backend (Miri cannot load a module), the property tests (ignored under Miri), the cryptographic paths outside that selection, and the C++ library |

### Fuzz targets

Each target exists in both languages with the same input layout, so one seed file drives both
(`core-rs/fuzz/src/lib.rs`, `core-cpp/fuzz/fuzz_input.hpp`). Outputs are exactly sized heap
allocations pre-filled with `0xA5`, so AddressSanitizer catches an access one byte too far and the
targets can tell a zero-filled output from an untouched one.

| Rust (`core-rs/fuzz/fuzz_targets/`) | C++ (`core-cpp/fuzz/`) | Properties |
|---|---|---|
| `ffi_status` | `fuzz_ffi_status` | every exported function, up to 24 calls per input on a session store opened from a fuzzed configuration (`eki_ks_open` or `eki_ks_open_v2`, audit log, approvers); NULL flags, lengths within the cap, cap + 1 and `SIZE_MAX`, any selector; status always defined and never `EKI_ERR_INTERNAL`; `EKI_ERR_NULL_POINTER` exactly when a pointer is NULL; every output zero after any failure with no exemption for `EKI_ERR_UNSUPPORTED`, or untouched when its length was above the cap; exact oracles for opening, generating, reading a log and the metadata functions; the log of a closed store verifies and reopens |
| `audit_verify` | `fuzz_audit_verify` | arbitrary bytes written to a file; the library accepts exactly what an independent strict parser of the record grammar and hash chain accepts, with and without `expected_head`, and reports the same record count |
| `unwrap_blob` | `fuzz_ks_unwrap` | arbitrary blob, algorithm, label and id, or a real wrap with bytes XORed over it, in a store opened from a fuzzed configuration; the exact status the validation order gives; `EKI_OK` only for an unmodified wrap, after which the key reports its algorithm, label and ACTIVE state and computes the original key's HMAC |
| `hybrid_kem` | `fuzz_hybrid_kem` | arbitrary public keys, secret keys and ciphertexts, and round trips with masked public keys and ciphertexts; statuses `EKI_OK` or `EKI_ERR_INVALID_ARGUMENT` only; decapsulation fails only when the X25519 part changed; a changed exchange never yields the same secret; without the KEM compiled in, `EKI_ERR_UNSUPPORTED` with zeroed outputs |
| `aead_open` | `fuzz_aead_open` | open of arbitrary inputs; seal of the recovered plaintext reproduces ciphertext and tag; seal then open round trip; one flipped tag bit is rejected |
| `hkdf` | `fuzz_hkdf` | exact status for every length; prefix stability between two output lengths; over-cap output untouched |
| `ecdsa_sign_verify` | `fuzz_ecdsa_sign_verify` | sign with a stored key, verify unchanged (accepted) and with a changed signature, message or public key (rejected) |

Each target has a corpus directory named after it, under `core-rs/fuzz/corpus/` and
`core-cpp/fuzz/corpus/`. A Rust target and its C++ counterpart hold the same named seeds, written
by `core-rs/fuzz/examples/seeds.rs`. The seeds are conformance vectors (RFC 4231, RFC 5869, RFC
8439, AES-GCM test cases, RFC 6979), artefacts the library produced (an audit log and variants of
it cut, edited and reordered, a wrapped key, a KEM key pair and ciphertext), and configurations
that reach the audit log, dual control, the PKCS#11 argument checks and NULL fields. Inputs that
libFuzzer adds are named by their SHA-1 and ignored by git.

The targets can find memory errors and undefined behaviour in either library (under the
sanitizers), uncaught panics and exceptions (`EKI_ERR_INTERNAL`), outputs left non-zero after a
failure, statuses outside the contract or in the wrong validation order, an audit verifier that
accepts a log the strict parser rejects or the reverse, forgeries accepted, round trips that do
not return their input, and lock or file state left behind by a closed handle.

What they do not reach:

| Not reached | Why | What covers it instead |
|---|---|---|
| The PKCS#11 backend | The targets use the software backend only. A configuration that selects PKCS#11 names a module path that does not exist, so the library's argument checks run and the module load fails with `EKI_ERR_BACKEND`; the SoftHSM2 token is never opened by a fuzz target. | only the unit tests and the `ks_pkcs11` and `ks_pkcs11_lifecycle` conformance modules |
| Concurrency | Every target is single-threaded. | unit tests of the handle lock and of the log lock across processes |
| Timing | Nothing measures time. | nothing |
| Failing I/O and failing randomness: a full disk, a short write, a failing random source | The targets run on a working file system and random source. | fault-injection unit tests |
| Pointers that lie about their length | The targets pass honest buffers; a caller that does not is outside the contract. | nothing |
| Disagreement between the two libraries | Each target checks one library against the contract and its own oracles. | the conformance harness |
| A wrong SHA-256 in the audit chain | The oracle of the `audit_verify` targets parses the grammar on its own but hashes with the same code as the library it checks (`sha2` in Rust, OpenSSL in C++). | the conformance `audit` module, in which each library verifies and continues the other's log |

Each target is meant to run for 200000 executions per campaign in each language, and the KEM
targets and `ffi_status` also in a build with the hybrid KEM compiled in. The campaign of
2026-11-11 is recorded run by run in [findings.md](findings.md). Every C++ run, and every Rust
run except `ffi_status`, reached 200000 executions with no finding. The Rust `ffi_status` target
did not reach that count in four runs. I stopped the first default-features run by hand at 34510
executions, after 2008 s; its rerun and both `pq` runs ended at their time limits, at 17795,
76679 and 82638 executions. None of the four found anything. The target is slow because each
logged call flushes the audit log with `F_FULLFSYNC` on macOS, and the machine also slept during
the runs. A follow-up run on a Linux server, where the flush is `fdatasync` and nothing sleeps,
took both builds of the target to 200000 executions in about twelve minutes each, again with no
finding.

`.github/workflows/fuzz.yml` runs every target from its committed seeds for at most 200000
executions or two minutes, whichever comes first, on each push and pull request and once a week.
That is a smoke test, not a campaign.

## Limits

### Secrets in process memory

- In the Rust library, temporaries inside the RustCrypto crates stay on the stack unwiped: the
  padded HMAC key block, the HKDF pseudorandom key, AES-GCM counter and tag temporaries, the AES
  key wrap scratch block, ECDSA signing temporaries and RFC 6979 state, `p256` candidate scalars,
  moved copies of signing keys, and X25519 and ML-KEM intermediates
  ([contract, secret handling](ffi-contract.md#secret-handling)). The C++ library does not control
  the stack either.
- The Rust library locks no pages, so key material can reach swap. The C++ library locks
  `secret_buffer` pages, best effort, when built with `EKI_MLOCK` (on by default); a failed
  `mlock` is not an error.
- A software ECDSA key in the C++ library is an `EVP_PKEY` in OpenSSL's memory, not in locked
  memory; OpenSSL clears it on free. I have not verified whether OpenSSL wipes the hybrid KEM
  `EVP_PKEY` objects on free.
- The PIN is a C string in caller memory before and after `eki_ks_open`; the library's own copy is
  wiped after login.

### Keys, tokens and approvers

- The wrapped blob is plain RFC 3394 output. The algorithm, label and id are not bound to it, so
  whoever can change them can have an AES key unwrapped as an HMAC key (or the reverse) under a
  label of their choosing.
- SoftHSM2 is a software token. The module runs inside the calling process and keeps its keys in
  files on disk protected by the PIN, so "never enters library memory" is a statement about
  `libekicore` and `libekicore_rs` only: it says nothing about the module's memory or its
  storage. Return codes have been checked against SoftHSM2 2.7.0 only.
- The token allows usage attributes to be set back. SoftHSM2 2.7.0 accepts setting a cleared
  usage flag back to TRUE, so only the library keeps state transitions one-way. Any program with
  the user PIN can move a key from REVOKED back to ACTIVE, or destroy it without dual control.
- Approvals are only as good as the approvers' key custody. The library checks that two different
  configured keys signed the request; whoever holds two approver private keys can destroy any key
  alone. The approver keys are fixed when the handle opens and are trusted as given.
- The software store is not persistent. Keys live in memory for the lifetime of the handle and
  are lost on close or crash.

### Audit log

- The log tail can be cut. A log cut after any complete record still verifies unless the head
  from `eki_ks_audit_head` is kept somewhere the attacker cannot write, and passed as
  `expected_head`. A writer of the file can also replace the whole chain with a consistent one;
  the chain is not signed.
- The log lock is advisory. `flock` excludes other handles of these libraries; a process that
  does not take the lock can still write the file.
- A write can fail after the operation happened. If a record cannot be written, the call returns
  `EKI_ERR_BACKEND` and undoes what it can; a destroyed key and a state change cannot be undone,
  and the log then holds no record of them ([contract, writing](ffi-contract.md#writing)).
- Durability on macOS depends on `F_FULLFSYNC`. `fsync` there does not flush the drive's write
  cache, so both libraries flush each audit record with `F_FULLFSYNC`: the Rust library through
  `sync_data`, the C++ library through `fcntl(F_FULLFSYNC)`, falling back to `fsync` on a file
  system that rejects it. On such a file system a power loss can still lose the last records
  written by the C++ library; the Rust library fails the write instead.
- The flush is slow, which shows in fuzzing throughput. The Rust `ffi_status` target flushes a
  record per logged call and ran at about 200 executions per second on an idle machine; it did
  not reach 200000 executions in any run of the 2026-11-11 campaign on the Mac, and did in a
  later run on Linux ([findings.md](findings.md)). The C++ target reached 200000 executions in
  103 s in that campaign, when the C++ library still flushed with `fsync`.

### Timing and threads

- ECDSA verification and everything else applied to public data runs in variable time; no
  constant-time property of the providers is measured here.
- The C++ `catch (...)` barrier also catches glibc's forced unwind, so cancelling a thread inside
  a library call is unsupported.
- A caught Rust panic still prints through the process-wide panic hook.
