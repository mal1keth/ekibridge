# Migration plan: C++ core to Rust behind one C ABI

In this repository `libekicore` (C++ on OpenSSL) plays an existing production core and
`libekicore_rs` (Rust on RustCrypto) plays its replacement. This document describes how a team
would move from the first to the second without a flag day: in what order, behind which gates,
with which switch to go back, and what a reviewer checks. It is written for engineers who would
run such a migration, and for a reader who wants to know how much of one this repository can
show. Its examples come from the repository's own history.

## What exists and what the plan assumes

No migration has been carried out with this code, and none of it has run in production. The plan
relies on some things the repository has and on some it does not have.

The repository has:

- both libraries behind one header, with scripts that check the header and the exported symbols;
- the conformance harness, the fuzz targets, the sanitizer presets and the Miri job that the
  gates name;
- two interop callers that load either library from a path given at run time;
- benchmark workloads for HMAC, HKDF and AEAD.

It does not have:

- a loader that picks a library per module. The interop callers choose a whole library at load
  time, so the repository demonstrates the switch of the whole library, not of one module (see
  [Strangler order](#strangler-order));
- benchmark workloads for ECDSA verification, the hybrid KEM or the key store, which the
  performance item of the gate needs for those steps;
- a completed differential run at the gate's 10^6 iterations (see
  [Cutover gate per module](#cutover-gate-per-module));
- production traffic. The soak periods, the alert rules and the rest of
  [Observability](#observability) describe what a deployment would do and have not been
  exercised.

I develop and test on macOS (Apple silicon). On Linux the CI workflows build and test the
implementation on Ubuntu 24.04. By hand I have run only parts of it on Linux (Debian 13, x86-64):
the C++ tests built with GCC, the Miri selection and one fuzz target.

## Goal

Replace the C++ implementation with the Rust one for every function of the
[C ABI](ffi-contract.md), with:

- no change to any caller's source code or build,
- a gate per module that has to be passed before production traffic reaches the new code,
- a rollback that is a configuration change, not a redeploy of the callers.

## Why one C ABI

Both libraries export the same 32 `eki_*` symbols declared in one header,
[`include/ekicore.h`](../include/ekicore.h). A caller compiled against that header can use either
library, so which implementation runs is decided at link time or load time and no caller has to
be rewritten. The conformance harness loads both libraries into one process and compares them
call by call, which is what makes the gates below measurable.

The header is generated from the Rust declarations and the C++ library is compiled against the
committed copy, so neither side can drift from it without failing the build or
[`scripts/check-header.sh`](../scripts/check-header.sh).
[`scripts/check-exports.sh`](../scripts/check-exports.sh) checks that both libraries export the
`eki_*` symbols and nothing else.

## Strangler order

| Step | Module | State it owns | What the step proves |
|---|---|---|---|
| 1 | HKDF-SHA256 | none | the loading, routing, version check and observability work, on the function with the smallest input space and no secret it keeps |
| 2 | HMAC-SHA256 | none | constant-time verification and the AUTH_FAILED path behave the same under real traffic |
| 3 | ECDSA P-256 verify | none | public-key parsing and signature acceptance match, including the edge cases (coordinates at the field prime, high-s, zero `r` or `s`) |
| 4 | AEAD | none | large buffers, the length caps and zero-on-error of plaintext behave the same, and the throughput budget holds |
| 5 | Key store, software backend | keys in memory, for one handle | handle lifetime, locking, last-error text and the store's check sequences, where a mistake loses only process-local keys |
| 6 | Key store, PKCS#11 backend | keys in the token, shared | both libraries read and write the same token objects; every key survives the switch in both directions |
| 7 | Lifecycle, audit log, dual control | key states in the token, the audit file, pending requests | state changes and audit chains written by one library are honoured and continued by the other |

The hybrid KEM is optional in both builds; a deployment that enables it moves it with the
stateless group, after step 4.

The stateless functions go first because they own nothing. A wrong answer affects one call, and
switching back restores the old behaviour completely. The key store owns keys: a wrong answer
there can destroy or expose a key, and some changes (a destroyed key, a revoked key) cannot be
undone by switching back. So the stateful steps come last.

The early steps are also the ones that can be compared exactly. HKDF, HMAC and ECDSA verify are
deterministic, and the harness checks byte-identical outputs and identical statuses for random
and hostile inputs. AEAD is deterministic too but has the largest inputs. The key store is
comparable only through its observable effects, because key material never leaves it and
signatures are not deterministic in every backend. Its gate therefore rests on cross-library
scenarios, not on output equality.

The key store's HMAC, wrap and sign paths use the same primitives as steps 1 to 4 inside each
library, so by the time the store moves, those primitives have run in production. Step 7 depends
on step 6, because states and audit records live in the token and the file the backend shares.

The unit of switching changes at step 5. Steps 1 to 4 can be switched per module by a loader that
resolves each module's `eki_*` symbols from the library chosen for it, the way the harness
resolves symbols from two libraries in one process. That loader is not part of this repository:
its interop callers take one library path and resolve every symbol from it, so they choose a
whole library at load time. From step 5 on the switch is the whole library in any case. A store
handle belongs to the library that opened it, and two ekicore libraries must not hold PKCS#11
stores open in one process at the same time (see the
[threat model](threat-model.md#pkcs11-specifics)).

## Cutover gate per module

A module moves to the Rust implementation only when every item is checked.

- [ ] Every conformance module that covers it passes against both libraries, PKCS#11 modules
      included, from a clean checkout:

  ```sh
  source scripts/softhsm-init.sh
  scripts/run-conformance.sh --all --with-pkcs11
  EKI_PQ=1 scripts/run-conformance.sh pq       # only if the hybrid KEM is enabled
  ```

- [ ] The differential run passes with identical status and outputs at 10^6 iterations per
      function or more (random inputs; mutated vectors for ECDSA verify). CI runs 2000 per
      function. The gate run raises the count and takes hours, not minutes: on an arm64 Mac the
      HMAC module alone took about 2 minutes and HKDF about 6, and I stopped AEAD after more than
      25 minutes, before it had finished and before ECDSA had started. I have not yet run this
      command to completion:

  ```sh
  EKI_DIFF_N=1000000 scripts/run-conformance.sh hmac hkdf aead ecdsa
  ```

- [ ] Every row of the error matrix for the module passes in both libraries with identical status
      and zeroed outputs (the conformance modules carry the rows of the
      [contract](ffi-contract.md#per-function-contract)).
- [ ] The module's fuzz targets in both libraries have run for the agreed number of CPU hours
      with no open finding ([findings](findings.md),
      [what the fuzzers cover](threat-model.md#fuzz-targets)). The one campaign recorded so far
      aimed at 200000 executions per target; the Rust `ffi_status` target reached that count only
      in a follow-up run on Linux.
- [ ] The C++ unit tests pass under AddressSanitizer and UndefinedBehaviorSanitizer
      (`cmake --preset asan && cmake --build --preset asan && ctest --preset asan`), and the Miri
      job of `.github/workflows/rust.yml` passes.
- [ ] On the module's workloads in [benchmarks](benchmarks.md), the ratio column of
      `scripts/bench.sh` (Rust time over C++ time) is at most 1.10, measured on the production
      hardware class; a larger ratio needs a written reason to accept it. Two things limit this
      item as it stands. First, the ratio divides a criterion median (Rust) by a Google Benchmark
      mean of one run (C++). Those are different statistics, so the ratio is approximate. Second,
      the repository has workloads for HMAC, HKDF and AEAD only. ECDSA verification, the hybrid
      KEM and the key-store steps (5 to 7) have none, so the item cannot be checked for them
      until workloads are written. The one run recorded so far, on a laptop and not on production
      hardware, has the HMAC and HKDF rows under 1.10 and every AEAD row over it (1.26 to 2.42).
- [ ] The diff has passed the [reviewer checklist](#reviewer-checklist).
- [ ] After the switch, the module runs on production traffic for a soak period (two weeks for a
      stateless module, four for a key store step) with no rise in `EKI_ERR_INTERNAL` or
      `EKI_ERR_BACKEND` and no unexplained change in the status mix (see
      [Observability](#observability)). The C++ library stays deployed and selectable until the
      soak ends.

## What the conformance suite does and does not show

It shows, for both libraries loaded into one process:

- published vectors (RFC 4231, RFC 5869, RFC 8439, the GCM specification, RFC 6979, Wycheproof)
  give the expected outputs and statuses;
- a seeded differential comparison of the stateless functions gives identical outputs and
  statuses;
- every row of the error matrix gives the contract's status, with outputs zero-filled;
- key store scenarios agree across libraries: cross-verification of signatures, wrap in one and
  unwrap in the other through a shared SoftHSM2 token, states and destruction seen across both;
- audit logs are byte-exact, verify in both, are continued by the other library, and every
  tampering the tests make (including forged chains with correct hashes around one bad record) is
  rejected by both;
- dual control works with approver keys held in the other library's software store.

It does not show:

- that either library is correct where both are wrong in the same way. Agreement between the two
  is not correctness; only the published vectors test against an outside answer;
- behaviour on hardware HSMs: every PKCS#11 run is against SoftHSM2;
- foreign token objects: they are covered by each library's own unit tests, not by the harness;
- the differences the contract leaves open (listed in
  [Known differences](ffi-contract.md#known-differences)), such as the undo of an operation
  after a panic inside a logged call;
- concurrency beyond what the unit tests exercise, behaviour under memory pressure, or resistance
  to timing and other side channels;
- that secrets are wiped: memory contents after a call are not inspected;
- performance, which [the benchmarks](benchmarks.md) measure separately.

## Runtime selection and rollback

- The library path comes from configuration, not from the build. Callers `dlopen` the configured
  path; neither interop caller links an ekicore library, each loads the path it is given:

  ```sh
  scripts/interop-demo.sh    # builds both libraries and both callers, runs each across the boundary
  build/release/interop/cpp-caller/cpp-caller target/release/libekicore_rs.dylib
  build/release/interop/cpp-caller/cpp-caller build/release/core-cpp/libekicore.dylib
  ```

  (`.so` instead of `.dylib` on Linux.) The same binary runs against either library; that
  argument is the switch. It selects the whole library, for every module at once.
- At load, the caller resolves every symbol it uses, checks `eki_abi_version() == 2` (the
  callers compare against `EKI_ABI_VERSION` from the header they were built with) and logs
  `eki_version()`, so every log line can be attributed to `ekicore-cpp` or `ekicore-rs` and a
  version. A library that fails the check is not used.
- A caller that links the library instead of loading it selects it at link or load time by the
  library search path; the rollback is then a change of that path and a restart.
- Rollback is flipping the configured path back to `libekicore` and restarting or reloading the
  process. Because both libraries share the ABI, the wrapped-key format, the PKCS#11 object mapping
  and the audit record format, no data migration is needed in either direction.
- PKCS#11 keys created by one library are usable by the other, and key states set by one are
  honoured by the other, so the key store can be switched without re-provisioning keys. An audit
  log written by one library is verified and continued by the other.
- Rollback does not restore destroyed keys, keys that were revoked or retired, or pending destroy
  requests (they live in the handle and end with the process).

## Observability

The repository has no monitoring. This is what a deployment would add around the library.

- Count every call by function and by `eki_status_name(status)`, labelled with `eki_version()`.
- Alert on any rise in `EKI_ERR_INTERNAL` or `EKI_ERR_BACKEND` after a cutover, and on any change
  in the ratio of `EKI_ERR_AUTH_FAILED` or `EKI_ERR_KEY_STATE` to `EKI_OK` for the same traffic.
- For the key store, record the last-error message on `EKI_ERR_BACKEND` (it carries the `CKR_*`
  name, the OpenSSL error string or the file system error). Message text differs between the two
  libraries, so alerts must match on status, not on text. Never log key material, PINs, plaintext
  or labels marked sensitive.
- With an audit log, keep the head from `eki_ks_audit_head` outside the host and run
  `eki_audit_verify` against it on a schedule; a cutover must not break the chain.

## Preserving identity semantics

Key ids (16 random bytes, `CKA_ID`), labels (`CKA_LABEL`), key states (usage attributes) and the
wrapped-key format are identical in both libraries, so a key generated or wrapped by one is found
and used by the other. The conformance suite shows: wrap in one library and unwrap in the other
with the same id and label, identical HMAC outputs afterwards, signatures from one verified by the
other, a state set through one library seen through the other, destruction visible across both,
and an audit log continued across libraries.

### What a full PKI would need

The library manages keys; it issues no certificates and knows no identities beyond key ids and
labels. A PKI on top of it would need more than the suite demonstrates.

| A PKI needs | What the library has |
|---|---|
| Certificates bound to key ids: a CA that signs with a token key, and a record of which certificate belongs to which `CKA_ID`. | Nothing in the ABI links a certificate to a key. |
| Rotation as a certificate event: a CA would have to issue a certificate for the new key and decide how long the old one may still verify. | `eki_ks_rotate` makes a new key under a new id and retires the old one. The suite shows the key side only. |
| Revocation that reaches relying parties, who learn of a revoked certificate only from a CRL or an OCSP responder. | A REVOKED key refuses to sign, which is a token state, not a statement anyone else can see. The library provides neither a CRL nor a responder. |
| An audit trail across programs. | The audit log records calls through one library handle; a CA's issuance and CRL signing in the same token through its own PKCS#11 session would leave no record there. |
| Key ceremony and custody: backups, split knowledge and M-of-N activation of CA keys. | These are outside the library; dual control here covers only the destruction of a key through one handle. |

[The PKI note](pki-note.md) runs a step-ca certificate authority whose keys live in the same kind
of token, and says what that run shows about key protection and revocation and what it does not.

## Four cases from this repository

These are four defects or near misses from this repository's history. Each comes with the check
that belongs in the gate or the review.

### A length above its cap must not become a slice

The contract lets a caller pass `okm_len = SIZE_MAX` with a small buffer: the length is above
`EKI_HKDF_MAX_OKM_LEN`, the call fails with `EKI_ERR_INVALID_ARGUMENT`, and the buffer is never
touched. In Rust, creating the slice with `slice::from_raw_parts` before checking the length
would already be undefined behaviour, even if no byte were read, because a slice must lie inside
one allocation. The Rust FFI layer therefore keeps pointer, length and maximum together in its
`Input` and `Output` wrappers and creates a slice only after the NULL rule and the maximum have
been checked. Miri runs the tests that pass such lengths
(`output_above_its_maximum_is_left_untouched`, `null_check_precedes_the_maximum`). The rule is C1
of the [contract](ffi-contract.md#pointer-and-length-rules).

### An error queue cleared too broadly

The C++ primitives first called `ERR_clear_error` after an expected failure (tag mismatch, bad
public key, bad signature). OpenSSL's error queue is per thread and shared with the host
application, so that also discarded entries the application had not read yet. On OpenSSL 3.5 a
GCM or ChaCha20 tag mismatch queues nothing at all, so the call removed only the application's
entries. The fix marks the queue when a call starts (`ERR_set_mark`), keeps the entries pushed
since the mark on `EKI_ERR_BACKEND`, because they carry the reason, and pops back to the mark on
every other status. Tests push a recognisable entry before a failing call and check that it is
still the only one afterwards. No differential test could see this: the Rust library has no
OpenSSL queue.

### Check orders that differed for foreign token objects

With a foreign object as the KEK and a key id that did not exist, `eki_ks_wrap` answered
`EKI_ERR_BACKEND` in the C++ library, which described the KEK before looking up the key, and
`EKI_ERR_KEY_NOT_FOUND` in the Rust library, which looks up both ids first, as the contract says.
The conformance suite could not catch it, because it creates no foreign objects; a comparison of
the two store sequences found it. The C++ store now looks up both ids before describing either,
and unit tests in both libraries pin the order with a foreign object made directly in the token.

### A hardware backend an interpreter could not run

Miri interprets the Rust code to find undefined behaviour, but it cannot execute the ARMv8 AES
and SHA-3 instructions that the `aes` and `keccak` crates select on such machines, and the whole
test suite would take hours because it interprets the elliptic-curve and AES arithmetic. The Miri
job sets `--cfg aes_backend="soft" --cfg keccak_backend="soft"` and runs the tests that exercise
the FFI layer's pointer handling. As a consequence Miri checks the portable code paths, not the
hardware ones that ship on ARMv8, and it does not run the PKCS#11 backend, which loads a native
module. The hardware paths run natively in the unit tests, the conformance tests and the fuzz
targets, which are built with AddressSanitizer. The PKCS#11 backend runs in the unit and
conformance tests only.

## Reviewer checklist

A reviewer applies this to every module's Rust diff before its cutover gate.

- [ ] `unsafe` stays in `core-rs/src/ffi.rs`. No `#[allow(unsafe_code)]` elsewhere; the crate
      root keeps `#![deny(unsafe_code)]`.
- [ ] Every `unsafe` block and impl has a `// SAFETY:` comment that names the caller rule it
      relies on (C1 to C7 of the [contract](ffi-contract.md#pointer-and-length-rules)) and why that
      rule makes the operation sound. `scripts/unsafe-inventory.sh` lists them and fails on a
      missing comment; the [inventory](ffi-contract.md#unsafe-inventory) in the contract is
      regenerated from it, and the diff of that inventory is reviewed block by block.
- [ ] Every new `unsafe fn` has a `# Safety` section, except the `extern "C"` functions, whose
      contract is the contract document.
- [ ] The validation order is kept. NULL checks in parameter order before anything else, then
      selectors, then lengths and formats, then store state, then cryptographic checks; the order
      matches the per-function table of the contract and the C++ sequence for the same function. A
      slice is created only after the NULL rule and the maximum are checked.
- [ ] Outputs are zeroed on error. Every output is passed to `barrier`, so it is zero-filled on
      every status other than `EKI_OK`; a variable-length output above its maximum is left
      untouched.
- [ ] Panics are contained. The body runs inside `barrier` or `contain_panic`; nothing can panic
      between the entry of the `extern "C"` function and `catch_unwind`; panic payloads are
      dropped through `drop_panic_payload`; the release profile still has `panic = "unwind"`. In
      the key store, no panic can leave the store inconsistent (the argument at `Handle::lock`).
- [ ] Secrets are kept out of plain memory and out of text. Key material is held in `SecretBox`
      or `Zeroizing` and never copied into a plain `Vec` or array that outlives the call; new
      dependencies that handle secrets are built with their `zeroize` feature; secrets never
      appear in last-error text, `Debug` output or logs; the
      [contract's list](ffi-contract.md#secret-handling) of what is not wiped is updated.
- [ ] Nothing is hand-rolled. Every primitive comes from a RustCrypto crate at a pinned version;
      no cryptographic arithmetic, padding or comparison is written by hand (the constant-time
      comparison is the crate's).
- [ ] The tests are enabled. The module's tests in `core-rs/tests/` and its conformance module
      run in CI (listed in `conformance/ci-modules.txt`), none is ignored or skipped without a
      stated reason, the Miri job includes the new FFI tests, and clippy passes with
      `-D warnings -W clippy::undocumented_unsafe_blocks`.
- [ ] The header and the exports still check. `scripts/check-header.sh` and
      `scripts/check-exports.sh` pass; a change to a declaration comes with a contract change and,
      if incompatible, an ABI version change.
