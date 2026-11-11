# Migration plan: C++ core to Rust behind one C ABI

`libekicore` (C++ on OpenSSL) plays the existing production core; `libekicore_rs` (Rust on
RustCrypto) plays its replacement. This document describes how a team would move from one to the
other module by module without a flag day: in what order, behind which gates, with which switch
to go back, and what a reviewer checks. Its examples come from this repository's history.

## Goal

Replace the C++ implementation with the Rust one for every function of the
[C ABI](ffi-contract.md), with:

- no change to any caller's source code or build,
- a gate per module that has to be passed before production traffic reaches the new code,
- a rollback that is a configuration change, not a redeploy of the callers.

## Why one C ABI

Both libraries export the same 32 `eki_*` symbols declared in one header,
[`include/ekicore.h`](../include/ekicore.h). A caller compiled against that header can use either
library, so which implementation runs becomes a link-time or load-time decision instead of a
rewrite of every caller. The conformance harness loads both libraries into one process and compares
them call by call, which is what makes the gates below measurable.

The header is generated from the Rust declarations and the C++ library is compiled against the
committed copy, so neither side can drift from it without a build or CI failure
([`scripts/check-header.sh`](../scripts/check-header.sh)); both libraries are checked to export the
`eki_*` symbols and nothing else ([`scripts/check-exports.sh`](../scripts/check-exports.sh)).

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

The reasoning:

- **Blast radius first.** The stateless functions own nothing: a wrong answer affects one call,
  and switching back restores the old behaviour completely. The key store owns keys; a wrong answer
  there can destroy or expose a key, and some changes (a destroyed key, a revoked key) cannot be
  undone by switching back. So the stateless functions go first and the stateful ones last.
- **Comparability.** HKDF, HMAC and ECDSA verify are deterministic and fully comparable: the
  harness checks byte-identical outputs and identical statuses for random and hostile inputs. AEAD
  is deterministic too but has the largest inputs. The key store is comparable only through its
  observable effects, because key material never leaves it and signatures are not deterministic in
  every backend, so its gate rests on cross-library scenarios rather than output equality.
- **Dependencies.** The key store's HMAC, wrap and sign paths use the same primitives as steps 1 to
  4 inside each library; by the time the store moves, those primitives have run in production.
  Step 7 depends on step 6, because states and audit records live in the token and the file the
  backend shares.
- **Unit of switching.** Steps 1 to 4 can be switched per module by a loader that resolves each
  module's `eki_*` symbols from the library chosen for it, the way the harness resolves symbols
  from two libraries in one process. From step 5 on the switch is the whole library: a store handle
  belongs to the library that opened it, and two ekicore libraries must not hold PKCS#11 stores
  open in one process at the same time (see the
  [threat model](threat-model.md#pkcs11-specifics)).

## Cutover gate per module

A module moves to the Rust implementation only when every item is checked.

- [ ] **Conformance green.** Every conformance module covering it passes against both libraries,
      PKCS#11 modules included, from a clean checkout:

  ```sh
  source scripts/softhsm-init.sh
  scripts/run-conformance.sh --all --with-pkcs11
  EKI_PQ=1 scripts/run-conformance.sh pq       # only if the hybrid KEM is enabled
  ```

- [ ] **Differential run.** At least 10^6 random inputs per function, identical status and
      outputs. CI runs 2000 per function; the gate run raises it, and takes hours rather than
      minutes (on an arm64 Mac the HMAC module alone took about 2 minutes, HKDF
      about 6, and AEAD more than 25):

  ```sh
  EKI_DIFF_N=1000000 scripts/run-conformance.sh hmac hkdf aead ecdsa
  ```

- [ ] **Error matrix.** Every row of the error matrix for the module passes in both libraries with
      identical status and zeroed outputs (the conformance modules carry the rows of the
      [contract](ffi-contract.md#per-function-contract)).
- [ ] **Fuzzing.** The module's fuzz targets in both libraries have run for the agreed number of
      CPU hours with no open finding ([findings](findings.md),
      [what the fuzzers cover](threat-model.md#fuzz-targets)).
- [ ] **Sanitizers and Miri.** The C++ unit tests pass under AddressSanitizer and
      UndefinedBehaviorSanitizer (`cmake --preset asan && cmake --build --preset asan && ctest
      --preset asan`), and the Miri job of `.github/workflows/rust.yml` passes.
- [ ] **Performance budget.** On the module's workloads in [benchmarks](benchmarks.md), the ratio
      column of `scripts/bench.sh` (Rust time over C++ time) is at most 1.10, measured on the
      production hardware class; a larger ratio needs a written reason to accept it.
- [ ] **Review.** The diff has passed the [reviewer checklist](#reviewer-checklist).
- [ ] **Soak.** After the switch, the module runs on production traffic for a soak period (two
      weeks for a stateless module, four for a key store step) with no rise in
      `EKI_ERR_INTERNAL` or `EKI_ERR_BACKEND` and no unexplained change in the status mix (see
      [Observability](#observability)). The C++ library stays deployed and selectable until the
      soak ends.

## Runtime selection and rollback

- The library path comes from configuration, not from the build. Callers `dlopen` the configured
  path; neither interop caller links an ekicore library, each loads the path it is given:

  ```sh
  scripts/interop-demo.sh    # builds both libraries and both callers, runs each across the boundary
  build/release/interop/cpp-caller/cpp-caller target/release/libekicore_rs.dylib
  build/release/interop/cpp-caller/cpp-caller build/release/core-cpp/libekicore.dylib
  ```

  (`.so` instead of `.dylib` on Linux.) The same binary runs against either library; that
  argument is the switch.
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
- What rollback does not restore: keys destroyed, keys revoked or retired, and pending destroy
  requests (they live in the handle and end with the process).

## Observability

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
labels. A PKI on top of it would need, beyond what the suite demonstrates:

- **Certificates bound to key ids.** A CA that signs with a token key and a record of which
  certificate belongs to which `CKA_ID`. Nothing in the ABI links a certificate to a key.
- **Rotation as a certificate event.** `eki_ks_rotate` makes a new key under a new id and retires
  the old one; a CA would have to issue a certificate for the new key and decide how long the old
  one may still verify. The suite shows the key side only.
- **Revocation and its propagation.** A REVOKED key refuses to sign, which is a token state, not a
  statement anyone else can see. Relying parties learn of a revoked certificate only from a CRL or
  an OCSP responder, which the library does not provide.
- **Audit across programs.** The audit log records calls through one library handle; a CA's
  issuance and CRL signing in the same token through its own PKCS#11 session would leave no record
  there.
- **Key ceremony and custody.** Backups, split knowledge and M-of-N activation of CA keys are
  outside the library; dual control here covers only the destruction of a key through one handle.

[The PKI note](pki-note.md) runs a step-ca certificate authority whose keys live in the same kind
of token, and says what that run shows about key protection and revocation and what it does not.

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

- that either library is correct where both are wrong in the same way: agreement is not
  correctness, which is why the vectors matter;
- behaviour on hardware HSMs: every PKCS#11 run is against SoftHSM2;
- foreign token objects: they are covered by each library's own unit tests, not by the harness;
- the differences the contract leaves open (listed in
  [Known differences](ffi-contract.md#known-differences)), such as the undo of an operation
  after a panic inside a logged call;
- concurrency beyond what the unit tests exercise, behaviour under memory pressure, or resistance
  to timing and other side channels;
- that secrets are wiped: memory contents after a call are not inspected;
- performance, which [the benchmarks](benchmarks.md) measure separately.

## Four cases from this repository

Four defects or near misses in this repository, each with the check that belongs in the gate or
the review.

**A length above its cap must not become a slice.** The contract lets a caller pass
`okm_len = SIZE_MAX` with a small buffer: the length is above `EKI_HKDF_MAX_OKM_LEN`, the call
fails with `EKI_ERR_INVALID_ARGUMENT`, and the buffer is never touched. In Rust, creating the slice
with `slice::from_raw_parts` before checking the length would already be undefined behaviour, even
if no byte were read, because a slice must lie inside one allocation. The Rust FFI layer therefore
keeps pointer, length and maximum together in its `Input` and `Output` wrappers and creates a slice
only after the NULL rule and the maximum have been checked; Miri runs the tests that pass such
lengths (`output_above_its_maximum_is_left_untouched`, `null_check_precedes_the_maximum`). The rule
is C1 of the [contract](ffi-contract.md#pointer-and-length-rules).

**An error queue cleared too broadly.** The C++ primitives first called `ERR_clear_error` after an
expected failure (tag mismatch, bad public key, bad signature). OpenSSL's error queue is per thread
and shared with the host application, so that also discarded entries the application had not read
yet; on OpenSSL 3.5 a GCM or ChaCha20 tag mismatch queues nothing at all, so the call removed only
the application's entries. The fix marks the queue when a call starts (`ERR_set_mark`), keeps the
entries pushed since the mark on `EKI_ERR_BACKEND`, because they carry the reason, and pops back to
the mark on every other status. Tests push a recognisable entry before a failing call and check
that it is still the only one afterwards. No differential test could see this: the Rust library has
no OpenSSL queue.

**Check orders that differed for foreign token objects.** With a foreign object as the KEK and a
key id that did not exist, `eki_ks_wrap` answered `EKI_ERR_BACKEND` in the C++ library, which
described the KEK before looking up the key, and `EKI_ERR_KEY_NOT_FOUND` in the Rust library,
which looks up both ids first, as the contract says. The conformance suite could not catch it,
because it creates no foreign objects; a comparison of the two store sequences found it. The
C++ store now looks up both ids before describing either, and unit tests in both libraries pin the
order with a foreign object made directly in the token.

**A hardware backend an interpreter could not run.** Miri interprets the Rust code to find
undefined behaviour, but it cannot execute the ARMv8 AES and SHA-3 instructions that the `aes` and
`keccak` crates select on such machines, and the whole test suite would take hours because it
interprets the elliptic-curve and AES arithmetic. The Miri job sets `--cfg aes_backend="soft"
--cfg keccak_backend="soft"` and runs the tests that exercise the FFI layer's pointer handling. The
consequence is stated rather than hidden: Miri checks the portable code paths, not the hardware
ones that ship on ARMv8, and it does not run the PKCS#11 backend, which loads a native module. Those
paths are covered by the unit and conformance tests, the sanitizers and fuzzing instead.

## Reviewer checklist

A reviewer applies this to every module's Rust diff before its cutover gate.

- [ ] **`unsafe` stays in `core-rs/src/ffi.rs`.** No `#[allow(unsafe_code)]` elsewhere; the crate
      root keeps `#![deny(unsafe_code)]`.
- [ ] **Every `unsafe` block and impl has a `// SAFETY:` comment** that names the caller rule it
      relies on (C1 to C7 of the [contract](ffi-contract.md#pointer-and-length-rules)) and why that
      rule makes the operation sound. `scripts/unsafe-inventory.sh` lists them and fails on a
      missing comment; the [inventory](ffi-contract.md#unsafe-inventory) in the contract is
      regenerated from it, and the diff of that inventory is reviewed block by block.
- [ ] **Every new `unsafe fn` has a `# Safety` section**, except the `extern "C"` functions, whose
      contract is the contract document.
- [ ] **Validation order.** NULL checks in parameter order before anything else, then selectors,
      then lengths and formats, then store state, then cryptographic checks; the order matches the
      per-function table of the contract and the C++ sequence for the same function. A slice is
      created only after the NULL rule and the maximum are checked.
- [ ] **Zero on error.** Every output is passed to `barrier`, so it is zero-filled on every status
      other than `EKI_OK`; a variable-length output above its maximum is left untouched.
- [ ] **Panics.** The body runs inside `barrier` or `contain_panic`; nothing can panic between the
      entry of the `extern "C"` function and `catch_unwind`; panic payloads are dropped through
      `drop_panic_payload`; the release profile still has `panic = "unwind"`. In the key store, no
      panic can leave the store inconsistent (the argument at `Handle::lock`).
- [ ] **Secret hygiene.** Key material is held in `SecretBox` or `Zeroizing` and never copied into
      a plain `Vec` or array that outlives the call; new dependencies that handle secrets are built
      with their `zeroize` feature; secrets never appear in last-error text, `Debug` output or logs;
      the [contract's list](ffi-contract.md#secret-handling) of what is not wiped is updated.
- [ ] **Nothing hand-rolled.** Every primitive comes from a RustCrypto crate at a pinned version;
      no cryptographic arithmetic, padding or comparison is written by hand (the constant-time
      comparison is the crate's).
- [ ] **Tests enabled.** The module's tests in `core-rs/tests/` and its conformance module run in
      CI (listed in `conformance/ci-modules.txt`), none is ignored or skipped without a stated
      reason, the Miri job includes the new FFI tests, and clippy passes with
      `-D warnings -W clippy::undocumented_unsafe_blocks`.
- [ ] **Header and exports.** `scripts/check-header.sh` and `scripts/check-exports.sh` pass; a
      change to a declaration comes with a contract change and, if incompatible, an ABI version
      change.
