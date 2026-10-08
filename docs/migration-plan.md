# Migration plan: C++ core to Rust behind one C ABI

`libekicore` (C++ on OpenSSL) plays the existing production core; `libekicore_rs` (Rust on
RustCrypto) plays its replacement. This document describes how a team would move from one to the
other module by module without a flag day.

## Goal

Replace the C++ implementation with the Rust one for every function of the
[C ABI](ffi-contract.md), with:

- no change to any caller's source code or build,
- a gate per module that has to be passed before production traffic reaches the new code,
- a rollback that is a configuration change, not a redeploy of the callers.

## Why one C ABI

Both libraries export the same `eki_*` symbols declared in one header,
[`include/ekicore.h`](../include/ekicore.h). A caller compiled against that header can use either
library, so which implementation runs becomes a link-time or load-time decision instead of a rewrite
of every caller. The conformance harness can load both libraries into one process and compare them
call by call, which is what makes the gates below measurable.

The header is generated from the Rust declarations and the C++ library is compiled against the
committed copy, so neither side can drift from it without a build or CI failure.

## Strangler order

HKDF → HMAC → AEAD → key store.

TODO(L10): rationale. One paragraph on why this order: risk and blast radius per module, how much
state each module owns, how easy each is to compare differentially, and which later modules depend
on earlier ones.

## Cutover gate per module

A module moves to the Rust implementation only when every item is checked:

- [ ] All published test vectors for the module (RFC and Wycheproof) pass in both libraries.
- [ ] Differential run: at least 10^6 random inputs per function, identical status and outputs.
- [ ] Every row of the error matrix for the module passes in both libraries with identical status
      and zeroed outputs.
- [ ] Fuzzing: the module's targets have run for the agreed number of CPU hours with no open
      finding (see [findings.md](findings.md)).
- [ ] Performance within 10 % of the C++ library on the module's workloads
      ([benchmarks.md](benchmarks.md)), or a documented reason to accept the difference.
- [ ] The diff has passed the review checklist below.

## Runtime selection and rollback

- The library path comes from configuration, not from the build. Callers `dlopen` the configured
  path (the `interop/` callers show this in miniature).
- At load, the caller checks `eki_abi_version() == 1` and logs `eki_version()`, so every log line can
  be attributed to `ekicore-cpp` or `ekicore-rs` and a version.
- Rollback is flipping the configured path back to `libekicore` and restarting or reloading the
  process. Because both libraries share the ABI and the wrapped-key format, no data migration is
  needed in either direction.
- PKCS#11 keys created by one library are usable by the other (same object mapping in the token),
  so the key store can be switched without re-provisioning keys.

## Observability

- Count every call by function and by `eki_status_name(status)`, labelled with `eki_version()`.
- Alert on any rise in `EKI_ERR_INTERNAL` or `EKI_ERR_BACKEND` after a cutover, and on any change in
  the ratio of `EKI_ERR_AUTH_FAILED` to `EKI_OK` for the same traffic.
- For the key store, record the last-error message on `EKI_ERR_BACKEND` (it carries the `CKR_*` name
  or the OpenSSL error string). Never log key material, PINs, plaintext or labels marked sensitive.

## Preserving identity semantics

Key ids (16 random bytes, `CKA_ID`), labels (`CKA_LABEL`) and the wrapped-key format are identical in
both libraries, so a key generated or wrapped by one is found and used by the other. The conformance
suite shows: wrap in one library and unwrap in the other with the same id and label, identical HMAC
outputs afterwards, signatures from one verified by the other, and destruction visible across both.

TODO(L10): what a full PKI would need beyond this (certificates bound to key ids, rotation,
revocation and its propagation, audit), and which of those the suite does not demonstrate.

## Review checklist

TODO(L10): the checklist a reviewer applies to every module's Rust diff before its cutover gate.
