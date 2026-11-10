# ekibridge

One small cryptographic core, implemented twice (C++ on OpenSSL and Rust on RustCrypto) behind a
single C ABI, with a conformance harness that proves the two are interchangeable.

[![rust](https://github.com/mal1keth/ekibridge/actions/workflows/rust.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/rust.yml)
[![cpp](https://github.com/mal1keth/ekibridge/actions/workflows/cpp.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/cpp.yml)
[![header](https://github.com/mal1keth/ekibridge/actions/workflows/header.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/header.yml)
[![conformance](https://github.com/mal1keth/ekibridge/actions/workflows/conformance.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/conformance.yml)
[![fuzz](https://github.com/mal1keth/ekibridge/actions/workflows/fuzz.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/fuzz.yml)
[![pq](https://github.com/mal1keth/ekibridge/actions/workflows/pq.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/pq.yml)

**Status: in progress, started October 2026.** The ABI, both build systems, CI, the test suites,
the conformance harness and vectors, the fuzz and benchmark harnesses and the interop callers are
in place, and the C++ primitives are implemented behind the internal API. The exported functions
are being implemented module by module; the table shows where each one stands. A function that is
not implemented yet is a stub that returns `EKI_ERR_UNSUPPORTED` and its tests are disabled: the
disabled tests are the specification the implementations are written against.

| Module | C++ | Rust | Conformance | Fuzz |
|---|---|---|---|---|
| ABI, build, CI | done | done | metadata module | n/a |
| HMAC-SHA256 | done | done | passing | planned |
| HKDF-SHA256 | done | done | passing | planned |
| AEAD (AES-256-GCM, ChaCha20-Poly1305) | done | done | passing | planned |
| ECDSA P-256 verify | done | done | passing | planned |
| Key store, software backend | done | done | passing | planned |
| Key store, PKCS#11 backend | done | done | passing | planned |
| Hybrid KEM (X25519 + ML-KEM-768) | done | done | passing | planned |
| Key lifecycle | done | done | passing | planned |
| Audit log | done | done | passing | planned |
| Dual control for destroy | done | done | passing | planned |
| Interop callers | passing | passing | n/a | n/a |
| Bindings (UniFFI, wasm) | n/a | planned | n/a | n/a |

## What it is

ekibridge is a small cryptographic library with four jobs: HMAC-SHA256, HKDF-SHA256, authenticated
encryption (AES-256-GCM and ChaCha20-Poly1305), and a key store that generates, signs with, wraps
and unwraps keys either in memory or inside a hardware security module through PKCS#11 (SoftHSM2
stands in for the hardware). A hybrid post-quantum key exchange (X25519 + ML-KEM-768) is optional.

It exists twice. `libekicore` is written in C++ on OpenSSL 3 and plays the part of an existing
production core; `libekicore_rs` is written in Rust on RustCrypto and plays its replacement. Both
export exactly the same C functions, declared once in [`include/ekicore.h`](include/ekicore.h), so
any program can load either library without recompiling. A conformance harness loads both into one
process and checks that they return byte-identical outputs and the same status for every input,
hostile ones included. Fuzzers, sanitizers and Miri cover the boundary, benchmarks compare the two,
and the [migration plan](docs/migration-plan.md) describes how a team would move from one to the
other module by module.

## The boundary

```
  application code (C, C++, Rust, Python, ...)        conformance harness
                     │                                        │ loads both libraries
                     │ #include "ekicore.h"                   │ into one process and
                     ▼                                        │ compares every result
┌────────────────── C ABI: include/ekicore.h ──────────────┐  │
│  eki_hmac_*   eki_hkdf_*   eki_aead_*   eki_ecdsa_*      │◀─┘
│  eki_ks_*  (key store)     eki_hybrid_kem_*  (optional)  │
└───────────────┬──────────────────────────────┬───────────┘
                │ link or dlopen               │ link or dlopen
     ┌──────────▼───────────┐       ┌──────────▼───────────┐
     │ libekicore (C++20)   │       │ libekicore_rs (Rust) │
     │ try/catch barrier    │       │ catch_unwind barrier │
     ├──────────────────────┤       ├──────────────────────┤
     │ OpenSSL 3 (EVP)      │       │ RustCrypto crates    │
     └──────────┬───────────┘       └──────────┬───────────┘
                └───────────────┬──────────────┘
                                │ key store backends
                ┌───────────────┴──────────────┐
                ▼                              ▼
         software store                 PKCS#11 module
          (in memory)                  (SoftHSM2 token)
```

## Quick start

### Prerequisites

macOS (Homebrew):

```sh
brew install cmake ninja openssl@3 softhsm opensc
cargo install cbindgen --version 0.29.4 --locked
```

Ubuntu 24.04:

```sh
sudo apt-get install -y build-essential cmake ninja-build libssl-dev softhsm2 opensc
cargo install cbindgen --version 0.29.4 --locked
```

Rust comes from [rustup](https://rustup.rs); `rust-toolchain.toml` selects the stable toolchain.
Miri and `cargo-fuzz` need a nightly toolchain as well (`rustup toolchain install nightly
--component miri rust-src`). On macOS the CMake build finds Homebrew's OpenSSL on its own; set
`OPENSSL_ROOT_DIR` to use a different one.

### Build and test

```sh
# C++ library and its unit tests
cmake --preset default
cmake --build --preset default
ctest --preset default

# Rust workspace
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings -W clippy::undocumented_unsafe_blocks

# The committed header matches the Rust declarations and compiles as C11 and C++20;
# both libraries export eki_* symbols and nothing else
scripts/check-header.sh
scripts/check-exports.sh
```

Other CMake presets: `release`, `asan` (AddressSanitizer + UndefinedBehaviorSanitizer), `tidy`
(clang-tidy on every source; run it with `cmake --build --preset tidy`) and `fuzz` (libFuzzer
targets; Homebrew LLVM on macOS, since Apple clang ships without libFuzzer). Build directories are
`build/<preset>/`.

```sh
cmake --preset asan && cmake --build --preset asan && ctest --preset asan
cargo +nightly miri test -p ekicore-rs --no-default-features
```

### SoftHSM2 token for the PKCS#11 tests

```sh
source scripts/softhsm-init.sh
```

This creates a throwaway token labelled `ekibridge` under `.softhsm/` (user PIN `1234`, SO PIN
`12345678`, test-only values) and exports `SOFTHSM2_CONF`, `EKI_PKCS11_MODULE`,
`EKI_PKCS11_TOKEN_LABEL` and `EKI_PKCS11_PIN`.

### Conformance

`scripts/run-conformance.sh` builds both libraries in release mode and runs the modules listed in `conformance/ci-modules.txt`:

```sh
scripts/run-conformance.sh                 # modules enabled in CI
scripts/run-conformance.sh --all           # every module
scripts/run-conformance.sh --with-pkcs11   # include PKCS#11 (source scripts/softhsm-init.sh first)
```

## Repository map

| Path | Contents |
|---|---|
| [`include/ekicore.h`](include/ekicore.h) | the C ABI, generated by cbindgen and committed |
| [`abi/`](abi/) | `ekicore-abi`: status enum, selector types, constants and structs the header is generated from |
| [`core-rs/`](core-rs/) | `ekicore-rs`, built as `libekicore_rs`; `unsafe` lives only in `src/ffi.rs` |
| [`core-cpp/`](core-cpp/) | `libekicore`, C++20 on OpenSSL 3, with GoogleTest unit tests |
| [`conformance/`](conformance/) | harness that loads both libraries and compares them, plus JSON test vectors |
| [`interop/`](interop/) | small callers that `dlopen` a library given on the command line |
| [`scripts/`](scripts/) | header and export checks, SoftHSM2 setup, conformance, benchmarks |
| [`docs/`](docs/) | contract, threat model, migration plan, benchmarks, findings |
| [`.github/workflows/`](.github/workflows/) | CI: one workflow per concern |
| [`CMakePresets.json`](CMakePresets.json), [`Cargo.toml`](Cargo.toml) | build entry points |

## Design decisions

- **One ABI, two implementations.** Both libraries export the same `eki_*` functions from one
  header. Which one runs is a link-time or load-time choice, never a source change in the caller.
- **The header is generated, then enforced both ways.** cbindgen produces it from the Rust
  declarations; the C++ library compiles against the committed copy, and CI regenerates it and fails
  on any difference.
- **A status enum out, plain integers in.** `eki_status` is a C enum the library writes. Selectors
  the caller passes (`eki_aead_alg`, `eki_key_alg`, `eki_ks_backend`) are `int32_t` with `#define`
  values, so an unknown value from C is rejected with a status instead of being undefined behaviour
  in Rust.
- **No exception or panic crosses the boundary.** Every exported function catches them and returns
  `EKI_ERR_INTERNAL`; on every error all outputs are zero-filled.
- **`unsafe` only in `ffi.rs`.** The rest of the Rust crate is `#![deny(unsafe_code)]`; every unsafe
  block states its invariant in a SAFETY comment, and clippy enforces that it has one.
- **Nothing hand-rolled.** Every primitive comes from OpenSSL 3 (EVP) or RustCrypto.
- **Standard wrapped-key format.** Wrapped keys are plain RFC 3394 AES key wrap (40 bytes), identical
  to PKCS#11 `CKM_AES_KEY_WRAP`; algorithm, label and id travel out of band.
- **One PKCS#11 object mapping.** Both libraries store keys in the token with the same attributes, so
  each can use keys the other created.

## Documentation

- [FFI contract](docs/ffi-contract.md): the normative description of every function, status and rule
- [Threat model](docs/threat-model.md)
- [Migration plan](docs/migration-plan.md)
- [Benchmarks](docs/benchmarks.md)
- [Findings](docs/findings.md): fuzzing and bug log
- [Security policy](SECURITY.md)

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
