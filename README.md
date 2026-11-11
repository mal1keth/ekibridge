# ekibridge

One small cryptographic core, implemented twice (C++ on OpenSSL and Rust on RustCrypto) behind a
single C ABI, with a conformance harness that checks the two are interchangeable.

[![rust](https://github.com/mal1keth/ekibridge/actions/workflows/rust.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/rust.yml)
[![cpp](https://github.com/mal1keth/ekibridge/actions/workflows/cpp.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/cpp.yml)
[![header](https://github.com/mal1keth/ekibridge/actions/workflows/header.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/header.yml)
[![conformance](https://github.com/mal1keth/ekibridge/actions/workflows/conformance.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/conformance.yml)
[![fuzz](https://github.com/mal1keth/ekibridge/actions/workflows/fuzz.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/fuzz.yml)
[![pq](https://github.com/mal1keth/ekibridge/actions/workflows/pq.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/pq.yml)
[![bindings](https://github.com/mal1keth/ekibridge/actions/workflows/bindings.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/bindings.yml)

**Status: in progress, started October 2026.** Every exported function is implemented in both
libraries and passes the conformance harness; the fuzzing campaign is still to come. No release is
tagged yet. The ABI is at version 2, which added key lifecycle states, the audit log and dual
control of destroy. The table shows where each module stands; benchmark results are not recorded
yet.

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
| Bindings (UniFFI, wasm) | n/a | done | n/a | n/a |

## What it is

ekibridge is a small cryptographic library with four jobs: HMAC-SHA256, HKDF-SHA256, authenticated
encryption (AES-256-GCM and ChaCha20-Poly1305), and a key store that generates, signs with, wraps
and unwraps keys either in memory or inside a hardware security module through PKCS#11 (SoftHSM2
stands in for the hardware). ECDSA P-256 signatures can be verified without a store. The key store
tracks a lifecycle state per key (active, retired, revoked), can append every call to a
hash-chained audit log, and can require two of up to eight approvers to sign before a key is
destroyed. A hybrid post-quantum key exchange (X25519 + ML-KEM-768) is optional.

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
```

Miri runs what the `miri` job of `.github/workflows/rust.yml` runs: the tests that exercise the
pointer handling of the C ABI (the `ffi` unit tests and the NULL-pointer, length and format tests
of each ABI test file). The whole suite would take hours, because Miri interprets the
elliptic-curve and AES arithmetic. The `--cfg` flags select the portable code of the `aes` and
`keccak` crates, whose ARMv8 instructions Miri cannot execute. The audit-log tests need file
access (`-Zmiri-disable-isolation`) and writes that are not made short on purpose: the library
writes each audit record with one write and fails the call when it is short.

```sh
soft='--cfg aes_backend="soft" --cfg keccak_backend="soft"'
RUSTFLAGS=$soft MIRIFLAGS='-Zmiri-disable-isolation -Zmiri-no-short-fd-operations' \
  cargo +nightly miri test -p ekicore-rs --no-default-features --lib -- 'ffi::'
RUSTFLAGS=$soft MIRIFLAGS='-Zmiri-disable-isolation -Zmiri-no-short-fd-operations' \
  cargo +nightly miri test -p ekicore-rs --no-default-features --test 'ffi_*' -- \
  null untouched invalid label_bounded unterminated unsupported length_checks \
  open_v2_rows get_info_v2_rows no_approver_rows audit_head_rows version status_names
```

### Bindings

```sh
# UniFFI: generate Python, Kotlin and Swift into target/uniffi/, then test the Python binding
bindings/uniffi/scripts/generate.sh
bindings/uniffi/scripts/test-python.sh

# wasm-bindgen: tests under Node (the CLI version must equal the wasm-bindgen pin)
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test -p ekicore-wasm --target wasm32-unknown-unknown
```

### SoftHSM2 token for the PKCS#11 tests

```sh
source scripts/softhsm-init.sh
```

This creates a throwaway token labelled `ekibridge` under `.softhsm/` (user PIN `1234`, SO PIN
`12345678`, test-only values) and exports `SOFTHSM2_CONF`, `EKI_PKCS11_MODULE`,
`EKI_PKCS11_TOKEN_LABEL` and `EKI_PKCS11_PIN`.

### Conformance

`scripts/run-conformance.sh` builds both libraries in release mode (CMake preset `release`, cargo
`--release`) and runs conformance modules against both. Without `--with-pkcs11` the PKCS#11
modules skip themselves.

```sh
scripts/run-conformance.sh                 # the modules listed in conformance/ci-modules.txt
scripts/run-conformance.sh --all           # every module
scripts/run-conformance.sh --with-pkcs11   # PKCS#11 modules too (source softhsm-init.sh first)
scripts/run-conformance.sh hmac aead       # just these modules
EKI_PQ=1 scripts/run-conformance.sh pq     # both libraries built with the hybrid KEM
```

`EKI_DIFF_N` sets the number of differential iterations per function (2000 by default). The
hybrid KEM in the C++ library needs OpenSSL 3.5 or later.

### Interop callers and the unsafe inventory

```sh
# A C++ program loads libekicore_rs and a Rust program loads libekicore, each by path
scripts/interop-demo.sh

# Every unsafe block of core-rs/src/ffi.rs with its SAFETY comment (fails on a missing one)
scripts/unsafe-inventory.sh
```

[`scripts/stepca-demo.sh`](scripts/stepca-demo.sh) runs a step-ca certificate authority with its
keys in a throwaway SoftHSM2 token. It needs step-ca, the step CLI, OpenSSL 4 with the libp11
provider, `jq`, `curl` and `nc` (Homebrew paths by default), and is described in the
[PKI note](docs/pki-note.md).

### Benchmarks

```sh
scripts/bench.sh            # both suites through the C ABI, merged into one table
```

See [benchmarks](docs/benchmarks.md) for what is measured and how to read the table.

## Repository map

| Path | Contents |
|---|---|
| [`include/ekicore.h`](include/ekicore.h) | the C ABI, generated by cbindgen and committed |
| [`abi/`](abi/) | `ekicore-abi`: status enum, selector types, constants and structs the header is generated from |
| [`core-rs/`](core-rs/) | `ekicore-rs`, built as `libekicore_rs`; `unsafe` lives only in `src/ffi.rs` |
| [`core-cpp/`](core-cpp/) | `libekicore`, C++20 on OpenSSL 3, with GoogleTest unit tests |
| [`conformance/`](conformance/) | harness that loads both libraries and compares them, plus JSON test vectors |
| [`interop/`](interop/) | small callers that `dlopen` a library given on the command line |
| [`bindings/uniffi/`](bindings/uniffi/) | `ekicore-uniffi`: UniFFI bindings (Python tested; Kotlin, Swift generated) over the safe Rust API |
| [`bindings/wasm/`](bindings/wasm/) | `ekicore-wasm`: the safe Rust API as WebAssembly for JavaScript, through wasm-bindgen |
| [`scripts/check-header.sh`](scripts/check-header.sh) | regenerates the header with cbindgen 0.29.4, compares it and compiles it as C11 and C++20 |
| [`scripts/check-exports.sh`](scripts/check-exports.sh) | checks that both libraries export the `eki_*` symbols and nothing else |
| [`scripts/softhsm-init.sh`](scripts/softhsm-init.sh) | creates the throwaway SoftHSM2 token and exports its variables (to be sourced) |
| [`scripts/run-conformance.sh`](scripts/run-conformance.sh) | builds both libraries and runs the conformance modules |
| [`scripts/interop-demo.sh`](scripts/interop-demo.sh) | builds and runs the interop callers across the language boundary |
| [`scripts/unsafe-inventory.sh`](scripts/unsafe-inventory.sh) | lists every `unsafe` item of `core-rs/src/ffi.rs` with its SAFETY comment |
| [`scripts/bench.sh`](scripts/bench.sh) | runs both benchmark suites and merges their results |
| [`scripts/stepca-demo.sh`](scripts/stepca-demo.sh) | step-ca with its CA keys in a SoftHSM2 token, for the PKI note |
| [`docs/`](docs/) | contract, threat model, migration plan, benchmarks, findings, PKI note |
| [`.github/workflows/`](.github/workflows/) | CI: Rust, C++, header, conformance, fuzzing, hybrid KEM, bindings, benchmarks |
| [`CMakeLists.txt`](CMakeLists.txt), [`CMakePresets.json`](CMakePresets.json), [`Cargo.toml`](Cargo.toml), [`rust-toolchain.toml`](rust-toolchain.toml) | build entry points and toolchain pin |
| [`deny.toml`](deny.toml), [`.clang-format`](.clang-format), [`.clang-tidy`](.clang-tidy) | dependency policy, C++ formatting and lint configuration |

## Why this design

- **Migration is a link-time decision**: both libraries export the same 32 `eki_*` functions
  from one header, so a caller switches by linking or `dlopen`ing the other library, not by
  changing its source.
- **Neither side can drift from the header**: cbindgen generates it from the Rust declarations,
  the C++ library compiles against the committed copy, and CI regenerates it and fails on any
  difference.
- **The conformance suite is the safety net**: a harness loads both libraries into one process
  and requires the same status and the same bytes on published vectors, a seeded differential run
  and every row of the error matrix.
- **`unsafe` is confined to one file**: the Rust crate is `#![deny(unsafe_code)]` except
  `core-rs/src/ffi.rs`, where the CI clippy run requires a SAFETY comment on every block and
  `scripts/unsafe-inventory.sh` lists them.
- **No panic or exception crosses the boundary**: every exported function runs inside
  `catch_unwind` or `try`/`catch (...)`, returns `EKI_ERR_INTERNAL` for what it catches and
  zero-fills its outputs on every error.
- **Nothing cryptographic is hand-rolled**: every primitive comes from OpenSSL 3 (EVP) or a pinned
  RustCrypto crate, and PKCS#11 keys are generated and used inside the token with one object
  mapping both libraries share.

## Three ways across the boundary

The same safe Rust functions leave the crate three ways.

**cbindgen, the C ABI** ([`core-rs/src/ffi.rs`](core-rs/src/ffi.rs)). A hand-written `extern "C"`
layer turns pointers into slices, catches panics and maps errors to `eki_status`; cbindgen only
writes the header. It gives full control of the ABI: fixed layouts, caller-owned buffers written in
place without copies, and one header the C++ library implements as well. Every pointer rule has
to be stated and upheld by hand, through SAFETY comments, Miri, fuzzing and review. It fits a stable contract that any
language with a C FFI can load, which is what makes the two libraries interchangeable.

**UniFFI** ([`bindings/uniffi/`](bindings/uniffi/)). Proc macros generate the C scaffolding from
annotated safe Rust, and `uniffi-bindgen` reads the built library to write Python, Kotlin and
Swift. No pointer handling is written: errors become exceptions, records become classes. A runtime
and its conventions come along: every argument is serialised and copied, the foreign code must come
from the same uniffi version as the library, and the exported symbols are UniFFI's, not an ABI a C
caller would use. It fits shipping one Rust library to mobile apps and scripting languages.

**wasm-bindgen** ([`bindings/wasm/`](bindings/wasm/)). A different target with its own memory
model: the module has a linear memory of its own and shares no address space with JavaScript, so
every `Uint8Array` is copied in and every result copied out, and code that needs the operating
system (PKCS#11, file modes, the system random source) has to be left out or supplied by the host.
wasm-bindgen generates the JavaScript glue and TypeScript types. It fits browsers, Node and edge
runtimes, where a native library cannot be loaded at all.

## Documentation

- [FFI contract](docs/ffi-contract.md): the normative description of every function, status and
  rule, with the unsafe inventory
- [Threat model](docs/threat-model.md)
- [Migration plan](docs/migration-plan.md): strangler order, cutover gates, rollback, reviewer
  checklist
- [Benchmarks](docs/benchmarks.md): workloads, method and results table
- [Findings](docs/findings.md): fuzzing and bug log
- [PKI note](docs/pki-note.md): a step-ca CA with its keys in a PKCS#11 token
- [UniFFI bindings](bindings/uniffi/README.md) and [wasm bindings](bindings/wasm/README.md)
- [Security policy](SECURITY.md)

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
