# ekibridge

[![rust](https://github.com/mal1keth/ekibridge/actions/workflows/rust.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/rust.yml)
[![cpp](https://github.com/mal1keth/ekibridge/actions/workflows/cpp.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/cpp.yml)
[![header](https://github.com/mal1keth/ekibridge/actions/workflows/header.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/header.yml)
[![conformance](https://github.com/mal1keth/ekibridge/actions/workflows/conformance.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/conformance.yml)
[![fuzz](https://github.com/mal1keth/ekibridge/actions/workflows/fuzz.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/fuzz.yml)
[![pq](https://github.com/mal1keth/ekibridge/actions/workflows/pq.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/pq.yml)
[![bindings](https://github.com/mal1keth/ekibridge/actions/workflows/bindings.yml/badge.svg)](https://github.com/mal1keth/ekibridge/actions/workflows/bindings.yml)

ekibridge is a small cryptographic library implemented twice behind one C ABI. `libekicore`,
written in C++ on OpenSSL 3, plays an existing production core, and `libekicore_rs`, written in
Rust on RustCrypto, plays its replacement. Both export the same C functions, declared once in
[`include/ekicore.h`](include/ekicore.h), so a program can load either library without being
recompiled.

The repository is a worked example of moving a C++ core to Rust without changing its callers.
Because the two libraries share an ABI, the migration is a choice of library at link or load
time. A conformance harness loads both into one process and requires the same bytes and the same
status from each on every input it feeds them, including hostile ones. The
[migration plan](docs/migration-plan.md) describes how a team would make the move module by
module.

## Status

The project is in progress. I started it in October 2026, and no release is tagged yet.

Every exported function is implemented in both libraries and passes the conformance harness. A
first fuzzing campaign of both libraries found nothing, though the Rust `ffi_status` target did
not reach its planned 200000 executions ([findings](docs/findings.md)). The ABI is at version 2,
which added key lifecycle states, the audit log and dual control of destroy. The benchmark table
is not filled in yet. So far I have built and tested the implementation on macOS (Apple silicon)
only. The CI workflows also run on Ubuntu 24.04, but they last ran there against the scaffolding,
before the functions were implemented.

The table shows where each module stands.

| Module | C++ | Rust | Conformance | Fuzz |
|---|---|---|---|---|
| ABI, build, CI | done | done | metadata module | n/a |
| HMAC-SHA256 | done | done | passing | fuzzed |
| HKDF-SHA256 | done | done | passing | fuzzed |
| AEAD (AES-256-GCM, ChaCha20-Poly1305) | done | done | passing | fuzzed |
| ECDSA P-256 verify | done | done | passing | fuzzed |
| Key store, software backend | done | done | passing | fuzzed |
| Key store, PKCS#11 backend | done | done | passing | argument checks only |
| Hybrid KEM (X25519 + ML-KEM-768) | done | done | passing | fuzzed |
| Key lifecycle | done | done | passing | fuzzed |
| Audit log | done | done | passing | fuzzed |
| Dual control for destroy | done | done | passing | fuzzed |
| Interop callers | passing | passing | n/a | n/a |
| Bindings (UniFFI, wasm) | n/a | done | n/a | n/a |

The fuzz targets use the software key store. A fuzzed configuration that selects PKCS#11 gets as
far as the library's argument checks and no token is opened, which is what "argument checks only"
means.

## What is in it

The stateless functions are HMAC-SHA256, HKDF-SHA256, authenticated encryption with AES-256-GCM
and ChaCha20-Poly1305, and verification of ECDSA P-256 signatures.

The key store generates keys, signs with them, and wraps and unwraps them. It keeps them either
in memory or, through PKCS#11, inside a hardware security module. The only token it has been
tested with is SoftHSM2, which is software. Since ABI 2 the store tracks a lifecycle state per key
(active, retired, revoked), can append a record of each key operation to a hash-chained audit log,
and can require two of up to eight approvers to sign before a key is destroyed.

A hybrid post-quantum KEM (X25519 + ML-KEM-768) is optional. It is compiled in with the cargo
feature `pq` in the Rust library and the CMake option `EKI_WITH_PQ` in the C++ one.

Around the two libraries there is the conformance harness, fuzz targets for both, a sanitizer
build of the C++ library and a Miri job for the pointer handling of the Rust one. Benchmarks
measure both through the C ABI.

## The boundary

An application includes the header and links or loads one of the two libraries. The conformance
harness loads both.

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

## Why this design

- Both libraries export the same 32 `eki_*` functions from one header, so migration is a decision
  at link or load time. A caller switches by linking or `dlopen`ing the other library, and its
  source stays as it is.
- Neither library can drift from the header. cbindgen generates it from the Rust declarations,
  the C++ library compiles against the committed copy, and CI regenerates it and fails on any
  difference.
- The conformance suite is the safety net. The harness loads both libraries into one process and
  requires the same status and the same bytes on published vectors, a seeded differential run and
  every row of the error matrix. Signing is checked by cross-verification, because signatures are
  not deterministic in every backend.
- `unsafe` is confined to one file, `core-rs/src/ffi.rs`; the rest of the Rust crate is
  `#![deny(unsafe_code)]`. In that file the CI clippy run requires a SAFETY comment on every
  block, and `scripts/unsafe-inventory.sh` lists them.
- No panic or exception crosses the boundary. Every exported function runs inside `catch_unwind`
  or `try`/`catch (...)`, returns `EKI_ERR_INTERNAL` for what it catches and zero-fills its
  outputs on every error. The [contract](docs/ffi-contract.md) has the one exception to the
  zero-fill: a buffer whose stated length is over its cap is left untouched.
- Every primitive comes from OpenSSL 3 (EVP) or a pinned RustCrypto crate, so nothing
  cryptographic is hand-rolled. PKCS#11 keys are generated and used inside the token, with one
  object mapping that both libraries share.

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
Miri and `cargo-fuzz` need a nightly toolchain as well
(`rustup toolchain install nightly --component miri rust-src`). On macOS the CMake build finds
Homebrew's OpenSSL on its own; set `OPENSSL_ROOT_DIR` to use a different one. I have not yet tried
the Ubuntu line on a Linux machine.

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

There are four more CMake presets. `release` is the optimized build. `asan` builds with
AddressSanitizer and UndefinedBehaviorSanitizer. `tidy` runs clang-tidy on every source as part
of `cmake --build --preset tidy`. `fuzz` builds the libFuzzer targets. On macOS `tidy` and `fuzz`
take their tools from Homebrew LLVM, since Apple clang ships without clang-tidy and libFuzzer.
Each preset builds into `build/<preset>/`.

```sh
cmake --preset asan && cmake --build --preset asan && ctest --preset asan
```

The Miri commands below are the ones the `miri` job of `.github/workflows/rust.yml` runs. They
cover the tests that exercise the pointer handling of the C ABI: the `ffi` unit tests, and the
NULL-pointer, length and format tests of each ABI test file. The whole suite would take hours
under Miri, because Miri interprets the elliptic-curve and AES arithmetic. The `--cfg` flags
select the portable code of the `aes` and `keccak` crates, whose ARMv8 instructions Miri cannot
execute. The audit-log tests need file access, hence `-Zmiri-disable-isolation`. They also need
`-Zmiri-no-short-fd-operations`: Miri makes some writes short on purpose, and the library writes
each audit record with one write and fails the call when that write is short.

```sh
soft='--cfg aes_backend="soft" --cfg keccak_backend="soft"'
RUSTFLAGS=$soft MIRIFLAGS='-Zmiri-disable-isolation -Zmiri-no-short-fd-operations' \
  cargo +nightly miri test -p ekicore-rs --no-default-features --lib -- 'ffi::'
RUSTFLAGS=$soft MIRIFLAGS='-Zmiri-disable-isolation -Zmiri-no-short-fd-operations' \
  cargo +nightly miri test -p ekicore-rs --no-default-features --test 'ffi_*' -- \
  null untouched invalid label_bounded unterminated unsupported length_checks \
  open_v2_rows get_info_v2_rows no_approver_rows audit_head_rows version status_names
```

The fuzz targets are run by `.github/workflows/fuzz.yml`, which has the exact invocations for
both languages. The [threat model](docs/threat-model.md) describes what each target checks.

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
`EKI_PKCS11_TOKEN_LABEL` and `EKI_PKCS11_PIN`. The script has to be sourced, because the tests
read those variables from the shell that runs them.

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

`EKI_DIFF_N` sets the number of differential iterations per function (2000 by default) and
`EKI_DIFF_SEED` their seed. The hybrid KEM in the C++ library needs OpenSSL 3.5 or later.

### Interop callers and the unsafe inventory

```sh
# A C++ program loads libekicore_rs and a Rust program loads libekicore, each by path
scripts/interop-demo.sh

# Every unsafe block of core-rs/src/ffi.rs with its SAFETY comment (fails on a missing one)
scripts/unsafe-inventory.sh
```

### step-ca demo

[`scripts/stepca-demo.sh`](scripts/stepca-demo.sh) runs a step-ca certificate authority with its
keys in a throwaway SoftHSM2 token. Besides SoftHSM2, OpenSC and OpenSSL 3 from the prerequisites
it needs step-ca, the step CLI, OpenSSL 4 with the libp11 provider, `jq`, `curl` and `nc`. The
tool paths default to Homebrew's, and I have run it on macOS only. The
[PKI note](docs/pki-note.md) describes the run and what it shows.

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

## Three ways across the boundary

The same safe Rust functions leave the crate three ways.

### cbindgen and the C ABI

[`core-rs/src/ffi.rs`](core-rs/src/ffi.rs) is a hand-written `extern "C"` layer that turns
pointers into slices, catches panics and maps errors to `eki_status`. cbindgen only writes the
header. This route gives full control of the ABI: fixed layouts, caller-owned buffers written in
place without copies, and one header that the C++ library implements as well. The cost is that
every pointer rule has to be stated and upheld by hand, which here means SAFETY comments, Miri,
fuzzing and review. It fits a stable contract that any language with a C FFI can load, and that
contract is what makes the two libraries interchangeable.

### UniFFI

In [`bindings/uniffi/`](bindings/uniffi/), proc macros generate the C scaffolding from annotated
safe Rust, and `uniffi-bindgen` reads the built library to write Python, Kotlin and Swift. There
is no pointer handling to write: errors become exceptions and records become classes. The cost
is a runtime and its conventions. Every argument is serialised and copied, the foreign code must
come from the same uniffi version as the library, and the exported symbols are UniFFI's own, which
a C caller would not use as an ABI. It fits shipping one Rust library to mobile apps and scripting
languages.

### wasm-bindgen

[`bindings/wasm/`](bindings/wasm/) builds the same functions for a different target with its own
memory model. The module has a linear memory of its own and shares no address space with
JavaScript, so every `Uint8Array` is copied in and every result is copied out. Code that needs the
operating system (PKCS#11, file modes, the system random source) has to be left out or supplied by
the host. wasm-bindgen generates the JavaScript glue and the TypeScript types. It fits browsers,
Node and edge runtimes, where a native library cannot be loaded at all.

## Documentation

- [FFI contract](docs/ffi-contract.md): the normative description of every function, status and
  rule, with the unsafe inventory
- [Threat model](docs/threat-model.md): what is protected, trust boundaries, adversaries, testing
  evidence and limits
- [Migration plan](docs/migration-plan.md): strangler order, cutover gates, rollback, reviewer
  checklist
- [Benchmarks](docs/benchmarks.md): workloads, method and results table
- [Findings](docs/findings.md): fuzzing and bug log
- [PKI note](docs/pki-note.md): a step-ca CA with its keys in a PKCS#11 token
- [UniFFI bindings](bindings/uniffi/README.md) and [wasm bindings](bindings/wasm/README.md)
- [Security policy](SECURITY.md)

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
