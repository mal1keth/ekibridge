# Benchmarks

Both libraries are measured through the C ABI with identical workloads, so a row of the results
table compares what a C caller would see from `libekicore` and from `libekicore_rs` for the same
call. I have not recorded a run yet, so the [results table](#results) is still empty.

## Workloads

| Workload | Call | Input |
|---|---|---|
| HMAC-SHA256, 64 B and 4 KiB | `eki_hmac_sha256` | 32-byte key, message of the size given |
| HKDF-SHA256, 32 B output | `eki_hkdf_sha256` | 32-byte input keying material, 16-byte salt, 16-byte info, 32-byte output |
| AES-256-GCM and ChaCha20-Poly1305 seal, 1 KiB and 64 KiB | `eki_aead_seal` | 32-byte key, 12-byte nonce, 16 bytes of associated data, plaintext of the size given |
| AES-256-GCM and ChaCha20-Poly1305 open, 1 KiB and 64 KiB | `eki_aead_open` | the same, opening a ciphertext and tag sealed once before the measurement |

The inputs are fixed byte patterns, the same in both suites. The AEAD nonce is reused across
iterations, which is acceptable for timing and never for real use. `open` measures the success
path. Neither suite checks the returned status inside the loop.

## How it is measured

`libekicore` is measured by
[`core-cpp/bench/primitives_bench.cpp`](../core-cpp/bench/primitives_bench.cpp) with Google
Benchmark 1.10.0. The benchmark links against the shared `libekicore`, built with CMake in Release
mode. Its figure is Google Benchmark's mean wall-clock time per iteration of one run.

`libekicore_rs` is measured by [`core-rs/benches/primitives.rs`](../core-rs/benches/primitives.rs)
with criterion 0.8, in cargo's bench profile (release settings). The benchmark calls the
`extern "C"` functions of `ekicore_rs::ffi` with raw pointers, as a C caller would. Its figure is
criterion's median estimate.

Both figures include the boundary: the NULL and length checks, the panic or exception barrier and
the zero-on-error bookkeeping. The two sides are not measured identically, though. One figure is a
mean and the other a median. And the C++ suite calls into a shared library while the Rust suite
calls into its own binary, which saves the Rust side the cost of a call through the dynamic
linker's stubs. That matters, if at all, only for the smallest workloads.

Benchmark names are the same in both suites (`hmac/sha256/64`, `aead_seal/aes-256-gcm/1024`,
...), and the script joins the two result sets on them.

## Run it

```sh
scripts/bench.sh            # full run
scripts/bench.sh --quick    # short warm-up and measurement, a smoke test with noisy numbers
```

The script configures and builds `build/bench` with Ninja in Release mode, with
`EKI_BUILD_BENCH=ON` and `EKI_BUILD_TESTS=OFF`. On macOS it points `OPENSSL_ROOT_DIR` at
Homebrew's `openssl@3` unless the variable is already set. It then runs the Google Benchmark
executable with JSON output, runs `cargo bench -p ekicore-rs --bench primitives`, and merges the
two result sets into one table. The raw Google Benchmark output goes to `bench-results/cpp.json`
and the table to `bench-results/summary.md`; the table is also printed. The script exits non-zero
if a workload is missing from either side.

For figures worth recording, plug a laptop into power, close other work, disable frequency
scaling where the operating system allows it, and use the full run. On shared CI machines, read
only the ratio between the libraries, never the absolute figures.

## Reading the table

- `ns/op` is the time per call in nanoseconds: the mean for `libekicore` and the median for
  `libekicore_rs`, as described above.
- `ratio` is the `libekicore_rs` time divided by the `libekicore` time, so a median over a mean.
  Below 1.0 the Rust library is faster, above 1.0 it is slower. The cutover gate of the
  [migration plan](migration-plan.md) uses this column.
- `MiB/s` is the Rust library's throughput: the input size of the workload (message, plaintext or
  ciphertext, or the 32-byte HKDF output) divided by its time per call.

## What the comparison means

A row compares two cryptographic back ends. It says little about C++ against Rust, because each
library spends almost all of its time inside its back end: OpenSSL 3 for `libekicore`, the
RustCrypto crates (`hmac`, `hkdf`, `sha2`, `aes-gcm`, `chacha20poly1305`) for `libekicore_rs`.

OpenSSL uses hand-written assembly for AES-GCM, ChaCha20-Poly1305 and SHA-256 on common CPUs. The
RustCrypto crates use CPU intrinsics where they have a backend for the CPU and portable Rust
otherwise, and which of the two applies differs per primitive and per architecture. A ratio far
from 1.0 therefore says which back end has the better code path for that primitive on that CPU,
and it can turn around on another machine.

The wrapper code of the two libraries matters only where the work per call is small (HMAC over 64
bytes, HKDF). There the per-call overhead of the boundary is part of what a caller pays. In the
C++ library the wrapper code also fetches its OpenSSL algorithm on every call (`EVP_MAC_fetch`,
`EVP_KDF_fetch`, `EVP_CIPHER_fetch`).

The crate versions are pinned in `core-rs/Cargo.toml`. The OpenSSL version is whatever the build
found, so record it with every run.

## Machine

This table describes the machine of the recorded run. Until there is one, its entries are
placeholders.

| | |
|---|---|
| Date | _yyyy-mm-dd_ |
| CPU | _model, cores, frequency scaling on/off_ |
| OS | _name and version_ |
| C++ compiler | _name and version_ |
| C++ flags | _CMake Release, notable flags_ |
| Rust toolchain | _rustc version_ |
| Rust profile | _bench (release settings), `RUSTFLAGS` if any_ |
| OpenSSL | _version_ |
| Crate versions | _aes-gcm, chacha20poly1305, hmac, hkdf, sha2_ |

## Results

The rows are the ones [`scripts/bench.sh`](../scripts/bench.sh) prints. The figures will come from
one run of that script on the machine described under [Machine](#machine); none is recorded yet.

| Workload | libekicore ns/op | libekicore_rs ns/op | ratio | MiB/s |
|---|---:|---:|---:|---:|
| HMAC-SHA256, 64 B | | | | |
| HMAC-SHA256, 4 KiB | | | | |
| HKDF-SHA256, 32 B output | | | | |
| AES-256-GCM seal, 1 KiB | | | | |
| AES-256-GCM seal, 64 KiB | | | | |
| AES-256-GCM open, 1 KiB | | | | |
| AES-256-GCM open, 64 KiB | | | | |
| ChaCha20-Poly1305 seal, 1 KiB | | | | |
| ChaCha20-Poly1305 seal, 64 KiB | | | | |
| ChaCha20-Poly1305 open, 1 KiB | | | | |
| ChaCha20-Poly1305 open, 64 KiB | | | | |
