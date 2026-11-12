# Benchmarks

Both libraries are measured through the C ABI with identical workloads, so a row of the results
table compares what a C caller would see from `libekicore` and from `libekicore_rs` for the same
call. The [results](#results) hold one run on each of two machines, an Apple M1 Pro laptop and a
virtual server with an AMD EPYC CPU; [Machines](#machines) says how far the figures can be
trusted. The two machines disagree about more than the absolute times, and that disagreement is
the main thing the tables show.

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

## Machines

Each recorded run is the last of three that I took within ten minutes on its machine.

| | Apple M1 Pro laptop | AMD EPYC virtual server |
|---|---|---|
| Date | 2026-11-12 | 2026-11-12 |
| CPU | Apple M1 Pro, 6 performance and 2 efficiency cores; macOS decides frequency and core placement, and neither can be fixed | AMD EPYC 9645, 4 virtual CPUs under KVM; the CPU reports AES-NI, VAES, VPCLMULQDQ, AVX-512 and the SHA extensions |
| OS | macOS 26.2 (25C56) | Debian 13, Linux 6.12 |
| C++ compiler | Apple clang 21.0.0 (clang-2100.1.1.101) | GCC 14.2.0 |
| C++ flags | CMake Release: `-O3 -DNDEBUG -std=c++20 -fPIC -fvisibility=hidden -fexceptions` | the same, and `-fstack-protector-strong -D_FORTIFY_SOURCE=2` |
| Rust toolchain | rustc 1.99.1 | rustc 1.99.1 |
| Rust profile | bench (release settings), no `RUSTFLAGS` | the same |
| OpenSSL | 3.5.9 (Homebrew) | 3.5.6 (Debian) |
| Crate versions | aes-gcm 0.11.1, chacha20poly1305 0.11.0, hmac 0.13.0, hkdf 0.13.0, sha2 0.11.1 | the same |

The laptop was on mains power but not idle. Other applications kept about two and a half cores
busy for the whole run, and the load average was 6.3 when it started and when it ended. Its
figures are therefore noisier than a quiet machine would give. The run before the recorded one,
under the same load, agreed with it within about 6% on every time and 0.14 on every ratio. The
first of the three started while the load was still falling from a heavier job and differed
more: by up to 16% on a `libekicore` time, 23% on a `libekicore_rs` time and 0.46 on a ratio
(ChaCha20-Poly1305 seal at 1 KiB, 1.79 against 1.33).

The server was idle, with a load average of 0.05 before the first run, and the hypervisor took
0.03 s of steal time over the three runs. It is still a virtual machine on shared hardware. Its
`libekicore_rs` times agree within about 6% across the three runs. Its `libekicore` times, each
the mean of one Google Benchmark run, moved more: within about 20% on every row but one, and on
AES-256-GCM seal at 1 KiB the first run gave 1,409 ns where the other two gave 944 and 1,048.
That row's ratio ranges from 0.59 to 0.88 over the three runs, and the ratios of the two 64 KiB
AES-256-GCM rows from 4.5 to 5.6.

On both machines, read the ratios to one decimal place at best.

## Results

The rows are the ones [`scripts/bench.sh`](../scripts/bench.sh) prints. Each table is one run of
that script on a machine described under [Machines](#machines).

### Apple M1 Pro laptop

| Workload | libekicore ns/op | libekicore_rs ns/op | ratio | MiB/s |
|---|---:|---:|---:|---:|
| HMAC-SHA256, 64 B | 1,266.2 | 218.5 | 0.17 | 279 |
| HMAC-SHA256, 4 KiB | 3,533.5 | 2,577.6 | 0.73 | 1,515 |
| HKDF-SHA256, 32 B output | 2,769.5 | 389.4 | 0.14 | 78 |
| AES-256-GCM seal, 1 KiB | 941.2 | 1,185.4 | 1.26 | 824 |
| AES-256-GCM seal, 64 KiB | 12,898.8 | 23,959.5 | 1.86 | 2,609 |
| AES-256-GCM open, 1 KiB | 923.1 | 1,168.0 | 1.27 | 836 |
| AES-256-GCM open, 64 KiB | 12,610.3 | 23,726.1 | 1.88 | 2,634 |
| ChaCha20-Poly1305 seal, 1 KiB | 1,654.6 | 2,203.1 | 1.33 | 443 |
| ChaCha20-Poly1305 seal, 64 KiB | 48,541.8 | 117,514.9 | 2.42 | 532 |
| ChaCha20-Poly1305 open, 1 KiB | 1,750.9 | 2,203.0 | 1.26 | 443 |
| ChaCha20-Poly1305 open, 64 KiB | 47,308.9 | 114,602.4 | 2.42 | 545 |

### AMD EPYC virtual server

| Workload | libekicore ns/op | libekicore_rs ns/op | ratio | MiB/s |
|---|---:|---:|---:|---:|
| HMAC-SHA256, 64 B | 1,122.2 | 286.5 | 0.26 | 213 |
| HMAC-SHA256, 4 KiB | 3,676.4 | 2,855.8 | 0.78 | 1,368 |
| HKDF-SHA256, 32 B output | 2,383.1 | 497.1 | 0.21 | 61 |
| AES-256-GCM seal, 1 KiB | 1,048.3 | 879.5 | 0.84 | 1,110 |
| AES-256-GCM seal, 64 KiB | 4,836.6 | 26,570.5 | 5.49 | 2,352 |
| AES-256-GCM open, 1 KiB | 1,012.6 | 812.7 | 0.80 | 1,202 |
| AES-256-GCM open, 64 KiB | 4,917.9 | 25,631.2 | 5.21 | 2,438 |
| ChaCha20-Poly1305 seal, 1 KiB | 1,375.8 | 2,713.0 | 1.97 | 360 |
| ChaCha20-Poly1305 seal, 64 KiB | 18,068.2 | 71,839.3 | 3.98 | 870 |
| ChaCha20-Poly1305 open, 1 KiB | 1,365.1 | 2,717.8 | 1.99 | 359 |
| ChaCha20-Poly1305 open, 64 KiB | 18,406.8 | 69,767.0 | 3.79 | 896 |

### What the two runs show

- On the two small calls the Rust library is several times faster on both machines. HMAC over
  64 bytes takes it about a sixth of the C++ library's time on the laptop and a quarter on the
  server; HKDF takes it about a seventh and a fifth. That fits the algorithm fetch the C++
  wrapper does on every call, described above, but I have not profiled either library to confirm
  where the time goes.
- HMAC over 4 KiB takes the Rust library about three quarters of the C++ library's time on both
  machines.
- On 64 KiB inputs the C++ library is faster for both AEAD algorithms on both machines, and by
  how much depends on the CPU. For AES-256-GCM the ratio is about 1.9 on the laptop and above 5
  on the server, where `libekicore` seals 64 KiB in under 5 microseconds (about 12,900 MiB/s
  against 2,350 for `libekicore_rs`). For ChaCha20-Poly1305 it is about 2.4 and about 4. At this
  size nearly all the time is inside the cipher, so these rows compare OpenSSL's code for each
  CPU with RustCrypto's. I have not checked which code path either back end took.
- At 1 KiB the machines disagree about AES-256-GCM: the C++ library is faster on the laptop
  (about 1.3) and the Rust library is faster on the server (about 0.8, on the server's noisiest
  rows). ChaCha20-Poly1305 at 1 KiB is faster in the C++ library on both, by about 1.3 and
  about 2.
- The cutover gate of the [migration plan](migration-plan.md#cutover-gate-per-module) allows a
  ratio of at most 1.10. HMAC and HKDF are under it on both machines. AES-256-GCM at 1 KiB is
  under it on the server only. Every other AEAD row is over it on both, by the widest margin on
  the server. The gate asks for a measurement on production hardware; neither machine is that,
  though the server is the nearer of the two.
