# Benchmarks

Both libraries are measured through the C ABI with identical workloads, so a row of the results
table compares what a C caller would see from `libekicore` and from `libekicore_rs` for the same
call. Each library uses the widest instructions it has code for on the CPU it runs on, so the
comparison is head to head. The [results](#results) cover two machines, an Apple M1 Pro laptop
and a virtual server with an AMD EPYC CPU, and [Machines](#machines) says how far the figures can
be trusted.

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

### Which CPU instructions each library uses

OpenSSL picks its code path at run time from the features the CPU reports. The RustCrypto crates
do the same, with one catch: on x86 the `aes` and `chacha20` crates compile their widest back
ends (AES with VAES on 256-bit and 512-bit registers, ChaCha20 with AVX-512) only when a build
flag asks for them. [`.cargo/config.toml`](../.cargo/config.toml) sets those flags for every
build in this workspace. Run-time detection stays on, so the library still runs on a CPU without
those instructions and uses the narrower back ends there. On the server's 64 KiB inputs the
flags roughly halved the Rust library's ChaCha20-Poly1305 times and took about a tenth off its
AES-256-GCM times; at 1 KiB they changed little.

Two crates have no wide back end to switch on. `polyval`, which computes the GCM hash,
multiplies on 128-bit registers, four blocks at a time. `poly1305` has an AVX2 back end on x86
and only portable code on ARM. The `aes-gcm` crate also passes over the data twice, once to
encrypt and once to hash, where OpenSSL's assembly does both in one pass.

Turning instruction sets on for the whole build at compile time is not part of the comparison.
On the server, rustc 1.99.1 crashed while compiling the `p256` crate both with
`-C target-cpu=native` and with the AVX-512 features named one by one.

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
RustCrypto crates use CPU intrinsics where they have a back end for the CPU and portable Rust
otherwise ([above](#which-cpu-instructions-each-library-uses)). A ratio far from 1.0 therefore
says which back end has the better code path for that primitive on that CPU, and it can turn
around on another machine.

The wrapper code of the two libraries matters only where the work per call is small (HMAC over 64
bytes, HKDF). There the per-call overhead of the boundary is part of what a caller pays. In the
C++ library the wrapper code also fetches its OpenSSL algorithm on every call (`EVP_MAC_fetch`,
`EVP_KDF_fetch`, `EVP_CIPHER_fetch`).

The crate versions are pinned in `core-rs/Cargo.toml`. The OpenSSL version is whatever the build
found, so record it with every run.

## Machines

Each figure in the results is the median of three runs of the script, taken within ten minutes
on its machine.

| | Apple M1 Pro laptop | AMD EPYC virtual server |
|---|---|---|
| Date | 2026-11-12 | 2026-11-12 |
| CPU | Apple M1 Pro, 6 performance and 2 efficiency cores; macOS decides frequency and core placement, and neither can be fixed | AMD EPYC 9645, 4 virtual CPUs under KVM; the CPU reports AES-NI, VAES, VPCLMULQDQ, AVX-512 and the SHA extensions |
| OS | macOS 26.2 (25C56) | Debian 13, Linux 6.12 |
| C++ compiler | Apple clang 21.0.0 (clang-2100.1.1.101) | GCC 14.2.0 |
| C++ flags | CMake Release: `-O3 -DNDEBUG -std=c++20 -fPIC -fvisibility=hidden -fexceptions` | the same, and `-fstack-protector-strong -D_FORTIFY_SOURCE=2` |
| Rust toolchain | rustc 1.99.1 | rustc 1.99.1 |
| Rust profile | bench (release settings); the flags of `.cargo/config.toml` do not apply on ARM | bench (release settings) with `--cfg aes_backend="avx512" --cfg chacha20_avx512` |
| OpenSSL | 3.5.9 (Homebrew) | 3.5.6 (Debian) |
| Crate versions | aes-gcm 0.11.1, chacha20poly1305 0.11.0, hmac 0.13.0, hkdf 0.13.0, sha2 0.11.1 | the same |

The laptop was on mains power but not idle. Other applications kept about two and a half cores
busy during the runs. Across its three runs the `libekicore` times of a row differ by up to 16%
and the `libekicore_rs` times by up to 9%, except ChaCha20-Poly1305 seal at 1 KiB, where one run
was 23% slower than the other two.

The server was idle, with a load average of 0.1 before the first run, and the hypervisor took
0.02 s of steal time over the three runs. It is still a virtual machine on shared hardware.
Across its three runs the `libekicore_rs` times of a row differ by up to 12%. The `libekicore`
times, each the mean of one Google Benchmark run, differ by up to 22%, except HMAC over 64 bytes,
where one run gave 1,747 ns against 1,073 and 1,123.

On both machines, read the ratios to one decimal place at best.

## Results

The rows are the ones [`scripts/bench.sh`](../scripts/bench.sh) prints, for the machines
described under [Machines](#machines).

### Apple M1 Pro laptop

| Workload | libekicore ns/op | libekicore_rs ns/op | ratio | MiB/s |
|---|---:|---:|---:|---:|
| HMAC-SHA256, 64 B | 1,266.2 | 218.0 | 0.17 | 280 |
| HMAC-SHA256, 4 KiB | 3,533.5 | 2,570.0 | 0.73 | 1,520 |
| HKDF-SHA256, 32 B output | 2,769.5 | 389.1 | 0.14 | 78 |
| AES-256-GCM seal, 1 KiB | 931.7 | 1,176.0 | 1.26 | 830 |
| AES-256-GCM seal, 64 KiB | 12,898.8 | 23,876.8 | 1.85 | 2,618 |
| AES-256-GCM open, 1 KiB | 923.1 | 1,170.6 | 1.27 | 834 |
| AES-256-GCM open, 64 KiB | 12,610.3 | 23,484.2 | 1.86 | 2,661 |
| ChaCha20-Poly1305 seal, 1 KiB | 1,654.6 | 2,205.2 | 1.33 | 443 |
| ChaCha20-Poly1305 seal, 64 KiB | 48,541.8 | 117,514.9 | 2.42 | 532 |
| ChaCha20-Poly1305 open, 1 KiB | 1,650.5 | 2,204.2 | 1.34 | 443 |
| ChaCha20-Poly1305 open, 64 KiB | 47,308.9 | 115,099.7 | 2.43 | 543 |

### AMD EPYC virtual server

| Workload | libekicore ns/op | libekicore_rs ns/op | ratio | MiB/s |
|---|---:|---:|---:|---:|
| HMAC-SHA256, 64 B | 1,123.0 | 278.0 | 0.25 | 220 |
| HMAC-SHA256, 4 KiB | 3,651.9 | 2,765.1 | 0.76 | 1,413 |
| HKDF-SHA256, 32 B output | 2,332.2 | 472.4 | 0.20 | 65 |
| AES-256-GCM seal, 1 KiB | 933.2 | 871.5 | 0.93 | 1,121 |
| AES-256-GCM seal, 64 KiB | 5,004.5 | 23,608.5 | 4.72 | 2,647 |
| AES-256-GCM open, 1 KiB | 976.4 | 861.9 | 0.88 | 1,133 |
| AES-256-GCM open, 64 KiB | 4,979.9 | 23,770.5 | 4.77 | 2,629 |
| ChaCha20-Poly1305 seal, 1 KiB | 1,386.1 | 2,198.4 | 1.59 | 444 |
| ChaCha20-Poly1305 seal, 64 KiB | 17,940.6 | 32,055.8 | 1.79 | 1,950 |
| ChaCha20-Poly1305 open, 1 KiB | 1,431.8 | 2,252.3 | 1.57 | 434 |
| ChaCha20-Poly1305 open, 64 KiB | 17,585.7 | 33,035.4 | 1.88 | 1,892 |

### What the results show

- On the two small calls the Rust library is several times faster on both machines. HMAC over
  64 bytes takes it about a sixth of the C++ library's time on the laptop and a quarter on the
  server; HKDF takes it about a seventh and a fifth. That fits the algorithm fetch the C++
  wrapper does on every call, described above, but I have not profiled either library to confirm
  where the time goes.
- HMAC over 4 KiB takes the Rust library about three quarters of the C++ library's time on both
  machines.
- ChaCha20-Poly1305 is faster in the C++ library on both machines: by about 1.3 at 1 KiB and 2.4
  at 64 KiB on the laptop, and by about 1.6 and 1.8 to 1.9 on the server.
- AES-256-GCM on 64 KiB inputs is where the libraries are furthest apart. The ratio is about 1.9
  on the laptop and 4.7 to 4.8 on the server, where `libekicore` seals 64 KiB in about 5
  microseconds (about 12,500 MiB/s against 2,650). The Rust library runs AES on 512-bit registers
  there too; what it lacks is a wide GCM hash and the single pass. Masking the CPU's wide AES and
  carry-less multiply instructions off for OpenSSL (`OPENSSL_ia32cap`) brings `openssl speed` on
  this workload down from 16 GB/s to between 3 and 4, so those instructions are where its lead
  comes from.
- At 1 KiB the machines disagree about AES-256-GCM: the C++ library is faster on the laptop
  (about 1.3) and the Rust library is slightly faster on the server (about 0.9).
- The cutover gate of the [migration plan](migration-plan.md#cutover-gate-per-module) allows a
  ratio of at most 1.10. HMAC and HKDF are under it on both machines. AES-256-GCM at 1 KiB is
  under it on the server only. Every other AEAD row is over it on both. The gate asks for a
  measurement on production hardware; neither machine is that, though the server is the nearer
  of the two.
