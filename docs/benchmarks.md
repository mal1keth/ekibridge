# Benchmarks

Both libraries are measured through the C ABI with identical workloads: criterion drives
`libekicore_rs`, Google Benchmark drives `libekicore`. Numbers are per call, median of the run.
`ratio` is `libekicore_rs / libekicore` (below 1.0 means the Rust library is faster). `MiB/s` is the
Rust library's throughput over the input size.

Not filled in yet: the table is populated from a real run on the machine described below.

## Machine

| | |
|---|---|
| Date | _yyyy-mm-dd_ |
| CPU | _model, cores, frequency scaling on/off_ |
| OS | _name and version_ |
| C++ compiler | _name and version_ |
| C++ flags | _preset (release), notable flags_ |
| Rust toolchain | _rustc version_ |
| Rust profile | _release, `RUSTFLAGS` if any_ |
| OpenSSL | _version_ |
| Crate versions | _aes-gcm, chacha20poly1305, hmac, hkdf, sha2_ |

## Results

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

## Reproduce

```sh
scripts/bench.sh
```

The script builds both libraries in release mode, runs both benchmark suites and prints a table in
the shape above. On a laptop, plug in power and close other work; on CI, treat the numbers as a
ratio between the libraries rather than as absolute figures.
