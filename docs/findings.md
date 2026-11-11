# Findings

A log of every fuzzing campaign and every bug found by fuzzing, sanitizers, Miri or the conformance
harness. One row per run of a target, newest first. `Runs` is the number of executions; a run
stopped by its time limit says so. `Coverage` is libFuzzer's `cov` figure at the end of the run
(instrumented edges reached), with the figure after loading the seeds in brackets. The Rust
figures count edges in `ekicore-rs` and the RustCrypto crates; the C++ figures count edges in
`libekicore` only, because OpenSSL is not instrumented, so the two languages' figures cannot be
compared with each other. `Result` is `clean` or a description of the failure. A finding stays in
the table after it is fixed: `Notes` names the fix and the regression test that now covers it.

Campaign setup for the 2026-11-11 runs: macOS 26.2 on Apple silicon (8 cores), Homebrew LLVM clang
23.1.3 and OpenSSL 3.5.9 for C++ (`cmake --preset fuzz`: libFuzzer, AddressSanitizer and
UndefinedBehaviorSanitizer; the KEM build adds `-DEKI_WITH_PQ=ON`), cargo-fuzz 0.13.2 on nightly
Rust for Rust (release build with AddressSanitizer, debug assertions and overflow checks; the KEM
build adds `--features pq`). Every run started from the committed named seeds only, copied to a
scratch directory, with `-runs=200000`. Software key store only; no PKCS#11 token was opened.

| Date | Target | Runs | Coverage | Result | Notes |
|---|---|---|---|---|---|
| 2026-11-11 | Rust `ffi_status`, `pq` | 82638 (time limit, 900 s) | 6132 (4560) | clean | Second attempt. Stopped by `-max_total_time=900`. One unit was reported slow (115 s); it runs in under 0.3 s alone, so the time went to system sleep, not to the input. Throughput is bounded by the audit log: every logged call flushes with `sync_data`, which is `F_FULLFSYNC` on macOS. |
| 2026-11-11 | Rust `ffi_status` | 17795 (time limit, 909 s) | 4883 (3698) | clean | Second attempt, under `caffeinate -i`. The machine still entered sleep during the run (power log, 20:37 to 20:39); the slowest unit was reported at 578 s and runs in under 50 ms alone. |
| 2026-11-11 | Rust `ffi_status`, `pq` | 76679 (time limit, 2408 s) | 6127 (4564) | clean | First attempt, in parallel with the other Rust `ffi_status` run. The machine slept several times (power log, from 19:54); the four slow units reported (up to 605 s) each run in under 0.4 s alone. |
| 2026-11-11 | Rust `ffi_status` | 34510 (stopped at 2008 s) | 5128 (3698) | clean | First attempt, stopped by hand after the system sleeps were found, then rerun (second row). Slow units as in the row above, none reproducible. |
| 2026-11-11 | Rust `unwrap_blob` | 200000 | 2128 (1689) | clean | |
| 2026-11-11 | Rust `ecdsa_sign_verify` | 200000 | 831 (747) | clean | |
| 2026-11-11 | Rust `hybrid_kem`, `pq` | 200000 | 1227 (1148) | clean | |
| 2026-11-11 | Rust `hybrid_kem` | 200000 | 207 (204) | clean | KEM not compiled in: every call checked to be `EKI_ERR_UNSUPPORTED` with zeroed outputs. |
| 2026-11-11 | Rust `audit_verify` | 200000 | 863 (553) | clean | |
| 2026-11-11 | Rust `hkdf` | 200000 | 249 (225) | clean | |
| 2026-11-11 | Rust `aead_open` | 200000 | 1209 (872) | clean | |
| 2026-11-11 | C++ `fuzz_ffi_status`, PQ build | 200000 | 4243 (3336) | clean | 83 s. |
| 2026-11-11 | C++ `fuzz_hybrid_kem`, PQ build | 200000 | 369 (357) | clean | |
| 2026-11-11 | C++ `fuzz_ffi_status` | 200000 | 4138 (3276) | clean | 103 s. The C++ library flushes audit records with `fsync`, which on macOS does not flush the drive cache, hence the difference in speed from Rust. |
| 2026-11-11 | C++ `fuzz_ks_unwrap` | 200000 | 1900 (1757) | clean | |
| 2026-11-11 | C++ `fuzz_ecdsa_sign_verify` | 200000 | 556 (543) | clean | |
| 2026-11-11 | C++ `fuzz_hybrid_kem` | 200000 | 236 (229) | clean | KEM not compiled in: every call checked to be `EKI_ERR_UNSUPPORTED` with zeroed outputs. |
| 2026-11-11 | C++ `fuzz_audit_verify` | 200000 | 530 (417) | clean | |
| 2026-11-11 | C++ `fuzz_hkdf` | 200000 | 189 (176) | clean | |
| 2026-11-11 | C++ `fuzz_aead_open` | 200000 | 324 (287) | clean | |

Nothing was found in this campaign: no crash, no sanitizer report and no property failure in any
run of either language. The Rust `ffi_status` target did not reach 200000 executions in either
build; its longest clean runs are 34510 executions (default features) and 82638 (`pq`).
