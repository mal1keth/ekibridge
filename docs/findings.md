# Findings

This is the log of fuzzing campaigns. It is for anyone who wants to know how much fuzzing stands
behind a claim made elsewhere in this repository, and what the fuzzing found. A bug found by
fuzzing, the sanitizers, Miri or the conformance harness is recorded here as well, and it stays
in the table after it is fixed. So far the log holds one campaign, one follow-up run on Linux
and no bug.

## How to read the table

There is one row per run of a target, newest first.

| Column | Meaning |
|---|---|
| `Runs` | The number of executions. A run that ended before its planned count says how: at its time limit, or stopped by hand. |
| `Coverage` | libFuzzer's `cov` figure at the end of the run (instrumented edges reached), with the figure after loading the seeds in brackets. |
| `Result` | `clean` or a description of the failure. |
| `Notes` | For a finding, the fix and the regression test that now covers it. |

The coverage figures of the two languages cannot be compared with each other. The Rust figures
count edges in `ekicore-rs` and the RustCrypto crates; the C++ figures count edges in
`libekicore` only, because OpenSSL is not instrumented.

## Follow-up run on Linux, 2026-11-11

The campaign below left the Rust `ffi_status` target short of its 200000 executions, so I ran
that target again on a Linux server. Neither thing that held it back on the Mac applies there:
`sync_data` is `fdatasync` on Linux, and the machine does not sleep. The server is an x86-64
virtual machine with 4 cores, Debian 13 and kernel 6.12. The build was the same as in the
campaign (cargo-fuzz 0.13.2, a release build with AddressSanitizer, debug assertions and overflow
checks), with rustc 1.102.0-nightly of 2026-11-10; the second run adds `--features pq`. Both runs
started from the 16 committed seeds, copied to a scratch directory, with `-runs=200000`, and ran
side by side from 21:03 to 21:15 UTC. `TMPDIR` pointed at a directory on the ext4 disk, so the
audit logs went to a real file system and not to the tmpfs that Debian mounts on `/tmp`.

| Date | Target | Runs | Coverage | Result | Notes |
|---|---|---|---|---|---|
| 2026-11-11 | Rust `ffi_status`, `pq` | 200000 | 6088 (4647) | clean | Linux x86-64. 721 s, about 277 executions per second. |
| 2026-11-11 | Rust `ffi_status` | 200000 | 5178 (3763) | clean | Linux x86-64. 716 s, about 279 executions per second. |

Both runs reached the full count with no crash, no sanitizer report and no property failure. The
coverage figures come from an x86-64 build and cannot be compared one to one with the arm64
figures of the campaign below.

## Campaign of 2026-11-11

I ran the campaign on macOS 26.2 on Apple silicon (8 cores). The C++ targets were built with
Homebrew LLVM clang 23.1.3 and OpenSSL 3.5.9 using `cmake --preset fuzz` (libFuzzer,
AddressSanitizer and UndefinedBehaviorSanitizer); the KEM build adds `-DEKI_WITH_PQ=ON`. The Rust
targets were built with cargo-fuzz 0.13.2 on nightly Rust, as a release build with
AddressSanitizer, debug assertions and overflow checks; the KEM build adds `--features pq`. Every
run started from the committed named seeds only, copied to a scratch directory, with
`-runs=200000`. The targets used the software key store only; no PKCS#11 token was opened.

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
| 2026-11-11 | C++ `fuzz_ffi_status` | 200000 | 4138 (3276) | clean | 103 s. At the time of this run the C++ library flushed audit records with `fsync`, which on macOS does not flush the drive cache, hence the difference in speed from Rust; it has used `F_FULLFSYNC` there since. |
| 2026-11-11 | C++ `fuzz_ks_unwrap` | 200000 | 1900 (1757) | clean | |
| 2026-11-11 | C++ `fuzz_ecdsa_sign_verify` | 200000 | 556 (543) | clean | |
| 2026-11-11 | C++ `fuzz_hybrid_kem` | 200000 | 236 (229) | clean | KEM not compiled in: every call checked to be `EKI_ERR_UNSUPPORTED` with zeroed outputs. |
| 2026-11-11 | C++ `fuzz_audit_verify` | 200000 | 530 (417) | clean | |
| 2026-11-11 | C++ `fuzz_hkdf` | 200000 | 189 (176) | clean | |
| 2026-11-11 | C++ `fuzz_aead_open` | 200000 | 324 (287) | clean | |

Nothing was found in this campaign: no crash, no sanitizer report and no property failure in any
run of either language.

The Rust `ffi_status` target did not reach 200000 executions in either build. I stopped its first
run by hand at 34510 executions; the other three runs ended at their time limits. Its longest
clean runs are 34510 executions (default features) and 82638 (`pq`). Two things held it back:
every logged call flushes the audit log with `F_FULLFSYNC` on macOS, and the machine went to
sleep during each of the four runs. The follow-up run on Linux, above, took the target to the
full count.
