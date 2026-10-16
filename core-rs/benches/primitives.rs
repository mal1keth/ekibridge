//! Benchmarks of `libekicore_rs` through its C ABI.
//!
//! Every workload calls the `extern "C"` functions in `ekicore_rs::ffi` with raw pointers, the
//! same way a C caller would, so the numbers include the boundary (argument checks,
//! `catch_unwind`, zero-on-error bookkeeping) and are directly comparable with
//! `core-cpp/bench/primitives_bench.cpp`, which runs identical workloads against `libekicore`.
//! Group and benchmark names match on both sides; `scripts/bench.sh` merges the two result sets.
//!
//! The returned status is ignored: a benchmark measures whatever the library does with these
//! inputs. Inputs are fixed byte patterns and the AEAD nonce is reused across iterations; that is
//! fine for timing and must never be copied into real code.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ekicore_abi::{
    EKI_AEAD_AES_256_GCM, EKI_AEAD_CHACHA20_POLY1305, EKI_AEAD_KEY_LEN, EKI_AEAD_NONCE_LEN,
    EKI_AEAD_TAG_LEN, EKI_HMAC_SHA256_LEN, eki_aead_alg,
};
use ekicore_rs::ffi;

/// HMAC-SHA256 message sizes.
const HMAC_SIZES: [usize; 2] = [64, 4096];
/// AEAD plaintext sizes.
const AEAD_SIZES: [usize; 2] = [1024, 64 * 1024];
/// Associated data length for every AEAD workload.
const AAD_LEN: usize = 16;
/// HKDF parameters: input keying material, salt, info and output lengths.
const HKDF_IKM_LEN: usize = 32;
const HKDF_SALT_LEN: usize = 16;
const HKDF_INFO_LEN: usize = 16;
const HKDF_OKM_LEN: usize = 32;

/// The two AEAD algorithms with the names used in benchmark ids.
const AEAD_ALGS: [(&str, eki_aead_alg); 2] = [
    ("aes-256-gcm", EKI_AEAD_AES_256_GCM),
    ("chacha20-poly1305", EKI_AEAD_CHACHA20_POLY1305),
];

/// A deterministic, non-constant byte pattern; `seed` keeps different inputs distinct.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn bench_hmac(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac");
    let key = pattern(32, 1);
    for size in HMAC_SIZES {
        let msg = pattern(size, 2);
        let mut out = [0u8; EKI_HMAC_SHA256_LEN];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("sha256", size), |b| {
            b.iter(|| {
                // SAFETY: `key` and `msg` are live slices of exactly the lengths passed, and
                // `out` is a 32-byte array that does not overlap them.
                let status = unsafe {
                    ffi::eki_hmac_sha256(
                        key.as_ptr(),
                        key.len(),
                        black_box(msg.as_ptr()),
                        msg.len(),
                        out.as_mut_ptr(),
                    )
                };
                black_box(status);
            });
        });
    }
    group.finish();
}

fn bench_hkdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("hkdf");
    let ikm = pattern(HKDF_IKM_LEN, 3);
    let salt = pattern(HKDF_SALT_LEN, 4);
    let info = pattern(HKDF_INFO_LEN, 5);
    let mut okm = [0u8; HKDF_OKM_LEN];
    group.throughput(Throughput::Bytes(HKDF_OKM_LEN as u64));
    group.bench_function(BenchmarkId::new("sha256", HKDF_OKM_LEN), |b| {
        b.iter(|| {
            // SAFETY: `ikm`, `salt` and `info` are live slices of exactly the lengths passed, and
            // `okm` is a writable array of `okm.len()` bytes that overlaps none of them.
            let status = unsafe {
                ffi::eki_hkdf_sha256(
                    black_box(ikm.as_ptr()),
                    ikm.len(),
                    salt.as_ptr(),
                    salt.len(),
                    info.as_ptr(),
                    info.len(),
                    okm.as_mut_ptr(),
                    okm.len(),
                )
            };
            black_box(status);
        });
    });
    group.finish();
}

fn bench_aead_seal(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_seal");
    let key = pattern(EKI_AEAD_KEY_LEN, 6);
    let nonce = pattern(EKI_AEAD_NONCE_LEN, 7);
    let aad = pattern(AAD_LEN, 8);
    for (name, alg) in AEAD_ALGS {
        for size in AEAD_SIZES {
            let pt = pattern(size, 9);
            let mut ct = vec![0u8; size];
            let mut tag = [0u8; EKI_AEAD_TAG_LEN];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::new(name, size), |b| {
                b.iter(|| {
                    // SAFETY: every input pointer comes from a live slice of exactly the length
                    // passed; `ct` has `pt.len()` writable bytes and `tag` 16, and no output
                    // overlaps an input or the other output.
                    let status = unsafe {
                        ffi::eki_aead_seal(
                            alg,
                            key.as_ptr(),
                            key.len(),
                            nonce.as_ptr(),
                            nonce.len(),
                            aad.as_ptr(),
                            aad.len(),
                            black_box(pt.as_ptr()),
                            pt.len(),
                            ct.as_mut_ptr(),
                            tag.as_mut_ptr(),
                        )
                    };
                    black_box(status);
                });
            });
        }
    }
    group.finish();
}

fn bench_aead_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_open");
    let key = pattern(EKI_AEAD_KEY_LEN, 6);
    let nonce = pattern(EKI_AEAD_NONCE_LEN, 7);
    let aad = pattern(AAD_LEN, 8);
    for (name, alg) in AEAD_ALGS {
        for size in AEAD_SIZES {
            // Seal once so that, with a real implementation, `open` measures the success path.
            let pt = pattern(size, 9);
            let mut ct = vec![0u8; size];
            let mut tag = [0u8; EKI_AEAD_TAG_LEN];
            // SAFETY: as in `bench_aead_seal`: inputs are live slices of the lengths passed, the
            // outputs have the required sizes and nothing overlaps.
            let _ = unsafe {
                ffi::eki_aead_seal(
                    alg,
                    key.as_ptr(),
                    key.len(),
                    nonce.as_ptr(),
                    nonce.len(),
                    aad.as_ptr(),
                    aad.len(),
                    pt.as_ptr(),
                    pt.len(),
                    ct.as_mut_ptr(),
                    tag.as_mut_ptr(),
                )
            };
            let mut out = vec![0u8; size];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::new(name, size), |b| {
                b.iter(|| {
                    // SAFETY: every input pointer comes from a live slice of exactly the length
                    // passed (`tag` is 16 bytes); `out` has `ct.len()` writable bytes and
                    // overlaps no input.
                    let status = unsafe {
                        ffi::eki_aead_open(
                            alg,
                            key.as_ptr(),
                            key.len(),
                            nonce.as_ptr(),
                            nonce.len(),
                            aad.as_ptr(),
                            aad.len(),
                            black_box(ct.as_ptr()),
                            ct.len(),
                            tag.as_ptr(),
                            out.as_mut_ptr(),
                        )
                    };
                    black_box(status);
                });
            });
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_hmac,
    bench_hkdf,
    bench_aead_seal,
    bench_aead_open
);
criterion_main!(benches);
