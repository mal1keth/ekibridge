//! Helpers shared by the conformance test modules.
//!
//! Each test file includes this module with `mod common;`, so not every helper is used by every
//! file.
#![allow(dead_code)]

pub mod ks;

use std::ffi::CString;
use std::fmt::Write as _;
use std::sync::OnceLock;

use ekicore_conformance::{Lib, both, describe, is_zero, status};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng as _, SeedableRng};

/// Both libraries, loaded once per test binary: `(libekicore, libekicore_rs)`. Call
/// [`setup`] first; this panics when the environment does not name the libraries.
pub fn libs() -> &'static (Lib, Lib) {
    static LIBS: OnceLock<(Lib, Lib)> = OnceLock::new();
    LIBS.get_or_init(both)
}

/// Start of every test: the two libraries, or `None` after printing a skip message when
/// `EKI_CPP_LIB` / `EKI_RS_LIB` are unset (a plain `cargo test --workspace` run). Use as
/// `let Some((a, b)) = common::setup("module::test") else { return };`.
pub fn setup(test: &str) -> Option<&'static (Lib, Lib)> {
    let set = |v: &str| std::env::var_os(v).is_some_and(|s| !s.is_empty());
    if set("EKI_CPP_LIB") && set("EKI_RS_LIB") {
        Some(libs())
    } else {
        eprintln!(
            "skipping {test}: EKI_CPP_LIB and EKI_RS_LIB are not set (scripts/run-conformance.sh \
             builds both libraries and sets them)"
        );
        None
    }
}

/// Both libraries as an array, for loops that do the same thing in each.
pub fn each() -> [&'static Lib; 2] {
    let (a, b) = libs();
    [a, b]
}

/// A NUL-terminated copy of `s` (panics on an interior NUL: a harness bug).
pub fn cstr(s: &str) -> CString {
    CString::new(s).expect("label contains NUL")
}

/// A label unique to this process and call site, so PKCS#11 runs never collide with old objects.
pub fn unique_label(tag: &str) -> CString {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    cstr(&format!("conf-{tag}-{}-{n}", std::process::id()))
}

// ---------------------------------------------------------------------------------------------
// Failure collection
// ---------------------------------------------------------------------------------------------

const MAX_SHOWN: usize = 25;

/// Collects failed checks and panics once at the end with a summary, so a run shows how many
/// cases fail and the first few reasons instead of stopping at the first.
pub struct Report {
    name: String,
    checks: usize,
    failed: usize,
    shown: Vec<String>,
}

impl Report {
    pub fn new(name: &str) -> Self {
        Report {
            name: name.to_owned(),
            checks: 0,
            failed: 0,
            shown: Vec::new(),
        }
    }

    /// Records one check; `msg` is built only on failure.
    pub fn check(&mut self, ok: bool, msg: impl FnOnce() -> String) -> bool {
        self.checks += 1;
        if !ok {
            self.failed += 1;
            if self.shown.len() < MAX_SHOWN {
                self.shown.push(msg());
            }
        }
        ok
    }

    /// `got == want` for one library's status.
    pub fn status(&mut self, lib: &Lib, ctx: &str, got: i32, want: i32) -> bool {
        self.check(got == want, || {
            format!(
                "{}: {ctx}: got {}, want {}",
                lib.name(),
                describe(got),
                describe(want)
            )
        })
    }

    /// `got` is one of `want`.
    pub fn status_in(&mut self, lib: &Lib, ctx: &str, got: i32, want: &[i32]) -> bool {
        self.check(want.contains(&got), || {
            let w: Vec<String> = want.iter().map(|&s| describe(s)).collect();
            format!(
                "{}: {ctx}: got {}, want one of {}",
                lib.name(),
                describe(got),
                w.join(", ")
            )
        })
    }

    /// `buf` is all zero (an output after an error).
    pub fn zeroed(&mut self, lib: &Lib, ctx: &str, what: &str, buf: &[u8]) -> bool {
        self.check(is_zero(buf), || {
            format!(
                "{}: {ctx}: {what} not zero-filled after error: {}",
                lib.name(),
                short_hex(buf)
            )
        })
    }

    /// `buf` is all zero after `lib` returned the error `status` (differential runs, where the
    /// status is not fixed in advance).
    pub fn zeroed_after(
        &mut self,
        lib: &Lib,
        ctx: &str,
        status: i32,
        what: &str,
        buf: &[u8],
    ) -> bool {
        self.check(is_zero(buf), || {
            format!(
                "{}: {ctx}: {what} not zero-filled after {}: {}",
                lib.name(),
                describe(status),
                short_hex(buf)
            )
        })
    }

    /// `buf` still holds the prefill pattern (an output the contract says is left untouched).
    pub fn untouched(&mut self, lib: &Lib, ctx: &str, what: &str, buf: &[u8]) -> bool {
        let ok = buf.iter().all(|&b| b == ekicore_conformance::PREFILL);
        self.check(ok, || {
            format!(
                "{}: {ctx}: {what} was written but must be left untouched",
                lib.name()
            )
        })
    }

    /// `got == want` for an output.
    pub fn bytes(&mut self, lib: &Lib, ctx: &str, what: &str, got: &[u8], want: &[u8]) -> bool {
        self.check(got == want, || {
            format!(
                "{}: {ctx}: {what} = {}, want {}",
                lib.name(),
                short_hex(got),
                short_hex(want)
            )
        })
    }

    /// Statuses of the two libraries agree.
    pub fn agree(&mut self, ctx: &str, sa: i32, sb: i32) -> bool {
        let (a, b) = libs();
        self.check(sa == sb, || {
            format!(
                "{ctx}: {} returned {}, {} returned {}",
                a.name(),
                describe(sa),
                b.name(),
                describe(sb)
            )
        })
    }

    /// Outputs of the two libraries agree.
    pub fn agree_bytes(&mut self, ctx: &str, what: &str, xa: &[u8], xb: &[u8]) -> bool {
        let (a, b) = libs();
        self.check(xa == xb, || {
            format!(
                "{ctx}: {what} differs: {} {} vs {} {}",
                a.name(),
                short_hex(xa),
                b.name(),
                short_hex(xb)
            )
        })
    }

    /// Panics with the summary if any check failed.
    pub fn finish(self) {
        if self.failed == 0 {
            return;
        }
        let mut msg = format!(
            "{}: {} of {} checks failed (first {} shown):",
            self.name,
            self.failed,
            self.checks,
            self.shown.len()
        );
        for s in &self.shown {
            let _ = write!(msg, "\n  {s}");
        }
        panic!("{msg}");
    }
}

/// Hex of at most 48 bytes, with the total length when longer.
pub fn short_hex(b: &[u8]) -> String {
    if b.len() <= 48 {
        hex::encode(b)
    } else {
        format!("{}... ({} bytes)", hex::encode(&b[..48]), b.len())
    }
}

// ---------------------------------------------------------------------------------------------
// Seeded randomness for the differential tests
// ---------------------------------------------------------------------------------------------

/// Base seed ("EKIB"); `EKI_DIFF_SEED` overrides it to reproduce or vary a run.
pub const BASE_SEED: u64 = 0x454B_4942;

/// Lengths the differential tests favour: block and tag boundaries, empty, and a few large ones.
pub const LENS: [usize; 15] = [
    0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 1000, 4096,
];

/// Iterations per function: `EKI_DIFF_N`, default 2000.
pub fn diff_n() -> usize {
    std::env::var("EKI_DIFF_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000)
}

/// The seed in use (for failure messages).
pub fn base_seed() -> u64 {
    std::env::var("EKI_DIFF_SEED")
        .ok()
        .and_then(|s| {
            let s = s.trim();
            match s.strip_prefix("0x") {
                Some(h) => u64::from_str_radix(h, 16).ok(),
                None => s.parse().ok(),
            }
        })
        .unwrap_or(BASE_SEED)
}

/// `ChaCha20Rng` with small helpers. Each function gets its own stream (the base seed XOR a hash
/// of the stream name), so adding a test never shifts the inputs of another.
pub struct Rng(ChaCha20Rng);

impl Rng {
    pub fn new(stream: &str) -> Self {
        // FNV-1a over the stream name.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in stream.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        Rng(ChaCha20Rng::seed_from_u64(base_seed() ^ h))
    }

    /// Uniform in `0..n` (`n > 0`; the modulo bias is irrelevant here).
    pub fn below(&mut self, n: usize) -> usize {
        (self.0.next_u64() % n as u64) as usize
    }

    /// True with probability `num / den`.
    pub fn chance(&mut self, num: usize, den: usize) -> bool {
        self.below(den) < num
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.0.fill_bytes(&mut v);
        v
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut a = [0u8; N];
        self.0.fill_bytes(&mut a);
        a
    }

    pub fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len())]
    }

    /// A length: three times in four from [`LENS`], otherwise uniform in `0..=max`.
    pub fn len(&mut self, max: usize) -> usize {
        if self.chance(3, 4) {
            self.pick(&LENS)
        } else {
            self.below(max + 1)
        }
    }

    /// Random bytes whose length comes from [`Rng::len`].
    pub fn data(&mut self, max: usize) -> Vec<u8> {
        let n = self.len(max);
        self.bytes(n)
    }

    /// Flips one random bit of a non-empty buffer.
    pub fn flip_bit(&mut self, b: &mut [u8]) {
        if !b.is_empty() {
            let i = self.below(b.len());
            b[i] ^= 1 << self.below(8);
        }
    }
}

/// Counts `EKI_OK` results per library so a differential run that never succeeded (both
/// libraries stubbed, or both rejecting every input) is reported instead of passing vacuously.
#[derive(Default)]
pub struct OkCount {
    pub a: usize,
    pub b: usize,
}

impl OkCount {
    pub fn add(&mut self, sa: i32, sb: i32) {
        self.a += usize::from(sa == status::EKI_OK);
        self.b += usize::from(sb == status::EKI_OK);
    }

    pub fn require_some(&self, r: &mut Report, what: &str) {
        let (a, b) = libs();
        for (lib, n) in [(a, self.a), (b, self.b)] {
            r.check(n > 0, || {
                format!(
                    "{}: {what}: no call returned EKI_OK in {} iterations; the differential \
                     comparison is vacuous",
                    lib.name(),
                    diff_n()
                )
            });
        }
    }
}

/// Context string for one differential iteration.
pub fn iter_ctx(what: &str, i: usize) -> String {
    format!("{what} iteration {i} (seed {:#x})", base_seed())
}
