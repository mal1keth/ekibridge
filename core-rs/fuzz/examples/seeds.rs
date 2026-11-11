//! Regenerates the seed corpora of both fuzzing setups.
//!
//! ```text
//! cargo run --manifest-path core-rs/fuzz/Cargo.toml --example seeds --features pq
//! ```
//!
//! The Rust targets (`src/lib.rs`) and the C++ targets (`core-cpp/fuzz/fuzz_input.hpp`) read the
//! same input layout, so each seed is written twice with the same bytes:
//! `core-rs/fuzz/corpus/<target>/<seed>` and `core-cpp/fuzz/corpus/fuzz_<target>/<seed>` (the
//! unwrap target is `unwrap_blob` in Rust and `fuzz_ks_unwrap` in C++).
//!
//! The values come from the RFC and spec vector files under `conformance/vectors/`, from RFC 3394
//! section 4.6, and from artefacts this library makes while the generator runs: audit logs, and
//! with the `pq` feature hybrid KEM key pairs and ciphertexts. Seeds that need the feature are
//! skipped without it. Before writing, every named seed of a target is removed; inputs that
//! libFuzzer added during a run (named by their SHA-1, 40 hex digits, and ignored by git) are left
//! alone.

use std::fs;
use std::path::{Path, PathBuf};

use ekicore_abi::{
    EKI_AUDIT_HASH_LEN, EKI_HYBRID_CT_LEN, EKI_HYBRID_PK_LEN, EKI_HYBRID_SK_LEN, EKI_KEY_AES_256,
    EKI_KEY_HMAC_SHA256, eki_ks,
};
use ekicore_rs::ffi::{
    eki_hybrid_kem_encap, eki_hybrid_kem_keygen, eki_ks_audit_head, eki_ks_hmac_sha256,
    eki_ks_open_v2, eki_ks_wrap,
};
use ekicore_rs_fuzz::{Config, OK, Scratch, Slot, Store, audit_rebuild};
use serde_json::Value;

/// RFC 3394 section 4.6: 256 bits of key data wrapped under a 256-bit KEK.
const RFC3394_4_6_WRAPPED: &str =
    "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21";

// --- Encoding --------------------------------------------------------------------------------

/// Writes input bytes in the layout `Reader` reads.
#[derive(Default, Clone)]
struct Enc(Vec<u8>);

impl Enc {
    fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    fn bool(self, v: bool) -> Self {
        self.u8(u8::from(v))
    }
    fn u16(mut self, v: usize) -> Self {
        let v = u16::try_from(v).expect("value fits in u16");
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn i32(mut self, v: i32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn array(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
    fn bytes(self, v: &[u8]) -> Self {
        self.u16(v.len()).array(v)
    }
    /// `InBuf`: the NULL flag, then the bytes.
    fn buf(self, null: bool, v: &[u8]) -> Self {
        self.bool(null).bytes(v)
    }
    /// `read_capped_len`: 0 the real length, 2 the cap plus one, 3 `usize::MAX`.
    fn len(self, mode: u8) -> Self {
        self.u8(mode)
    }
    /// `read_key_ref`: a key the session made, by index.
    fn known(self, index: u8) -> Self {
        self.u8(2).u8(index)
    }
    /// `read_key_ref`: 16 raw bytes.
    fn raw_id(self, id: &[u8; 16]) -> Self {
        self.u8(1).array(id)
    }
    /// `read_key_ref`: NULL.
    fn null_id(self) -> Self {
        self.u8(0)
    }
    /// `read_label`: a NUL-terminated label.
    fn label(self, text: &[u8]) -> Self {
        self.u8(1).bytes(text)
    }
    /// `read_label`: 65 bytes without a NUL.
    fn label_65(self, text: &[u8]) -> Self {
        self.u8(2).bytes(text)
    }
    /// `read_label`: NULL.
    fn null_label(self) -> Self {
        self.u8(0)
    }
    fn config(self, c: &Cfg) -> Self {
        let mut e = self
            .i32(c.backend)
            .u8(c.flags)
            .bytes(c.token_label)
            .bytes(c.pin)
            .u8(c.audit)
            .u8(c.count)
            .u8(c.source);
        match c.source {
            1 => e = e.bytes(&c.raw_keys),
            2 => e = e.array(&c.picks),
            _ => {}
        }
        e
    }
}

/// The fields of a `Config` as the input spells them.
#[derive(Clone)]
struct Cfg {
    backend: i32,
    flags: u8,
    token_label: &'static [u8],
    pin: &'static [u8],
    /// `read_audit_path`: 0 NULL, 1 the run's log, 2 "", 3 4097 bytes, 4 a directory, 5 missing.
    audit: u8,
    count: u8,
    /// 0 NULL, 1 raw bytes, 2 generated keys.
    source: u8,
    raw_keys: Vec<u8>,
    picks: Vec<u8>,
}

impl Cfg {
    fn software() -> Self {
        Self {
            backend: 1,
            flags: 0,
            token_label: b"",
            pin: b"",
            audit: 0,
            count: 0,
            source: 0,
            raw_keys: Vec::new(),
            picks: Vec::new(),
        }
    }
    fn audited() -> Self {
        Self {
            audit: 1,
            ..Self::software()
        }
    }
    fn dual(picks: &[u8]) -> Self {
        Self {
            count: u8::try_from(picks.len()).expect("few approvers"),
            source: 2,
            picks: picks.to_vec(),
            ..Self::audited()
        }
    }
}

// --- Vectors ---------------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cases(file: &str) -> Vec<Value> {
    let path = repo_root().join("conformance/vectors").join(file);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text).expect("vector file is JSON");
    doc["cases"].as_array().expect("cases array").clone()
}

fn hex_field(case: &Value, field: &str) -> Vec<u8> {
    let text = case[field]
        .as_str()
        .unwrap_or_else(|| panic!("case has no string {field}"));
    hex::decode(text).expect("field is hex")
}

fn named<'a>(cases: &'a [Value], name: &str) -> &'a Value {
    cases
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case named {name}"))
}

struct Aead {
    alg: i32,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    tag: Vec<u8>,
}

fn aead(case: &Value, alg: i32) -> Aead {
    Aead {
        alg,
        key: hex_field(case, "key"),
        nonce: hex_field(case, "nonce"),
        aad: hex_field(case, "aad"),
        pt: hex_field(case, "pt"),
        ct: hex_field(case, "ct"),
        tag: hex_field(case, "tag"),
    }
}

// --- Artefacts made by the library ------------------------------------------------------------

/// A store with the run's audit log, opened with `eki_ks_open_v2`.
fn audited_store(scratch: &Scratch) -> Store {
    let mut config = Config::software();
    config.set_audit_log(scratch);
    let mut out = Slot::<*mut eki_ks>::new(false);
    // SAFETY: the config view points into buffers `config` owns; `out` is a live, aligned
    // `eki_ks *`.
    let status = unsafe { eki_ks_open_v2(&config.v2(), out.ptr()) } as i32;
    assert_eq!(status, OK, "opening a store with an audit log");
    Store::from_raw(out.get())
}

/// A log of five records (open, two generates, wrap, hmac) and close, with the head before close.
fn audit_log() -> (Vec<u8>, [u8; EKI_AUDIT_HASH_LEN]) {
    let scratch = Scratch::new("seeds");
    scratch.reset();
    let store = audited_store(&scratch);
    let kek = store.generate(EKI_KEY_AES_256, c"seed-kek");
    let key = store.generate(EKI_KEY_HMAC_SHA256, c"seed-mac");
    let mut out = [0_u8; 40];
    let mut head = [0_u8; EKI_AUDIT_HASH_LEN];
    let mut seq = 0_u64;
    // SAFETY: `store` is open; the ids are live structs; `out` is a writable 40-byte buffer, then
    // the first 32 bytes of it, `msg` a live 4-byte array; `head` and `seq` are writable.
    unsafe {
        assert_eq!(
            eki_ks_wrap(store.ptr(), &kek, &key, out.as_mut_ptr()) as i32,
            OK
        );
        let msg = b"seed";
        let status =
            eki_ks_hmac_sha256(store.ptr(), &key, msg.as_ptr(), msg.len(), out.as_mut_ptr());
        assert_eq!(status as i32, OK);
        assert_eq!(
            eki_ks_audit_head(store.ptr(), head.as_mut_ptr(), &mut seq) as i32,
            OK
        );
    }
    drop(store);
    let log = fs::read(&scratch.log_path).expect("reading the log");
    scratch.reset();
    let rebuilt = audit_rebuild(&log).expect("the library writes valid logs");
    assert_eq!(rebuilt.records, seq + 1, "close adds one record");
    (log, head)
}

/// A hybrid KEM key pair and a ciphertext to it, or `None` without the `pq` feature.
fn kem() -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut pk = vec![0_u8; EKI_HYBRID_PK_LEN];
    let mut sk = vec![0_u8; EKI_HYBRID_SK_LEN];
    let mut ct = vec![0_u8; EKI_HYBRID_CT_LEN];
    let mut ss = [0_u8; 32];
    // SAFETY: each buffer has exactly the size the function writes or reads.
    unsafe {
        if eki_hybrid_kem_keygen(pk.as_mut_ptr(), sk.as_mut_ptr()) as i32 != OK {
            return None;
        }
        let status = eki_hybrid_kem_encap(pk.as_ptr(), ct.as_mut_ptr(), ss.as_mut_ptr());
        assert_eq!(status as i32, OK);
    }
    Some((pk, sk, ct))
}

// --- Output ----------------------------------------------------------------------------------

/// Writes seeds of one target to both corpora.
struct Target {
    dirs: [PathBuf; 2],
    written: usize,
}

impl Target {
    fn new(rust: &str, cpp: &str) -> Self {
        let root = repo_root();
        let dirs = [
            root.join("core-rs/fuzz/corpus").join(rust),
            root.join("core-cpp/fuzz/corpus").join(cpp),
        ];
        for dir in &dirs {
            fs::create_dir_all(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
            for entry in fs::read_dir(dir).expect("corpus directory") {
                let path = entry.expect("entry").path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let hashed = name.len() == 40 && name.bytes().all(|b| b.is_ascii_hexdigit());
                if !hashed {
                    fs::remove_file(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                }
            }
        }
        Self { dirs, written: 0 }
    }

    fn put(&mut self, name: &str, e: Enc) {
        for dir in &self.dirs {
            let path = dir.join(name);
            fs::write(&path, &e.0).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
        self.written += 1;
    }
}

fn flip(mut bytes: Vec<u8>, index: usize) -> Vec<u8> {
    bytes[index] ^= 0x01;
    bytes
}

fn main() {
    let chacha = cases("aead_chacha20poly1305_rfc8439.json");
    let gcm = cases("aead_aes256gcm_spec.json");
    let hkdf = cases("hkdf_sha256_rfc5869.json");
    let hmac = cases("hmac_sha256_rfc4231.json");
    let ecdsa = cases("ecdsa_p256_rfc6979.json");
    let rfc8439 = aead(named(&chacha, "RFC 8439 2.8.2"), 2);
    let tc16 = aead(named(&gcm, "GCM spec Test Case 16"), 1);
    let a1 = named(&hkdf, "RFC 5869 A.1");
    let tc1 = named(&hmac, "RFC 4231 4.2 (Test Case 1)");
    let tc2 = named(&hmac, "RFC 4231 4.3 (Test Case 2)");
    let sample = &ecdsa[0];
    let mut total = 0;

    // aead_open: alg, key, nonce, aad, ct, tag.
    let mut t = Target::new("aead_open", "fuzz_aead_open");
    let open = |v: &Aead, tag: &[u8]| {
        Enc::default()
            .i32(v.alg)
            .bytes(&v.key)
            .bytes(&v.nonce)
            .bytes(&v.aad)
            .bytes(&v.ct)
            .array(tag)
    };
    t.put("rfc8439-2.8.2", open(&rfc8439, &rfc8439.tag));
    t.put(
        "rfc8439-2.8.2-bad-tag",
        open(&rfc8439, &flip(rfc8439.tag.clone(), 0)),
    );
    let a5 = aead(named(&chacha, "RFC 8439 A.5"), 2);
    t.put("rfc8439-a.5", open(&a5, &a5.tag));
    for n in 13..=16 {
        let v = aead(named(&gcm, &format!("GCM spec Test Case {n}")), 1);
        t.put(&format!("gcm-tc{n}"), open(&v, &v.tag));
    }
    t.put("gcm-tc16-bad-tag", open(&tc16, &flip(tc16.tag.clone(), 0)));
    total += t.written;

    // hkdf: ikm, salt, info, two lengths.
    let mut t = Target::new("hkdf", "fuzz_hkdf");
    let derive = |c: &Value, l1: usize, l2: usize| {
        Enc::default()
            .bytes(&hex_field(c, "ikm"))
            .bytes(&hex_field(c, "salt"))
            .bytes(&hex_field(c, "info"))
            .u16(l1)
            .u16(l2)
    };
    for (name, case) in [
        ("a.1", "RFC 5869 A.1"),
        ("a.2", "RFC 5869 A.2"),
        ("a.3", "RFC 5869 A.3"),
    ] {
        let c = named(&hkdf, case);
        let len = usize::try_from(c["length"].as_u64().expect("length")).expect("fits");
        t.put(&format!("rfc5869-{name}"), derive(c, len, 1));
    }
    t.put("rfc5869-a.1-okm-8160-8161", derive(a1, 8160, 8161));
    t.put("rfc5869-a.1-okm-0", derive(a1, 0, 42));
    total += t.written;

    // audit_verify: head mode, [head], file.
    let (log, head) = audit_log();
    let lines: Vec<&[u8]> = log.split_inclusive(|&b| b == b'\n').collect();
    let full_head = audit_rebuild(&log).expect("valid").hash;
    let mut t = Target::new("audit_verify", "fuzz_audit_verify");
    t.put("empty", Enc::default().u8(0));
    t.put("library-log", Enc::default().u8(0).array(&log));
    t.put("library-log-head", Enc::default().u8(1).array(&log));
    t.put(
        "library-log-raw-head",
        Enc::default().u8(2).array(&full_head).array(&log),
    );
    let cut = lines[..lines.len() - 1].concat();
    t.put("tail-cut", Enc::default().u8(0).array(&cut));
    t.put(
        "tail-cut-full-head",
        Enc::default().u8(2).array(&full_head).array(&cut),
    );
    t.put(
        "head-before-close",
        Enc::default().u8(2).array(&head).array(&cut),
    );
    let middle = [lines[0], lines[2]].concat();
    t.put("middle-line-removed", Enc::default().u8(0).array(&middle));
    t.put(
        "byte-flipped",
        Enc::default().u8(0).array(&flip(log.clone(), 40)),
    );
    t.put(
        "no-final-newline",
        Enc::default().u8(0).array(&log[..log.len() - 1]),
    );
    t.put("one-record", Enc::default().u8(1).array(lines[0]));
    total += t.written;

    // hybrid_kem: mode 0 masks, mode 1 sk and ct, mode 2 pk.
    let mut t = Target::new("hybrid_kem", "fuzz_hybrid_kem");
    t.put("round-trip", Enc::default().u8(0).bytes(b"").bytes(b""));
    let mut ct_mask = vec![0_u8; 40];
    ct_mask[39] = 0x01;
    t.put(
        "round-trip-mlkem-ct-flip",
        Enc::default().u8(0).bytes(b"").bytes(&ct_mask),
    );
    t.put(
        "round-trip-x25519-ct-flip",
        Enc::default().u8(0).bytes(b"").bytes(&[0x01]),
    );
    t.put(
        "round-trip-pk-flip",
        Enc::default().u8(0).bytes(&[0, 0x01]).bytes(b""),
    );
    t.put("decap-zeros", Enc::default().u8(1).bytes(b"").bytes(b""));
    t.put("encap-zeros", Enc::default().u8(2).bytes(b""));
    if let Some((pk, sk, ct)) = kem() {
        t.put("decap-library", Enc::default().u8(1).bytes(&sk).bytes(&ct));
        let mut zero_x25519 = ct.clone();
        zero_x25519[..32].fill(0);
        t.put(
            "decap-x25519-zero",
            Enc::default().u8(1).bytes(&sk).bytes(&zero_x25519),
        );
        t.put("encap-library", Enc::default().u8(2).bytes(&pk));
        let mut zero_x25519 = pk.clone();
        zero_x25519[..32].fill(0);
        t.put(
            "encap-x25519-zero",
            Enc::default().u8(2).bytes(&zero_x25519),
        );
    } else {
        println!("hybrid KEM seeds from the library skipped: built without the pq feature");
    }
    total += t.written;

    // ecdsa_sign_verify: msg, tamper mode, mask.
    let mut t = Target::new("ecdsa_sign_verify", "fuzz_ecdsa_sign_verify");
    let msg = hex_field(sample, "msg");
    for (name, mode, mask) in [
        ("sample", 0, &[][..]),
        ("sample-sig-flip", 1, &[0x01][..]),
        ("sample-msg-extended", 2, &[0, 0, 0, 0, 0, 0, b'!'][..]),
        ("sample-pk-flip", 3, &[0, 0, 0x01][..]),
        ("empty-message", 0, &[][..]),
    ] {
        let m = if name == "empty-message" {
            &[][..]
        } else {
            &msg[..]
        };
        t.put(name, Enc::default().bytes(m).u8(mode).bytes(mask));
    }
    total += t.written;

    // unwrap_blob: use_config, [config], from_wrap, blob, alg, id, label.
    let mut t = Target::new("unwrap_blob", "fuzz_ks_unwrap");
    let id = *b"ekibridge-fuzz-1";
    let unwrap = |config: Option<&Cfg>, from_wrap: bool, blob: &[u8], alg: i32| {
        let mut e = Enc::default().bool(config.is_some());
        if let Some(c) = config {
            e = e.config(c);
        }
        e.bool(from_wrap).bytes(blob).i32(alg).array(&id)
    };
    let rfc3394 = hex::decode(RFC3394_4_6_WRAPPED).expect("hex");
    t.put(
        "wrapped-hmac-key",
        unwrap(None, true, b"", 2).label(b"fuzz-unwrapped"),
    );
    t.put(
        "wrapped-hmac-key-as-aes",
        unwrap(None, true, b"", 1).label(b"fuzz-unwrapped"),
    );
    t.put(
        "wrapped-hmac-key-byte-flipped",
        unwrap(None, true, &[0, 0, 0, 0x80], 2).label(b"fuzz-unwrapped"),
    );
    t.put("rfc3394-4.6", unwrap(None, false, &rfc3394, 2).label(b"x"));
    t.put(
        "rfc3394-4.6-short",
        unwrap(None, false, &rfc3394[..39], 2).label(b"x"),
    );
    t.put("alg-ecdsa", unwrap(None, true, b"", 3).label(b"x"));
    t.put("label-65-bytes", unwrap(None, true, b"", 2).label_65(b""));
    t.put(
        "label-control-byte",
        unwrap(None, true, b"", 2).label(b"bad\x01label"),
    );
    t.put("label-null", unwrap(None, true, b"", 2).null_label());
    let dual = Cfg::dual(&[0, 1, 2]);
    t.put(
        "config-audit-dual",
        unwrap(Some(&dual), true, b"", 2).label(b"fuzz-unwrapped"),
    );
    let pkcs11 = Cfg {
        backend: 2,
        flags: 7,
        token_label: b"fuzz-token",
        pin: b"0000",
        ..Cfg::software()
    };
    t.put(
        "config-pkcs11-no-module",
        unwrap(Some(&pkcs11), true, b"", 2).label(b"x"),
    );
    let raw_approvers = Cfg {
        count: 2,
        source: 1,
        raw_keys: vec![0x04; 130],
        ..Cfg::software()
    };
    t.put(
        "config-raw-approvers",
        unwrap(Some(&raw_approvers), true, b"", 2).label(b"x"),
    );
    t.put(
        "config-duplicate-approvers",
        unwrap(Some(&Cfg::dual(&[1, 1])), true, b"", 2).label(b"x"),
    );
    total += t.written;

    // ffi_status: the session's store, then calls.
    let mut t = Target::new("ffi_status", "fuzz_ffi_status");
    let none = || Enc::default().u8(0);
    t.put(
        "hmac-rfc4231-tc1",
        none()
            .u8(0)
            .buf(false, &hex_field(tc1, "key"))
            .buf(false, &hex_field(tc1, "data"))
            .bool(false),
    );
    t.put(
        "hmac-verify-rfc4231-tc2",
        none()
            .u8(1)
            .buf(false, &hex_field(tc2, "key"))
            .buf(false, &hex_field(tc2, "data"))
            .buf(false, &hex_field(tc2, "mac")),
    );
    let hkdf_call = |e: Enc, ikm_mode: u8, okm_mode: u8| {
        e.u8(2)
            .buf(false, &hex_field(a1, "ikm"))
            .len(ikm_mode)
            .buf(false, &hex_field(a1, "salt"))
            .len(0)
            .buf(false, &hex_field(a1, "info"))
            .len(0)
            .bool(false)
            .u16(42)
            .len(okm_mode)
    };
    t.put("hkdf-rfc5869-a.1", hkdf_call(none(), 0, 0));
    t.put(
        "hkdf-lengths-over-cap",
        hkdf_call(hkdf_call(none(), 2, 0), 0, 3),
    );
    let seal = |e: Enc, v: &Aead, pt_mode: u8| {
        e.u8(3)
            .i32(v.alg)
            .buf(false, &v.key)
            .buf(false, &v.nonce)
            .buf(false, &v.aad)
            .buf(false, &v.pt)
            .len(pt_mode)
            .bool(false)
            .bool(false)
    };
    let open_call = |e: Enc, v: &Aead, ct_mode: u8| {
        e.u8(4)
            .i32(v.alg)
            .buf(false, &v.key)
            .buf(false, &v.nonce)
            .buf(false, &v.aad)
            .buf(false, &v.ct)
            .len(ct_mode)
            .bool(false)
            .array(&v.tag)
            .bool(false)
    };
    t.put("aead-seal-rfc8439-2.8.2", seal(none(), &rfc8439, 0));
    t.put("aead-open-gcm-tc16", open_call(none(), &tc16, 0));
    t.put(
        "aead-lengths-over-cap",
        open_call(seal(none(), &rfc8439, 2), &tc16, 3),
    );
    t.put(
        "ecdsa-rfc6979-sample",
        none()
            .u8(5)
            .bool(false)
            .array(&hex_field(sample, "public_key"))
            .buf(false, &hex_field(sample, "msg"))
            .bool(false)
            .array(&hex_field(sample, "sig")),
    );
    t.put(
        "null-pointers",
        none()
            .u8(0)
            .buf(false, b"k")
            .buf(true, b"")
            .bool(true)
            .u8(3)
            .i32(99)
            .buf(false, &tc16.key)
            .buf(false, &tc16.nonce)
            .buf(false, b"")
            .buf(false, &[1])
            .len(0)
            .bool(true)
            .bool(false)
            .u8(1)
            .buf(false, b"k")
            .buf(false, b"m")
            .buf(true, b""),
    );
    t.put(
        "kem-chain",
        none()
            .u8(6)
            .bool(false)
            .bool(false)
            .u8(7)
            .bool(false)
            .bool(true)
            .bytes(b"")
            .bool(false)
            .bool(false)
            .u8(8)
            .bool(false)
            .bool(true)
            .bytes(b"")
            .bool(false)
            .bool(true)
            .bytes(b"")
            .bool(false),
    );
    let mut paths = none();
    for choice in 0..6 {
        paths = paths.u8(9).u8(choice).u8(0).bool(false);
    }
    t.put("audit-verify-paths", paths);
    let mut meta = none();
    for value in [0, 12, 13, -1, i32::MIN, i32::MAX] {
        meta = meta.u8(10).i32(value);
    }
    t.put("metadata", meta);
    let open_op = |e: Enc, op: u8, c: &Cfg| e.u8(op).bool(false).bool(false).config(c);
    let mut opens = none();
    for c in [
        Cfg {
            backend: 0,
            ..Cfg::software()
        },
        Cfg {
            backend: 2,
            ..Cfg::software()
        },
        pkcs11.clone(),
        Cfg {
            flags: 7,
            backend: 2,
            token_label: b"a-token-label-longer-than-32-bytes",
            pin: b"0000",
            ..Cfg::software()
        },
        Cfg {
            audit: 2,
            ..Cfg::software()
        },
        Cfg {
            audit: 3,
            ..Cfg::software()
        },
        Cfg {
            audit: 4,
            ..Cfg::software()
        },
        Cfg {
            audit: 5,
            ..Cfg::software()
        },
        Cfg {
            count: 1,
            ..Cfg::software()
        },
        Cfg {
            count: 255,
            source: 1,
            ..Cfg::software()
        },
        raw_approvers.clone(),
        Cfg::dual(&[1, 1]),
        Cfg::dual(&[0, 1, 2, 3]),
    ] {
        opens = open_op(open_op(opens, 11, &c), 12, &c);
    }
    t.put("open-configurations", opens);

    let v1 = Enc::default().u8(1).config(&Cfg::software());
    t.put(
        "store-lifecycle",
        v1.u8(14)
            .bool(false)
            .i32(2)
            .label(b"mac")
            .bool(false)
            .u8(19)
            .bool(false)
            .known(0)
            .buf(false, b"message")
            .bool(false)
            .u8(20)
            .bool(false)
            .known(0)
            .buf(false, b"message")
            .buf(false, &[0; 32])
            .u8(14)
            .bool(false)
            .i32(1)
            .label(b"kek")
            .bool(false)
            .u8(21)
            .bool(false)
            .known(1)
            .known(0)
            .bool(false)
            .u8(22)
            .bool(false)
            .known(1)
            .bool(true)
            .buf(false, b"")
            .i32(2)
            .label(b"unwrapped")
            .raw_id(&id)
            .u8(14)
            .bool(false)
            .i32(3)
            .label(b"signer")
            .bool(false)
            .u8(18)
            .bool(false)
            .known(3)
            .buf(false, b"message")
            .bool(false)
            .u8(17)
            .bool(false)
            .known(3)
            .bool(false)
            .u8(24)
            .bool(false)
            .known(0)
            .bool(false)
            .u8(25)
            .bool(false)
            .known(1)
            .u8(15)
            .bool(false)
            .known(0)
            .bool(false)
            .u8(16)
            .bool(false)
            .known(1)
            .bool(false)
            .u8(23)
            .bool(false)
            .known(2)
            .u8(13)
            .bool(false)
            .bool(false)
            .u16(64)
            .u8(23)
            .bool(false)
            .null_id(),
    );
    let v2 = Enc::default().u8(2).config(&Cfg::dual(&[0, 1]));
    let approve = |e: Enc, approver: u8| {
        e.u8(27)
            .bool(false)
            .bool(false)
            .array(&[0; 32])
            .bool(true)
            .bool(false)
            .array(&[0; 65])
            .bool(true)
            .u8(approver)
            .bool(false)
            .array(&[0; 64])
            .bool(true)
            .u8(approver)
            .bool(false)
    };
    let dual_seq = v2
        .u8(14)
        .bool(false)
        .i32(2)
        .label(b"doomed")
        .bool(false)
        .u8(23)
        .bool(false)
        .known(0)
        .u8(26)
        .bool(false)
        .known(0)
        .bool(false);
    let dual_seq = approve(approve(approve(dual_seq, 0), 0), 1)
        .u8(28)
        .bool(false)
        .bool(false)
        .bool(false)
        .u8(9)
        .u8(1)
        .u8(2)
        .bool(false)
        .u8(12)
        .bool(false)
        .bool(false)
        .config(&Cfg::audited());
    t.put("store-audit-dual-control", dual_seq);
    let mut handle_null = Enc::default().u8(2).config(&Cfg::audited());
    for op in 13..=28 {
        handle_null = handle_null.u8(op).bool(true);
        handle_null = match op {
            13 => handle_null.bool(false).u16(16),
            14 => handle_null.i32(1).label(b"x").bool(false),
            15..=17 | 24 | 26 => handle_null.known(0).bool(false),
            18 | 19 => handle_null.known(0).buf(false, b"m").bool(false),
            20 => handle_null.known(0).buf(false, b"m").buf(false, &[0; 32]),
            21 => handle_null.known(0).known(0).bool(false),
            22 => handle_null
                .known(0)
                .bool(false)
                .buf(false, &[0; 40])
                .i32(1)
                .label(b"x")
                .raw_id(&id),
            23 | 25 => handle_null.known(0),
            27 => approve(Enc::default(), 0).0[2..]
                .iter()
                .fold(handle_null, |e, &b| e.u8(b)),
            _ => handle_null.bool(false).bool(false),
        };
    }
    t.put("handle-null", handle_null);
    total += t.written;

    println!("wrote {total} seeds to each of the two corpora");
}
