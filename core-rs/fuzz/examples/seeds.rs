//! Regenerates the seed corpora of both fuzzing setups from the published test vectors.
//!
//! ```text
//! cargo run --manifest-path core-rs/fuzz/Cargo.toml --example seeds
//! ```
//!
//! Writes `core-rs/fuzz/corpus/<target>/<seed>` (the byte layout `arbitrary` decodes into the
//! input structs of `src/lib.rs`) and `core-cpp/fuzz/corpus/<target>/<seed>` (the length-prefixed
//! layout read by `core-cpp/fuzz/fuzz_input.hpp`). The values come from the RFC and spec vector
//! files under `conformance/vectors/`, plus RFC 3394 §4.6 for the unwrap target. Each Rust seed
//! is decoded again with `arbitrary` and compared with the value it was built from, so a change
//! in `arbitrary`'s format makes this program fail instead of writing seeds that mean nothing.
//!
//! Existing files with the same names are overwritten; other files in the corpus directories
//! (inputs libFuzzer saved during a run) are left alone.

use std::fs;
use std::path::{Path, PathBuf};

use arbitrary::{Arbitrary, Unstructured};
use ekicore_rs_fuzz::{AeadOpenInput, HkdfInput, InBuf, StatelessCall, UnwrapInput};
use serde_json::Value;

/// RFC 3394 §4.6: 256 bits of key data wrapped under a 256-bit KEK.
const RFC3394_4_6_WRAPPED: &str =
    "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21";

// ---------------------------------------------------------------------------------------------
// Encoders
// ---------------------------------------------------------------------------------------------

/// Builds input bytes in the layout `arbitrary` 1.x decodes (`Arbitrary::arbitrary_take_rest`).
#[derive(Default)]
struct ArbEnc(Vec<u8>);

impl ArbEnc {
    fn i32(&mut self, v: i32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn bool(&mut self, v: bool) -> &mut Self {
        self.0.push(u8::from(v));
        self
    }
    fn array(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    /// A byte array that is the last field: `arbitrary` reads the whole array, then reads its
    /// last element a second time from whatever follows, so that byte is written twice.
    fn array_last(&mut self, v: &[u8]) -> &mut Self {
        self.array(v);
        if let Some(&b) = v.last() {
            self.0.push(b);
        }
        self
    }
    /// A `Vec<u8>`: each element is preceded by a "continue" byte, and a 0 byte ends the list.
    /// The last field of a struct ends at the end of the input instead.
    fn vec(&mut self, v: &[u8], last: bool) -> &mut Self {
        for &b in v {
            self.0.extend_from_slice(&[1, b]);
        }
        if !last {
            self.0.push(0);
        }
        self
    }
    /// `Unstructured::int_in_range(0..=9000)`: two big-endian bytes, reduced modulo 9001.
    fn okm_len(&mut self, v: usize) -> &mut Self {
        let v = u16::try_from(v).expect("okm_len fits in u16");
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// Enum variant `index` of `count`: a u32 `x` with `(x * count) >> 32 == index`.
    fn variant(&mut self, index: u64, count: u64) -> &mut Self {
        let x = u32::try_from((index << 32).div_ceil(count)).expect("variant fits");
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }
    fn in_buf(&mut self, b: &InBuf, last: bool) -> &mut Self {
        self.bool(b.null).vec(&b.data, last)
    }
}

/// Builds input bytes in the layout of `core-cpp/fuzz/fuzz_input.hpp`: integers little-endian,
/// fixed arrays as they are, byte strings as a 2-byte little-endian length and the bytes.
#[derive(Default)]
struct LpEnc(Vec<u8>);

impl LpEnc {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn i32(&mut self, v: i32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u16(&mut self, v: usize) -> &mut Self {
        let v = u16::try_from(v).expect("value fits in u16");
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }
    fn array(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u16(v.len()).array(v)
    }
    fn in_buf(&mut self, b: &InBuf) -> &mut Self {
        self.bool(b.null).bytes(&b.data)
    }
}

fn rust_aead_open(i: &AeadOpenInput) -> Vec<u8> {
    let mut e = ArbEnc::default();
    e.i32(i.alg)
        .vec(&i.key, false)
        .vec(&i.nonce, false)
        .vec(&i.aad, false);
    e.vec(&i.ct, false).array_last(&i.tag);
    e.0
}

fn cpp_aead_open(i: &AeadOpenInput) -> Vec<u8> {
    let mut e = LpEnc::default();
    e.i32(i.alg)
        .bytes(&i.key)
        .bytes(&i.nonce)
        .bytes(&i.aad)
        .bytes(&i.ct)
        .array(&i.tag);
    e.0
}

fn rust_hkdf(i: &HkdfInput) -> Vec<u8> {
    let mut e = ArbEnc::default();
    e.vec(&i.ikm, false)
        .vec(&i.salt, false)
        .vec(&i.info, false)
        .okm_len(i.okm_len);
    e.0
}

const STATELESS_VARIANTS: u64 = 6;

fn rust_stateless(c: &StatelessCall) -> Vec<u8> {
    let mut e = ArbEnc::default();
    match c {
        StatelessCall::Hmac { key, msg, out_null } => {
            e.variant(0, STATELESS_VARIANTS)
                .in_buf(key, false)
                .in_buf(msg, false);
            e.bool(*out_null);
        }
        StatelessCall::HmacVerify { key, msg, tag } => {
            e.variant(1, STATELESS_VARIANTS)
                .in_buf(key, false)
                .in_buf(msg, false);
            e.in_buf(tag, true);
        }
        StatelessCall::Hkdf {
            ikm,
            salt,
            info,
            okm_null,
            okm_len,
        } => {
            e.variant(2, STATELESS_VARIANTS)
                .in_buf(ikm, false)
                .in_buf(salt, false);
            e.in_buf(info, false).bool(*okm_null).okm_len(*okm_len);
        }
        StatelessCall::AeadSeal {
            alg,
            key,
            nonce,
            aad,
            pt,
            ct_out_null,
            tag_out_null,
        } => {
            e.variant(3, STATELESS_VARIANTS)
                .i32(*alg)
                .in_buf(key, false);
            e.in_buf(nonce, false).in_buf(aad, false).in_buf(pt, false);
            e.bool(*ct_out_null).bool(*tag_out_null);
        }
        StatelessCall::AeadOpen {
            alg,
            key,
            nonce,
            aad,
            ct,
            tag_null,
            tag,
            pt_out_null,
        } => {
            e.variant(4, STATELESS_VARIANTS)
                .i32(*alg)
                .in_buf(key, false);
            e.in_buf(nonce, false).in_buf(aad, false).in_buf(ct, false);
            e.bool(*tag_null).array(tag).bool(*pt_out_null);
        }
        StatelessCall::EcdsaVerify {
            public_key_null,
            public_key,
            msg,
            sig_null,
            sig,
        } => {
            e.variant(5, STATELESS_VARIANTS)
                .bool(*public_key_null)
                .array(public_key);
            e.in_buf(msg, false).bool(*sig_null).array_last(sig);
        }
    }
    e.0
}

/// The C++ target picks the function from the first byte modulo 6, in the order of
/// `StatelessCall`, and reads the same fields in the same order.
fn cpp_stateless(c: &StatelessCall) -> Vec<u8> {
    let mut e = LpEnc::default();
    match c {
        StatelessCall::Hmac { key, msg, out_null } => {
            e.u8(0).in_buf(key).in_buf(msg).bool(*out_null);
        }
        StatelessCall::HmacVerify { key, msg, tag } => {
            e.u8(1).in_buf(key).in_buf(msg).in_buf(tag);
        }
        StatelessCall::Hkdf {
            ikm,
            salt,
            info,
            okm_null,
            okm_len,
        } => {
            e.u8(2)
                .in_buf(ikm)
                .in_buf(salt)
                .in_buf(info)
                .bool(*okm_null)
                .u16(*okm_len);
        }
        StatelessCall::AeadSeal {
            alg,
            key,
            nonce,
            aad,
            pt,
            ct_out_null,
            tag_out_null,
        } => {
            e.u8(3)
                .i32(*alg)
                .in_buf(key)
                .in_buf(nonce)
                .in_buf(aad)
                .in_buf(pt);
            e.bool(*ct_out_null).bool(*tag_out_null);
        }
        StatelessCall::AeadOpen {
            alg,
            key,
            nonce,
            aad,
            ct,
            tag_null,
            tag,
            pt_out_null,
        } => {
            e.u8(4)
                .i32(*alg)
                .in_buf(key)
                .in_buf(nonce)
                .in_buf(aad)
                .in_buf(ct);
            e.bool(*tag_null).array(tag).bool(*pt_out_null);
        }
        StatelessCall::EcdsaVerify {
            public_key_null,
            public_key,
            msg,
            sig_null,
            sig,
        } => {
            e.u8(5).bool(*public_key_null).array(public_key).in_buf(msg);
            e.bool(*sig_null).array(sig);
        }
    }
    e.0
}

fn rust_unwrap(i: &UnwrapInput) -> Vec<u8> {
    let mut e = ArbEnc::default();
    e.bool(i.from_wrap)
        .vec(&i.blob, false)
        .i32(i.alg)
        .array(&i.id)
        .vec(&i.label, true);
    e.0
}

fn cpp_unwrap(i: &UnwrapInput) -> Vec<u8> {
    let mut e = LpEnc::default();
    e.bool(i.from_wrap)
        .bytes(&i.blob)
        .i32(i.alg)
        .array(&i.id)
        .bytes(&i.label);
    e.0
}

// ---------------------------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cases(file: &str) -> Vec<Value> {
    let path = repo_root().join("conformance/vectors").join(file);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text).expect("vector file is JSON");
    doc["cases"]
        .as_array()
        .expect("vector file has a cases array")
        .clone()
}

fn hex_field(case: &Value, field: &str) -> Vec<u8> {
    let text = case[field]
        .as_str()
        .unwrap_or_else(|| panic!("case has no string {field}"));
    hex::decode(text).expect("field is hex")
}

fn fixed<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes
        .try_into()
        .expect("fixed-size field has the expected length")
}

fn named<'a>(cases: &'a [Value], name: &str) -> &'a Value {
    cases
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case named {name}"))
}

fn buf(data: &[u8]) -> InBuf {
    InBuf {
        null: false,
        data: data.to_vec(),
    }
}

fn null_buf(data: &[u8]) -> InBuf {
    InBuf {
        null: true,
        data: data.to_vec(),
    }
}

fn aead_case(case: &Value, alg: i32) -> AeadOpenInput {
    AeadOpenInput {
        alg,
        key: hex_field(case, "key"),
        nonce: hex_field(case, "nonce"),
        aad: hex_field(case, "aad"),
        ct: hex_field(case, "ct"),
        tag: fixed(&hex_field(case, "tag")),
    }
}

// ---------------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------------

struct Writer {
    written: usize,
}

impl Writer {
    fn put(&mut self, dir: &Path, name: &str, bytes: &[u8]) {
        fs::create_dir_all(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        self.written += 1;
    }

    /// Writes one seed for the Rust target `rust` and the C++ target `cpp` (if any), after
    /// checking that the Rust bytes decode back to `value`.
    fn seed<T>(
        &mut self,
        rust: &str,
        cpp: Option<&str>,
        name: &str,
        value: &T,
        encode_rust: fn(&T) -> Vec<u8>,
        encode_cpp: fn(&T) -> Vec<u8>,
    ) where
        T: for<'a> Arbitrary<'a> + PartialEq + std::fmt::Debug,
    {
        let bytes = encode_rust(value);
        let decoded = T::arbitrary_take_rest(Unstructured::new(&bytes))
            .unwrap_or_else(|e| panic!("{rust}/{name}: seed does not decode: {e}"));
        assert_eq!(
            &decoded, value,
            "{rust}/{name}: seed decodes to a different value"
        );
        let root = repo_root();
        self.put(&root.join("core-rs/fuzz/corpus").join(rust), name, &bytes);
        if let Some(cpp) = cpp {
            self.put(
                &root.join("core-cpp/fuzz/corpus").join(cpp),
                name,
                &encode_cpp(value),
            );
        }
    }
}

fn no_cpp<T>(_: &T) -> Vec<u8> {
    Vec::new()
}

fn main() {
    let chacha = cases("aead_chacha20poly1305_rfc8439.json");
    let gcm = cases("aead_aes256gcm_spec.json");
    let hkdf = cases("hkdf_sha256_rfc5869.json");
    let hmac = cases("hmac_sha256_rfc4231.json");
    let ecdsa = cases("ecdsa_p256_rfc6979.json");
    let mut w = Writer { written: 0 };

    // aead_open: published vectors (open succeeds once AEAD is real), plus a flipped tag.
    let rfc8439 = aead_case(named(&chacha, "RFC 8439 2.8.2"), 2);
    let tc16 = aead_case(named(&gcm, "GCM spec Test Case 16"), 1);
    let aead_seeds = [
        ("rfc8439-2.8.2", rfc8439.clone()),
        ("rfc8439-a.5", aead_case(named(&chacha, "RFC 8439 A.5"), 2)),
        (
            "gcm-tc13",
            aead_case(named(&gcm, "GCM spec Test Case 13"), 1),
        ),
        (
            "gcm-tc14",
            aead_case(named(&gcm, "GCM spec Test Case 14"), 1),
        ),
        (
            "gcm-tc15",
            aead_case(named(&gcm, "GCM spec Test Case 15"), 1),
        ),
        ("gcm-tc16", tc16.clone()),
        (
            "rfc8439-2.8.2-bad-tag",
            AeadOpenInput {
                tag: flip(rfc8439.tag),
                ..rfc8439.clone()
            },
        ),
        (
            "gcm-tc16-bad-tag",
            AeadOpenInput {
                tag: flip(tc16.tag),
                ..tc16.clone()
            },
        ),
    ];
    for (name, input) in &aead_seeds {
        w.seed(
            "aead_open",
            Some("fuzz_aead_open"),
            name,
            input,
            rust_aead_open,
            cpp_aead_open,
        );
    }

    // hkdf: RFC 5869 A.1-A.3 at their own lengths, plus A.1's inputs at and past the cap.
    let rfc5869 = [
        ("rfc5869-a.1", "RFC 5869 A.1"),
        ("rfc5869-a.2", "RFC 5869 A.2"),
        ("rfc5869-a.3", "RFC 5869 A.3"),
    ];
    for (name, case) in rfc5869 {
        let c = named(&hkdf, case);
        let input = HkdfInput {
            ikm: hex_field(c, "ikm"),
            salt: hex_field(c, "salt"),
            info: hex_field(c, "info"),
            okm_len: usize::try_from(c["length"].as_u64().expect("length")).expect("fits"),
        };
        w.seed("hkdf", None, name, &input, rust_hkdf, no_cpp);
    }
    let a1 = named(&hkdf, "RFC 5869 A.1");
    for (name, okm_len) in [
        ("rfc5869-a.1-okm-8160", 8160),
        ("rfc5869-a.1-okm-8161", 8161),
    ] {
        let input = HkdfInput {
            ikm: hex_field(a1, "ikm"),
            salt: hex_field(a1, "salt"),
            info: hex_field(a1, "info"),
            okm_len,
        };
        w.seed("hkdf", None, name, &input, rust_hkdf, no_cpp);
    }

    // ffi_status: one published vector per function, plus NULL-pointer shapes from the matrix.
    let tc1 = named(&hmac, "RFC 4231 4.2 (Test Case 1)");
    let tc2 = named(&hmac, "RFC 4231 4.3 (Test Case 2)");
    let sample = &ecdsa[0];
    let calls = [
        (
            "hmac-rfc4231-tc1",
            StatelessCall::Hmac {
                key: buf(&hex_field(tc1, "key")),
                msg: buf(&hex_field(tc1, "data")),
                out_null: false,
            },
        ),
        (
            "hmac-msg-null-len-0",
            StatelessCall::Hmac {
                key: buf(&hex_field(tc2, "key")),
                msg: null_buf(&[]),
                out_null: false,
            },
        ),
        (
            "hmac-verify-rfc4231-tc2",
            StatelessCall::HmacVerify {
                key: buf(&hex_field(tc2, "key")),
                msg: buf(&hex_field(tc2, "data")),
                tag: buf(&hex_field(tc2, "mac")),
            },
        ),
        (
            "hkdf-rfc5869-a.1",
            StatelessCall::Hkdf {
                ikm: buf(&hex_field(a1, "ikm")),
                salt: buf(&hex_field(a1, "salt")),
                info: buf(&hex_field(a1, "info")),
                okm_null: false,
                okm_len: 42,
            },
        ),
        (
            "aead-seal-rfc8439-2.8.2",
            StatelessCall::AeadSeal {
                alg: 2,
                key: buf(&rfc8439.key),
                nonce: buf(&rfc8439.nonce),
                aad: buf(&rfc8439.aad),
                pt: buf(&hex_field(named(&chacha, "RFC 8439 2.8.2"), "pt")),
                ct_out_null: false,
                tag_out_null: false,
            },
        ),
        (
            "aead-seal-ct-out-null-alg-99",
            StatelessCall::AeadSeal {
                alg: 99,
                key: buf(&tc16.key),
                nonce: buf(&tc16.nonce),
                aad: buf(&[]),
                pt: buf(&[0x01]),
                ct_out_null: true,
                tag_out_null: false,
            },
        ),
        (
            "aead-open-gcm-tc16",
            StatelessCall::AeadOpen {
                alg: 1,
                key: buf(&tc16.key),
                nonce: buf(&tc16.nonce),
                aad: buf(&tc16.aad),
                ct: buf(&tc16.ct),
                tag_null: false,
                tag: tc16.tag,
                pt_out_null: false,
            },
        ),
        (
            "ecdsa-rfc6979-sample",
            StatelessCall::EcdsaVerify {
                public_key_null: false,
                public_key: fixed(&hex_field(sample, "public_key")),
                msg: buf(&hex_field(sample, "msg")),
                sig_null: false,
                sig: fixed(&hex_field(sample, "sig")),
            },
        ),
    ];
    for (name, call) in &calls {
        w.seed(
            "ffi_status",
            Some("fuzz_ffi_status"),
            name,
            call,
            rust_stateless,
            cpp_stateless,
        );
    }

    // unwrap_blob: a real wrap (succeeds once the store is real), a tampered one, and shapes
    // from the error matrix.
    let id: [u8; 16] = *b"ekibridge-fuzz-1";
    let label = b"fuzz-unwrapped".to_vec();
    let base = UnwrapInput {
        from_wrap: true,
        blob: Vec::new(),
        alg: 2,
        id,
        label,
    };
    let rfc3394 = hex::decode(RFC3394_4_6_WRAPPED).expect("hex");
    let unwraps = [
        ("wrapped-hmac-key", base.clone()),
        (
            "wrapped-hmac-key-as-aes",
            UnwrapInput {
                alg: 1,
                ..base.clone()
            },
        ),
        (
            "wrapped-hmac-key-byte-flipped",
            UnwrapInput {
                blob: vec![0, 0, 0, 0x80],
                ..base.clone()
            },
        ),
        (
            "rfc3394-4.6",
            UnwrapInput {
                from_wrap: false,
                blob: rfc3394.clone(),
                ..base.clone()
            },
        ),
        (
            "rfc3394-4.6-short",
            UnwrapInput {
                from_wrap: false,
                blob: rfc3394[..39].to_vec(),
                ..base.clone()
            },
        ),
        (
            "alg-ecdsa",
            UnwrapInput {
                alg: 3,
                ..base.clone()
            },
        ),
        (
            "label-65-bytes",
            UnwrapInput {
                label: vec![b'x'; 65],
                ..base.clone()
            },
        ),
        (
            "label-control-byte",
            UnwrapInput {
                label: b"bad\x01label".to_vec(),
                ..base.clone()
            },
        ),
    ];
    for (name, input) in &unwraps {
        w.seed(
            "unwrap_blob",
            Some("fuzz_ks_unwrap"),
            name,
            input,
            rust_unwrap,
            cpp_unwrap,
        );
    }

    println!("wrote {} seed files", w.written);
}

fn flip(mut tag: [u8; 16]) -> [u8; 16] {
    tag[0] ^= 0x01;
    tag
}
