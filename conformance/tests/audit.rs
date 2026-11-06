//! The audit log (ABI 2 contract §5, §7, §8) on the software backend of both libraries: the
//! byte-exact record format, what is logged, `eki_ks_audit_head`, `eki_audit_verify`, a log
//! written by one library verified and continued by the other, tampering, and the
//! `eki_ks_open_v2` rows that need a file.
//!
//! The harness parses every record and checks its shape, its fields and the chaining of `prev`
//! to the previous `hash` as text. It does not recompute SHA-256 itself (the conformance crate has
//! no hash dependency): that a hash is right is shown by the other library's `eki_audit_verify`
//! accepting the chain with the writer's head as `expected_head`.

mod common;

use std::ffi::CString;
use std::path::{Path, PathBuf};

use common::ks::{self, Flow, run};
use common::lifecycle::{Approvers, audit_head, open_v2};
use common::{Report, cstr, unique_label};
use ekicore_conformance::sel::{KEY_AES_256 as AES, KEY_ECDSA_P256 as EC, KEY_HMAC_SHA256 as HMAC};
use ekicore_conformance::status::*;
use ekicore_conformance::{
    In, KsConfig, KsConfigV2, Lib, PREFILL_U32, PREFILL_U64, Store, eki_key_id, prefill_array,
    prefill_key_id, prefill_key_info, prefill_key_info_v2,
};

/// Every `op` value of §5.
const OPS: [&str; 14] = [
    "open",
    "close",
    "generate",
    "unwrap",
    "rotate",
    "revoke",
    "destroy",
    "destroy_request",
    "destroy_approve",
    "sign",
    "hmac",
    "hmac_verify",
    "wrap",
    "get_public_key",
];

/// The `prev` of the first record.
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------------------------

/// A directory of its own under the system temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ekibridge-audit-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("harness: cannot create {}: {e}", dir.display()));
        TempDir(dir)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_encoded_bytes().to_vec()).expect("path contains a NUL")
}

fn read(path: &Path) -> Flow<Vec<u8>> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes)
        .unwrap_or_else(|e| panic!("harness: cannot write {}: {e}", path.display()));
}

/// `eki_audit_verify(path, expected_head)`: the status and `records_out`.
fn verify(lib: &Lib, path: &Path, expected_head: Option<&[u8; 32]>) -> (i32, u64) {
    let mut records = PREFILL_U64;
    let s = lib.audit_verify(
        Some(c_path(path).as_c_str()),
        expected_head,
        Some(&mut records),
    );
    (s, records)
}

/// Checks a verification that must fail with `want`: the status, and `records_out` zero-filled.
fn verify_fails(
    r: &mut Report,
    lib: &Lib,
    row: &str,
    path: &Path,
    head: Option<&[u8; 32]>,
    want: i32,
) {
    let (s, records) = verify(lib, path, head);
    if r.status(lib, row, s, want) {
        r.check(records == 0, || {
            format!("{}: {row}: records_out = {records:#x}", lib.name())
        });
    }
}

/// Checks a verification that must succeed with `n` records.
fn verify_ok(r: &mut Report, lib: &Lib, row: &str, path: &Path, head: Option<&[u8; 32]>, n: u64) {
    let (s, records) = verify(lib, path, head);
    if r.status(lib, row, s, EKI_OK) {
        r.check(records == n, || {
            format!("{}: {row}: records_out = {records}, want {n}", lib.name())
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------------------------

/// One parsed record.
#[derive(Clone, Debug)]
struct Record {
    seq: u64,
    time: String,
    op: String,
    key: String,
    key2: String,
    status: i32,
    prev: String,
    hash: String,
}

impl Record {
    /// The raw 32 bytes of `hash`.
    fn hash_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(&self.hash, &mut out).expect("parse_record checked the hex");
        out
    }
}

/// What the harness expects of one record.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Expected {
    op: &'static str,
    key: String,
    key2: String,
    status: i32,
}

fn hex_id(id: &eki_key_id) -> String {
    hex::encode(id.bytes)
}

fn rec(
    op: &'static str,
    key: Option<&eki_key_id>,
    key2: Option<&eki_key_id>,
    status: i32,
) -> Expected {
    Expected {
        op,
        key: key.map(hex_id).unwrap_or_default(),
        key2: key2.map(hex_id).unwrap_or_default(),
        status,
    }
}

fn take(rest: &mut &str, literal: &str) -> Result<(), String> {
    match rest.strip_prefix(literal) {
        Some(tail) => {
            *rest = tail;
            Ok(())
        }
        None => Err(format!("expected {literal:?} at {:?}", short(rest))),
    }
}

fn short(s: &str) -> &str {
    &s[..s.len().min(40)]
}

/// The text up to the next `"`, which is consumed.
fn quoted<'a>(rest: &mut &'a str) -> Result<&'a str, String> {
    let end = rest
        .find('"')
        .ok_or_else(|| format!("unterminated string at {:?}", short(rest)))?;
    let value = &rest[..end];
    *rest = &rest[end + 1..];
    Ok(value)
}

/// A decimal number without sign or leading zeros.
fn decimal(rest: &mut &str) -> Result<u64, String> {
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let digits = &rest[..end];
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(format!("not a canonical decimal at {:?}", short(rest)));
    }
    let value = digits
        .parse()
        .map_err(|e| format!("decimal {digits:?}: {e}"))?;
    *rest = &rest[end..];
    Ok(value)
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `YYYY-MM-DDTHH:MM:SSZ` with plausible ranges.
fn is_time(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let num = |r: std::ops::Range<usize>| s[r].parse::<u32>().unwrap_or(99);
    b.len() == 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && b[19] == b'Z'
        && (1..=12).contains(&num(5..7))
        && (1..=31).contains(&num(8..10))
        && num(11..13) < 24
        && num(14..16) < 60
        && num(17..19) < 61
}

/// Seconds since the Unix epoch of a `time` value that passed `is_time` (days from the civil
/// date, proleptic Gregorian calendar).
fn epoch_seconds(time: &str) -> i64 {
    let num = |r: std::ops::Range<usize>| time[r].parse::<i64>().unwrap_or(0);
    let (y, m, d) = (num(0..4), num(5..7), num(8..10));
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + num(11..13) * 3600 + num(14..16) * 60 + num(17..19)
}

/// Seconds since the Unix epoch, now.
fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Parses one line (without its `\n`) with the exact shape of §5.
fn parse_record(line: &str) -> Result<Record, String> {
    let mut rest = line;
    take(&mut rest, "{\"seq\":")?;
    let seq = decimal(&mut rest)?;
    take(&mut rest, ",\"time\":\"")?;
    let time = quoted(&mut rest)?.to_owned();
    take(&mut rest, ",\"op\":\"")?;
    let op = quoted(&mut rest)?.to_owned();
    take(&mut rest, ",\"key\":\"")?;
    let key = quoted(&mut rest)?.to_owned();
    take(&mut rest, ",\"key2\":\"")?;
    let key2 = quoted(&mut rest)?.to_owned();
    take(&mut rest, ",\"status\":")?;
    let status = i32::try_from(decimal(&mut rest)?).map_err(|e| format!("status: {e}"))?;
    take(&mut rest, ",\"prev\":\"")?;
    let prev = quoted(&mut rest)?.to_owned();
    take(&mut rest, ",\"hash\":\"")?;
    let hash = quoted(&mut rest)?.to_owned();
    take(&mut rest, "}")?;
    if !rest.is_empty() {
        return Err(format!("trailing text {:?}", short(rest)));
    }
    if !is_time(&time) {
        return Err(format!("time {time:?} is not YYYY-MM-DDTHH:MM:SSZ"));
    }
    if !OPS.contains(&op.as_str()) {
        return Err(format!("op {op:?} is not one of §5"));
    }
    for (name, value) in [("key", &key), ("key2", &key2)] {
        if !(value.is_empty() || is_lower_hex(value, 32)) {
            return Err(format!(
                "{name} {value:?} is neither empty nor 32 lowercase hex"
            ));
        }
    }
    for (name, value) in [("prev", &prev), ("hash", &hash)] {
        if !is_lower_hex(value, 64) {
            return Err(format!("{name} {value:?} is not 64 lowercase hex"));
        }
    }
    Ok(Record {
        seq,
        time,
        op,
        key,
        key2,
        status,
        prev,
        hash,
    })
}

/// Parses a whole log and checks what the harness can check without SHA-256: every line has the
/// shape of §5 and at most 512 bytes, `seq` runs from 1, `prev` is the previous `hash` (64 zeros
/// first), and the file ends with `\n`.
fn parse_log(bytes: &[u8]) -> Result<Vec<Record>, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))?;
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let body = text
        .strip_suffix('\n')
        .ok_or("the log does not end with \\n")?;
    let mut records: Vec<Record> = Vec::new();
    for (i, line) in body.split('\n').enumerate() {
        if line.len() + 1 > 512 {
            return Err(format!(
                "line {} has {} bytes with its \\n",
                i + 1,
                line.len() + 1
            ));
        }
        let record = parse_record(line).map_err(|e| format!("line {}: {e}", i + 1))?;
        let want_seq = i as u64 + 1;
        if record.seq != want_seq {
            return Err(format!(
                "line {}: seq {}, want {want_seq}",
                i + 1,
                record.seq
            ));
        }
        let want_prev = records.last().map_or(ZERO_HASH, |p| p.hash.as_str());
        if record.prev != want_prev {
            return Err(format!(
                "line {}: prev does not equal the previous hash",
                i + 1
            ));
        }
        records.push(record);
    }
    Ok(records)
}

/// The records of the log at `path`, or a scenario stop.
fn records_of(lib: &Lib, path: &Path) -> Flow<Vec<Record>> {
    parse_log(&read(path)?).map_err(|e| format!("log written by {}: {e}", lib.name()))
}

/// Compares records with the expected ops, keys and statuses.
fn check_records(r: &mut Report, lib: &Lib, ctx: &str, got: &[Record], want: &[Expected]) {
    r.check(got.len() == want.len(), || {
        format!(
            "{}: {ctx}: {} records, want {}: {:?}",
            lib.name(),
            got.len(),
            want.len(),
            got.iter().map(|g| g.op.as_str()).collect::<Vec<_>>()
        )
    });
    for (g, w) in got.iter().zip(want) {
        let same = g.op == w.op && g.key == w.key && g.key2 == w.key2 && g.status == w.status;
        r.check(same, || {
            format!(
                "{}: {ctx}: record {}: op {:?} key {:?} key2 {:?} status {}, want {w:?}",
                lib.name(),
                g.seq,
                g.op,
                g.key,
                g.key2,
                g.status
            )
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Scripted logs
// ---------------------------------------------------------------------------------------------

/// A log written by one library: the records the harness expects, and the `(seq, hash)` pairs
/// `eki_ks_audit_head` reported along the way.
struct Script {
    expected: Vec<Expected>,
    heads: Vec<(u64, [u8; 32])>,
}

/// Runs one call that must be logged with `want` as record `expected.len() + 1`: the call's
/// status is checked against `want.status`, then `eki_ks_audit_head` must report the new seq.
fn logged(
    r: &mut Report,
    st: &Store,
    script: &mut Script,
    want: Expected,
    status: i32,
) -> Flow<()> {
    let lib = st.lib();
    r.status(lib, &format!("scripted {}", want.op), status, want.status);
    script.expected.push(want);
    let (hash, seq) = audit_head(st)?;
    let n = script.expected.len() as u64;
    r.check(seq == n, || {
        format!(
            "{}: audit_head after {} reports seq {seq}, want {n}",
            lib.name(),
            script.expected.last().map_or("?", |e| e.op)
        )
    });
    script.heads.push((seq, hash));
    Ok(())
}

/// A call that must not be logged: `eki_ks_audit_head` still reports the previous seq.
fn not_logged(r: &mut Report, st: &Store, script: &Script, what: &str) -> Flow<()> {
    let (_, seq) = audit_head(st)?;
    let n = script.expected.len() as u64;
    r.check(seq == n, || {
        format!(
            "{}: {what} was logged (audit_head seq {seq}, want {n})",
            st.lib().name()
        )
    });
    Ok(())
}

/// The full scripted sequence: every op of §5, failed calls, calls that are not logged, and dual
/// control with approvers held in `ap`. The handle is closed at the end.
fn write_full_log(r: &mut Report, lib: &Lib, ap: &Approvers, path: &Path) -> Flow<Script> {
    let cfg = KsConfigV2::software()
        .with_audit_log(path)
        .with_approvers(&ap.first(2));
    let st = open_v2(lib, &cfg)?;
    let mut script = Script {
        expected: Vec::new(),
        heads: Vec::new(),
    };
    logged(r, &st, &mut script, rec("open", None, None, EKI_OK), EKI_OK)?;
    let msg = b"audited message".to_vec();
    let missing = ks::fresh_id();

    let mut kek = prefill_key_id();
    let s = st.generate(AES, Some(&unique_label("audit-kek")), Some(&mut kek));
    logged(
        r,
        &st,
        &mut script,
        rec("generate", Some(&kek), None, EKI_OK),
        s,
    )?;
    let mut hk = prefill_key_id();
    let s = st.generate(HMAC, Some(&unique_label("audit-hmac")), Some(&mut hk));
    logged(
        r,
        &st,
        &mut script,
        rec("generate", Some(&hk), None, EKI_OK),
        s,
    )?;
    let mut ec = prefill_key_id();
    let s = st.generate(EC, Some(&unique_label("audit-ec")), Some(&mut ec));
    logged(
        r,
        &st,
        &mut script,
        rec("generate", Some(&ec), None, EKI_OK),
        s,
    )?;
    let s = st.generate(AES, Some(&cstr("")), Some(&mut prefill_key_id()));
    let want = rec("generate", None, None, EKI_ERR_INVALID_ARGUMENT);
    logged(r, &st, &mut script, want, s)?;

    let s = st.sign(Some(&ec), In::from(&msg), Some(&mut prefill_array()));
    logged(r, &st, &mut script, rec("sign", Some(&ec), None, EKI_OK), s)?;
    let s = st.sign(Some(&missing), In::from(&msg), Some(&mut prefill_array()));
    let want = rec("sign", Some(&missing), None, EKI_ERR_KEY_NOT_FOUND);
    logged(r, &st, &mut script, want, s)?;
    let s = st.sign(None, In::from(&msg), Some(&mut prefill_array()));
    r.status(lib, "scripted sign with id NULL", s, EKI_ERR_NULL_POINTER);
    not_logged(r, &st, &script, "a call that failed its NULL checks")?;

    let mut tag = prefill_array::<32>();
    let s = st.hmac_sha256(Some(&hk), In::from(&msg), Some(&mut tag));
    logged(r, &st, &mut script, rec("hmac", Some(&hk), None, EKI_OK), s)?;
    let s = st.hmac_sha256_verify(Some(&hk), In::from(&msg), In::from(&tag));
    logged(
        r,
        &st,
        &mut script,
        rec("hmac_verify", Some(&hk), None, EKI_OK),
        s,
    )?;
    let mut wrong = tag;
    wrong[31] ^= 0x80;
    let s = st.hmac_sha256_verify(Some(&hk), In::from(&msg), In::from(&wrong));
    let want = rec("hmac_verify", Some(&hk), None, EKI_ERR_AUTH_FAILED);
    logged(r, &st, &mut script, want, s)?;
    let s = st.get_public_key(Some(&ec), Some(&mut prefill_array()));
    logged(
        r,
        &st,
        &mut script,
        rec("get_public_key", Some(&ec), None, EKI_OK),
        s,
    )?;

    let mut blob = prefill_array::<40>();
    let s = st.wrap(Some(&kek), Some(&hk), Some(&mut blob));
    logged(
        r,
        &st,
        &mut script,
        rec("wrap", Some(&hk), Some(&kek), EKI_OK),
        s,
    )?;
    let unwrapped = ks::fresh_id();
    let label = unique_label("audit-unwrapped");
    let s = st.unwrap(
        Some(&kek),
        In::from(&blob),
        HMAC,
        Some(&label),
        Some(&unwrapped),
    );
    let want = rec("unwrap", Some(&unwrapped), Some(&kek), EKI_OK);
    logged(r, &st, &mut script, want, s)?;
    let mut rotated = prefill_key_id();
    let s = st.rotate(Some(&hk), Some(&mut rotated));
    logged(
        r,
        &st,
        &mut script,
        rec("rotate", Some(&hk), Some(&rotated), EKI_OK),
        s,
    )?;
    let s = st.rotate(Some(&hk), Some(&mut prefill_key_id()));
    let want = rec("rotate", Some(&hk), None, EKI_ERR_KEY_STATE);
    logged(r, &st, &mut script, want, s)?;
    let s = st.revoke(Some(&unwrapped));
    logged(
        r,
        &st,
        &mut script,
        rec("revoke", Some(&unwrapped), None, EKI_OK),
        s,
    )?;

    // Not logged: get_info, get_info_v2, last_error_message, audit_head.
    let s = st.get_info(Some(&kek), Some(&mut prefill_key_info()));
    r.status(lib, "scripted get_info", s, EKI_OK);
    let s = st.get_info_v2(Some(&kek), Some(&mut prefill_key_info_v2()));
    r.status(lib, "scripted get_info_v2", s, EKI_OK);
    let _ = st.last_error();
    let _ = audit_head(&st)?;
    not_logged(
        r,
        &st,
        &script,
        "get_info, get_info_v2, last_error_message or audit_head",
    )?;

    // Dual control.
    let s = st.destroy(Some(&ec));
    let want = rec("destroy", Some(&ec), None, EKI_ERR_APPROVAL_REQUIRED);
    logged(r, &st, &mut script, want, s)?;
    let mut request = prefill_array::<32>();
    let s = st.destroy_request(Some(&ec), Some(&mut request));
    logged(
        r,
        &st,
        &mut script,
        rec("destroy_request", Some(&ec), None, EKI_OK),
        s,
    )?;
    let sig0 = ap.sign(0, &request, &ec)?;
    let mut remaining = PREFILL_U32;
    let s = st.destroy_approve(
        Some(&request),
        Some(&ap.keys[0]),
        Some(&sig0),
        Some(&mut remaining),
    );
    let want = rec("destroy_approve", Some(&ec), None, EKI_OK);
    logged(r, &st, &mut script, want, s)?;
    let unknown = [0x33; 32];
    let s = st.destroy_approve(
        Some(&unknown),
        Some(&ap.keys[0]),
        Some(&sig0),
        Some(&mut remaining),
    );
    let want = rec("destroy_approve", None, None, EKI_ERR_KEY_NOT_FOUND);
    logged(r, &st, &mut script, want, s)?;
    let sig1 = ap.sign(1, &request, &ec)?;
    let s = st.destroy_approve(
        Some(&request),
        Some(&ap.keys[1]),
        Some(&sig1),
        Some(&mut remaining),
    );
    let want = rec("destroy_approve", Some(&ec), None, EKI_OK);
    logged(r, &st, &mut script, want, s)?;
    r.check(remaining == 0, || {
        format!(
            "{}: scripted second approval: remaining {remaining}",
            lib.name()
        )
    });

    drop(st);
    script.expected.push(rec("close", None, None, EKI_OK));
    Ok(script)
}

/// A short log: open, two generates, one HMAC, close (5 records). Returns its expected records.
fn write_short_log(lib: &Lib, path: &Path) -> Flow<Vec<Expected>> {
    let st = open_v2(lib, &KsConfigV2::software().with_audit_log(path))?;
    let kek = ks::generate(&st, AES, &unique_label("short-kek"))?;
    let hk = ks::generate(&st, HMAC, &unique_label("short-hmac"))?;
    ks::hmac(&st, &hk, b"short")?;
    drop(st);
    Ok(vec![
        rec("open", None, None, EKI_OK),
        rec("generate", Some(&kek), None, EKI_OK),
        rec("generate", Some(&hk), None, EKI_OK),
        rec("hmac", Some(&hk), None, EKI_OK),
        rec("close", None, None, EKI_OK),
    ])
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// The scripted log of each library is byte-exact (§5), records exactly the calls §5 names, and
/// is accepted by both libraries' `eki_audit_verify` with the same record count. Each head that
/// `eki_ks_audit_head` reported equals the hash of that record in the file, and the other library
/// accepts the log cut after that record with that head as `expected_head` (§8: A's head equals
/// what B computes). Approvals are signed by the other library.
#[test]
fn scripted_log_is_exact_and_verifies_in_both() {
    let Some((a, b)) = common::setup("audit::scripted_log_is_exact_and_verifies_in_both") else {
        return;
    };
    run("audit::scripted_log_is_exact_and_verifies_in_both", |r| {
        let dir = TempDir::new("scripted");
        for (x, y) in [(a, b), (b, a)] {
            let ap = Approvers::new(y, 2)?;
            let path = dir.file(&format!("{}.log", x.name()));
            let started = now_seconds();
            let script = write_full_log(r, x, &ap, &path)?;
            let finished = now_seconds();
            let records = records_of(x, &path)?;
            check_records(r, x, "scripted log", &records, &script.expected);
            for record in &records {
                let t = epoch_seconds(&record.time);
                r.check(started - 1 <= t && t <= finished + 1, || {
                    format!(
                        "{}: record {} has time {}, not the UTC time of the call",
                        x.name(),
                        record.seq,
                        record.time
                    )
                });
            }
            check_mode_0600(r, x, &path);
            let n = records.len() as u64;
            let last = records.last().map(Record::hash_bytes);
            for lib in [x, y] {
                verify_ok(
                    r,
                    lib,
                    &format!("verify the log of {}", x.name()),
                    &path,
                    None,
                    n,
                );
                verify_ok(
                    r,
                    lib,
                    &format!("verify the log of {} with its last hash", x.name()),
                    &path,
                    last.as_ref(),
                    n,
                );
            }
            let bytes = read(&path)?;
            for (seq, head) in &script.heads {
                let Some(record) = records.get(*seq as usize - 1) else {
                    continue;
                };
                r.check(record.hash_bytes() == *head, || {
                    format!(
                        "{}: audit_head at seq {seq} differs from the hash in the file",
                        x.name()
                    )
                });
                let cut = dir.file(&format!("{}-cut-{seq}.log", x.name()));
                write(&cut, &prefix_lines(&bytes, *seq as usize));
                verify_ok(
                    r,
                    y,
                    &format!("{}'s head at seq {seq} as expected_head", x.name()),
                    &cut,
                    Some(head),
                    *seq,
                );
            }
        }
        Ok(())
    });
}

/// §8: library x writes a log and closes it; y verifies it, opens the same file with
/// `eki_ks_open_v2`, appends and closes; x verifies the whole file, then continues it once more,
/// and y verifies again. The chain crosses the libraries without a break.
#[test]
fn log_continued_by_the_other_library() {
    let Some((a, b)) = common::setup("audit::log_continued_by_the_other_library") else {
        return;
    };
    run("audit::log_continued_by_the_other_library", |r| {
        let dir = TempDir::new("continued");
        for (x, y) in [(a, b), (b, a)] {
            let path = dir.file(&format!("{}-then-{}.log", x.name(), y.name()));
            let mut expected = write_short_log(x, &path)?;
            let n1 = expected.len() as u64;
            verify_ok(r, y, "the other library verifies", &path, None, n1);
            verify_ok(r, x, "the writer verifies", &path, None, n1);

            for (lib, round) in [(y, "first continuation"), (x, "second continuation")] {
                let before = expected.len() as u64;
                let st = open_v2(lib, &KsConfigV2::software().with_audit_log(&path))?;
                let (_, seq) = audit_head(&st)?;
                r.check(seq == before + 1, || {
                    format!(
                        "{}: {round}: seq after open is {seq}, want {}",
                        lib.name(),
                        before + 1
                    )
                });
                let id = ks::generate(&st, EC, &unique_label("continued"))?;
                drop(st);
                expected.push(rec("open", None, None, EKI_OK));
                expected.push(rec("generate", Some(&id), None, EKI_OK));
                expected.push(rec("close", None, None, EKI_OK));
                let records = records_of(lib, &path)?;
                check_records(r, lib, round, &records, &expected);
                let last = records.last().map(Record::hash_bytes);
                for verifier in [x, y] {
                    verify_ok(
                        r,
                        verifier,
                        &format!("{round} by {}", lib.name()),
                        &path,
                        last.as_ref(),
                        expected.len() as u64,
                    );
                }
            }
        }
        Ok(())
    });
}

/// The `eki_audit_verify` rows of §5 and §7 that need no tampering: NULL, path length, missing
/// file, empty file, and `expected_head`.
#[test]
fn verify_error_matrix() {
    let Some((a, b)) = common::setup("audit::verify_error_matrix") else {
        return;
    };
    run("audit::verify_error_matrix", |r| {
        let dir = TempDir::new("matrix");
        for writer in [a, b] {
            let path = dir.file(&format!("{}.log", writer.name()));
            let n = write_short_log(writer, &path)?.len() as u64;
            let records = records_of(writer, &path)?;
            let head = records.last().map(Record::hash_bytes).unwrap_or([0; 32]);
            let mut other_head = head;
            other_head[0] ^= 0x01;
            let empty = dir.file("empty.log");
            write(&empty, b"");
            let missing = dir.file("missing.log");
            let long = cstr(&format!("/{}", "a".repeat(4096)));
            for lib in [a, b] {
                verify_ok(r, lib, "full log, expected_head NULL", &path, None, n);
                verify_ok(r, lib, "full log, its last hash", &path, Some(&head), n);
                verify_fails(
                    r,
                    lib,
                    "full log, another expected_head",
                    &path,
                    Some(&other_head),
                    EKI_ERR_AUTH_FAILED,
                );
                verify_ok(r, lib, "empty file", &empty, None, 0);
                verify_ok(
                    r,
                    lib,
                    "empty file, 32 zero bytes as head",
                    &empty,
                    Some(&[0; 32]),
                    0,
                );
                verify_fails(
                    r,
                    lib,
                    "empty file, a non-zero head",
                    &empty,
                    Some(&head),
                    EKI_ERR_AUTH_FAILED,
                );
                verify_fails(r, lib, "missing file", &missing, None, EKI_ERR_BACKEND);
                verify_fails(r, lib, "a directory", &dir.0, None, EKI_ERR_BACKEND);
                for (row, p) in [
                    ("path \"\"", cstr("")),
                    ("path of 4097 bytes", long.clone()),
                ] {
                    let mut records = PREFILL_U64;
                    let s = lib.audit_verify(Some(p.as_c_str()), None, Some(&mut records));
                    if r.status(lib, row, s, EKI_ERR_INVALID_ARGUMENT) {
                        r.check(records == 0, || {
                            format!("{}: {row}: records_out = {records:#x}", lib.name())
                        });
                    }
                }
            }
        }
        Ok(())
    });
}

/// §5 and §7 tampering rows, for logs written by each library and checked by both: every single
/// byte changed, a line removed from the middle, the last `\n` removed, the tail removed with
/// and without `expected_head`, and a few malformed endings.
#[test]
fn tampering_is_detected_by_both() {
    let Some((a, b)) = common::setup("audit::tampering_is_detected_by_both") else {
        return;
    };
    run("audit::tampering_is_detected_by_both", |r| {
        let dir = TempDir::new("tamper");
        for writer in [a, b] {
            let path = dir.file(&format!("{}.log", writer.name()));
            write_short_log(writer, &path)?;
            let bytes = read(&path)?;
            let records = records_of(writer, &path)?;
            let n = records.len();
            let head = records.last().map(Record::hash_bytes).unwrap_or([0; 32]);
            let lines: Vec<&[u8]> = bytes.split_inclusive(|&c| c == b'\n').collect();
            let probe = dir.file("probe.log");
            let ctx = |row: &str| format!("log of {}: {row}", writer.name());

            // Every single byte changed.
            for i in 0..bytes.len() {
                let mut t = bytes.clone();
                t[i] ^= 0x01;
                write(&probe, &t);
                for lib in [a, b] {
                    let (s, records_out) = verify(lib, &probe, None);
                    r.check(s == EKI_ERR_AUTH_FAILED && records_out == 0, || {
                        format!(
                            "{}: {}: got {} with records_out {records_out:#x}, want \
                             EKI_ERR_AUTH_FAILED and 0",
                            lib.name(),
                            ctx(&format!("byte {i} changed")),
                            ekicore_conformance::describe(s)
                        )
                    });
                }
            }

            let mut variants: Vec<Variant> = Vec::new();
            let without = |skip: usize| -> Vec<u8> {
                lines
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != skip)
                    .flat_map(|(_, l)| l.iter().copied())
                    .collect()
            };
            variants.push((
                "line 3 removed from the middle".into(),
                without(2),
                None,
                EKI_ERR_AUTH_FAILED,
                0,
            ));
            variants.push((
                "first line removed".into(),
                without(0),
                None,
                EKI_ERR_AUTH_FAILED,
                0,
            ));
            variants.push((
                "last line without \\n".into(),
                bytes[..bytes.len() - 1].to_vec(),
                None,
                EKI_ERR_AUTH_FAILED,
                0,
            ));
            let tail_cut = prefix_lines(&bytes, n - 1);
            variants.push((
                "tail removed, expected_head of the full log".into(),
                tail_cut.clone(),
                Some(head),
                EKI_ERR_AUTH_FAILED,
                0,
            ));
            variants.push((
                "tail removed, expected_head NULL (documented limit)".into(),
                tail_cut,
                None,
                EKI_OK,
                n as u64 - 1,
            ));
            variants.push((
                "last line twice".into(),
                [bytes.as_slice(), lines[n - 1]].concat(),
                None,
                EKI_ERR_AUTH_FAILED,
                0,
            ));
            variants.push((
                "lines 2 and 3 swapped".into(),
                [lines[0], lines[2], lines[1], lines[3..].concat().as_slice()].concat(),
                None,
                EKI_ERR_AUTH_FAILED,
                0,
            ));
            variants.push((
                "empty line at the end".into(),
                [bytes.as_slice(), b"\n".as_slice()].concat(),
                None,
                EKI_ERR_AUTH_FAILED,
                0,
            ));
            variants.push((
                "CR before every \\n".into(),
                lines
                    .iter()
                    .flat_map(|l| [&l[..l.len() - 1], b"\r\n".as_slice()].concat())
                    .collect(),
                None,
                EKI_ERR_AUTH_FAILED,
                0,
            ));
            variants.push((
                "a line of 600 bytes appended".into(),
                [bytes.as_slice(), [b'a'; 599].as_slice(), b"\n".as_slice()].concat(),
                None,
                EKI_ERR_AUTH_FAILED,
                0,
            ));
            variants.push((
                "space after the first comma".into(),
                {
                    let text =
                        String::from_utf8_lossy(&bytes).replacen(",\"time\"", ", \"time\"", 1);
                    text.into_bytes()
                },
                None,
                EKI_ERR_AUTH_FAILED,
                0,
            ));
            for (row, content, h, want, count) in &variants {
                write(&probe, content);
                for lib in [a, b] {
                    if *want == EKI_OK {
                        verify_ok(r, lib, &ctx(row), &probe, h.as_ref(), *count);
                    } else {
                        verify_fails(r, lib, &ctx(row), &probe, h.as_ref(), *want);
                    }
                }
            }
        }
        Ok(())
    });
}

/// The `eki_ks_open_v2` rows that need a file (§4, §5, §7), and `eki_ks_audit_head` without a
/// log: a log with a flipped byte, a log locked by an open handle of either library, a log in a
/// directory that does not exist, an empty existing file.
#[test]
fn open_v2_audit_rows() {
    let Some((a, b)) = common::setup("audit::open_v2_audit_rows") else {
        return;
    };
    run("audit::open_v2_audit_rows", |r| {
        let dir = TempDir::new("open");
        for lib in [a, b] {
            // audit_head on a handle without a log.
            for (kind, st) in [
                ("eki_ks_open", ks::open(lib, &KsConfig::software())?),
                ("eki_ks_open_v2", open_v2(lib, &KsConfigV2::software())?),
            ] {
                let row = format!("audit_head, {kind} handle without a log");
                let mut hash = prefill_array::<32>();
                let mut seq = PREFILL_U64;
                let s = st.audit_head(Some(&mut hash), Some(&mut seq));
                if r.status(lib, &row, s, EKI_ERR_UNSUPPORTED) {
                    r.zeroed(lib, &row, "hash_out", &hash);
                    r.check(seq == 0, || {
                        format!("{}: {row}: seq_out = {seq:#x}", lib.name())
                    });
                }
            }

            // A log with one byte flipped: AUTH_FAILED, *out NULL, the file unchanged.
            let path = dir.file(&format!("{}-flipped.log", lib.name()));
            write_short_log(lib, &path)?;
            let mut bytes = read(&path)?;
            let i = bytes.len() / 2;
            bytes[i] ^= 0x01;
            write(&path, &bytes);
            for opener in [a, b] {
                let (s, st) = opener.ks_open_v2(&KsConfigV2::software().with_audit_log(&path));
                r.status(
                    opener,
                    "open_v2, existing log with a flipped byte",
                    s,
                    EKI_ERR_AUTH_FAILED,
                );
                r.check(st.is_none(), || {
                    format!(
                        "{}: open_v2 of a tampered log returned a handle",
                        opener.name()
                    )
                });
                r.check(read(&path)? == bytes, || {
                    format!(
                        "{}: open_v2 of a tampered log changed the file",
                        opener.name()
                    )
                });
            }

            // A log held by an open handle: a second handle of either library fails to open.
            let path = dir.file(&format!("{}-locked.log", lib.name()));
            let cfg = KsConfigV2::software().with_audit_log(&path);
            let holder = open_v2(lib, &cfg)?;
            for opener in [a, b] {
                let (s, st) = opener.ks_open_v2(&cfg);
                let row = format!("open_v2, log locked by an open handle of {}", lib.name());
                r.status(opener, &row, s, EKI_ERR_BACKEND);
                r.check(st.is_none(), || {
                    format!("{}: {row}: a handle was returned", opener.name())
                });
            }
            let (_, seq) = audit_head(&holder)?;
            r.check(seq == 1, || {
                format!(
                    "{}: the failed opens wrote to the held log (seq {seq})",
                    lib.name()
                )
            });
            drop(holder);
            let again = open_v2(lib, &cfg).map_err(|e| format!("{e} (after the holder closed)"))?;
            drop(again);
            verify_ok(r, lib, "the log after the lock rows", &path, None, 4);

            // A file that cannot be created.
            let nodir = dir.file("no-such-dir").join("audit.log");
            let (s, _) = lib.ks_open_v2(&KsConfigV2::software().with_audit_log(&nodir));
            r.status(
                lib,
                "open_v2, log in a directory that does not exist",
                s,
                EKI_ERR_BACKEND,
            );

            // An existing empty file is a valid log with 0 records: the chain starts at 1.
            let path = dir.file(&format!("{}-empty.log", lib.name()));
            write(&path, b"");
            let st = open_v2(lib, &KsConfigV2::software().with_audit_log(&path))?;
            let (_, seq) = audit_head(&st)?;
            r.check(seq == 1, || {
                format!("{}: open_v2 on an empty file: seq {seq}", lib.name())
            });
            drop(st);
            let records = records_of(lib, &path)?;
            check_records(
                r,
                lib,
                "log started in an empty file",
                &records,
                &[
                    rec("open", None, None, EKI_OK),
                    rec("close", None, None, EKI_OK),
                ],
            );
        }
        Ok(())
    });
}

/// (row, file content, expected_head, expected status, expected records_out)
type Variant = (String, Vec<u8>, Option<[u8; 32]>, i32, u64);

/// The first `n` lines of `bytes`, each with its `\n`.
fn prefix_lines(bytes: &[u8], n: usize) -> Vec<u8> {
    bytes
        .split_inclusive(|&c| c == b'\n')
        .take(n)
        .flat_map(|l| l.iter().copied())
        .collect()
}

/// A log created by the library has mode 0600 (§5).
fn check_mode_0600(r: &mut Report, lib: &Lib, path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => {
            let mode = m.permissions().mode() & 0o777;
            r.check(mode == 0o600, || {
                format!("{}: the new log has mode {mode:o}, want 600", lib.name())
            });
        }
        Err(e) => {
            r.check(false, || {
                format!("{}: stat {}: {e}", lib.name(), path.display())
            });
        }
    }
}
