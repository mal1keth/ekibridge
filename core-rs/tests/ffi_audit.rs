//! The audit log through the C ABI, on the software store: what `eki_ks_open_v2` does with a
//! log, the record of every call, `eki_ks_audit_head` and `eki_audit_verify`.
//!
//! Rows: "Opening a store with ABI 2", "Audit log" and "Audit functions" of docs/ffi-contract.md.
//! Records are checked independently of the library: each line is split into its fields here and
//! its hash is recomputed with `sha2`.

mod common;

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use common::lifecycle::{self, Approvers, FILL_U64, audit_head, audit_verify};
use common::{
    FILL, In, Store, assert_open_v2_fails, assert_zero, config_v2, fixed_id, ks, label,
    software_config, try_open_v2,
};
use ekicore_abi::eki_status::{
    EKI_ERR_AUTH_FAILED, EKI_ERR_BACKEND, EKI_ERR_INVALID_ARGUMENT, EKI_ERR_KEY_NOT_FOUND,
    EKI_ERR_NULL_POINTER, EKI_OK,
};
use ekicore_abi::{
    EKI_KEY_AES_256, EKI_KEY_ECDSA_P256, EKI_KEY_HMAC_SHA256, eki_key_id, eki_ks_config_v2,
};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------------------------
// Files and records.
// ---------------------------------------------------------------------------------------------

/// A directory of its own under the system temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ekicore-rs-ffi-audit-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temporary directory");
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
    CString::new(path.as_os_str().as_bytes()).expect("path has no NUL")
}

/// Creates a FIFO at `path`. The standard library cannot create one, and a child process is not an
/// option because a process spawned while another test holds a log lock keeps that lock until it
/// executes its program.
fn make_fifo(path: &Path) {
    let text = c_path(path);
    // SAFETY: `text` is a live NUL-terminated string that `mkfifo` only reads.
    let made = unsafe { libc::mkfifo(text.as_ptr(), 0o600) };
    assert_eq!(made, 0, "mkfifo: {}", std::io::Error::last_os_error());
}

/// Runs `f` on another thread and waits up to ten seconds for its result, so that a call that
/// waits for the writer of a FIFO fails the test instead of hanging it.
fn within_ten_seconds<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(f());
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the call returned instead of waiting")
}

/// A software configuration with the audit log at `path` and no approvers.
fn logged_config(path: &CString) -> eki_ks_config_v2 {
    config_v2(&software_config(), Some(path), None, 0)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// Seconds since 1970 of a `YYYY-MM-DDTHH:MM:SSZ` time (days from civil, Howard Hinnant).
fn epoch_seconds(time: &str) -> u64 {
    let field = |range: std::ops::Range<usize>| -> i64 { time[range].parse().expect("digits") };
    let (y, m, d) = (field(0..4), field(5..7), field(8..10));
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 + field(11..13) * 3600 + field(14..16) * 60 + field(17..19);
    u64::try_from(seconds).expect("after 1970")
}

/// One record, split into its fields by this test, not by the library.
#[derive(Debug)]
struct Record {
    seq: u64,
    time: String,
    op: String,
    key: String,
    key2: String,
    status: u32,
    hash: [u8; 32],
}

impl Record {
    /// `op key key2 status`, the part a scripted call decides.
    fn summary(&self) -> String {
        format!("{} {} {} {}", self.op, self.key, self.key2, self.status)
    }
}

/// The records of the log at `path`, after checking every line against the format: the exact
/// field order, `seq` from 1, `prev` the previous hash, `hash` SHA-256 of the line before
/// `,"hash":`.
fn records(path: &Path) -> Vec<Record> {
    let text = String::from_utf8(std::fs::read(path).expect("log readable")).expect("ASCII");
    assert!(
        text.is_empty() || text.ends_with('\n'),
        "ends with a newline"
    );
    let mut prev = [0_u8; 32];
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        assert!(line.len() < 512, "line {index} is {} bytes", line.len());
        let (covered, hash) = line.split_once(",\"hash\":\"").expect("hash field");
        let hash = hash.strip_suffix("\"}").expect("closing");
        let computed: [u8; 32] = Sha256::digest(covered.as_bytes()).into();
        assert_eq!(hash, hex::encode(computed), "line {index}: hash");
        let field = |name: &str, quoted: bool| -> String {
            let start = covered.find(&format!("\"{name}\":")).expect("field") + name.len() + 3;
            let rest = &covered[start..];
            let end = rest.find(',').unwrap_or(rest.len());
            let value = &rest[..end];
            if quoted {
                value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .expect("quoted")
                    .to_owned()
            } else {
                value.to_owned()
            }
        };
        let record = Record {
            seq: field("seq", false).parse().expect("seq"),
            time: field("time", true),
            op: field("op", true),
            key: field("key", true),
            key2: field("key2", true),
            status: field("status", false).parse().expect("status"),
            hash: computed,
        };
        let expected = format!(
            "{{\"seq\":{},\"time\":\"{}\",\"op\":\"{}\",\"key\":\"{}\",\"key2\":\"{}\",\"status\":{},\"prev\":\"{}\"",
            record.seq,
            record.time,
            record.op,
            record.key,
            record.key2,
            record.status,
            hex::encode(prev)
        );
        assert_eq!(covered, expected, "line {index}: exact shape");
        assert_eq!(record.seq, index as u64 + 1, "line {index}: seq");
        prev = computed;
        out.push(record);
    }
    out
}

fn hex_id(id: &eki_key_id) -> String {
    hex::encode(id.bytes)
}

/// `eki_audit_verify` of `path`; returns the status and the record count it wrote.
fn verify(path: &Path, expected_head: Option<&[u8; 32]>) -> (ekicore_abi::eki_status, u64) {
    let path = c_path(path);
    let mut records = FILL_U64;
    let status = audit_verify(path.as_ptr(), expected_head, Some(&mut records));
    (status, records)
}

/// Writes a log of a few records with a software store and returns its records.
fn short_log(path: &Path) -> Vec<Record> {
    let store = Store::open_v2(&logged_config(&c_path(path)));
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test");
    let _ = store.hmac(&mac, b"m");
    store.destroy(&mac);
    drop(store);
    records(path)
}

// ---------------------------------------------------------------------------------------------
// What is logged.
// ---------------------------------------------------------------------------------------------

#[test]
fn every_call_writes_one_exact_record() {
    let dir = TempDir::new("scripted");
    let path = dir.file("audit.log");
    let started = now();
    let store = Store::open_v2(&logged_config(&c_path(&path)));
    let ks = store.ptr();
    let mut heads = vec![store.audit_head()];
    let mut expected = vec!["open   0".to_owned()];
    let mut step = |line: String, store: &Store| {
        expected.push(line);
        heads.push(store.audit_head());
    };

    let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
    step(format!("generate {}  0", hex_id(&kek)), &store);
    let mut id = common::prefilled_id();
    assert_eq!(
        ks::generate(ks, EKI_KEY_AES_256, label("").as_ptr(), Some(&mut id)),
        EKI_ERR_INVALID_ARGUMENT
    );
    step("generate   2".to_owned(), &store);
    let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
    step(format!("generate {}  0", hex_id(&mac)), &store);
    let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");
    step(format!("generate {}  0", hex_id(&ec)), &store);

    // Not logged: get_info, get_info_v2, last_error_message, audit_head, failed NULL checks.
    let before = store.audit_head();
    let _ = store.info(&kek);
    let _ = store.info_v2(&kek);
    let _ = common::last_error(ks);
    let _ = store.audit_head();
    assert_eq!(
        ks::sign(ks, None, In::Bytes(b"m"), Some(&mut [0; 64])),
        EKI_ERR_NULL_POINTER
    );
    assert_eq!(
        lifecycle::hmac_verify(ks, Some(&mac), In::Null(1), In::Bytes(&[0; 32])),
        EKI_ERR_NULL_POINTER
    );
    assert_eq!(store.audit_head(), before, "nothing logged");
    let tag = store.hmac(&mac, b"m");
    step(format!("hmac {}  0", hex_id(&mac)), &store);
    let unknown = ks::unknown_id();
    assert_eq!(
        lifecycle::hmac_verify(ks, Some(&mac), In::Bytes(b"m"), In::Bytes(&tag)),
        EKI_OK
    );
    step(format!("hmac_verify {}  0", hex_id(&mac)), &store);
    assert_eq!(
        lifecycle::hmac_verify(ks, Some(&mac), In::Bytes(b"m"), In::Null(0)),
        EKI_ERR_INVALID_ARGUMENT
    );
    step(format!("hmac_verify {}  2", hex_id(&mac)), &store);
    let _ = store.sign(&ec, In::Bytes(b"m"));
    step(format!("sign {}  0", hex_id(&ec)), &store);
    assert_eq!(
        ks::sign(ks, Some(&unknown), In::Bytes(b"m"), Some(&mut [0; 64])),
        EKI_ERR_KEY_NOT_FOUND
    );
    step(format!("sign {}  6", hex_id(&unknown)), &store);
    let _ = store.public_key(&ec);
    step(format!("get_public_key {}  0", hex_id(&ec)), &store);
    let blob = store.wrap(&kek, &mac);
    step(format!("wrap {} {} 0", hex_id(&mac), hex_id(&kek)), &store);
    let copy = fixed_id(0x41);
    store.unwrap(&kek, &blob, EKI_KEY_HMAC_SHA256, "eki-test copy", &copy);
    step(
        format!("unwrap {} {} 0", hex_id(&copy), hex_id(&kek)),
        &store,
    );
    let mut flipped = blob;
    flipped[0] ^= 1;
    let text = label("eki-test bad");
    let other = fixed_id(0x42);
    assert_eq!(
        ks::unwrap(
            ks,
            Some(&kek),
            In::Bytes(&flipped),
            EKI_KEY_HMAC_SHA256,
            text.as_ptr(),
            Some(&other)
        ),
        EKI_ERR_AUTH_FAILED
    );
    step(
        format!("unwrap {} {} 5", hex_id(&other), hex_id(&kek)),
        &store,
    );
    let new = store.rotate(&mac);
    step(
        format!("rotate {} {} 0", hex_id(&mac), hex_id(&new)),
        &store,
    );
    let mut out = common::prefilled_id();
    assert_eq!(
        lifecycle::rotate(ks, Some(&mac), Some(&mut out)),
        ekicore_abi::eki_status::EKI_ERR_KEY_STATE
    );
    step(format!("rotate {}  11", hex_id(&mac)), &store);
    store.revoke(&ec);
    step(format!("revoke {}  0", hex_id(&ec)), &store);
    store.destroy(&copy);
    step(format!("destroy {}  0", hex_id(&copy)), &store);
    let mut request = [FILL; 32];
    assert_eq!(
        lifecycle::destroy_request(ks, Some(&kek), Some(&mut request)),
        ekicore_abi::eki_status::EKI_ERR_UNSUPPORTED
    );
    step(format!("destroy_request {}  4", hex_id(&kek)), &store);
    let mut remaining = 0;
    assert_eq!(
        lifecycle::destroy_approve(
            ks,
            Some(&[1; 32]),
            Some(&[0; 65]),
            Some(&[0; 64]),
            Some(&mut remaining)
        ),
        ekicore_abi::eki_status::EKI_ERR_UNSUPPORTED
    );
    step("destroy_approve   4".to_owned(), &store);
    // The guard destroys the keys it still tracks, in the order they were made, then closes.
    for id in [kek, mac, ec, new] {
        expected.push(format!("destroy {}  0", hex_id(&id)));
    }
    drop(store);
    expected.push("close   0".to_owned());
    let finished = now();

    let records = records(&path);
    let summaries: Vec<String> = records.iter().map(Record::summary).collect();
    assert_eq!(summaries, expected);
    for record in &records {
        let t = epoch_seconds(&record.time);
        assert!(
            started <= t + 1 && t <= finished + 1,
            "time {}",
            record.time
        );
    }
    // Each head the handle reported is the hash and seq of the record written last.
    for (hash, seq) in heads {
        let record = &records[usize::try_from(seq).expect("small") - 1];
        assert_eq!(record.hash, hash, "head of seq {seq}");
    }
    let mode = std::fs::metadata(&path)
        .expect("exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "created with mode 0600");
    let last = records.last().expect("records").hash;
    assert_eq!(verify(&path, Some(&last)), (EKI_OK, records.len() as u64));
}

#[test]
fn dual_control_calls_name_the_key_of_the_request() {
    let dir = TempDir::new("dual");
    let path = c_path(&dir.file("audit.log"));
    let approvers = Approvers::new(3);
    let keys = approvers.bytes(3);
    let store = Store::open_v2(&config_v2(&software_config(), Some(&path), Some(&keys), 3));
    let id = store.generate(EKI_KEY_HMAC_SHA256, "eki-test doomed");
    store.forget(&id);
    assert_eq!(
        ks::destroy(store.ptr(), Some(&id)),
        ekicore_abi::eki_status::EKI_ERR_APPROVAL_REQUIRED
    );
    let request = store.request(&id);
    assert_eq!(
        store.approve(&approvers, 0, &[9; 32], &id),
        (EKI_ERR_KEY_NOT_FOUND, 0)
    );
    assert_eq!(store.approve(&approvers, 0, &request, &id), (EKI_OK, 1));
    assert_eq!(store.approve(&approvers, 1, &request, &id), (EKI_OK, 0));
    drop(store);
    let summaries: Vec<String> = records(&dir.file("audit.log"))
        .iter()
        .map(Record::summary)
        .collect();
    let id = hex_id(&id);
    assert_eq!(
        summaries,
        [
            "open   0".to_owned(),
            format!("generate {id}  0"),
            format!("destroy {id}  12"),
            format!("destroy_request {id}  0"),
            "destroy_approve   6".to_owned(),
            format!("destroy_approve {id}  0"),
            format!("destroy_approve {id}  0"),
            "close   0".to_owned(),
        ]
    );
}

// ---------------------------------------------------------------------------------------------
// eki_ks_open_v2 with a log.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_log_is_continued_across_handles() {
    let dir = TempDir::new("continued");
    let path = dir.file("audit.log");
    let first = short_log(&path);
    let store = Store::open_v2(&logged_config(&c_path(&path)));
    let (hash, seq) = store.audit_head();
    assert_eq!(
        seq,
        first.len() as u64 + 1,
        "the open record continues the chain"
    );
    drop(store);
    let all = records(&path);
    assert_eq!(all.len(), first.len() + 2);
    assert_eq!(all[first.len()].hash, hash);
    assert_eq!(all[first.len()].op, "open");
}

#[test]
fn an_empty_existing_file_starts_at_seq_1() {
    let dir = TempDir::new("empty");
    let path = dir.file("audit.log");
    std::fs::write(&path, b"").expect("writable");
    let store = Store::open_v2(&logged_config(&c_path(&path)));
    assert_eq!(store.audit_head().1, 1);
}

#[test]
fn a_tampered_log_is_refused_and_left_unchanged() {
    let dir = TempDir::new("tampered");
    let path = dir.file("audit.log");
    short_log(&path);
    let mut bytes = std::fs::read(&path).expect("readable");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    std::fs::write(&path, &bytes).expect("writable");
    assert_open_v2_fails(&logged_config(&c_path(&path)), EKI_ERR_AUTH_FAILED);
    assert_eq!(std::fs::read(&path).expect("readable"), bytes, "unchanged");
    // The same with approvers: the log is checked after everything else.
    let approvers = Approvers::new(2);
    let keys = approvers.bytes(2);
    let path = c_path(&path);
    let cfg = config_v2(&software_config(), Some(&path), Some(&keys), 2);
    assert_open_v2_fails(&cfg, EKI_ERR_AUTH_FAILED);
}

#[test]
fn a_locked_log_cannot_be_opened_twice() {
    let dir = TempDir::new("locked");
    let path = c_path(&dir.file("audit.log"));
    let holder = Store::open_v2(&logged_config(&path));
    assert_open_v2_fails(&logged_config(&path), EKI_ERR_BACKEND);
    assert_eq!(holder.audit_head().1, 1, "the holder's log is untouched");
    drop(holder);
    let store = Store::open_v2(&logged_config(&path));
    assert_eq!(store.audit_head().1, 3, "open, close, open");
}

#[test]
fn a_log_that_cannot_be_created_is_a_backend_failure() {
    let dir = TempDir::new("uncreatable");
    let missing = c_path(&dir.file("no such directory/audit.log"));
    assert_open_v2_fails(&logged_config(&missing), EKI_ERR_BACKEND);
    let directory = c_path(&dir.0);
    assert_open_v2_fails(&logged_config(&directory), EKI_ERR_BACKEND);
    // 4096 bytes is a valid length; the path names nothing that can be created.
    let mut long = dir.0.as_os_str().as_bytes().to_vec();
    long.push(b'/');
    long.resize(4096, b'a');
    let long = CString::new(long).expect("no NUL");
    assert_open_v2_fails(&logged_config(&long), EKI_ERR_BACKEND);
    let too_long = CString::new(vec![b'a'; 4097]).expect("no NUL");
    assert_open_v2_fails(&logged_config(&too_long), EKI_ERR_INVALID_ARGUMENT);
    let empty = CString::default();
    assert_open_v2_fails(&logged_config(&empty), EKI_ERR_INVALID_ARGUMENT);
}

#[test]
fn a_log_must_be_a_regular_file() {
    let dir = TempDir::new("special");
    let fifo = dir.file("fifo");
    make_fifo(&fifo);
    for (row, path) in [
        ("a directory", dir.0.clone()),
        ("/dev/null", PathBuf::from("/dev/null")),
        ("a FIFO", fifo),
    ] {
        let verified = {
            let path = path.clone();
            within_ten_seconds(move || verify(&path, None))
        };
        assert_eq!(verified, (EKI_ERR_BACKEND, 0), "{row}: eki_audit_verify");
        let opened = within_ten_seconds(move || {
            let path = c_path(&path);
            let opened = try_open_v2(&logged_config(&path));
            (opened.status, opened.out_is_null)
        });
        assert_eq!(opened, (EKI_ERR_BACKEND, true), "{row}: eki_ks_open_v2");
    }
    // A symbolic link is followed: what it leads to is a regular file.
    let target = dir.file("target.log");
    short_log(&target);
    let link = dir.file("link.log");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let records = records(&target).len() as u64;
    assert_eq!(verify(&link, None), (EKI_OK, records), "a symbolic link");
    let store = Store::open_v2(&logged_config(&c_path(&link)));
    assert_eq!(store.audit_head().1, records + 1, "a symbolic link, open");
}

#[test]
fn an_unterminated_audit_path_is_read_no_further_than_4097_bytes() {
    let unterminated = vec![b'a'; 4097].into_boxed_slice();
    let mut cfg = config_v2(&software_config(), None, None, 0);
    cfg.audit_log_path = unterminated.as_ptr().cast();
    let opened = try_open_v2(&cfg);
    assert_eq!(opened.status, EKI_ERR_INVALID_ARGUMENT);
    assert!(opened.out_is_null);
}

// ---------------------------------------------------------------------------------------------
// eki_audit_verify.
// ---------------------------------------------------------------------------------------------

#[test]
fn verify_accepts_exact_logs_and_counts_them() {
    let dir = TempDir::new("verify-ok");
    let path = dir.file("audit.log");
    let all = short_log(&path);
    let head = all.last().expect("records").hash;
    assert_eq!(verify(&path, None), (EKI_OK, all.len() as u64));
    assert_eq!(verify(&path, Some(&head)), (EKI_OK, all.len() as u64));
    let mut other = head;
    other[0] ^= 1;
    assert_eq!(verify(&path, Some(&other)), (EKI_ERR_AUTH_FAILED, 0));
    let empty = dir.file("empty.log");
    std::fs::write(&empty, b"").expect("writable");
    assert_eq!(verify(&empty, None), (EKI_OK, 0));
    assert_eq!(verify(&empty, Some(&[0; 32])), (EKI_OK, 0), "the zero head");
    assert_eq!(verify(&empty, Some(&head)), (EKI_ERR_AUTH_FAILED, 0));
}

#[test]
fn verify_rejects_every_change() {
    let dir = TempDir::new("verify-tamper");
    let path = dir.file("audit.log");
    let all = short_log(&path);
    let head = all.last().expect("records").hash;
    let bytes = std::fs::read(&path).expect("readable");
    let changed = dir.file("changed.log");
    for index in 0..bytes.len() {
        let mut copy = bytes.clone();
        copy[index] ^= 0x01;
        std::fs::write(&changed, &copy).expect("writable");
        assert_eq!(
            verify(&changed, None),
            (EKI_ERR_AUTH_FAILED, 0),
            "byte {index}"
        );
    }
    let lines: Vec<&[u8]> = bytes.split_inclusive(|&b| b == b'\n').collect();
    let crlf: Vec<u8> = lines
        .iter()
        .flat_map(|l| [&l[..l.len() - 1], b"\r\n"].concat())
        .collect();
    let rows: [(&str, Vec<u8>); 7] = [
        (
            "a line removed from the middle",
            [&lines[..1], &lines[2..]].concat().concat(),
        ),
        (
            "the last newline removed",
            bytes[..bytes.len() - 1].to_vec(),
        ),
        (
            "lines swapped",
            [lines[1], lines[0], lines[2], lines[3]].concat(),
        ),
        ("a trailing empty line", [&bytes[..], b"\n"].concat()),
        ("CRLF line ends", crlf),
        (
            "a line of 600 bytes",
            [&bytes[..], &[b'x'; 599], b"\n"].concat(),
        ),
        ("a record repeated", [&bytes[..], lines[3]].concat()),
    ];
    for (row, content) in rows {
        std::fs::write(&changed, &content).expect("writable");
        assert_eq!(verify(&changed, None), (EKI_ERR_AUTH_FAILED, 0), "{row}");
    }
    // A cut tail is visible only through expected_head.
    let cut = lines[..2].concat();
    std::fs::write(&changed, &cut).expect("writable");
    assert_eq!(verify(&changed, Some(&head)), (EKI_ERR_AUTH_FAILED, 0));
    assert_eq!(verify(&changed, None), (EKI_OK, 2), "documented limit");
    assert_eq!(verify(&changed, Some(&all[1].hash)), (EKI_OK, 2));
}

#[test]
fn verify_path_and_null_rows() {
    let dir = TempDir::new("verify-rows");
    assert_eq!(verify(&dir.file("missing.log"), None), (EKI_ERR_BACKEND, 0));
    assert_eq!(verify(&dir.0, None), (EKI_ERR_BACKEND, 0), "a directory");
    let path = dir.file("audit.log");
    short_log(&path);
    let path = c_path(&path);
    for (row, text) in [
        ("empty path", CString::default()),
        (
            "4097 bytes",
            CString::new(vec![b'a'; 4097]).expect("no NUL"),
        ),
    ] {
        let mut records = FILL_U64;
        assert_eq!(
            audit_verify(text.as_ptr(), None, Some(&mut records)),
            EKI_ERR_INVALID_ARGUMENT,
            "{row}"
        );
        assert_eq!(records, 0);
    }
    let unterminated = vec![b'a'; 4097].into_boxed_slice();
    let mut records = FILL_U64;
    assert_eq!(
        audit_verify(unterminated.as_ptr().cast(), None, Some(&mut records)),
        EKI_ERR_INVALID_ARGUMENT,
        "no NUL within 4097 bytes"
    );
    let mut records = FILL_U64;
    assert_eq!(
        audit_verify(core::ptr::null(), None, Some(&mut records)),
        EKI_ERR_NULL_POINTER
    );
    assert_eq!(records, 0);
    assert_eq!(
        audit_verify(path.as_ptr(), None, None),
        EKI_ERR_NULL_POINTER
    );
    assert_eq!(
        audit_verify(core::ptr::null(), Some(&[0; 32]), None),
        EKI_ERR_NULL_POINTER
    );
}

#[test]
fn audit_head_rows_on_a_logged_handle() {
    let dir = TempDir::new("head");
    let path = c_path(&dir.file("audit.log"));
    let store = Store::open_v2(&logged_config(&path));
    let mut hash = [FILL; 32];
    assert_eq!(
        audit_head(store.ptr(), Some(&mut hash), None),
        EKI_ERR_NULL_POINTER
    );
    assert_zero(&hash);
    let mut seq = FILL_U64;
    assert_eq!(
        audit_head(store.ptr(), None, Some(&mut seq)),
        EKI_ERR_NULL_POINTER
    );
    assert_eq!(seq, 0);
    let (hash, seq) = store.audit_head();
    assert_eq!(seq, 1);
    assert_ne!(hash, [0; 32]);
}
