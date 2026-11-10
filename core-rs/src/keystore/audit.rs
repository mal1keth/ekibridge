//! The audit log of a key store handle (ABI 2 contract, section 5): one line per call, appended to
//! a file and chained by SHA-256, and the stateless verifier behind `eki_audit_verify`.
//!
//! A record is one line with a fixed grammar:
//!
//! ```text
//! {"seq":1,"time":"2026-11-11T09:30:00Z","op":"generate","key":"<32 hex>","key2":"","status":0,"prev":"<64 hex>","hash":"<64 hex>"}
//! ```
//!
//! Its `hash` is SHA-256 over every byte of the line before `,"hash":`, so each hash covers the
//! previous one through `prev`. The format is byte-exact because the C++ library verifies and
//! continues logs this library writes, and the other way round.
//!
//! [`format_line`] is the only code that produces a line. The verifier does not parse a line
//! into a structure that it then trusts: it extracts the fields a writer chooses (`time`, `op`,
//! `key`, `key2`, `status`), formats the line those fields must give at that position of the
//! chain (the expected `seq`, the previous hash as `prev`, the hash recomputed), and requires the
//! file to hold exactly those bytes. Every deviation (a wrong sequence number, a broken chain, a
//! wrong hash, a non-canonical number, a stray byte) is therefore one and the same failure, and
//! the writer and the verifier cannot disagree about the grammar.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ekicore_abi::{EKI_AUDIT_HASH_LEN, EKI_AUDIT_PATH_MAX_LEN, EKI_KEY_ID_LEN, eki_status};
use sha2::{Digest, Sha256};

use super::KeyId;
use crate::error::Error;

/// The longest line the verifier accepts, in bytes, its `\n` included. The longest line the
/// formatter can produce has 325 bytes (a 20-digit `seq` and the longest `op`).
/// cbindgen:ignore
pub const LINE_MAX: usize = 512;

/// The `prev` of the first record, and the head of an empty log.
/// cbindgen:ignore
pub const ZERO_HASH: [u8; EKI_AUDIT_HASH_LEN] = [0; EKI_AUDIT_HASH_LEN];

/// The largest status value a record may carry: `EKI_ERR_APPROVAL_REQUIRED`, the last status of
/// ABI version 2.
/// cbindgen:ignore
const STATUS_MAX: u32 = eki_status::EKI_ERR_APPROVAL_REQUIRED as u32;

/// Mode of a log file this library creates: read and write for the owner only.
/// cbindgen:ignore
const LOG_FILE_MODE: u32 = 0o600;

// --- Fields of a record ------------------------------------------------------------------------

/// The `op` of a record: the call it records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// The handle was opened; the first record a handle writes.
    Open,
    /// The handle was closed; the last record a handle writes.
    Close,
    /// `eki_ks_generate`.
    Generate,
    /// `eki_ks_unwrap`.
    Unwrap,
    /// `eki_ks_rotate`.
    Rotate,
    /// `eki_ks_revoke`.
    Revoke,
    /// `eki_ks_destroy`.
    Destroy,
    /// `eki_ks_destroy_request`.
    DestroyRequest,
    /// `eki_ks_destroy_approve`.
    DestroyApprove,
    /// `eki_ks_sign`.
    Sign,
    /// `eki_ks_hmac_sha256`.
    Hmac,
    /// `eki_ks_hmac_sha256_verify`.
    HmacVerify,
    /// `eki_ks_wrap`.
    Wrap,
    /// `eki_ks_get_public_key`.
    GetPublicKey,
}

impl Op {
    /// Every op, so that a name can be looked up without a second table.
    const ALL: [Self; 14] = [
        Self::Open,
        Self::Close,
        Self::Generate,
        Self::Unwrap,
        Self::Rotate,
        Self::Revoke,
        Self::Destroy,
        Self::DestroyRequest,
        Self::DestroyApprove,
        Self::Sign,
        Self::Hmac,
        Self::HmacVerify,
        Self::Wrap,
        Self::GetPublicKey,
    ];

    /// The text of the `op` field.
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Close => "close",
            Self::Generate => "generate",
            Self::Unwrap => "unwrap",
            Self::Rotate => "rotate",
            Self::Revoke => "revoke",
            Self::Destroy => "destroy",
            Self::DestroyRequest => "destroy_request",
            Self::DestroyApprove => "destroy_approve",
            Self::Sign => "sign",
            Self::Hmac => "hmac",
            Self::HmacVerify => "hmac_verify",
            Self::Wrap => "wrap",
            Self::GetPublicKey => "get_public_key",
        }
    }

    /// The op whose name is `text`.
    fn from_name(text: &[u8]) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|op| op.name().as_bytes() == text)
    }
}

/// A `time` value: whole seconds since the Unix epoch, between 1970-01-01T00:00:00Z and
/// 9999-12-31T23:59:59Z, the range in which `YYYY-MM-DDTHH:MM:SSZ` has four year digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp(u64);

/// Seconds in a day.
/// cbindgen:ignore
const DAY: u64 = 86_400;

/// 9999-12-31T23:59:59Z in seconds since the epoch.
/// cbindgen:ignore
const TIMESTAMP_MAX: u64 = 253_402_300_799;

impl Timestamp {
    /// The time `seconds` after the epoch, if it is within the range.
    pub fn from_secs(seconds: u64) -> Option<Self> {
        (seconds <= TIMESTAMP_MAX).then_some(Self(seconds))
    }

    /// The current UTC time from the system clock, truncated to the second.
    pub fn now() -> Result<Self, String> {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "the system clock is set before 1970".to_owned())?;
        Self::from_secs(since.as_secs())
            .ok_or_else(|| "the system clock is set after the year 9999".to_owned())
    }

    /// `YYYY-MM-DDTHH:MM:SSZ`.
    fn format(self) -> String {
        let (days, second_of_day) = (self.0 / DAY, self.0 % DAY);
        let (year, month, day) = civil_from_days(days);
        let (hour, minute, second) = (
            second_of_day / 3600,
            second_of_day / 60 % 60,
            second_of_day % 60,
        );
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }

    /// The time `text` names, if it has the shape `DDDD-DD-DDTDD:DD:DDZ` with every field in
    /// its range. A day that the month does not have (February 30) is not rejected here: it
    /// names another date, which then formats differently and fails the comparison with the line.
    fn parse(text: &[u8]) -> Option<Self> {
        let [
            y0,
            y1,
            y2,
            y3,
            b'-',
            m0,
            m1,
            b'-',
            d0,
            d1,
            b'T',
            h0,
            h1,
            b':',
            i0,
            i1,
            b':',
            s0,
            s1,
            b'Z',
        ] = *text
        else {
            return None;
        };
        let year = decimal(&[y0, y1, y2, y3])?;
        let month = decimal(&[m0, m1])?;
        let day = decimal(&[d0, d1])?;
        let hour = decimal(&[h0, h1])?;
        let minute = decimal(&[i0, i1])?;
        let second = decimal(&[s0, s1])?;
        let in_range = year >= 1970
            && (1..=12).contains(&month)
            && (1..=31).contains(&day)
            && hour < 24
            && minute < 60
            && second < 60;
        if !in_range {
            return None;
        }
        let days = days_from_civil(year, month, day);
        Self::from_secs(days * DAY + hour * 3600 + minute * 60 + second)
    }
}

/// The value of a run of ASCII digits, or `None` if a byte is not a digit. Called only with at
/// most four digits, so the value cannot overflow.
fn decimal(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0_u64, |value, &byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u64::from(byte - b'0'))
    })
}

/// The proleptic Gregorian date of the day `days` after 1970-01-01 (H. Hinnant,
/// `civil_from_days`, for non-negative day counts).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// The number of days from 1970-01-01 to a date of 1970 or later (H. Hinnant,
/// `days_from_civil`). `month` is 1 to 12 and `day` 1 to 31.
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = year - u64::from(month <= 2);
    let era = year / 400;
    let year_of_era = year % 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// What a writer puts into a record. `seq`, `prev` and `hash` follow from the position of the
/// record in the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fields {
    /// The UTC time of the call.
    pub time: Timestamp,
    /// The call.
    pub op: Op,
    /// The `key` id, or `None` for an empty field.
    pub key: Option<KeyId>,
    /// The `key2` id, or `None` for an empty field.
    pub key2: Option<KeyId>,
    /// The status the call returned, 0 to [`STATUS_MAX`].
    pub status: u32,
}

/// The value of a status for the `status` field.
pub fn status_value(status: eki_status) -> u32 {
    // The enum is `#[repr(i32)]` with values 0 to 12, so the conversion keeps the value.
    status as u32
}

/// Lowercase hexadecimal digits of `bytes`.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    text
}

/// The id whose 32 lowercase hexadecimal digits are `text`; `None` for any other text,
/// uppercase digits included.
fn key_id_from_hex(text: &[u8]) -> Option<KeyId> {
    let value = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    if text.len() != EKI_KEY_ID_LEN * 2 {
        return None;
    }
    let mut id = [0; EKI_KEY_ID_LEN];
    for (byte, &[high, low]) in id.iter_mut().zip(text.as_chunks::<2>().0) {
        *byte = (value(high)? << 4) | value(low)?;
    }
    Some(KeyId(id))
}

/// The text of a `key` or `key2` field: 32 hex digits, or nothing.
fn key_text(key: Option<KeyId>) -> String {
    key.map(|id| hex(&id.0)).unwrap_or_default()
}

/// The record at position `seq` of a chain whose previous hash is `prev`: the whole line with
/// its `\n`, and its hash.
pub fn format_line(
    seq: u64,
    fields: &Fields,
    prev: &[u8; EKI_AUDIT_HASH_LEN],
) -> (Vec<u8>, [u8; EKI_AUDIT_HASH_LEN]) {
    let covered = format!(
        "{{\"seq\":{seq},\"time\":\"{time}\",\"op\":\"{op}\",\"key\":\"{key}\",\"key2\":\"{key2}\",\
         \"status\":{status},\"prev\":\"{prev}\"",
        time = fields.time.format(),
        op = fields.op.name(),
        key = key_text(fields.key),
        key2 = key_text(fields.key2),
        status = fields.status,
        prev = hex(prev),
    );
    let hash: [u8; EKI_AUDIT_HASH_LEN] = Sha256::digest(covered.as_bytes()).into();
    let mut line = covered.into_bytes();
    line.extend_from_slice(b",\"hash\":\"");
    line.extend_from_slice(hex(&hash).as_bytes());
    line.extend_from_slice(b"\"}\n");
    (line, hash)
}

// --- Matching a line ---------------------------------------------------------------------------

/// A position in a line being matched.
struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    /// Consumes `text`, which must come next.
    fn literal(&mut self, text: &[u8]) -> Option<()> {
        self.rest = self.rest.strip_prefix(text)?;
        Some(())
    }

    /// Consumes and returns the bytes up to the next `"`, and the `"`.
    fn quoted(&mut self) -> Option<&'a [u8]> {
        let end = self.rest.iter().position(|&byte| byte == b'"')?;
        let (value, rest) = self.rest.split_at(end);
        self.rest = rest.get(1..)?;
        Some(value)
    }

    /// Consumes and returns the run of ASCII digits that comes next, possibly empty.
    fn digits(&mut self) -> &'a [u8] {
        let end = self
            .rest
            .iter()
            .position(|byte| !byte.is_ascii_digit())
            .unwrap_or(self.rest.len());
        let (digits, rest) = self.rest.split_at(end);
        self.rest = rest;
        digits
    }
}

/// The fields a writer chose in `line` (without its `\n`), if the line has the grammar of a
/// record. `seq`, `prev` and `hash` are only stepped over: the caller formats the line those
/// fields must give and compares, which checks them.
fn match_fields(line: &[u8]) -> Option<Fields> {
    let mut cursor = Cursor { rest: line };
    cursor.literal(b"{\"seq\":")?;
    cursor.digits();
    cursor.literal(b",\"time\":\"")?;
    let time = Timestamp::parse(cursor.quoted()?)?;
    cursor.literal(b",\"op\":\"")?;
    let op = Op::from_name(cursor.quoted()?)?;
    cursor.literal(b",\"key\":\"")?;
    let key = optional_key(cursor.quoted()?)?;
    cursor.literal(b",\"key2\":\"")?;
    let key2 = optional_key(cursor.quoted()?)?;
    cursor.literal(b",\"status\":")?;
    let status = status_from(cursor.digits())?;
    Some(Fields {
        time,
        op,
        key,
        key2,
        status,
    })
}

/// A `key` or `key2` field: empty, or an id.
fn optional_key(text: &[u8]) -> Option<Option<KeyId>> {
    if text.is_empty() {
        Some(None)
    } else {
        key_id_from_hex(text).map(Some)
    }
}

/// A `status` field: one or two digits naming a status value. Leading zeros are not rejected
/// here; the comparison with the formatted line rejects them.
fn status_from(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.len() > 2 {
        return None;
    }
    let value = u32::try_from(decimal(digits)?).ok()?;
    (value <= STATUS_MAX).then_some(value)
}

// --- Verifying a log ---------------------------------------------------------------------------

/// Where a valid log ends: the number of records, the hash of the last one (the head) and the
/// length of the file in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chain {
    /// The number of records, which is also the `seq` of the last one.
    pub records: u64,
    /// The hash of the last record; [`ZERO_HASH`] for an empty log.
    pub head: [u8; EKI_AUDIT_HASH_LEN],
    /// The length of the log in bytes.
    pub len: u64,
}

impl Chain {
    /// The chain of an empty log. A function rather than an associated constant, which cbindgen
    /// would export into the C header.
    pub const fn empty() -> Self {
        Self {
            records: 0,
            head: ZERO_HASH,
            len: 0,
        }
    }
}

/// Why a log failed verification.
#[derive(Debug)]
pub enum VerifyError {
    /// The log could not be read: `EKI_ERR_BACKEND`.
    Io(io::Error),
    /// The log is not a valid chain: `EKI_ERR_AUTH_FAILED`.
    Invalid,
}

/// Verifies the log `reader` yields, record by record, holding at most one line in memory.
///
/// Every line, its `\n` included, has at most [`LINE_MAX`] bytes and is exactly the record that
/// its fields give at its position in the chain. The log ends with `\n` (or is empty). A
/// trailing empty line and `\r\n` line ends fail like any other deviation.
pub fn verify(reader: impl Read) -> Result<Chain, VerifyError> {
    let mut reader = BufReader::new(reader);
    let mut chain = Chain::empty();
    let mut line = Vec::with_capacity(LINE_MAX);
    loop {
        line.clear();
        // Reads up to the next `\n` but never more than `LINE_MAX` bytes, so a hostile file
        // cannot make the line buffer grow.
        let read = (&mut reader)
            .take(LINE_MAX as u64)
            .read_until(b'\n', &mut line)
            .map_err(VerifyError::Io)?;
        if read == 0 {
            return Ok(chain);
        }
        chain = next_link(&chain, &line).ok_or(VerifyError::Invalid)?;
    }
}

/// The chain after `line` (with its `\n`), if `line` is the next record of `chain`. A line
/// without `\n` is either the end of a file that does not end with `\n` or longer than
/// [`LINE_MAX`]; both fail.
fn next_link(chain: &Chain, line: &[u8]) -> Option<Chain> {
    let body = line.strip_suffix(b"\n")?;
    let fields = match_fields(body)?;
    let seq = chain.records.checked_add(1)?;
    let (expected, hash) = format_line(seq, &fields, &chain.head);
    (expected == line).then_some(Chain {
        records: seq,
        head: hash,
        len: chain.len.checked_add(u64::try_from(line.len()).ok()?)?,
    })
}

/// The path of an audit log as the caller gave it (the bytes before the NUL), if it has 1 to
/// `EKI_AUDIT_PATH_MAX_LEN` bytes.
pub fn parse_path(text: &[u8]) -> Result<PathBuf, Error> {
    if !(1..=EKI_AUDIT_PATH_MAX_LEN).contains(&text.len()) {
        return Err(Error::InvalidArgument);
    }
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(text)))
}

/// `eki_audit_verify`: the path format (`INVALID_ARGUMENT`), the file (`BACKEND` when it cannot
/// be opened or read, a directory included), the chain and `expected_head` (`AUTH_FAILED`).
/// Returns the number of records.
pub fn verify_file(
    path: &[u8],
    expected_head: Option<&[u8; EKI_AUDIT_HASH_LEN]>,
) -> Result<u64, Error> {
    let path = parse_path(path)?;
    let file = File::open(path).map_err(|_| Error::Backend)?;
    let chain = verify(file).map_err(|error| match error {
        VerifyError::Io(_) => Error::Backend,
        VerifyError::Invalid => Error::AuthFailed,
    })?;
    // The head is public, so a variable-time comparison leaks nothing.
    if expected_head.is_some_and(|head| *head != chain.head) {
        return Err(Error::AuthFailed);
    }
    Ok(chain.records)
}

// --- Writing a log -----------------------------------------------------------------------------

/// Where records go: the locked log file, or a substitute in the tests.
pub trait Sink: Send {
    /// Appends `bytes` with one write and flushes them to stable storage before returning. A
    /// write that takes fewer bytes is a failure.
    fn append(&mut self, bytes: &[u8]) -> io::Result<()>;

    /// Cuts the file back to its first `len` bytes and flushes that change.
    fn truncate(&mut self, len: u64) -> io::Result<()>;
}

/// The log file, opened for appending and locked for the life of the handle. Dropping it closes
/// the file, which releases the lock.
struct LogFile(File);

impl Sink for LogFile {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let written = loop {
            match self.0.write(bytes) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                other => break other?,
            }
        };
        if written != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short write: {written} of {} bytes", bytes.len()),
            ));
        }
        self.0.sync_data()
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.0.set_len(len)?;
        self.0.sync_data()
    }
}

/// Why a log could not be opened.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The existing content failed verification: `EKI_ERR_AUTH_FAILED`.
    Invalid,
    /// The file could not be opened, created, locked or read: `EKI_ERR_BACKEND`.
    Failed(String),
}

/// The audit log of a handle: where the next record goes and the chain so far.
pub struct AuditLog {
    sink: Box<dyn Sink>,
    chain: Chain,
    /// Set when a failed write could not be cut off again: the file then ends in a partial
    /// line, and a record appended after it could never be verified, so nothing more is written.
    broken: bool,
}

impl AuditLog {
    /// Opens the log at `path` for the life of a handle: opened for appending and created with
    /// mode 0600 if missing; locked exclusively without waiting (a lock of the open file, which
    /// a second open of the same file in this process does not share); then verified from the
    /// start. Nothing is written: a log that fails is left byte for byte as it was.
    pub fn open(path: &Path) -> Result<Self, OpenError> {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(LOG_FILE_MODE)
            .open(path)
            .map_err(|error| OpenError::Failed(format!("opening the audit log failed: {error}")))?;
        file.try_lock().map_err(|error| {
            OpenError::Failed(match error {
                TryLockError::WouldBlock => "the audit log is locked by another handle".to_owned(),
                TryLockError::Error(error) => format!("locking the audit log failed: {error}"),
            })
        })?;
        let chain = verify(&file).map_err(|error| match error {
            VerifyError::Io(error) => {
                OpenError::Failed(format!("reading the audit log failed: {error}"))
            }
            VerifyError::Invalid => OpenError::Invalid,
        })?;
        Ok(Self::continuing(Box::new(LogFile(file)), chain))
    }

    /// A log that writes to `sink` and continues `chain`.
    pub fn continuing(sink: Box<dyn Sink>, chain: Chain) -> Self {
        Self {
            sink,
            chain,
            broken: false,
        }
    }

    /// The hash and `seq` of the last record.
    pub fn head(&self) -> ([u8; EKI_AUDIT_HASH_LEN], u64) {
        (self.chain.head, self.chain.records)
    }

    /// Appends the next record. On failure the text says why, the chain is unchanged, and a
    /// partly written line is cut off again.
    pub fn append(&mut self, fields: &Fields) -> Result<(), String> {
        if self.broken {
            return Err(
                "the audit log ends in a partial record that could not be removed, \
                        so no record can be added"
                    .to_owned(),
            );
        }
        let seq = self
            .chain
            .records
            .checked_add(1)
            .ok_or_else(|| "the audit log has no sequence number left".to_owned())?;
        let (line, hash) = format_line(seq, fields, &self.chain.head);
        let len = u64::try_from(line.len())
            .ok()
            .and_then(|added| self.chain.len.checked_add(added))
            .ok_or_else(|| "the audit log is too long".to_owned())?;
        if let Err(error) = self.sink.append(&line) {
            if self.sink.truncate(self.chain.len).is_err() {
                self.broken = true;
            }
            return Err(format!("writing the audit record failed: {error}"));
        }
        // Every step that can fail is behind: the chain moves on in one assignment.
        self.chain = Chain {
            records: seq,
            head: hash,
            len,
        };
        Ok(())
    }
}

/// A substitute for the log file in the unit tests of this module and of the store.
#[cfg(test)]
pub(crate) mod recorder {
    use std::io;
    use std::sync::{Arc, Mutex};

    use super::Sink;

    /// A sink that records what it was given and can be told to fail.
    #[derive(Clone, Default)]
    pub(crate) struct Recorder {
        pub(crate) bytes: Arc<Mutex<Vec<u8>>>,
        /// `append` writes half of the line, then fails.
        pub(crate) fail_append: Arc<Mutex<bool>>,
        /// `truncate` fails.
        pub(crate) fail_truncate: Arc<Mutex<bool>>,
    }

    impl Sink for Recorder {
        fn append(&mut self, line: &[u8]) -> io::Result<()> {
            let mut bytes = self.bytes.lock().expect("test lock");
            if *self.fail_append.lock().expect("test lock") {
                bytes.extend_from_slice(&line[..line.len() / 2]);
                return Err(io::Error::other("injected write failure"));
            }
            bytes.extend_from_slice(line);
            Ok(())
        }

        fn truncate(&mut self, len: u64) -> io::Result<()> {
            if *self.fail_truncate.lock().expect("test lock") {
                return Err(io::Error::other("injected truncate failure"));
            }
            let len = usize::try_from(len).expect("small");
            self.bytes.lock().expect("test lock").truncate(len);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::recorder::Recorder;
    use super::*;

    const ID: KeyId = KeyId([0xAB; EKI_KEY_ID_LEN]);
    const ID2: KeyId = KeyId([0x01; EKI_KEY_ID_LEN]);

    fn fields(op: Op, key: Option<KeyId>, key2: Option<KeyId>, status: u32) -> Fields {
        Fields {
            time: Timestamp::from_secs(1_794_389_400).expect("in range"),
            op,
            key,
            key2,
            status,
        }
    }

    /// A log of `n` records built with the formatter.
    fn log_of(n: u64) -> (Vec<u8>, Chain) {
        let mut bytes = Vec::new();
        let mut chain = Chain::empty();
        for seq in 1..=n {
            let op = Op::ALL[usize::try_from(seq).expect("small") % Op::ALL.len()];
            let (line, hash) = format_line(seq, &fields(op, Some(ID), None, 0), &chain.head);
            bytes.extend_from_slice(&line);
            chain = Chain {
                records: seq,
                head: hash,
                len: bytes.len() as u64,
            };
        }
        (bytes, chain)
    }

    fn verdict(bytes: &[u8]) -> Result<Chain, ()> {
        verify(bytes).map_err(|_| ())
    }

    #[test]
    fn timestamps_format_known_dates() {
        for (seconds, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (1_794_389_400, "2026-11-11T09:30:00Z"),
            (4_107_542_399, "2100-02-28T23:59:59Z"),
            (4_107_542_400, "2100-03-01T00:00:00Z"),
            (TIMESTAMP_MAX, "9999-12-31T23:59:59Z"),
        ] {
            let time = Timestamp::from_secs(seconds).expect("in range");
            assert_eq!(time.format(), text, "{seconds}");
            assert_eq!(Timestamp::parse(text.as_bytes()), Some(time), "{text}");
        }
        assert_eq!(Timestamp::from_secs(TIMESTAMP_MAX + 1), None);
    }

    #[test]
    fn every_day_from_1970_to_2500_round_trips() {
        let mut previous = None;
        for days in 0..194_000 {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days);
            if let Some((y, m, d)) = previous {
                assert!((year, month, day) > (y, m, d), "dates increase");
            }
            previous = Some((year, month, day));
        }
    }

    #[test]
    fn timestamp_parse_rejects_shapes_and_ranges() {
        for text in [
            "2026-11-11T09:30:00",
            "2026-11-11 09:30:00Z",
            "2026-11-11T09:30:00z",
            "26-11-11T09:30:00Z",
            "2026-13-11T09:30:00Z",
            "2026-00-11T09:30:00Z",
            "2026-11-00T09:30:00Z",
            "2026-11-32T09:30:00Z",
            "2026-11-11T24:00:00Z",
            "2026-11-11T09:60:00Z",
            "2026-11-11T09:30:60Z",
            "1969-12-31T23:59:59Z",
            "2026-1a-11T09:30:00Z",
            "+026-11-11T09:30:00Z",
        ] {
            assert_eq!(Timestamp::parse(text.as_bytes()), None, "{text}");
        }
    }

    #[test]
    fn line_has_the_exact_shape_and_hash() {
        let (line, hash) = format_line(1, &fields(Op::Generate, Some(ID), None, 0), &ZERO_HASH);
        let text = String::from_utf8(line).expect("ASCII");
        let covered = format!(
            "{{\"seq\":1,\"time\":\"2026-11-11T09:30:00Z\",\"op\":\"generate\",\"key\":\"{}\",\
             \"key2\":\"\",\"status\":0,\"prev\":\"{}\"",
            "ab".repeat(16),
            "0".repeat(64)
        );
        assert_eq!(text, format!("{covered},\"hash\":\"{}\"}}\n", hex(&hash)));
        let expected: [u8; 32] = Sha256::digest(covered.as_bytes()).into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn known_record_hash() {
        // Pins the hash input byte for byte, for comparison with the C++ library: SHA-256 of
        // the text before `,"hash":`.
        let (line, hash) = format_line(
            7,
            &fields(Op::Unwrap, Some(ID), Some(ID2), 5),
            &[0x11; EKI_AUDIT_HASH_LEN],
        );
        assert_eq!(
            String::from_utf8(line).expect("ASCII"),
            format!(
                "{{\"seq\":7,\"time\":\"2026-11-11T09:30:00Z\",\"op\":\"unwrap\",\"key\":\"{}\",\
                 \"key2\":\"{}\",\"status\":5,\"prev\":\"{}\",\"hash\":\"{}\"}}\n",
                "ab".repeat(16),
                "01".repeat(16),
                "11".repeat(32),
                hex(&hash),
            )
        );
        assert_eq!(
            hex(&hash),
            "b846dab28101f7ca131a082f37621adbef8de7b6b9ea1010295cef3c994801bd"
        );
    }

    #[test]
    fn longest_line_fits() {
        let (line, _) = format_line(
            u64::MAX,
            &fields(Op::DestroyApprove, Some(ID), Some(ID2), STATUS_MAX),
            &ZERO_HASH,
        );
        assert_eq!(line.len(), 325);
        assert!(line.len() <= LINE_MAX);
    }

    #[test]
    fn formatted_logs_verify() {
        assert_eq!(verdict(b""), Ok(Chain::empty()));
        for n in [1, 2, 15] {
            let (bytes, chain) = log_of(n);
            assert_eq!(verdict(&bytes), Ok(chain));
        }
    }

    #[test]
    fn every_op_and_status_round_trips() {
        let mut chain = Chain::empty();
        let mut bytes = Vec::new();
        for op in Op::ALL {
            for status in 0..=STATUS_MAX {
                for (key, key2) in [(None, None), (Some(ID), None), (Some(ID), Some(ID2))] {
                    let seq = chain.records + 1;
                    let (line, hash) =
                        format_line(seq, &fields(op, key, key2, status), &chain.head);
                    bytes.extend_from_slice(&line);
                    chain = Chain {
                        records: seq,
                        head: hash,
                        len: bytes.len() as u64,
                    };
                }
            }
        }
        assert_eq!(verdict(&bytes), Ok(chain));
    }

    #[test]
    fn any_changed_byte_fails() {
        let (bytes, _) = log_of(3);
        for i in 0..bytes.len() {
            for flip in [0x01, 0x20, 0x80] {
                let mut changed = bytes.clone();
                changed[i] ^= flip;
                assert_eq!(verdict(&changed), Err(()), "byte {i} ^ {flip:#x}");
            }
        }
    }

    #[test]
    fn structural_tampering_fails() {
        let (bytes, chain) = log_of(4);
        let lines: Vec<&[u8]> = bytes.split_inclusive(|&b| b == b'\n').collect();
        let joined = |parts: &[&[u8]]| parts.concat();
        let rows: Vec<(&str, Vec<u8>)> = vec![
            ("line removed", joined(&[lines[0], lines[2], lines[3]])),
            ("first line removed", joined(&lines[1..])),
            (
                "lines swapped",
                joined(&[lines[0], lines[2], lines[1], lines[3]]),
            ),
            ("line repeated", joined(&[&bytes, lines[3]])),
            ("no final newline", bytes[..bytes.len() - 1].to_vec()),
            ("empty line at the end", joined(&[&bytes, b"\n"])),
            ("empty line first", joined(&[b"\n", &bytes])),
            (
                "CRLF",
                lines
                    .iter()
                    .flat_map(|l| [&l[..l.len() - 1], b"\r\n"].concat())
                    .collect(),
            ),
            ("long line", joined(&[&bytes, &[b'a'; 600], b"\n"])),
            ("NUL byte appended", joined(&[&bytes, b"\0"])),
        ];
        for (row, content) in rows {
            assert_eq!(verdict(&content), Err(()), "{row}");
        }
        // Cutting the tail off is not visible in the chain alone.
        let cut = joined(&lines[..3]);
        let cut_chain = verdict(&cut).expect("a prefix is a valid chain");
        assert_eq!(cut_chain.records, 3);
        assert_ne!(cut_chain.head, chain.head);
    }

    #[test]
    fn non_canonical_fields_fail_even_with_a_correct_hash() {
        // Each line is re-hashed after the edit, so only the grammar can reject it.
        let base = fields(Op::Sign, Some(ID), None, 6);
        let (line, _) = format_line(1, &base, &ZERO_HASH);
        let text = String::from_utf8(line).expect("ASCII");
        let rehash = |edited: &str| -> Vec<u8> {
            let covered = edited
                .split(",\"hash\":")
                .next()
                .expect("has a hash field")
                .to_owned();
            let hash: [u8; 32] = Sha256::digest(covered.as_bytes()).into();
            format!("{covered},\"hash\":\"{}\"}}\n", hex(&hash)).into_bytes()
        };
        assert!(
            verdict(&rehash(&text)).is_ok(),
            "the rehash itself is faithful"
        );
        for (row, from, to) in [
            ("leading zero in seq", "\"seq\":1,", "\"seq\":01,"),
            ("seq 2 first", "\"seq\":1,", "\"seq\":2,"),
            ("leading zero in status", "\"status\":6,", "\"status\":06,"),
            ("status 13", "\"status\":6,", "\"status\":13,"),
            ("uppercase key", &"ab".repeat(16), &"AB".repeat(16)),
            ("short key", &"ab".repeat(16), &"ab".repeat(15)),
            ("unknown op", "\"op\":\"sign\"", "\"op\":\"Sign\""),
            ("space", ",\"time\"", ", \"time\""),
            ("February 30", "2026-11-11", "2026-02-30"),
            ("other key order", "\"key\":", "\"kex\":"),
        ] {
            let edited = text.replacen(from, to, 1);
            assert_ne!(edited, text, "{row}: the edit applies");
            assert_eq!(verdict(&rehash(&edited)), Err(()), "{row}");
        }
    }

    #[test]
    fn hostile_bytes_never_panic() {
        let (bytes, _) = log_of(2);
        for cut in 0..bytes.len() {
            let _ = verdict(&bytes[..cut]);
            let _ = match_fields(&bytes[..cut]);
        }
        for junk in [
            &b"{"[..],
            b"{\"seq\":",
            b"\xff\xfe\n",
            b"\"\"\"\n",
            &[b'9'; 600],
        ] {
            let _ = verdict(junk);
        }
    }

    #[test]
    fn path_length_is_checked() {
        assert_eq!(parse_path(b""), Err(Error::InvalidArgument));
        assert_eq!(
            parse_path(&[b'a'; EKI_AUDIT_PATH_MAX_LEN + 1]),
            Err(Error::InvalidArgument)
        );
        assert!(parse_path(&[b'a'; EKI_AUDIT_PATH_MAX_LEN]).is_ok());
    }

    #[test]
    fn failed_write_is_cut_off_and_the_chain_stays() {
        let recorder = Recorder::default();
        let mut log = AuditLog::continuing(Box::new(recorder.clone()), Chain::empty());
        log.append(&fields(Op::Open, None, None, 0))
            .expect("written");
        let head = log.head();
        *recorder.fail_append.lock().expect("test lock") = true;
        let error = log
            .append(&fields(Op::Sign, Some(ID), None, 0))
            .expect_err("injected failure");
        assert!(error.contains("injected write failure"), "{error}");
        assert_eq!(log.head(), head, "the chain did not move");
        *recorder.fail_append.lock().expect("test lock") = false;
        log.append(&fields(Op::Close, None, None, 0))
            .expect("written");
        let bytes = recorder.bytes.lock().expect("test lock").clone();
        let chain = verdict(&bytes).expect("still a valid log");
        assert_eq!(chain.records, 2);
        assert_eq!(log.head(), (chain.head, 2));
    }

    #[test]
    fn failed_cut_stops_all_writing() {
        let recorder = Recorder::default();
        let mut log = AuditLog::continuing(Box::new(recorder.clone()), Chain::empty());
        *recorder.fail_append.lock().expect("test lock") = true;
        *recorder.fail_truncate.lock().expect("test lock") = true;
        assert!(log.append(&fields(Op::Open, None, None, 0)).is_err());
        *recorder.fail_append.lock().expect("test lock") = false;
        let error = log
            .append(&fields(Op::Close, None, None, 0))
            .expect_err("broken");
        assert!(error.contains("partial record"), "{error}");
        assert_eq!(log.head(), (ZERO_HASH, 0));
    }

    #[test]
    fn file_log_is_created_0600_locked_and_continued() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "ekicore-rs-audit-unit-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("audit.log");
        let mut log = AuditLog::open(&path).expect("created");
        let mode = std::fs::metadata(&path)
            .expect("exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(
            matches!(AuditLog::open(&path), Err(OpenError::Failed(_))),
            "locked"
        );
        log.append(&fields(Op::Open, None, None, 0))
            .expect("written");
        let head = log.head();
        drop(log);
        let log = AuditLog::open(&path).expect("reopened after the lock was released");
        assert_eq!(log.head(), head);
        drop(log);
        let mut bytes = std::fs::read(&path).expect("readable");
        assert_eq!(
            verify_file(path.as_os_str().as_bytes(), Some(&head.0)),
            Ok(1)
        );
        bytes[3] ^= 1;
        std::fs::write(&path, &bytes).expect("writable");
        assert!(matches!(AuditLog::open(&path), Err(OpenError::Invalid)));
        assert_eq!(std::fs::read(&path).expect("readable"), bytes, "unchanged");
        assert_eq!(
            verify_file(dir.as_os_str().as_bytes(), None),
            Err(Error::Backend),
            "a directory"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
