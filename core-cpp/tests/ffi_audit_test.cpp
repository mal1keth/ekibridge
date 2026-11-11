// The audit log through the C ABI (docs/ffi-contract.md, "Audit log"): the byte-exact record format
// with SHA-256 recomputed independently, what is logged, the head, the verifier's matrix, the
// writer's open rows, and the rollback when a record cannot be written.
// Write failures are provoked with RLIMIT_FSIZE (and SIGXFSZ ignored), which makes write() fail
// with EFBIG at the limit or return a short count across it; macOS has no /dev/full.

#include "lifecycle_support.hpp"
#include "test_support.hpp"

#include <gtest/gtest.h>

#include <ekicore.h>

#include <openssl/evp.h>

#include <sys/resource.h>
#include <sys/stat.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <optional>
#include <regex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using eki_test::bytes;
using eki_test::fixed_id;
using eki_test::last_error;
using eki_test::name;
using eki_test::prefilled;
using eki_test::prefilled_id;
using eki_test::software_config;
using eki_test::unknown_id;
using eki_test::lifecycle::Approvers;
using eki_test::lifecycle::Handle;
using eki_test::lifecycle::Head;
using eki_test::lifecycle::kFillU32;
using eki_test::lifecycle::kFillU64;
using eki_test::lifecycle::read_file;
using eki_test::lifecycle::Request;
using eki_test::lifecycle::TempDir;
using eki_test::lifecycle::widen;
using eki_test::lifecycle::write_file;
namespace lifecycle = eki_test::lifecycle;

constexpr std::string_view zero_hash =
    "0000000000000000000000000000000000000000000000000000000000000000";

std::string to_hex(std::span<const std::uint8_t> data) {
  constexpr std::string_view digits = "0123456789abcdef";
  std::string out;
  for (const std::uint8_t byte : data) {
    out += digits.at(static_cast<unsigned>(byte) >> 4U);
    out += digits.at(byte & 0x0FU);
  }
  return out;
}

std::string id_hex(const eki_key_id& id) {
  return to_hex(id.bytes);
}

std::string sha256_hex(std::string_view text) {
  std::array<std::uint8_t, EVP_MAX_MD_SIZE> digest{};
  unsigned int len = 0;
  EXPECT_EQ(EVP_Digest(text.data(), text.size(), digest.data(), &len, EVP_sha256(), nullptr), 1);
  return to_hex(std::span{digest}.first(len));
}

// The fields of a record a test chooses, as the contract names them.
struct Fields {
  std::string seq;
  std::string time;
  std::string op;
  std::string key;
  std::string key2;
  std::string status;
};

// A record line with these fields after prev, with its correct hash. Used both to state what the
// library must write and to forge lines that are wrong in exactly one way.
std::string forge(const Fields& f, std::string_view prev) {
  std::string line = R"({"seq":)" + f.seq + R"(,"time":")" + f.time + R"(","op":")" + f.op +
                     R"(","key":")" + f.key + R"(","key2":")" + f.key2 + R"(","status":)" +
                     f.status + R"(,"prev":")" + std::string{prev} + "\"";
  const std::string hash = sha256_hex(line);
  return line + R"(,"hash":")" + hash + "\"}\n";
}

std::string hash_of(const std::string& line) {
  const std::size_t at = line.rfind(R"("hash":")");
  return at == std::string::npos ? std::string{} : line.substr(at + 8, 64);
}

// One record as read back from a file.
struct Record {
  std::uint64_t seq = 0;
  std::string time;
  std::string op;
  std::string key;
  std::string key2;
  std::int64_t status = -1;
  std::string prev;
  std::string hash;
  std::string line;
};

// The records of a file whose every line has the record shape; a test failure otherwise.
std::vector<Record> records_of(const std::string& path) {
  static const std::regex shape(R"re(\{"seq":([0-9]+),"time":"([^"]*)","op":"([a-z_]*)",)re"
                                R"re("key":"([0-9a-f]*)","key2":"([0-9a-f]*)","status":([0-9]+),)re"
                                R"re("prev":"([0-9a-f]{64})","hash":"([0-9a-f]{64})"\})re");
  const std::string content = read_file(path);
  std::vector<Record> records;
  std::size_t start = 0;
  while (start < content.size()) {
    const std::size_t end = content.find('\n', start);
    if (end == std::string::npos) {
      ADD_FAILURE() << "the file does not end with a newline";
      break;
    }
    const std::string line = content.substr(start, end - start);
    std::smatch match;
    if (!std::regex_match(line, match, shape)) {
      ADD_FAILURE() << "not a record: " << line;
      break;
    }
    records.push_back(Record{
        .seq = std::stoull(match.str(1)),
        .time = match.str(2),
        .op = match.str(3),
        .key = match.str(4),
        .key2 = match.str(5),
        .status = std::stoll(match.str(6)),
        .prev = match.str(7),
        .hash = match.str(8),
        .line = line + "\n",
    });
    start = end + 1;
  }
  return records;
}

// Seconds since the epoch of a "YYYY-MM-DDTHH:MM:SSZ" time, or nullopt for another shape.
std::optional<std::time_t> epoch_of(const std::string& time) {
  static const std::regex shape(
      R"(([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z)");
  std::smatch match;
  if (!std::regex_match(time, match, shape)) {
    return std::nullopt;
  }
  std::tm parts{};
  parts.tm_year = std::stoi(match.str(1)) - 1900;
  parts.tm_mon = std::stoi(match.str(2)) - 1;
  parts.tm_mday = std::stoi(match.str(3));
  parts.tm_hour = std::stoi(match.str(4));
  parts.tm_min = std::stoi(match.str(5));
  parts.tm_sec = std::stoi(match.str(6));
  return timegm(&parts);
}

// What a test expects of one record.
struct Expected {
  std::string op;
  std::string key;
  std::string key2;
  eki_status status = EKI_OK;
};

Expected rec(std::string op, const eki_key_id* key = nullptr, const eki_key_id* key2 = nullptr,
             eki_status status = EKI_OK) {
  return Expected{
      .op = std::move(op),
      .key = key == nullptr ? "" : id_hex(*key),
      .key2 = key2 == nullptr ? "" : id_hex(*key2),
      .status = status,
  };
}

// What a call is expected to record, with the ids held by address. A test passes the call and
// its plan as two arguments of one function, and the order in which arguments are evaluated is
// unspecified (GCC evaluates the last one first), so an id that the call fills must not be read
// while the arguments are built. `expected` reads the ids once the call has returned.
struct Planned {
  std::string op;
  const eki_key_id* key = nullptr;
  const eki_key_id* key2 = nullptr;
  eki_status status = EKI_OK;

  [[nodiscard]] Expected expected() const {
    return rec(op, key, key2, status);
  }
};

Planned plan(std::string op, const eki_key_id* key = nullptr, const eki_key_id* key2 = nullptr,
             eki_status status = EKI_OK) {
  return Planned{.op = std::move(op), .key = key, .key2 = key2, .status = status};
}

// The seconds a test ran in.
struct Window {
  std::time_t started = 0;
  std::time_t finished = 0;
};

// NOLINTBEGIN(readability-function-cognitive-complexity)

// Every record is exactly the line its fields make, chained from 64 zeros, with times inside
// [started - 1, finished + 1], and the fields match `expected`.
void check_log(const std::string& path, const std::vector<Expected>& expected,
               const Window& window) {
  const std::vector<Record> records = records_of(path);
  ASSERT_EQ(records.size(), expected.size());
  std::string prev{zero_hash};
  for (std::size_t i = 0; i < records.size(); ++i) {
    SCOPED_TRACE("record " + std::to_string(i + 1));
    const Record& r = records.at(i);
    const Expected& want = expected.at(i);
    EXPECT_EQ(r.seq, i + 1);
    EXPECT_EQ(r.op, want.op);
    EXPECT_EQ(r.key, want.key);
    EXPECT_EQ(r.key2, want.key2);
    EXPECT_EQ(name(static_cast<eki_status>(r.status)), name(want.status));
    const std::optional<std::time_t> t = epoch_of(r.time);
    ASSERT_TRUE(t.has_value()) << r.time;
    EXPECT_GE(t.value_or(0), window.started - 1);
    EXPECT_LE(t.value_or(0), window.finished + 1);
    const Fields fields{
        .seq = std::to_string(r.seq),
        .time = r.time,
        .op = want.op,
        .key = want.key,
        .key2 = want.key2,
        .status = std::to_string(want.status),
    };
    EXPECT_EQ(r.line, forge(fields, prev));
    prev = r.hash;
  }
}

// eki_audit_verify with an optional head; records_out, or nullopt with the status on failure.
eki_status verify(const std::string& path, const std::optional<Head>& head,
                  std::uint64_t& records) {
  records = kFillU64;
  const eki_status status =
      eki_audit_verify(path.c_str(), head.has_value() ? head->data() : nullptr, &records);
  if (status != EKI_OK) {
    EXPECT_EQ(records, 0U) << "records_out is zero-filled on failure";
  }
  return status;
}

Head head_bytes(const std::string& hex_text) {
  Head head{};
  const std::vector<std::uint8_t> raw = eki_test::hex(hex_text);
  std::ranges::copy(raw, head.begin());
  return head;
}

// Lowers RLIMIT_FSIZE for the life of the object, with SIGXFSZ ignored so that a write past the
// limit fails with EFBIG (or returns short) instead of killing the process.
class FileSizeLimit {
public:
  explicit FileSizeLimit(std::uintmax_t limit) : previous_(std::signal(SIGXFSZ, SIG_IGN)) {
    if (getrlimit(RLIMIT_FSIZE, &saved_) != 0) {
      ADD_FAILURE() << "getrlimit failed";
      return;
    }
    rlimit lowered = saved_;
    lowered.rlim_cur = static_cast<rlim_t>(limit);
    active_ = setrlimit(RLIMIT_FSIZE, &lowered) == 0;
    EXPECT_TRUE(active_) << "setrlimit failed";
  }
  FileSizeLimit(const FileSizeLimit&) = delete;
  FileSizeLimit& operator=(const FileSizeLimit&) = delete;
  FileSizeLimit(FileSizeLimit&&) = delete;
  FileSizeLimit& operator=(FileSizeLimit&&) = delete;
  // Raising the soft limit back to its saved value cannot fail: the hard limit is unchanged.
  ~FileSizeLimit() {
    if (active_) {
      static_cast<void>(setrlimit(RLIMIT_FSIZE, &saved_));
    }
    static_cast<void>(std::signal(SIGXFSZ, previous_));
  }

private:
  void (*previous_)(int);
  rlimit saved_{};
  bool active_ = false;
};

std::uintmax_t size_of(const std::string& path) {
  return std::filesystem::file_size(path);
}

bool contains(const std::optional<std::string>& text, std::string_view part) {
  return text.has_value() && text->find(part) != std::string::npos;
}

// One generate between open and close: each line equals the line its fields make, byte for byte,
// with the hash recomputed here; the file is 0600 and ends with a newline.
TEST(FfiAudit, RecordFormatIsExact) {
  const TempDir dir;
  const std::string path = dir.file("exact.log");
  const std::time_t started = std::time(nullptr);
  eki_key_id id{};
  {
    Handle h(software_config());
    ASSERT_TRUE(h.open(widen(software_config(), path.c_str())));
    ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "exact", id));
  }
  const std::time_t finished = std::time(nullptr);
  check_log(path, {rec("open"), rec("generate", &id), rec("close")},
            {.started = started, .finished = finished});
  struct stat info{};
  ASSERT_EQ(::stat(path.c_str(), &info), 0);
  EXPECT_EQ(info.st_mode & 0777U, 0600U);
  std::uint64_t records = 0;
  EKI_EXPECT_STATUS(verify(path, std::nullopt, records), EKI_OK);
  EXPECT_EQ(records, 3U);
}

// Every eki_ks_* call that passed its NULL checks is logged with its final status, with the ids
// the contract names; NULL-check failures, get_info, get_info_v2, last_error_message and
// audit_head are not. audit_head follows every record.
TEST(FfiAudit, ScriptedLogRecordsEveryCall) {
  const TempDir dir;
  const std::string path = dir.file("script.log");
  const Approvers approvers(2);
  const std::time_t started = std::time(nullptr);
  std::vector<Expected> want{rec("open")};
  {
    Handle h(software_config());
    ASSERT_TRUE(
        h.open(widen(software_config(), path.c_str(), approvers.keys(), approvers.count())));
    eki_ks* ks = h.get();
    const auto logged = [&](eki_status got, const Planned& planned) {
      EKI_EXPECT_STATUS(got, planned.status);
      want.push_back(planned.expected());
      Head hash{};
      std::uint64_t seq = 0;
      EKI_EXPECT_STATUS(eki_ks_audit_head(ks, hash.data(), &seq), EKI_OK);
      EXPECT_EQ(seq, want.size()) << want.back().op;
    };
    const eki_key_id missing = unknown_id();
    const std::span<const std::uint8_t> msg = bytes("script");
    eki_key_id kek = prefilled_id();
    eki_key_id mac = prefilled_id();
    eki_key_id ec = prefilled_id();
    eki_key_id none = prefilled_id();
    logged(eki_ks_generate(ks, EKI_KEY_AES_256, "kek", &kek), plan("generate", &kek));
    h.track(kek);
    logged(eki_ks_generate(ks, EKI_KEY_HMAC_SHA256, "mac", &mac), plan("generate", &mac));
    h.track(mac);
    logged(eki_ks_generate(ks, EKI_KEY_ECDSA_P256, "ec", &ec), plan("generate", &ec));
    h.track(ec);
    logged(eki_ks_generate(ks, EKI_KEY_AES_256, "", &none),
           plan("generate", nullptr, nullptr, EKI_ERR_INVALID_ARGUMENT));
    logged(eki_ks_generate(ks, 99, "x", &none),
           plan("generate", nullptr, nullptr, EKI_ERR_INVALID_ARGUMENT));

    lifecycle::Signature sig{};
    logged(eki_ks_sign(ks, &ec, msg.data(), msg.size(), sig.data()), plan("sign", &ec));
    logged(eki_ks_sign(ks, &missing, msg.data(), msg.size(), sig.data()),
           plan("sign", &missing, nullptr, EKI_ERR_KEY_NOT_FOUND));
    // Failed NULL checks: not logged.
    EKI_EXPECT_STATUS(eki_ks_sign(ks, &ec, msg.data(), msg.size(), nullptr), EKI_ERR_NULL_POINTER);
    EKI_EXPECT_STATUS(eki_ks_rotate(ks, nullptr, &none), EKI_ERR_NULL_POINTER);
    EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, &mac, nullptr), EKI_ERR_NULL_POINTER);

    lifecycle::Tag tag{};
    logged(eki_ks_hmac_sha256(ks, &mac, msg.data(), msg.size(), tag.data()), plan("hmac", &mac));
    logged(eki_ks_hmac_sha256_verify(ks, &mac, msg.data(), msg.size(), tag.data(), tag.size()),
           plan("hmac_verify", &mac));
    logged(eki_ks_hmac_sha256_verify(ks, &mac, msg.data(), msg.size(), tag.data(), 31),
           plan("hmac_verify", &mac, nullptr, EKI_ERR_INVALID_ARGUMENT));
    lifecycle::PublicKey pk{};
    logged(eki_ks_get_public_key(ks, &ec, pk.data()), plan("get_public_key", &ec));
    lifecycle::Blob blob{};
    logged(eki_ks_wrap(ks, &kek, &mac, blob.data()), plan("wrap", &mac, &kek));
    const eki_key_id copy = fixed_id(0x42);
    logged(eki_ks_unwrap(ks, &kek, blob.data(), blob.size(), EKI_KEY_HMAC_SHA256, "copy", &copy),
           plan("unwrap", &copy, &kek));
    h.track(copy);
    logged(eki_ks_unwrap(ks, &kek, blob.data(), blob.size(), EKI_KEY_HMAC_SHA256, "copy", &copy),
           plan("unwrap", &copy, &kek, EKI_ERR_KEY_EXISTS));
    eki_key_id rotated{};
    logged(h.rotate(mac, rotated), plan("rotate", &mac, &rotated));
    eki_key_id again{};
    logged(h.rotate(mac, again), plan("rotate", &mac, nullptr, EKI_ERR_KEY_STATE));
    logged(eki_ks_revoke(ks, &copy), plan("revoke", &copy));

    // Not logged.
    eki_key_info info{};
    eki_key_info_v2 info_v2{};
    EKI_EXPECT_STATUS(eki_ks_get_info(ks, &kek, &info), EKI_OK);
    EKI_EXPECT_STATUS(eki_ks_get_info_v2(ks, &kek, &info_v2), EKI_OK);
    static_cast<void>(last_error(ks));
    EXPECT_EQ(lifecycle::head_seq(ks), std::optional<std::uint64_t>{want.size()});

    // Dual control.
    logged(eki_ks_destroy(ks, &ec), plan("destroy", &ec, nullptr, EKI_ERR_APPROVAL_REQUIRED));
    Request request{};
    logged(eki_ks_destroy_request(ks, &ec, request.data()), plan("destroy_request", &ec));
    std::uint32_t remaining = 0;
    logged(eki_ks_destroy_approve(ks, request.data(), approvers.key(0).data(),
                                  approvers.sign(0, request, ec).data(), &remaining),
           plan("destroy_approve", &ec));
    const Request unknown{};
    logged(eki_ks_destroy_approve(ks, unknown.data(), approvers.key(0).data(),
                                  approvers.sign(0, request, ec).data(), &remaining),
           plan("destroy_approve", nullptr, nullptr, EKI_ERR_KEY_NOT_FOUND));
    logged(eki_ks_destroy_approve(ks, request.data(), approvers.key(1).data(),
                                  approvers.sign(1, request, ec).data(), &remaining),
           plan("destroy_approve", &ec));
    EXPECT_EQ(remaining, 0U);
  }
  const std::time_t finished = std::time(nullptr);
  want.push_back(rec("close"));
  check_log(path, want, {.started = started, .finished = finished});
  std::uint64_t records = 0;
  EKI_EXPECT_STATUS(verify(path, std::nullopt, records), EKI_OK);
  EXPECT_EQ(records, want.size());
}

// audit_head reports the hash and seq of the last record; a handle without a log is UNSUPPORTED
// with both outputs zero-filled.
TEST(FfiAudit, AuditHead) {
  const TempDir dir;
  const std::string path = dir.file("head.log");
  Handle h(software_config());
  ASSERT_TRUE(h.open(widen(software_config(), path.c_str())));
  eki_key_id id{};
  ASSERT_TRUE(h.generate(EKI_KEY_HMAC_SHA256, "head", id));
  Head hash = prefilled<EKI_AUDIT_HASH_LEN>();
  std::uint64_t seq = kFillU64;
  EKI_EXPECT_STATUS(eki_ks_audit_head(h.get(), hash.data(), &seq), EKI_OK);
  EXPECT_EQ(seq, 2U);
  const std::vector<Record> records = records_of(path);
  ASSERT_EQ(records.size(), 2U);
  EXPECT_EQ(to_hex(hash), records.back().hash);
  std::uint64_t count = 0;
  EKI_EXPECT_STATUS(verify(path, hash, count), EKI_OK);
  EXPECT_EQ(count, 2U);

  Handle plain(software_config());
  ASSERT_TRUE(plain.open(widen(software_config())));
  hash = prefilled<EKI_AUDIT_HASH_LEN>();
  seq = kFillU64;
  EKI_EXPECT_STATUS(eki_ks_audit_head(plain.get(), hash.data(), &seq), EKI_ERR_UNSUPPORTED);
  EXPECT_TRUE(eki_test::all_zero(hash));
  EXPECT_EQ(seq, 0U);
}

// eki_audit_verify: path and file rows, and the chain rows ("Verification").
TEST(FfiAudit, VerifyMatrix) {
  const TempDir dir;
  const std::string path = dir.file("verify.log");
  {
    Handle h(software_config());
    ASSERT_TRUE(h.open(widen(software_config(), path.c_str())));
    eki_key_id id{};
    for (int i = 0; i < 3; ++i) {
      ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "verify", id));
    }
  }
  const std::string log = read_file(path);
  const std::vector<Record> records = records_of(path);
  ASSERT_EQ(records.size(), 5U);
  const Head full_head = head_bytes(records.back().hash);
  std::uint64_t n = 0;
  const std::string probe = dir.file("probe.log");
  const auto verify_text = [&](std::string_view content, const std::optional<Head>& head) {
    write_file(probe, content);
    return verify(probe, head, n);
  };

  // Path rows.
  EKI_EXPECT_STATUS(eki_audit_verify("", nullptr, &n), EKI_ERR_INVALID_ARGUMENT);
  const std::string too_long(EKI_AUDIT_PATH_MAX_LEN + 1, 'a');
  EKI_EXPECT_STATUS(eki_audit_verify(too_long.c_str(), nullptr, &n), EKI_ERR_INVALID_ARGUMENT);
  EKI_EXPECT_STATUS(verify(dir.file("missing.log"), std::nullopt, n), EKI_ERR_BACKEND);
  EKI_EXPECT_STATUS(verify(dir.path().string(), std::nullopt, n), EKI_ERR_BACKEND);

  // The intact log, with and without its head.
  EKI_EXPECT_STATUS(verify(path, std::nullopt, n), EKI_OK);
  EXPECT_EQ(n, 5U);
  EKI_EXPECT_STATUS(verify(path, full_head, n), EKI_OK);
  Head other = full_head;
  other.front() ^= 1U;
  EKI_EXPECT_STATUS(verify(path, other, n), EKI_ERR_AUTH_FAILED);

  // An empty file: 0 records; its head is 32 zero bytes.
  EKI_EXPECT_STATUS(verify_text("", std::nullopt), EKI_OK);
  EXPECT_EQ(n, 0U);
  EKI_EXPECT_STATUS(verify_text("", Head{}), EKI_OK);
  EKI_EXPECT_STATUS(verify_text("", full_head), EKI_ERR_AUTH_FAILED);

  // Every single byte changed.
  for (std::size_t i = 0; i < log.size(); ++i) {
    std::string flipped = log;
    flipped.at(i) = static_cast<char>(static_cast<unsigned char>(flipped.at(i)) ^ 1U);
    EXPECT_EQ(name(verify_text(flipped, std::nullopt)), name(EKI_ERR_AUTH_FAILED)) << "byte " << i;
  }

  // Lines removed, ends changed.
  const std::size_t tail_at = log.size() - records.back().line.size();
  const std::string without_tail = log.substr(0, tail_at);
  EKI_EXPECT_STATUS(verify_text(without_tail, full_head), EKI_ERR_AUTH_FAILED);
  EKI_EXPECT_STATUS(verify_text(without_tail, std::nullopt), EKI_OK);
  EXPECT_EQ(n, 4U);
  EKI_EXPECT_STATUS(verify_text(records.at(0).line + records.at(2).line, std::nullopt),
                    EKI_ERR_AUTH_FAILED);
  EKI_EXPECT_STATUS(verify_text(log.substr(0, log.size() - 1), std::nullopt), EKI_ERR_AUTH_FAILED);
  EKI_EXPECT_STATUS(verify_text(log + "\n", std::nullopt), EKI_ERR_AUTH_FAILED);
  std::string crlf = records.at(0).line;
  crlf.insert(crlf.size() - 1, "\r");
  EKI_EXPECT_STATUS(verify_text(crlf, std::nullopt), EKI_ERR_AUTH_FAILED);
  std::string spaced = records.at(0).line;
  spaced.insert(spaced.find(",\"time\""), " ");
  EKI_EXPECT_STATUS(verify_text(spaced, std::nullopt), EKI_ERR_AUTH_FAILED);
  EKI_EXPECT_STATUS(verify_text(std::string(600, 'a') + "\n", std::nullopt), EKI_ERR_AUTH_FAILED);
  EKI_EXPECT_STATUS(verify_text(log + std::string(600, 'a') + "\n", std::nullopt),
                    EKI_ERR_AUTH_FAILED);
}

// Lines forged with correct hashes that break one rule of the grammar each: the verifier checks
// the shape and the values, not only the chain.
TEST(FfiAudit, VerifyRejectsForgedLines) {
  const TempDir dir;
  const std::string probe = dir.file("forged.log");
  const std::string key(32, 'a');
  const Fields good{
      .seq = "1",
      .time = "2026-11-11T09:30:00Z",
      .op = "generate",
      .key = key,
      .key2 = "",
      .status = "0",
  };
  std::uint64_t n = 0;
  const auto check = [&](const Fields& fields, eki_status expected, const char* row) {
    write_file(probe, forge(fields, zero_hash));
    EXPECT_EQ(name(verify(probe, std::nullopt, n)), name(expected)) << row;
  };
  check(good, EKI_OK, "a forged line that obeys every rule");
  EXPECT_EQ(n, 1U);
  const auto with = [&good](auto change) {
    Fields f = good;
    change(f);
    return f;
  };
  check(with([](Fields& f) { f.seq = "2"; }), EKI_ERR_AUTH_FAILED, "seq 2 first");
  check(with([](Fields& f) { f.seq = "01"; }), EKI_ERR_AUTH_FAILED, "seq with a leading zero");
  check(with([](Fields& f) { f.seq = "0"; }), EKI_ERR_AUTH_FAILED, "seq 0");
  check(with([](Fields& f) { f.status = "00"; }), EKI_ERR_AUTH_FAILED, "status 00");
  check(with([](Fields& f) { f.status = "-1"; }), EKI_ERR_AUTH_FAILED, "status -1");
  check(with([](Fields& f) { f.status = "12"; }), EKI_OK, "status 12, the last ABI 2 status");
  check(with([](Fields& f) { f.status = "13"; }), EKI_ERR_AUTH_FAILED, "status 13");
  check(with([](Fields& f) { f.status = "100"; }), EKI_ERR_AUTH_FAILED, "status of 3 digits");
  check(with([](Fields& f) { f.status = "2147483647"; }), EKI_ERR_AUTH_FAILED, "status INT32_MAX");
  check(with([](Fields& f) { f.op = "erase"; }), EKI_ERR_AUTH_FAILED, "unknown op");
  check(with([](Fields& f) { f.op = "Generate"; }), EKI_ERR_AUTH_FAILED, "op in upper case");
  check(with([](Fields& f) { f.key = std::string(31, 'a'); }), EKI_ERR_AUTH_FAILED,
        "key of 31 digits");
  check(with([](Fields& f) { f.key = std::string(32, 'A'); }), EKI_ERR_AUTH_FAILED,
        "key in upper case");
  check(with([](Fields& f) { f.key2 = std::string(32, 'g'); }), EKI_ERR_AUTH_FAILED,
        "key2 not hex");
  check(with([](Fields& f) { f.time = "2026-11-11 09:30:00Z"; }), EKI_ERR_AUTH_FAILED,
        "time with a space");
  check(with([](Fields& f) { f.time = "2026-13-11T09:30:00Z"; }), EKI_ERR_AUTH_FAILED, "month 13");
  check(with([](Fields& f) { f.time = "2026-11-11T24:00:00Z"; }), EKI_ERR_AUTH_FAILED, "hour 24");
  check(with([](Fields& f) { f.time = "2026-11-11T09:30:60Z"; }), EKI_ERR_AUTH_FAILED, "second 60");
  check(with([](Fields& f) { f.time = "2026-11-11T09:60:00Z"; }), EKI_ERR_AUTH_FAILED, "minute 60");
  check(with([](Fields& f) { f.time = "2026-00-11T09:30:00Z"; }), EKI_ERR_AUTH_FAILED, "month 0");
  check(with([](Fields& f) { f.time = "2026-11-00T09:30:00Z"; }), EKI_ERR_AUTH_FAILED, "day 0");
  check(with([](Fields& f) { f.time = "2026-11-31T09:30:00Z"; }), EKI_ERR_AUTH_FAILED,
        "November 31");
  check(with([](Fields& f) { f.time = "2026-02-29T09:30:00Z"; }), EKI_ERR_AUTH_FAILED,
        "February 29 of a common year");
  check(with([](Fields& f) { f.time = "2028-02-29T09:30:00Z"; }), EKI_OK,
        "February 29 of a leap year");
  check(with([](Fields& f) { f.time = "2100-02-29T09:30:00Z"; }), EKI_ERR_AUTH_FAILED,
        "February 29 of 2100");
  check(with([](Fields& f) { f.time = "2000-02-29T09:30:00Z"; }), EKI_OK, "February 29 of 2000");
  check(with([](Fields& f) { f.time = "1969-12-31T23:59:59Z"; }), EKI_ERR_AUTH_FAILED,
        "a time before 1970");
  check(with([](Fields& f) { f.time = "1970-01-01T00:00:00Z"; }), EKI_OK, "the epoch");
  check(with([](Fields& f) { f.time = "9999-12-31T23:59:59Z"; }), EKI_OK, "the last second");

  // A prev that is not the previous hash; an upper-case hash.
  write_file(probe, forge(good, std::string(64, '1')));
  EKI_EXPECT_STATUS(verify(probe, std::nullopt, n), EKI_ERR_AUTH_FAILED);
  std::string upper = forge(good, zero_hash);
  std::transform(upper.end() - 67, upper.end() - 3, upper.end() - 67,
                 [](char c) { return static_cast<char>(std::toupper(c)); });
  write_file(probe, upper);
  EKI_EXPECT_STATUS(verify(probe, std::nullopt, n), EKI_ERR_AUTH_FAILED);
  // Two good lines chain.
  const std::string first = forge(good, zero_hash);
  Fields second = good;
  second.seq = "2";
  write_file(probe, first + forge(second, hash_of(first)));
  EKI_EXPECT_STATUS(verify(probe, std::nullopt, n), EKI_OK);
  EXPECT_EQ(n, 2U);
}

// The writer: an existing empty file starts at seq 1; a log continues across handles, also one
// another writer made; a locked log cannot be opened; a tampered one is AUTH_FAILED and stays
// byte for byte as it was.
TEST(FfiAudit, WriterOpenRows) {
  const TempDir dir;
  const std::string path = dir.file("writer.log");
  write_file(path, "");
  {
    Handle h(software_config());
    ASSERT_TRUE(h.open(widen(software_config(), path.c_str())));
    EXPECT_EQ(lifecycle::head_seq(h.get()), std::optional<std::uint64_t>{1});
    // Locked for the life of the handle, also against a second handle in this process.
    for (int i = 0; i < 2; ++i) {
      EXPECT_TRUE(
          lifecycle::open_v2_fails(widen(software_config(), path.c_str()), EKI_ERR_BACKEND));
    }
    EXPECT_EQ(lifecycle::head_seq(h.get()), std::optional<std::uint64_t>{1});
  }
  {
    Handle h(software_config());
    ASSERT_TRUE(h.open(widen(software_config(), path.c_str())));
    EXPECT_EQ(lifecycle::head_seq(h.get()), std::optional<std::uint64_t>{3});
  }
  std::uint64_t n = 0;
  EKI_EXPECT_STATUS(verify(path, std::nullopt, n), EKI_OK);
  EXPECT_EQ(n, 4U);

  // A log another writer made: the chain continues from its head.
  const std::string foreign = dir.file("foreign.log");
  const std::string line = forge(
      Fields{
          .seq = "1",
          .time = "2026-11-11T09:30:00Z",
          .op = "open",
          .key = "",
          .key2 = "",
          .status = "0",
      },
      zero_hash);
  write_file(foreign, line);
  {
    Handle h(software_config());
    ASSERT_TRUE(h.open(widen(software_config(), foreign.c_str())));
  }
  const std::vector<Record> continued = records_of(foreign);
  ASSERT_EQ(continued.size(), 3U);
  EXPECT_EQ(continued.at(1).seq, 2U);
  EXPECT_EQ(continued.at(1).prev, hash_of(line));

  // Tampered, or ending without a newline: AUTH_FAILED, file unchanged ("Opening a store with
  // ABI 2" in docs/ffi-contract.md).
  std::string tampered = read_file(path);
  tampered.at(10) = tampered.at(10) == '0' ? '1' : '0';
  write_file(path, tampered);
  EXPECT_TRUE(
      lifecycle::open_v2_fails(widen(software_config(), path.c_str()), EKI_ERR_AUTH_FAILED));
  EXPECT_EQ(read_file(path), tampered);
  const std::string cut = line.substr(0, line.size() - 1);
  write_file(foreign, cut);
  EXPECT_TRUE(
      lifecycle::open_v2_fails(widen(software_config(), foreign.c_str()), EKI_ERR_AUTH_FAILED));
  EXPECT_EQ(read_file(foreign), cut);
}

// A log must be a regular file: a directory, a device and a FIFO (which must not make the call wait
// for a writer) are BACKEND for the verifier and for the open call, whose *out stays NULL; a
// symbolic link to a regular file is followed.
TEST(FfiAudit, LogMustBeARegularFile) {
  const TempDir dir;
  const std::string fifo = dir.file("fifo");
  ASSERT_EQ(mkfifo(fifo.c_str(), S_IRUSR | S_IWUSR), 0) << "mkfifo failed";
  const std::string target = dir.file("target.log");
  {
    Handle h(software_config());
    ASSERT_TRUE(h.open(widen(software_config(), target.c_str())));
  }
  const std::string link = dir.file("link.log");
  std::filesystem::create_symlink(target, link);

  std::uint64_t n = 0;
  for (const std::string& path : {dir.path().string(), std::string{"/dev/null"}, fifo}) {
    EKI_EXPECT_STATUS(verify(path, std::nullopt, n), EKI_ERR_BACKEND) << path;
    EXPECT_TRUE(lifecycle::open_v2_fails(widen(software_config(), path.c_str()), EKI_ERR_BACKEND))
        << path;
  }
  EKI_EXPECT_STATUS(verify(link, std::nullopt, n), EKI_OK);
  EXPECT_EQ(n, 2U);
  Handle h(software_config());
  ASSERT_TRUE(h.open(widen(software_config(), link.c_str())));
  EXPECT_EQ(lifecycle::head_seq(h.get()), std::optional<std::uint64_t>{3});
}

// A record that cannot be written: the call is BACKEND with a text saying so, a key the call
// created is destroyed again, a request it changed is put back, a state change stays (no state
// leads back), the file is cut back to the intact chain, and the log goes on once writing works
// again.
TEST(FfiAudit, WriteFailureRollsBack) {
  const TempDir dir;
  const std::string path = dir.file("rollback.log");
  const Approvers approvers(2);
  Handle h(software_config());
  ASSERT_TRUE(h.open(widen(software_config(), path.c_str(), approvers.keys(), approvers.count())));
  eki_ks* ks = h.get();
  eki_key_id kek{};
  eki_key_id mac{};
  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "rollback kek", kek));
  ASSERT_TRUE(h.generate(EKI_KEY_HMAC_SHA256, "rollback mac", mac));
  lifecycle::Blob blob{};
  ASSERT_EQ(name(eki_ks_wrap(ks, &kek, &mac, blob.data())), name(EKI_OK));
  Request pending{};
  ASSERT_EQ(name(eki_ks_destroy_request(ks, &mac, pending.data())), name(EKI_OK));

  // Fails at the limit (EFBIG) and across it (a short write the writer cuts back).
  for (const std::uintmax_t slack : {std::uintmax_t{0}, std::uintmax_t{10}}) {
    SCOPED_TRACE(slack == 0 ? "EFBIG" : "short write");
    eki_key_id old{};
    eki_key_id doomed{};
    ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "rotated", old));
    ASSERT_TRUE(h.generate(EKI_KEY_HMAC_SHA256, "revoked", doomed));
    const std::string before = read_file(path);
    const std::optional<std::uint64_t> seq = lifecycle::head_seq(ks);
    {
      const FileSizeLimit limit(before.size() + slack);
      eki_key_id id = prefilled_id();
      EKI_EXPECT_STATUS(eki_ks_generate(ks, EKI_KEY_AES_256, "unlogged", &id), EKI_ERR_BACKEND);
      EXPECT_TRUE(eki_test::all_zero(eki_test::id_bytes(id)));
      const std::optional<std::string> text = last_error(ks);
      EXPECT_TRUE(contains(text, "the audit record could not be written")) << text.value_or("");
      EXPECT_TRUE(contains(text, "the key this call created was destroyed again"));

      const eki_key_id copy = fixed_id(0x43);
      EKI_EXPECT_STATUS(
          eki_ks_unwrap(ks, &kek, blob.data(), blob.size(), EKI_KEY_HMAC_SHA256, "copy", &copy),
          EKI_ERR_BACKEND);
      eki_key_info info{};
      EKI_EXPECT_STATUS(eki_ks_get_info(ks, &copy, &info), EKI_ERR_KEY_NOT_FOUND);

      // The new key is destroyed again; the old one stays RETIRED.
      eki_key_id rotated = prefilled_id();
      EKI_EXPECT_STATUS(eki_ks_rotate(ks, &old, &rotated), EKI_ERR_BACKEND);
      EXPECT_TRUE(eki_test::all_zero(eki_test::id_bytes(rotated)));
      // Read before get_info_v2, which resets the text.
      const std::optional<std::string> rotate_text = last_error(ks);
      EXPECT_TRUE(contains(rotate_text, "the key this call created was destroyed again"))
          << rotate_text.value_or("");
      EXPECT_TRUE(contains(rotate_text, "the key stays RETIRED, which cannot be undone"));
      EXPECT_EQ(h.state(old), EKI_KEY_STATE_RETIRED);

      EKI_EXPECT_STATUS(eki_ks_revoke(ks, &doomed), EKI_ERR_BACKEND);
      EXPECT_TRUE(contains(last_error(ks), "the key stays REVOKED, which cannot be undone"));
      EXPECT_EQ(h.state(doomed), EKI_KEY_STATE_REVOKED);

      Request replaced = prefilled<EKI_DESTROY_REQUEST_LEN>();
      EKI_EXPECT_STATUS(eki_ks_destroy_request(ks, &mac, replaced.data()), EKI_ERR_BACKEND);
      EXPECT_TRUE(eki_test::all_zero(replaced));

      std::uint32_t remaining = kFillU32;
      EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, pending.data(), approvers.key(0).data(),
                                               approvers.sign(0, pending, mac).data(), &remaining),
                        EKI_ERR_BACKEND);
      EXPECT_EQ(remaining, 0U);

      // A call that fails on its own is BACKEND too: its record could not be written either.
      const eki_key_id missing = unknown_id();
      EKI_EXPECT_STATUS(eki_ks_revoke(ks, &missing), EKI_ERR_BACKEND);
    }
    EXPECT_EQ(read_file(path), before) << "the file is cut back to the intact chain";
    EXPECT_EQ(lifecycle::head_seq(ks), seq);
    std::uint64_t n = 0;
    EKI_EXPECT_STATUS(verify(path, std::nullopt, n), EKI_OK);
  }

  // The pending request survived with no approval: one approval now leaves one to go.
  std::uint32_t remaining = kFillU32;
  EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, pending.data(), approvers.key(1).data(),
                                           approvers.sign(1, pending, mac).data(), &remaining),
                    EKI_OK);
  EXPECT_EQ(remaining, 1U);

  // A destroy that happened cannot be undone; the text says so.
  {
    const FileSizeLimit limit(size_of(path));
    remaining = kFillU32;
    EKI_EXPECT_STATUS(eki_ks_destroy_approve(ks, pending.data(), approvers.key(0).data(),
                                             approvers.sign(0, pending, mac).data(), &remaining),
                      EKI_ERR_BACKEND);
    EXPECT_EQ(remaining, 0U);
    EXPECT_TRUE(contains(last_error(ks), "cannot be undone"));
  }
  eki_key_info info{};
  EKI_EXPECT_STATUS(eki_ks_get_info(ks, &mac, &info), EKI_ERR_KEY_NOT_FOUND);

  // Writing works again.
  eki_key_id later{};
  ASSERT_TRUE(h.generate(EKI_KEY_AES_256, "later", later));
  std::uint64_t n = 0;
  EKI_EXPECT_STATUS(verify(path, std::nullopt, n), EKI_OK);
  EXPECT_EQ(lifecycle::head_seq(ks), std::optional<std::uint64_t>{n});
}

// An open record that cannot be written: no handle, and the file is left empty. A close record
// that cannot be written leaves a log without it that still verifies.
TEST(FfiAudit, OpenAndCloseRecordFailures) {
  const TempDir dir;
  const std::string path = dir.file("open-fail.log");
  {
    const FileSizeLimit limit(0);
    EXPECT_TRUE(lifecycle::open_v2_fails(widen(software_config(), path.c_str()), EKI_ERR_BACKEND));
  }
  EXPECT_EQ(size_of(path), 0U);
  Handle h(software_config());
  ASSERT_TRUE(h.open(widen(software_config(), path.c_str())));
  EXPECT_EQ(lifecycle::head_seq(h.get()), std::optional<std::uint64_t>{1});
  {
    const FileSizeLimit limit(size_of(path));
    h.close();
  }
  std::uint64_t n = 0;
  EKI_EXPECT_STATUS(verify(path, std::nullopt, n), EKI_OK);
  EXPECT_EQ(n, 1U);
}

// NOLINTEND(readability-function-cognitive-complexity)

} // namespace
