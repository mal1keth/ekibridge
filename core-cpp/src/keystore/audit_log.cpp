// The audit log (ABI 2 contract section 5): the record formatter, the record matcher, the stateless
// verifier and the writer. See ekicore/audit_log.hpp for the format.

#include <ekicore/audit_log.hpp>
#include <ekicore/keystore.hpp>
#include <ekicore/openssl_raii.hpp>

#include <openssl/evp.h>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace ekicore::keystore {

namespace audit {

file_descriptor::file_descriptor(file_descriptor&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)) {}

file_descriptor& file_descriptor::operator=(file_descriptor&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) {
      static_cast<void>(::close(fd_));
    }
    fd_ = std::exchange(other.fd_, -1);
  }
  return *this;
}

file_descriptor::~file_descriptor() {
  if (fd_ >= 0) {
    // A failed close cannot be reported from a destructor; the descriptor is gone either way.
    static_cast<void>(::close(fd_));
  }
}

namespace {

// --- the pieces of a record --------------------------------------------------------------------

// The op names of section 5, indexed by audit::op.
constexpr std::array<std::string_view, 14> op_names{
    "open",    "close",           "generate",        "unwrap", "rotate", "revoke",
    "destroy", "destroy_request", "destroy_approve", "sign",   "hmac",   "hmac_verify",
    "wrap",    "get_public_key",
};

constexpr std::string_view hex_digits = "0123456789abcdef";

// "YYYY-MM-DDTHH:MM:SSZ": 'd' stands for a decimal digit, every other byte for itself.
constexpr std::string_view time_shape = "dddd-dd-ddTdd:dd:ddZ";

// Canonical decimals: a seq fits in 20 digits (uint64_t); a status is one of the ABI 2 status
// values, 0..=12, so it has at most 2 digits.
constexpr std::size_t max_seq_digits = 20;
constexpr std::size_t max_status_digits = 2;
constexpr std::uint64_t max_status = EKI_ERR_APPROVAL_REQUIRED;

// The first year a record time may have: the Unix epoch's.
constexpr unsigned first_year = 1970;

constexpr std::size_t id_hex_len = std::size_t{2} * EKI_KEY_ID_LEN;
constexpr std::size_t digest_hex_len = std::size_t{2} * EKI_AUDIT_HASH_LEN;

// The literal text between the fields. The hash covers everything before hash_field.
constexpr std::string_view seq_field = R"({"seq":)";
constexpr std::string_view time_field = R"(,"time":")";
constexpr std::string_view op_field = R"(","op":")";
constexpr std::string_view key_field = R"(","key":")";
constexpr std::string_view key2_field = R"(","key2":")";
constexpr std::string_view status_field = R"(","status":)";
constexpr std::string_view prev_field = R"(,"prev":")";
constexpr std::string_view prev_end = R"(")";
constexpr std::string_view hash_field = R"(,"hash":")";
constexpr std::string_view record_end = "\"}\n";

std::string_view op_name(op operation) {
  return op_names.at(static_cast<std::size_t>(operation));
}

// The byte at index of text. Precondition: index < text.size(), which every caller has checked.
char byte_at(std::string_view text, std::size_t index) noexcept {
  return *std::next(text.begin(), static_cast<std::ptrdiff_t>(index));
}

// The lowercase hex digit of the low four bits of nibble.
char hex_digit(unsigned nibble) noexcept {
  return byte_at(hex_digits, nibble & 0x0FU);
}

// SHA-256 of text through EVP. False when OpenSSL fails (its reason is on the error queue).
bool sha256(std::string_view text, digest& out) noexcept {
  unsigned int len = 0;
  return EVP_Digest(text.data(), text.size(), out.data(), &len, EVP_sha256(), nullptr) == 1 &&
         len == out.size();
}

// --- the formatter -----------------------------------------------------------------------------

// A record under construction, in a fixed buffer. Every append reports whether the text fit.
class line_buffer {
public:
  bool append(std::string_view text) noexcept {
    if (text.size() > bytes_.size() - size_) {
      return false;
    }
    std::ranges::copy(text, std::span{bytes_}.subspan(size_).begin());
    size_ += text.size();
    return true;
  }

  bool append_decimal(std::uint64_t value) noexcept {
    const std::span<char> free = std::span{bytes_}.subspan(size_);
    const std::to_chars_result result =
        std::to_chars(free.data(), free.data() + free.size(), value);
    if (result.ec != std::errc{}) {
      return false;
    }
    size_ += static_cast<std::size_t>(result.ptr - free.data());
    return true;
  }

  // Lowercase hexadecimal, two digits per byte.
  bool append_hex(std::span<const std::uint8_t> data) noexcept {
    if (2 * data.size() > bytes_.size() - size_) {
      return false;
    }
    auto out = std::span{bytes_}.subspan(size_).begin();
    for (const std::uint8_t byte : data) {
      *out++ = hex_digit(static_cast<unsigned>(byte) >> 4U);
      *out++ = hex_digit(byte);
    }
    size_ += 2 * data.size();
    return true;
  }

  // A key id field's value: 32 hex digits, or nothing for an empty field.
  bool append_id(const std::optional<key_id>& id) noexcept {
    return !id.has_value() || append_hex(*id);
  }

  [[nodiscard]] std::string_view view() const noexcept {
    return {bytes_.data(), size_};
  }

private:
  std::array<char, max_line_len> bytes_{};
  std::size_t size_ = 0;
};

// The UTC time now, as "YYYY-MM-DDTHH:MM:SSZ". False when the clock cannot be read or the year
// does not have four digits.
bool utc_now(std::array<char, time_shape.size() + 1>& out) noexcept {
  const std::time_t now = std::time(nullptr);
  std::tm parts{};
  if (now == static_cast<std::time_t>(-1) || gmtime_r(&now, &parts) == nullptr) {
    return false;
  }
  return std::strftime(out.data(), out.size(), "%Y-%m-%dT%H:%M:%SZ", &parts) == time_shape.size();
}

// Writes the record of entry that follows end into line, and its hash into hash: seq
// end.records + 1, time now, prev end.head.
outcome format_record(const entry& record, const chain_end& end, line_buffer& line, digest& hash) {
  std::array<char, time_shape.size() + 1> time{};
  if (!utc_now(time)) {
    return {
        .status = EKI_ERR_BACKEND,
        .detail = "reading the UTC time for the audit record failed",
    };
  }
  if (record.status < 0 || static_cast<std::uint64_t>(record.status) > max_status) {
    return {.status = EKI_ERR_INTERNAL, .detail = "a status outside 0..=12 cannot be logged"};
  }
  const bool fits =
      line.append(seq_field) && line.append_decimal(end.records + 1) && line.append(time_field) &&
      line.append({time.data(), time_shape.size()}) && line.append(op_field) &&
      line.append(op_name(record.operation)) && line.append(key_field) &&
      line.append_id(record.key) && line.append(key2_field) && line.append_id(record.key2) &&
      line.append(status_field) && line.append_decimal(static_cast<std::uint64_t>(record.status)) &&
      line.append(prev_field) && line.append_hex(end.head) && line.append(prev_end);
  if (!fits) {
    return {.status = EKI_ERR_INTERNAL, .detail = "the audit record does not fit in a line"};
  }
  if (!sha256(line.view(), hash)) {
    return openssl_failure("SHA-256 of the audit record");
  }
  if (!(line.append(hash_field) && line.append_hex(hash) && line.append(record_end))) {
    return {.status = EKI_ERR_INTERNAL, .detail = "the audit record does not fit in a line"};
  }
  return {};
}

// --- the matcher -------------------------------------------------------------------------------

// Reads one line from left to right. Each step consumes what it matched and reports whether it
// matched; after a failed step the cursor is not used again.
class line_cursor {
public:
  explicit line_cursor(std::string_view line) noexcept : line_(line), rest_(line) {}

  bool literal(std::string_view text) noexcept {
    if (!rest_.starts_with(text)) {
      return false;
    }
    rest_.remove_prefix(text.size());
    return true;
  }

  // A canonical decimal of at most max_digits digits: no sign, no leading zero unless the number
  // is 0, and a value that fits in a uint64_t.
  bool decimal(std::size_t max_digits, std::uint64_t& value) {
    const std::size_t digits = std::min(rest_.find_first_not_of("0123456789"), rest_.size());
    if (digits == 0 || digits > max_digits || (digits > 1 && rest_.front() == '0')) {
      return false;
    }
    std::uint64_t parsed = 0;
    for (const char c : rest_.substr(0, digits)) {
      const auto digit = static_cast<std::uint64_t>(c - '0');
      if (parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
        return false;
      }
      parsed = (parsed * 10) + digit;
    }
    value = parsed;
    rest_.remove_prefix(digits);
    return true;
  }

  // The text up to the next '"', which is consumed too.
  bool quoted(std::string_view& value) {
    const std::size_t quote = rest_.find('"');
    if (quote == std::string_view::npos) {
      return false;
    }
    value = rest_.substr(0, quote);
    rest_.remove_prefix(quote + 1);
    return true;
  }

  [[nodiscard]] bool at_end() const noexcept {
    return rest_.empty();
  }

  // The number of bytes matched so far.
  [[nodiscard]] std::size_t position() const noexcept {
    return line_.size() - rest_.size();
  }

private:
  std::string_view line_;
  std::string_view rest_;
};

bool is_digit(char c) noexcept {
  return c >= '0' && c <= '9';
}

// The two-digit number at offset of a time that has the shape.
unsigned two_digits(std::string_view time, std::size_t offset) noexcept {
  return (static_cast<unsigned>(byte_at(time, offset) - '0') * 10U) +
         static_cast<unsigned>(byte_at(time, offset + 1) - '0');
}

// Whether year is a leap year of the Gregorian calendar.
bool is_leap_year(unsigned year) noexcept {
  return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

// The number of days of month (1..=12) in a leap year or a common year.
unsigned days_in_month(bool leap_year, unsigned month) noexcept {
  constexpr std::array<unsigned, 12> days{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (month == 2 && leap_year) {
    return 29;
  }
  return *std::next(days.begin(), static_cast<std::ptrdiff_t>(month - 1));
}

// "YYYY-MM-DDTHH:MM:SSZ" naming a real UTC second from 1970 on: a day the month has (leap years
// included), hour 00..23, minute 00..59, second 00..59. The writer formats the time with gmtime_r,
// which never gives a leap second, so 60 is not a value a record can hold.
bool is_time(std::string_view time) noexcept {
  const bool shaped = std::ranges::equal(
      time, time_shape, [](char c, char shape) { return shape == 'd' ? is_digit(c) : c == shape; });
  if (!shaped) {
    return false;
  }
  const unsigned year = (two_digits(time, 0) * 100U) + two_digits(time, 2);
  const unsigned month = two_digits(time, 5);
  const unsigned day = two_digits(time, 8);
  return year >= first_year && month >= 1 && month <= 12 && day >= 1 &&
         day <= days_in_month(is_leap_year(year), month) && two_digits(time, 11) < 24 &&
         two_digits(time, 14) < 60 && two_digits(time, 17) < 60;
}

bool is_op(std::string_view name) noexcept {
  return std::ranges::find(op_names, name) != op_names.end();
}

// The value of a lowercase hexadecimal digit, or nullopt for any other byte (uppercase included).
std::optional<std::uint8_t> hex_value(char c) noexcept {
  const std::size_t value = hex_digits.find(c);
  if (value == std::string_view::npos) {
    return std::nullopt;
  }
  return static_cast<std::uint8_t>(value);
}

// Decodes exactly 2 * out.size() lowercase hex digits.
bool parse_hex(std::string_view text, std::span<std::uint8_t> out) noexcept {
  if (text.size() != 2 * out.size()) {
    return false;
  }
  const auto* in = text.begin();
  for (std::uint8_t& byte : out) {
    const std::optional<std::uint8_t> high = hex_value(*in++);
    const std::optional<std::uint8_t> low = hex_value(*in++);
    if (!high.has_value() || !low.has_value()) {
      return false;
    }
    byte = static_cast<std::uint8_t>((static_cast<unsigned>(*high) << 4U) | *low);
  }
  return true;
}

// A key or key2 value: empty, or 32 lowercase hex digits.
bool is_id(std::string_view text) noexcept {
  key_id ignored{};
  return text.empty() || (text.size() == id_hex_len && parse_hex(text, ignored));
}

// The fields of one line as the grammar splits it.
struct record_text {
  std::uint64_t seq = 0;
  std::string_view time;
  std::string_view op;
  std::string_view key;
  std::string_view key2;
  std::uint64_t status = 0;
  std::string_view prev;
  std::string_view hash;
  // The bytes the hash covers: the line up to and including the closing quote of prev.
  std::size_t hashed_len = 0;
};

// Splits a line (without its '\n') into its fields; false when it does not have the exact shape.
bool split_record(std::string_view line, record_text& fields) {
  line_cursor cursor{line};
  const bool head =
      cursor.literal(seq_field) && cursor.decimal(max_seq_digits, fields.seq) &&
      cursor.literal(time_field) && cursor.quoted(fields.time) && cursor.literal(R"(,"op":")") &&
      cursor.quoted(fields.op) && cursor.literal(R"(,"key":")") && cursor.quoted(fields.key) &&
      cursor.literal(R"(,"key2":")") && cursor.quoted(fields.key2) &&
      cursor.literal(R"(,"status":)") && cursor.decimal(max_status_digits, fields.status) &&
      cursor.literal(prev_field) && cursor.quoted(fields.prev);
  if (!head) {
    return false;
  }
  fields.hashed_len = cursor.position();
  return cursor.literal(hash_field) && cursor.quoted(fields.hash) && cursor.literal("}") &&
         cursor.at_end();
}

// Whether every field holds a value of its kind.
bool fields_valid(const record_text& fields) noexcept {
  return is_time(fields.time) && is_op(fields.op) && is_id(fields.key) && is_id(fields.key2) &&
         fields.status <= max_status && fields.prev.size() == digest_hex_len &&
         fields.hash.size() == digest_hex_len;
}

// Checks that one line (without its '\n') is the record that continues end: the exact shape, valid
// fields, seq end.records + 1, prev end.head, and the right hash. On success end moves past it
// (records and head; size is the caller's).
eki_status check_line(std::string_view line, chain_end& end) {
  record_text fields;
  if (!split_record(line, fields) || !fields_valid(fields) || fields.seq != end.records + 1) {
    return EKI_ERR_AUTH_FAILED;
  }
  digest prev{};
  digest hash{};
  if (!parse_hex(fields.prev, prev) || !parse_hex(fields.hash, hash) || prev != end.head) {
    return EKI_ERR_AUTH_FAILED;
  }
  digest computed{};
  if (!sha256(line.substr(0, fields.hashed_len), computed)) {
    return EKI_ERR_BACKEND;
  }
  if (computed != hash) {
    return EKI_ERR_AUTH_FAILED;
  }
  end.records = fields.seq;
  end.head = hash;
  return EKI_OK;
}

// --- the verifier ------------------------------------------------------------------------------

// Reads fd from offset 0 to its end and checks every line. A line is collected in a buffer of
// max_line_len bytes, so a line longer than that (its '\n' included) fails as soon as its 513th
// byte arrives; a final line without '\n' fails at the end of the file. EKI_ERR_BACKEND when a
// read fails.
eki_status verify_descriptor(int fd, chain_end& end) {
  end = chain_end{};
  std::array<char, 4096> chunk{};
  std::array<char, max_line_len> line{};
  auto* filled = line.begin();
  while (true) {
    const ssize_t got = ::pread(fd, chunk.data(), chunk.size(), static_cast<off_t>(end.size));
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got < 0) {
      return EKI_ERR_BACKEND;
    }
    if (got == 0) {
      break;
    }
    end.size += static_cast<std::uint64_t>(got);
    for (const char c : std::span{chunk}.first(static_cast<std::size_t>(got))) {
      if (filled == line.end()) {
        return EKI_ERR_AUTH_FAILED;
      }
      *filled++ = c;
      if (c != '\n') {
        continue;
      }
      const auto line_len = static_cast<std::size_t>(filled - line.begin());
      const eki_status status = check_line({line.data(), line_len - 1}, end);
      if (status != EKI_OK) {
        return status;
      }
      filled = line.begin();
    }
  }
  return filled == line.begin() ? EKI_OK : EKI_ERR_AUTH_FAILED;
}

bool is_regular_file(int fd) noexcept {
  struct stat info{};
  return ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode);
}

// An EKI_ERR_BACKEND outcome for a failed system call: "<what> failed: <errno text>".
outcome io_failure(std::string_view what, int error) {
  outcome result{.status = EKI_ERR_BACKEND, .detail = std::string{what}};
  result.detail += " failed: ";
  result.detail += std::error_code(error, std::generic_category()).message();
  return result;
}

// Writes line with one write call (repeated only when interrupted before writing anything) and
// flushes the file with fsync.
outcome write_line(int fd, std::string_view line) {
  ssize_t written = ::write(fd, line.data(), line.size());
  while (written < 0 && errno == EINTR) {
    written = ::write(fd, line.data(), line.size());
  }
  if (written < 0) {
    return io_failure("writing the audit record", errno);
  }
  if (static_cast<std::size_t>(written) != line.size()) {
    return {
        .status = EKI_ERR_BACKEND,
        .detail = "writing the audit record failed: " + std::to_string(written) + " of " +
                  std::to_string(line.size()) + " bytes were written",
    };
  }
  int synced = ::fsync(fd);
  while (synced != 0 && errno == EINTR) {
    synced = ::fsync(fd);
  }
  if (synced != 0) {
    return io_failure("flushing the audit log to disk", errno);
  }
  return {};
}

} // namespace

eki_status verify_path(const char* path, chain_end& end) {
  // O_NONBLOCK: opening a FIFO must not wait for a writer; the file-type check then rejects it.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): open(2) is variadic by definition
  const file_descriptor fd{::open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK)};
  if (!fd.valid() || !is_regular_file(fd.get())) {
    return EKI_ERR_BACKEND;
  }
  return verify_descriptor(fd.get(), end);
}

} // namespace audit

audit_log::audit_log(audit::file_descriptor fd, const audit::chain_end& end) noexcept
    : fd_(std::move(fd)), end_(end) {}

outcome audit_log::open(const std::string& path, std::unique_ptr<audit_log>& out) {
  out.reset();
  constexpr int flags = O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NONBLOCK;
  constexpr mode_t owner_only = S_IRUSR | S_IWUSR;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): open(2) is variadic by definition
  audit::file_descriptor fd{::open(path.c_str(), flags, owner_only)};
  if (!fd.valid()) {
    return audit::io_failure("opening the audit log", errno);
  }
  // flock locks belong to the open file description, so a second open of the same file, in this
  // process or another, is refused while this descriptor holds the lock.
  if (::flock(fd.get(), LOCK_EX | LOCK_NB) != 0) {
    return audit::io_failure("locking the audit log", errno);
  }
  if (!audit::is_regular_file(fd.get())) {
    return {.status = EKI_ERR_BACKEND, .detail = "the audit log is not a regular file"};
  }
  audit::chain_end end;
  const eki_status verified = audit::verify_descriptor(fd.get(), end);
  if (verified != EKI_OK) {
    return {.status = verified, .detail = "the existing audit log failed verification"};
  }
  out = std::make_unique<audit_log>(std::move(fd), end);
  return {};
}

outcome audit_log::append(const audit::entry& entry) {
  if (damaged_) {
    return {
        .status = EKI_ERR_BACKEND,
        .detail = "the audit log is damaged: a record that failed to be written could not be "
                  "removed from the file",
    };
  }
  audit::line_buffer line;
  audit::digest hash{};
  outcome result = audit::format_record(entry, end_, line, hash);
  if (result.status != EKI_OK) {
    return result;
  }
  result = audit::write_line(fd_.get(), line.view());
  if (result.status != EKI_OK) {
    roll_back();
    return result;
  }
  end_.records += 1;
  end_.head = hash;
  end_.size += line.view().size();
  return {};
}

void audit_log::roll_back() noexcept {
  if (::ftruncate(fd_.get(), static_cast<off_t>(end_.size)) != 0) {
    damaged_ = true;
  }
}

} // namespace ekicore::keystore
