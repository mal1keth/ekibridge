// Helpers shared by the libFuzzer targets: an input splitter, exactly sized heap buffers and the
// property checks.
//
// Input layout (the seed generator, core-rs/fuzz/examples/seeds.rs, writes the same one):
// integers are little-endian, fixed-size arrays are raw bytes, and byte strings are a 2-byte
// little-endian length followed by that many bytes. A field cut short by the end of the input is
// zero-padded (integers, arrays) or shortened (byte strings), so every input is valid.

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "ekicore.h"

namespace ekifuzz {

// Calls __builtin_trap() when a checked property does not hold, so libFuzzer records a crash.
inline void require(bool property) {
  if (!property) {
    __builtin_trap();
  }
}

// Every status of ABI version 1 is in 0..=10 (EKI_OK..EKI_ERR_INTERNAL).
inline void require_status_in_range(int32_t status) {
  require(status >= EKI_OK && status <= EKI_ERR_INTERNAL);
}

// A heap allocation of exactly size() bytes, so AddressSanitizer reports a read or write even
// one byte past the end. data() is never NULL, also for size 0, which makes the NULL flags of the
// targets the only source of NULL pointers.
class Buffer {
public:
  explicit Buffer(size_t size, uint8_t fill = 0)
      : data_(std::make_unique<uint8_t[]>(size)), size_(size) {
    std::fill_n(data_.get(), size_, fill);
  }

  explicit Buffer(std::span<const uint8_t> bytes) : Buffer(bytes.size()) {
    std::copy(bytes.begin(), bytes.end(), data_.get());
  }

  [[nodiscard]] uint8_t* data() {
    return data_.get();
  }
  [[nodiscard]] const uint8_t* data() const {
    return data_.get();
  }
  [[nodiscard]] size_t size() const {
    return size_;
  }
  [[nodiscard]] std::span<const uint8_t> span() const {
    return {data_.get(), size_};
  }

  [[nodiscard]] bool all(uint8_t value) const {
    return std::all_of(data_.get(), data_.get() + size_, [value](uint8_t b) { return b == value; });
  }

  [[nodiscard]] bool equals(std::span<const uint8_t> other) const {
    return std::equal(data_.get(), data_.get() + size_, other.begin(), other.end());
  }

private:
  std::unique_ptr<uint8_t[]> data_;
  size_t size_;
};

// Reads typed fields from the front of a libFuzzer input.
class Input {
public:
  Input(const uint8_t* data, size_t size) : rest_(data, size) {}

  uint8_t u8() {
    if (rest_.empty()) {
      return 0;
    }
    const uint8_t value = rest_.front();
    rest_ = rest_.subspan(1);
    return value;
  }

  bool boolean() {
    return (u8() & 1U) != 0;
  }

  uint16_t u16() {
    const auto lo = static_cast<uint16_t>(u8());
    const auto hi = static_cast<uint16_t>(u8());
    return static_cast<uint16_t>(lo | static_cast<uint16_t>(hi << 8U));
  }

  int32_t i32() {
    uint32_t value = 0;
    for (unsigned shift = 0; shift < 32; shift += 8) {
      value |= static_cast<uint32_t>(u8()) << shift;
    }
    return static_cast<int32_t>(value);
  }

  template <size_t N> std::array<uint8_t, N> array() {
    std::array<uint8_t, N> out{};
    for (auto& b : out) {
      b = u8();
    }
    return out;
  }

  Buffer bytes() {
    const size_t len = std::min<size_t>(u16(), rest_.size());
    Buffer out(rest_.first(len));
    rest_ = rest_.subspan(len);
    return out;
  }

private:
  std::span<const uint8_t> rest_;
};

// A caller-supplied input buffer and a flag that passes NULL in its place. The length argument
// is the buffer's size either way: the contract defines both NULL with length 0 (treated as
// empty) and NULL with a nonzero length (EKI_ERR_NULL_POINTER).
struct InBuf {
  bool null;
  Buffer bytes;

  static InBuf read(Input& in) {
    const bool null = in.boolean();
    return InBuf{null, in.bytes()};
  }

  [[nodiscard]] const uint8_t* ptr() const {
    return null ? nullptr : bytes.data();
  }
  [[nodiscard]] size_t len() const {
    return bytes.size();
  }
};

} // namespace ekifuzz
