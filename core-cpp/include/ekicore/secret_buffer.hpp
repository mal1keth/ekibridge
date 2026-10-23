#pragma once

// The container that secret bytes (key material, a PIN) live in. A secret_buffer owns a fixed-size
// block of memory and gives three guarantees:
// - the bytes are overwritten with zeros, by a call the optimiser cannot remove, before the memory
//   goes back to the system;
// - the bytes are never duplicated by accident: the type cannot be copied, and the one way to put
//   bytes in by copy, copy_of(), names the duplication at the call site;
// - where the platform allows it, the pages are locked into RAM so they are not written to swap.
//
// What it does not cover: copies that the caller makes from data() or span(), values that pass
// through registers or the stack, core dumps, hibernation images, and a debugger attached to the
// process. The guarantees concern the buffer's own storage; what the caller does with the bytes
// handed out is outside them.
//
// The storage policy is a template parameter so that the wipe, which is the buffer's job and not
// the allocator's, can be observed: a test allocator that inspects the bytes inside release() sees
// the state that the buffer left them in, without reading freed memory.

#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <utility>

namespace ekicore {

// What an allocator hands out: page-aligned storage owned exclusively by one buffer.
struct secret_allocation {
  std::uint8_t* data = nullptr;
  std::size_t capacity = 0;
  bool locked = false;
};

// Default storage policy: whole pages from the system, locked when EKI_MLOCK is defined.
//
// The storage is obtained with mmap and not from malloc or aligned_alloc. An anonymous mapping is
// zero-filled, page-aligned, and consists of pages that nothing else can be placed in; munmap hands
// them back to the kernel at once, where a malloc arena would keep them mapped on a free list.
//
// Every allocation is rounded up to a whole number of pages and owns those pages alone. mlock and
// munlock work on whole pages: if two secrets shared a page, the first destructor's munlock would
// silently unlock the other secret. Giving every buffer its own pages removes that hazard. The
// cost is one page (4 KiB or 16 KiB) per secret, which is acceptable because a key store holds few
// secrets.
//
// EKI_MLOCK must have the same value in every translation unit that includes this header, since
// it changes what the inline functions do; the test target forwards it for that reason.
struct locked_page_allocator {
  // Returns storage for at least size bytes, zero-filled. size == 0 gives an empty allocation.
  // Throws std::bad_alloc when the size cannot be rounded up to whole pages or the system refuses
  // the mapping. Locking is best effort: when mlock fails (for example under RLIMIT_MEMLOCK) the
  // storage is still returned, with locked == false.
  [[nodiscard]] static secret_allocation allocate(std::size_t size) {
    if (size == 0) {
      return {};
    }
    const long page_size_or_error = ::sysconf(_SC_PAGESIZE);
    if (page_size_or_error <= 0) {
      throw std::bad_alloc();
    }
    const auto page_size = static_cast<std::size_t>(page_size_or_error);
    if (size > std::numeric_limits<std::size_t>::max() - (page_size - 1)) {
      throw std::bad_alloc();
    }
    const std::size_t capacity = (size + page_size - 1) / page_size * page_size;

    // MAP_ANONYMOUS is the Linux spelling and MAP_ANON the BSD and macOS one.
#ifdef MAP_ANONYMOUS
    constexpr int anonymous = MAP_ANONYMOUS;
#else
    constexpr int anonymous = MAP_ANON;
#endif
    void* const pages =
        ::mmap(nullptr, capacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | anonymous, -1, 0);
    if (pages == MAP_FAILED) {
      throw std::bad_alloc();
    }

    bool locked = false;
#ifdef EKI_MLOCK
    locked = ::mlock(pages, capacity) == 0;
#endif
    return {.data = static_cast<std::uint8_t*>(pages), .capacity = capacity, .locked = locked};
  }

  // Gives the pages back to the system. The caller has already wiped them. munlock runs only for
  // storage that mlock accepted. Neither call can fail for a range that allocate() returned, so
  // their results are not examined.
  static void release(secret_allocation allocation) noexcept {
    if (allocation.data == nullptr) {
      return;
    }
#ifdef EKI_MLOCK
    if (allocation.locked) {
      ::munlock(allocation.data, allocation.capacity);
    }
#endif
    ::munmap(allocation.data, allocation.capacity);
  }
};

// Owns size bytes of secret storage obtained from Allocator, wipes them on destruction, and cannot
// be copied. Allocator provides allocate(size) and release(allocation); release must not throw.
template <typename Allocator = locked_page_allocator> class basic_secret_buffer {
  static_assert(noexcept(Allocator::release(secret_allocation{})),
                "release runs from the destructor and the move operations and must not throw");

public:
  // An empty buffer: no allocation, null data().
  basic_secret_buffer() noexcept = default;

  // size bytes, all zero. size == 0 gives an empty buffer and allocates nothing. Throws
  // std::bad_alloc when the allocator cannot provide the storage. The zero fill is done here and
  // not left to the allocator, so that a buffer starts at zero whatever the allocator's storage
  // held before.
  explicit basic_secret_buffer(std::size_t size) {
    if (size == 0) {
      return;
    }
    allocation_ = Allocator::allocate(size);
    size_ = size;
    std::fill_n(allocation_.data, size, std::uint8_t{0});
  }

  // A new buffer holding a copy of source. Copying is not offered any other way, so every
  // duplication of a secret is visible where it happens.
  [[nodiscard]] static basic_secret_buffer copy_of(bytes source) {
    basic_secret_buffer copy(source.size());
    std::ranges::copy(source, copy.data());
    return copy;
  }

  basic_secret_buffer(const basic_secret_buffer&) = delete;
  basic_secret_buffer& operator=(const basic_secret_buffer&) = delete;

  // Takes over other's storage without copying a byte; other is left empty.
  basic_secret_buffer(basic_secret_buffer&& other) noexcept
      : allocation_(std::exchange(other.allocation_, secret_allocation{})),
        size_(std::exchange(other.size_, 0)) {}

  // Wipes and releases what this buffer held, then takes over other's storage; other is left
  // empty. Assigning a buffer to itself changes nothing.
  basic_secret_buffer& operator=(basic_secret_buffer&& other) noexcept {
    if (this != &other) {
      reset();
      allocation_ = std::exchange(other.allocation_, secret_allocation{});
      size_ = std::exchange(other.size_, 0);
    }
    return *this;
  }

  // The wipe happens here, in the buffer, before the allocator sees the storage.
  ~basic_secret_buffer() {
    reset();
  }

  // Overwrites the contents with zeros. The allocation and the size are kept.
  void wipe() noexcept {
    ossl::cleanse(span());
  }

  [[nodiscard]] std::uint8_t* data() noexcept {
    return allocation_.data;
  }
  [[nodiscard]] const std::uint8_t* data() const noexcept {
    return allocation_.data;
  }
  [[nodiscard]] std::size_t size() const noexcept {
    return size_;
  }
  [[nodiscard]] bool empty() const noexcept {
    return size_ == 0;
  }
  [[nodiscard]] mut_bytes span() noexcept {
    return {allocation_.data, size_};
  }
  [[nodiscard]] bytes span() const noexcept {
    return {allocation_.data, size_};
  }

  // Whether the pages are locked into RAM. False for an empty buffer, when EKI_MLOCK is not
  // defined, and when the system refused the lock.
  [[nodiscard]] bool locked() const noexcept {
    return allocation_.locked;
  }

private:
  // Wipes the contents, hands the storage back and returns to the empty state. An empty buffer
  // holds no storage, so the allocator is not called.
  void reset() noexcept {
    if (allocation_.data != nullptr) {
      wipe();
      Allocator::release(allocation_);
    }
    allocation_ = secret_allocation{};
    size_ = 0;
  }

  secret_allocation allocation_{};
  std::size_t size_ = 0;
};

using secret_buffer = basic_secret_buffer<>;

} // namespace ekicore
