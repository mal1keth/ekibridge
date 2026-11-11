// ekicore::secret_buffer. The wipe is observed through an allocator that records the bytes it is
// handed in release(), so no test reads memory after it has been given back. The remaining
// behaviour (zero start, copy_of, wipe(), page ownership) is checked on the default allocator.

#include "test_support.hpp"

#include <ekicore/primitives.hpp>
#include <ekicore/secret_buffer.hpp>

#include <gtest/gtest.h>

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <numeric>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

using eki_test::all_zero;
using ekicore::secret_allocation;

static_assert(!std::is_copy_constructible_v<ekicore::secret_buffer>);
static_assert(!std::is_copy_assignable_v<ekicore::secret_buffer>);
static_assert(std::is_nothrow_move_constructible_v<ekicore::secret_buffer>);
static_assert(std::is_nothrow_move_assignable_v<ekicore::secret_buffer>);
static_assert(std::is_nothrow_default_constructible_v<ekicore::secret_buffer>);
// A size is never silently turned into a buffer.
static_assert(!std::is_convertible_v<std::size_t, ekicore::secret_buffer>);
static_assert(
    std::is_same_v<decltype(std::declval<ekicore::secret_buffer&>().span()), ekicore::mut_bytes>);
static_assert(
    std::is_same_v<decltype(std::declval<const ekicore::secret_buffer&>().span()), ekicore::bytes>);

constexpr std::uint8_t kSecret = 0x5A;

// Fresh storage is filled with this, so that a buffer which skipped its own zero fill would show.
constexpr std::uint8_t kGarbage = 0xC3;

// One call of release(): the address and the bytes the buffer left behind.
struct release_record {
  std::uintptr_t address = 0;
  std::vector<std::uint8_t> contents;
};

// Heap storage that logs every allocation and, at release, copies the bytes it was handed into a
// record before freeing them. The state is static because an allocator is used without an
// instance; the fixture resets it before each test.
struct recording_allocator {
  static inline std::vector<release_record> releases;
  static inline std::vector<std::uintptr_t> allocations;

  static void reset() {
    releases.clear();
    allocations.clear();
  }

  [[nodiscard]] static secret_allocation allocate(std::size_t size) {
    std::uint8_t* const storage = std::allocator<std::uint8_t>().allocate(size);
    std::fill_n(storage, size, kGarbage);
    allocations.push_back(reinterpret_cast<std::uintptr_t>(storage));
    return {.data = storage, .capacity = size, .locked = false};
  }

  // Recording can throw bad_alloc out of this noexcept function, which ends the test run; that is
  // an acceptable outcome for a test double.
  // NOLINTNEXTLINE(bugprone-exception-escape)
  static void release(secret_allocation allocation) noexcept {
    release_record record;
    record.address = reinterpret_cast<std::uintptr_t>(allocation.data);
    record.contents.assign(allocation.data, allocation.data + allocation.capacity);
    releases.push_back(std::move(record));
    std::allocator<std::uint8_t>().deallocate(allocation.data, allocation.capacity);
  }
};

using recording_buffer = ekicore::basic_secret_buffer<recording_allocator>;

class SecretBuffer : public ::testing::Test {
protected:
  void SetUp() override {
    recording_allocator::reset();
  }
};

void fill(ekicore::mut_bytes buf, std::uint8_t value) {
  std::ranges::fill(buf, value);
}

testing::AssertionResult holds_only(ekicore::bytes buf, std::uint8_t value) {
  const auto it = std::ranges::find_if(buf, [value](std::uint8_t b) { return b != value; });
  if (it == buf.end()) {
    return testing::AssertionSuccess();
  }
  return testing::AssertionFailure() << "byte " << (it - buf.begin()) << " of " << buf.size()
                                     << " is " << int{*it} << ", expected " << int{value};
}

std::uintptr_t address_of(const void* ptr) {
  return reinterpret_cast<std::uintptr_t>(ptr);
}

std::size_t page_size() {
  return static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
}

// ---------------------------------------------------------------------------------------------
// What the buffer does with its storage, observed through the recording allocator
// ---------------------------------------------------------------------------------------------

TEST_F(SecretBuffer, DestructorReleasesZeroedStorageOverTheFullSize) {
  constexpr std::size_t kSize = 48;
  std::uintptr_t address = 0;
  {
    recording_buffer buf(kSize);
    address = address_of(buf.data());
    // The allocator filled the storage with garbage; the constructor must have cleared all of it.
    EXPECT_TRUE(all_zero(buf.span()));
    fill(buf.span(), kSecret);
    EXPECT_TRUE(holds_only(buf.span(), kSecret));
    EXPECT_TRUE(recording_allocator::releases.empty());
  }
  ASSERT_EQ(recording_allocator::releases.size(), 1U);
  const release_record& released = recording_allocator::releases.front();
  EXPECT_EQ(released.address, address);
  EXPECT_EQ(released.contents.size(), kSize);
  EXPECT_TRUE(all_zero(released.contents));
}

TEST_F(SecretBuffer, MoveAssignmentWipesAndReleasesTheTargetsPreviousStorage) {
  recording_buffer target(32);
  recording_buffer source(16);
  fill(target.span(), 0x11);
  fill(source.span(), 0x22);
  const std::uintptr_t target_address = address_of(target.data());
  const std::uintptr_t source_address = address_of(source.data());
  // Looked at after the move, through a reference taken before it.
  const recording_buffer& moved_from = source;

  target = std::move(source);

  ASSERT_EQ(recording_allocator::releases.size(), 1U);
  EXPECT_EQ(recording_allocator::releases.front().address, target_address);
  EXPECT_EQ(recording_allocator::releases.front().contents.size(), 32U);
  EXPECT_TRUE(all_zero(recording_allocator::releases.front().contents));

  // The target now owns the source's storage, untouched; the source owns nothing.
  EXPECT_EQ(address_of(target.data()), source_address);
  EXPECT_EQ(target.size(), 16U);
  EXPECT_TRUE(holds_only(target.span(), 0x22));
  // The state of the source after the move is what these lines test. The static analyzer of
  // clang-tidy 18 follows the reference and reports the reads.
  // NOLINTBEGIN(clang-analyzer-cplusplus.Move)
  EXPECT_TRUE(moved_from.empty());
  EXPECT_EQ(moved_from.size(), 0U);
  EXPECT_EQ(moved_from.data(), nullptr);
  EXPECT_TRUE(moved_from.span().empty());
  // NOLINTEND(clang-analyzer-cplusplus.Move)
}

TEST_F(SecretBuffer, MoveAssignmentIntoAnEmptyTargetReleasesNothing) {
  recording_buffer target;
  recording_buffer source(8);
  const recording_buffer& moved_from = source;

  target = std::move(source);

  EXPECT_TRUE(recording_allocator::releases.empty());
  EXPECT_EQ(target.size(), 8U);
  EXPECT_TRUE(moved_from.empty());
}

TEST_F(SecretBuffer, MoveConstructionTransfersTheStorageWithoutCopying) {
  {
    recording_buffer original(24);
    fill(original.span(), kSecret);
    const std::uintptr_t address = address_of(original.data());
    const recording_buffer& moved_from = original;

    const recording_buffer moved(std::move(original));

    EXPECT_EQ(address_of(moved.data()), address);
    EXPECT_EQ(moved.size(), 24U);
    EXPECT_TRUE(holds_only(moved.span(), kSecret));
    // As above: the state of the moved-from buffer is what is tested.
    // NOLINTBEGIN(clang-analyzer-cplusplus.Move)
    EXPECT_TRUE(moved_from.empty());
    EXPECT_EQ(moved_from.data(), nullptr);
    // NOLINTEND(clang-analyzer-cplusplus.Move)
    EXPECT_EQ(recording_allocator::allocations.size(), 1U);
    EXPECT_TRUE(recording_allocator::releases.empty());
  }
  ASSERT_EQ(recording_allocator::releases.size(), 1U);
  EXPECT_TRUE(all_zero(recording_allocator::releases.front().contents));
}

TEST_F(SecretBuffer, EmptyAndMovedFromBuffersReleaseNothing) {
  {
    const recording_buffer defaulted;
    const recording_buffer zero_sized(0);
    EXPECT_TRUE(defaulted.empty());
    EXPECT_TRUE(zero_sized.empty());
  }
  EXPECT_TRUE(recording_allocator::allocations.empty());
  EXPECT_TRUE(recording_allocator::releases.empty());

  {
    recording_buffer source(8);
    recording_buffer destination(std::move(source));
    recording_buffer another;
    another = std::move(destination);
    // source and destination are both moved-from now; only `another` owns storage.
  }
  EXPECT_EQ(recording_allocator::allocations.size(), 1U);
  EXPECT_EQ(recording_allocator::releases.size(), 1U);
}

TEST_F(SecretBuffer, WipeKeepsTheAllocation) {
  recording_buffer buf(12);
  fill(buf.span(), kSecret);
  const std::uintptr_t address = address_of(buf.data());

  buf.wipe();

  EXPECT_TRUE(recording_allocator::releases.empty());
  EXPECT_EQ(address_of(buf.data()), address);
  EXPECT_EQ(buf.size(), 12U);
  EXPECT_TRUE(all_zero(buf.span()));
}

TEST_F(SecretBuffer, CopyOfAllocatesOnceAndItsStorageIsWipedToo) {
  const std::array<std::uint8_t, 5> source{1, 2, 3, 4, 5};
  {
    const auto copy = recording_buffer::copy_of(source);
    EXPECT_EQ(recording_allocator::allocations.size(), 1U);
    EXPECT_TRUE(std::ranges::equal(source, copy.span()));
  }
  ASSERT_EQ(recording_allocator::releases.size(), 1U);
  EXPECT_EQ(recording_allocator::releases.front().contents.size(), source.size());
  EXPECT_TRUE(all_zero(recording_allocator::releases.front().contents));
}

// ---------------------------------------------------------------------------------------------
// The default allocator
// ---------------------------------------------------------------------------------------------

void expect_zero_filled(std::size_t size) {
  SCOPED_TRACE(size);
  const ekicore::secret_buffer buf(size);
  EXPECT_EQ(buf.size(), size);
  EXPECT_FALSE(buf.empty());
  ASSERT_NE(buf.data(), nullptr);
  EXPECT_EQ(buf.span().size(), size);
  EXPECT_EQ(buf.span().data(), buf.data());
  EXPECT_TRUE(all_zero(buf.span()));
}

TEST_F(SecretBuffer, NewBufferReadsAsZeroBytes) {
  const std::size_t page = page_size();
  expect_zero_filled(1);
  expect_zero_filled(31);
  expect_zero_filled(32);
  expect_zero_filled(page - 1);
  expect_zero_filled(page);
  expect_zero_filled(page + 1);
  expect_zero_filled((3 * page) + 7);
}

void expect_empty(const ekicore::secret_buffer& buf) {
  EXPECT_TRUE(buf.empty());
  EXPECT_EQ(buf.size(), 0U);
  EXPECT_EQ(buf.data(), nullptr);
  EXPECT_TRUE(buf.span().empty());
  EXPECT_FALSE(buf.locked());
}

TEST_F(SecretBuffer, DefaultConstructedAndZeroSizedBuffersAreEmpty) {
  expect_empty(ekicore::secret_buffer());
  expect_empty(ekicore::secret_buffer(0));
}

TEST_F(SecretBuffer, CopyOfCopiesTheBytesAndDoesNotAliasTheSource) {
  std::array<std::uint8_t, 32> source{};
  std::iota(source.begin(), source.end(), std::uint8_t{1});
  const std::array<std::uint8_t, 32> original = source;

  ekicore::secret_buffer copy = ekicore::secret_buffer::copy_of(source);

  ASSERT_EQ(copy.size(), source.size());
  EXPECT_NE(copy.data(), source.data());
  EXPECT_TRUE(std::ranges::equal(original, copy.span()));

  // Neither side sees a later write to the other.
  source.fill(0xEE);
  EXPECT_TRUE(std::ranges::equal(original, copy.span()));
  fill(copy.span(), 0x77);
  EXPECT_TRUE(holds_only(source, 0xEE));
}

TEST_F(SecretBuffer, CopyOfAnEmptySpanIsAnEmptyBuffer) {
  const auto copy = ekicore::secret_buffer::copy_of({});
  EXPECT_TRUE(copy.empty());
  EXPECT_EQ(copy.data(), nullptr);
}

TEST_F(SecretBuffer, WipeZeroesTheContentsAndKeepsTheSize) {
  ekicore::secret_buffer buf(100);
  fill(buf.span(), kSecret);
  const std::uint8_t* const address = buf.data();
  const bool locked = buf.locked();

  buf.wipe();

  EXPECT_EQ(buf.size(), 100U);
  EXPECT_EQ(buf.data(), address);
  EXPECT_EQ(buf.locked(), locked);
  EXPECT_TRUE(all_zero(buf.span()));

  // Nothing to wipe is not an error.
  ekicore::secret_buffer empty;
  empty.wipe();
  EXPECT_TRUE(empty.empty());
}

// The pages that a buffer's bytes touch: the pages mlock and munlock act on for it.
struct page_span {
  std::uintptr_t first;
  std::uintptr_t last;
};

page_span pages_of(const ekicore::secret_buffer& buf) {
  const std::size_t page = page_size();
  const std::uintptr_t start = address_of(buf.data());
  return {.first = start / page, .last = (start + buf.size() - 1) / page};
}

TEST_F(SecretBuffer, StorageIsPageAlignedAndNeverSharesAPage) {
  const std::size_t page = page_size();
  std::vector<ekicore::secret_buffer> buffers;
  for (const std::size_t size :
       {std::size_t{1}, std::size_t{16}, std::size_t{32}, std::size_t{33}, page, page + 1}) {
    buffers.emplace_back(size);
  }

  std::vector<page_span> spans;
  for (const ekicore::secret_buffer& buf : buffers) {
    EXPECT_EQ(address_of(buf.data()) % page, 0U);
    spans.push_back(pages_of(buf));
  }
  // Ordered by first page, two spans overlap only if some neighbouring pair does.
  std::ranges::sort(spans, {}, &page_span::first);
  const auto overlapping =
      std::ranges::adjacent_find(spans, [](const page_span& lower, const page_span& upper) {
        return lower.last >= upper.first;
      });
  EXPECT_TRUE(overlapping == spans.end()) << "two buffers share a page";
}

struct rounding {
  std::size_t size;
  std::size_t capacity;
};

void expect_rounding(rounding expected) {
  SCOPED_TRACE(expected.size);
  const secret_allocation allocation = ekicore::locked_page_allocator::allocate(expected.size);
  EXPECT_EQ(allocation.capacity, expected.capacity);
  EXPECT_EQ(address_of(allocation.data) % page_size(), 0U);
  ekicore::locked_page_allocator::release(allocation);
}

TEST_F(SecretBuffer, AllocatorRoundsTheCapacityUpToWholePages) {
  const std::size_t page = page_size();
  expect_rounding({.size = 1, .capacity = page});
  expect_rounding({.size = page - 1, .capacity = page});
  expect_rounding({.size = page, .capacity = page});
  expect_rounding({.size = page + 1, .capacity = 2 * page});
  expect_rounding({.size = 5 * page, .capacity = 5 * page});
}

TEST_F(SecretBuffer, AllocatorGivesNothingForSizeZeroAndReleasingNothingIsHarmless) {
  const secret_allocation allocation = ekicore::locked_page_allocator::allocate(0);
  EXPECT_EQ(allocation.data, nullptr);
  EXPECT_EQ(allocation.capacity, 0U);
  EXPECT_FALSE(allocation.locked);
  ekicore::locked_page_allocator::release(allocation);
}

void expect_bad_alloc(std::size_t size) {
  SCOPED_TRACE(size);
  EXPECT_THROW({ const ekicore::secret_buffer buf(size); }, std::bad_alloc);
}

TEST_F(SecretBuffer, SizesThatCannotBeRoundedOrMappedThrowBadAlloc) {
  constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
  const std::size_t page = page_size();
  // These two overflow the rounding up to whole pages.
  expect_bad_alloc(kMax);
  expect_bad_alloc(kMax - page + 2);
  // These round up without overflow and are then refused by the system: no mapping is that large.
  expect_bad_alloc(kMax - page + 1);
  expect_bad_alloc(kMax / 2);
}

TEST_F(SecretBuffer, LockedCanBeCalledAndIsFalseWithoutMlock) {
  const ekicore::secret_buffer buf(32);
#ifdef EKI_MLOCK
  // Locking is best effort (RLIMIT_MEMLOCK may refuse it), so either answer is valid here.
  SUCCEED() << "locked() = " << buf.locked();
#else
  EXPECT_FALSE(buf.locked());
#endif
}

TEST_F(SecretBuffer, SelfMoveAssignmentKeepsTheContents) {
  ekicore::secret_buffer buf(16);
  fill(buf.span(), kSecret);
  const std::uint8_t* const address = buf.data();
  // -Wself-move only recognises `x = std::move(x)` on one variable; a reference gets past it.
  ekicore::secret_buffer& alias = buf;

  buf = std::move(alias);

  EXPECT_EQ(buf.data(), address);
  EXPECT_EQ(buf.size(), 16U);
  EXPECT_TRUE(holds_only(buf.span(), kSecret));
}

} // namespace
