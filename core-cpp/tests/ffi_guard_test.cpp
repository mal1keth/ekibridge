// The exception barrier and the pointer helpers of ekicore/ffi_guard.hpp, exercised directly. The
// shipped library carries no hook for injecting a fault, so a callable that throws stands in for
// an implementation that fails.

#include "test_support.hpp"

#include <gtest/gtest.h>

#include <ekicore.h>
#include <ekicore/ffi_guard.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>

namespace {

using eki_test::all_zero;
using eki_test::name;
using eki_test::prefilled;
using eki_test::untouched;
using ekicore::ffi_barrier;
using ekicore::fixed_output;
using ekicore::fixed_span;
using ekicore::mut_bytes;
using ekicore::sized_output;
using ekicore::sized_span;

constexpr std::array<eki_status, 11> kStatuses{
    EKI_OK,
    EKI_ERR_NULL_POINTER,
    EKI_ERR_INVALID_ARGUMENT,
    EKI_ERR_BUFFER_TOO_SMALL,
    EKI_ERR_UNSUPPORTED,
    EKI_ERR_AUTH_FAILED,
    EKI_ERR_KEY_NOT_FOUND,
    EKI_ERR_KEY_EXISTS,
    EKI_ERR_WRONG_KEY_TYPE,
    EKI_ERR_BACKEND,
    EKI_ERR_INTERNAL,
};

// A thrown type that is not derived from std::exception.
struct ForeignError {
  int code;
};

// The helper returned a span (not std::nullopt) with this data pointer and size.
template <typename T>
bool holds(const std::optional<std::span<T>>& result, const void* data, std::size_t size) {
  return result.has_value() && static_cast<const void*>(result->data()) == data &&
         result->size() == size;
}

// The barrier is noexcept even for a callable that is not, so no exception can reach the C caller.
TEST(FfiGuard, BarrierIsNoexcept) {
  const auto may_throw = []() -> eki_status { throw std::runtime_error("failure"); };
  static_assert(!noexcept(may_throw()));
  static_assert(noexcept(ffi_barrier(may_throw)));
  static_assert(noexcept(ffi_barrier(std::span<const mut_bytes>{}, may_throw)));
}

TEST(FfiGuard, StatusPassesThrough) {
  for (const eki_status status : kStatuses) {
    EXPECT_EQ(name(ffi_barrier([status] { return status; })), name(status));
  }
}

TEST(FfiGuard, StdExceptionBecomesInternal) {
  EXPECT_EQ(name(ffi_barrier([]() -> eki_status { throw std::runtime_error("failure"); })),
            name(EKI_ERR_INTERNAL));
}

TEST(FfiGuard, BadAllocBecomesInternal) {
  EXPECT_EQ(name(ffi_barrier([]() -> eki_status { throw std::bad_alloc(); })),
            name(EKI_ERR_INTERNAL));
}

// Throwing types outside the std::exception hierarchy is the point of this test.
// NOLINTBEGIN(bugprone-std-exception-baseclass)
TEST(FfiGuard, NonStdExceptionBecomesInternal) {
  EXPECT_EQ(name(ffi_barrier([]() -> eki_status { throw 42; })), name(EKI_ERR_INTERNAL));
  EXPECT_EQ(name(ffi_barrier([]() -> eki_status { throw ForeignError{7}; })),
            name(EKI_ERR_INTERNAL));
}
// NOLINTEND(bugprone-std-exception-baseclass)

// The body writes into both outputs and then throws, as an implementation interrupted half way.
TEST(FfiGuard, OutputsAreZeroedAfterAnException) {
  auto fixed = prefilled<32>();
  auto sized = prefilled<20>();
  const std::array outputs{
      fixed_output(fixed.data(), fixed.size()),
      sized_output<20>(sized.data(), sized.size()),
  };
  const eki_status status = ffi_barrier(outputs, [&]() -> eki_status {
    std::ranges::fill(fixed, 0x11);
    std::ranges::fill(sized, 0x22);
    throw std::runtime_error("interrupted");
  });
  EXPECT_EQ(name(status), name(EKI_ERR_INTERNAL));
  EXPECT_TRUE(all_zero(fixed));
  EXPECT_TRUE(all_zero(sized));
}

TEST(FfiGuard, OutputsAreZeroedAfterAnErrorStatus) {
  for (const eki_status error : kStatuses) {
    if (error == EKI_OK) {
      continue;
    }
    auto fixed = prefilled<32>();
    auto sized = prefilled<20>();
    const std::array outputs{
        fixed_output(fixed.data(), fixed.size()),
        sized_output<20>(sized.data(), sized.size()),
    };
    const eki_status status = ffi_barrier(outputs, [&] {
      std::ranges::fill(fixed, 0x11);
      return error;
    });
    EXPECT_EQ(name(status), name(error));
    EXPECT_TRUE(all_zero(fixed)) << name(error);
    EXPECT_TRUE(all_zero(sized)) << name(error);
  }
}

TEST(FfiGuard, OutputsAreLeftAsWrittenAfterOk) {
  auto fixed = prefilled<32>();
  auto sized = prefilled<20>();
  const std::array outputs{
      fixed_output(fixed.data(), fixed.size()),
      sized_output<20>(sized.data(), sized.size()),
  };
  const eki_status status = ffi_barrier(outputs, [&] {
    std::ranges::fill(fixed, 0x11);
    return EKI_OK;
  });
  EXPECT_EQ(name(status), name(EKI_OK));
  EXPECT_TRUE(std::ranges::all_of(fixed, [](std::uint8_t b) { return b == 0x11; }));
  EXPECT_TRUE(untouched(sized));
}

// A length above the valid range means the caller's buffer is not known to be that large.
TEST(FfiGuard, SizedOutputWithOutOfRangeLengthIsNotTouched) {
  auto in_range = prefilled<8>();
  auto out_of_range = prefilled<9>();
  const std::array outputs{
      sized_output<8>(in_range.data(), in_range.size()),
      sized_output<8>(out_of_range.data(), out_of_range.size()),
  };
  EXPECT_EQ(name(ffi_barrier(outputs, [] { return EKI_ERR_INVALID_ARGUMENT; })),
            name(EKI_ERR_INVALID_ARGUMENT));
  EXPECT_TRUE(all_zero(in_range));
  EXPECT_TRUE(untouched(out_of_range));
}

// A NULL output is skipped, not dereferenced.
TEST(FfiGuard, NullOutputsAreSkipped) {
  EXPECT_TRUE(fixed_output(nullptr, 32).empty());
  EXPECT_TRUE(sized_output<8>(nullptr, 8).empty());
  const std::array outputs{
      fixed_output(nullptr, 32),
      sized_output<8>(nullptr, 8),
  };
  EXPECT_EQ(name(ffi_barrier(outputs, [] { return EKI_ERR_BACKEND; })), name(EKI_ERR_BACKEND));
}

TEST(FfiGuard, SizedSpanFollowsThePointerRule) {
  const auto* const null_in = static_cast<const std::uint8_t*>(nullptr);
  EXPECT_TRUE(holds(sized_span(null_in, 0), nullptr, 0));
  EXPECT_FALSE(sized_span(null_in, 1).has_value());

  // A non-NULL pointer with length 0 is not carried along: the span has no data pointer at all.
  const std::array<std::uint8_t, 4> buf{1, 2, 3, 4};
  EXPECT_TRUE(holds(sized_span(buf.data(), 0), nullptr, 0));
  EXPECT_TRUE(holds(sized_span(buf.data(), buf.size()), buf.data(), buf.size()));
}

TEST(FfiGuard, FixedSpanRejectsNull) {
  EXPECT_FALSE(fixed_span(static_cast<std::uint8_t*>(nullptr), 16).has_value());
  auto buf = prefilled<16>();
  EXPECT_TRUE(holds(fixed_span(buf.data(), buf.size()), buf.data(), buf.size()));
}

// The whole shape of an entry point: a NULL input with a non-zero length is NULL_POINTER, and the
// output that was not NULL is zero-filled although the primitive was never reached.
eki_status example_entry_point(const std::uint8_t* in, std::size_t in_len, std::uint8_t* out) {
  const std::array outputs{fixed_output(out, 16)};
  return ffi_barrier(outputs, [&] {
    const auto in_span = sized_span(in, in_len);
    const auto out_span = fixed_span(out, 16);
    if (!in_span || !out_span) {
      return EKI_ERR_NULL_POINTER;
    }
    std::ranges::fill(*out_span, static_cast<std::uint8_t>(in_span->size()));
    return EKI_OK;
  });
}

TEST(FfiGuard, NullInputReportsNullPointerAndZeroesOutputs) {
  auto out = prefilled<16>();
  EXPECT_EQ(name(example_entry_point(nullptr, 1, out.data())), name(EKI_ERR_NULL_POINTER));
  EXPECT_TRUE(all_zero(out));

  out = prefilled<16>();
  EXPECT_EQ(name(example_entry_point(nullptr, 0, out.data())), name(EKI_OK));
  EXPECT_TRUE(all_zero(out)); // filled with the input length, 0

  EXPECT_EQ(name(example_entry_point(nullptr, 0, nullptr)), name(EKI_ERR_NULL_POINTER));
}

} // namespace
