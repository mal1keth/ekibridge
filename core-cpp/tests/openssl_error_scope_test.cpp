// ekicore::ossl::error_scope, exercised directly: which of a call's entries on OpenSSL's error
// queue survive it, and that the caller's entries and marks always do. The primitive tests check
// the same property through the primitives; the BACKEND path cannot be provoked from there.

#include "error_queue_support.hpp"

#include <ekicore/openssl_raii.hpp>

#include <gtest/gtest.h>

#include <ekicore.h>

#include <openssl/err.h>

namespace {

using eki_test::push_caller_error;
using eki_test::queue_holds_only;

// Stands for an entry that OpenSSL pushes while a primitive runs; returns its packed code.
unsigned long push_library_error() {
  ERR_raise(ERR_LIB_EVP, 7);
  return ERR_peek_last_error();
}

TEST(OpensslErrorScope, ExpectedFailureRemovesOnlyTheCallsEntries) {
  const unsigned long caller = push_caller_error();
  {
    ekicore::ossl::error_scope errors;
    push_library_error();
    push_library_error();
    EXPECT_EQ(errors.settle(EKI_ERR_AUTH_FAILED), EKI_ERR_AUTH_FAILED);
  }
  EXPECT_TRUE(queue_holds_only(caller));
}

TEST(OpensslErrorScope, SuccessLeavesTheQueueAsFound) {
  const unsigned long caller = push_caller_error();
  {
    ekicore::ossl::error_scope errors;
    push_library_error();
    EXPECT_EQ(errors.settle(EKI_OK), EKI_OK);
  }
  EXPECT_TRUE(queue_holds_only(caller));
}

TEST(OpensslErrorScope, WithoutSettleTheCallsEntriesAreRemoved) {
  const unsigned long caller = push_caller_error();
  {
    const ekicore::ossl::error_scope errors;
    push_library_error();
  }
  EXPECT_TRUE(queue_holds_only(caller));
}

TEST(OpensslErrorScope, BackendKeepsTheReasonOnTopOfTheCallersEntries) {
  const unsigned long caller = push_caller_error();
  unsigned long reason = 0;
  {
    ekicore::ossl::error_scope errors;
    reason = push_library_error();
    EXPECT_EQ(errors.settle(EKI_ERR_BACKEND), EKI_ERR_BACKEND);
  }
  EXPECT_EQ(ERR_peek_last_error(), reason);
  EXPECT_EQ(ERR_get_error(), caller);
  // The scope's mark is gone: with no mark left, popping to a mark finds none.
  EXPECT_EQ(ERR_pop_to_mark(), 0);
  EXPECT_EQ(ERR_peek_error(), 0UL);
  ERR_clear_error();
}

// ERR_set_mark sets no mark on an empty queue; every entry is then the call's own.
TEST(OpensslErrorScope, EmptyQueue) {
  ERR_clear_error();
  {
    ekicore::ossl::error_scope errors;
    push_library_error();
    EXPECT_EQ(errors.settle(EKI_ERR_INVALID_ARGUMENT), EKI_ERR_INVALID_ARGUMENT);
  }
  EXPECT_EQ(ERR_peek_error(), 0UL);

  unsigned long reason = 0;
  {
    ekicore::ossl::error_scope errors;
    reason = push_library_error();
    EXPECT_EQ(errors.settle(EKI_ERR_BACKEND), EKI_ERR_BACKEND);
  }
  EXPECT_TRUE(queue_holds_only(reason));
}

// Marks are counted per entry, so a mark the caller set on the same top entry outlives the scope.
TEST(OpensslErrorScope, CallersMarkSurvives) {
  const unsigned long caller = push_caller_error();
  ASSERT_EQ(ERR_set_mark(), 1);
  {
    ekicore::ossl::error_scope errors;
    push_library_error();
    EXPECT_EQ(errors.settle(EKI_ERR_AUTH_FAILED), EKI_ERR_AUTH_FAILED);
  }
  push_library_error();
  EXPECT_EQ(ERR_pop_to_mark(), 1);
  EXPECT_TRUE(queue_holds_only(caller));
}

} // namespace
