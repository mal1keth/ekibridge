// Helpers for the tests that check what the primitives leave on OpenSSL's per-thread error queue,
// which the library shares with the code that calls it.

#pragma once

#include <gtest/gtest.h>

#include <openssl/err.h>

#include <ios>

namespace eki_test {

// Pushes an entry onto this thread's error queue, standing in for one left there by the code that
// calls the library, and returns its packed code.
inline unsigned long push_caller_error() {
  ERR_raise(ERR_LIB_USER, 42);
  return ERR_peek_last_error();
}

// EXPECT_TRUE(queue_holds_only(code)): the error queue holds exactly one entry, code, which is
// therefore also the entry on top. The queue is emptied either way, so that no test sees the
// entries of another.
inline testing::AssertionResult queue_holds_only(unsigned long code) {
  const unsigned long top = ERR_peek_last_error();
  const unsigned long bottom = ERR_get_error();
  const unsigned long next = ERR_peek_error();
  ERR_clear_error();
  if (top == code && bottom == code && next == 0) {
    return testing::AssertionSuccess();
  }
  return testing::AssertionFailure() << std::hex << "expected only 0x" << code << "; top 0x" << top
                                     << ", bottom 0x" << bottom << ", next 0x" << next;
}

} // namespace eki_test
