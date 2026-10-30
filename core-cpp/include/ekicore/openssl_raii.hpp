#pragma once

// Owning handles for the OpenSSL objects used by the primitives, a scope that confines the
// primitives' entries on OpenSSL's error queue to the call that raised them, and two small helpers
// that every primitive needs: zeroing an output buffer and feeding long inputs to an int-sized
// update call.

#include <ekicore.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace ekicore::ossl {

// Calls the OpenSSL free function Free on destruction. Every OpenSSL free function accepts nullptr.
template <auto Free> struct deleter {
  template <typename T> void operator()(T* ptr) const noexcept {
    Free(ptr);
  }
};

using mac = std::unique_ptr<EVP_MAC, deleter<&EVP_MAC_free>>;
using mac_ctx = std::unique_ptr<EVP_MAC_CTX, deleter<&EVP_MAC_CTX_free>>;
using kdf = std::unique_ptr<EVP_KDF, deleter<&EVP_KDF_free>>;
using kdf_ctx = std::unique_ptr<EVP_KDF_CTX, deleter<&EVP_KDF_CTX_free>>;
using cipher = std::unique_ptr<EVP_CIPHER, deleter<&EVP_CIPHER_free>>;
using cipher_ctx = std::unique_ptr<EVP_CIPHER_CTX, deleter<&EVP_CIPHER_CTX_free>>;
using pkey = std::unique_ptr<EVP_PKEY, deleter<&EVP_PKEY_free>>;
using pkey_ctx = std::unique_ptr<EVP_PKEY_CTX, deleter<&EVP_PKEY_CTX_free>>;
using md_ctx = std::unique_ptr<EVP_MD_CTX, deleter<&EVP_MD_CTX_free>>;
using bignum = std::unique_ptr<BIGNUM, deleter<&BN_clear_free>>;
using ecdsa_sig = std::unique_ptr<ECDSA_SIG, deleter<&ECDSA_SIG_free>>;
using ec_group = std::unique_ptr<EC_GROUP, deleter<&EC_GROUP_free>>;
using param_bld = std::unique_ptr<OSSL_PARAM_BLD, deleter<&OSSL_PARAM_BLD_free>>;
using params = std::unique_ptr<OSSL_PARAM, deleter<&OSSL_PARAM_free>>;

// Confines the entries that one primitive call pushes onto this thread's OpenSSL error queue to
// that call. The queue is shared with the rest of the process, so entries that were already on it
// belong to the caller and are never removed. Construction marks the current top entry; settle()
// records the call's status, and destruction then keeps the entries pushed since the mark for
// EKI_ERR_BACKEND, whose reason they carry, and removes them for every other status: an expected
// failure (tag mismatch, bad public key, bad signature) is not an OpenSSL error, and a successful
// call leaves the queue as it found it. Without a settle() call the entries are removed.
//
// ERR_set_mark sets no mark on an empty queue. Every entry is then this call's own, so removing
// them means clearing the queue, and keeping them means doing nothing. The queue holds 16 entries:
// a call that pushes enough to wrap around overwrites the caller's entries and the mark with them,
// and removal then clears the whole queue.
class error_scope {
public:
  error_scope() noexcept : marked_(ERR_set_mark() == 1) {}
  error_scope(const error_scope&) = delete;
  error_scope(error_scope&&) = delete;
  error_scope& operator=(const error_scope&) = delete;
  error_scope& operator=(error_scope&&) = delete;

  ~error_scope() {
    if (keep_) {
      if (marked_) {
        ERR_clear_last_mark();
      }
    } else if (marked_) {
      ERR_pop_to_mark();
    } else {
      ERR_clear_error();
    }
  }

  // Records the call's outcome and returns it unchanged, so that a primitive can end with
  // `return errors.settle(status);`.
  eki_status settle(eki_status status) noexcept {
    keep_ = status == EKI_ERR_BACKEND;
    return status;
  }

private:
  bool marked_;
  bool keep_ = false;
};

// Overwrites buf with zeros in a way the compiler cannot elide.
inline void cleanse(std::span<std::uint8_t> buf) noexcept {
  if (!buf.empty()) {
    OPENSSL_cleanse(buf.data(), buf.size());
  }
}

// Largest length handed to a single EVP_*Update call, whose length parameter is an int.
inline constexpr std::size_t max_update_len = INT_MAX;

// Calls update(offset, length) for consecutive chunks of at most max_update_len bytes covering
// [0, total). Stops at the first chunk for which update returns false and returns false; returns
// true when every chunk succeeded (and immediately when total is 0).
template <typename Update> bool for_each_chunk(std::size_t total, const Update& update) {
  for (std::size_t offset = 0; offset < total;) {
    const std::size_t remaining = total - offset;
    const std::size_t len = remaining < max_update_len ? remaining : max_update_len;
    if (!update(offset, len)) {
      return false;
    }
    offset += len;
  }
  return true;
}

} // namespace ekicore::ossl
