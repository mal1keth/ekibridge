#pragma once

// Owning handles for the OpenSSL objects used by the primitives, plus two small helpers that every
// primitive needs: zeroing an output buffer and feeding long inputs to an int-sized update call.

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

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

// Drains this thread's OpenSSL error queue into one line ("error:...; error:..."), oldest first.
// Returns "" when the queue is empty. Meant for the key store's last-error message; it allocates,
// so it may throw std::bad_alloc, which the FFI barrier turns into EKI_ERR_INTERNAL.
inline std::string last_openssl_error() {
  std::string message;
  std::array<char, 256> line{};
  for (unsigned long code = ERR_get_error(); code != 0; code = ERR_get_error()) {
    ERR_error_string_n(code, line.data(), line.size());
    if (!message.empty()) {
      message += "; ";
    }
    message += line.data();
  }
  return message;
}

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
