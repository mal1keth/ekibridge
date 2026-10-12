// AES-256-GCM and ChaCha20-Poly1305 with detached 16-byte tags, over OpenSSL's EVP_CIPHER
// interface.

#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

// The parameter lists mirror the AEAD inputs (key, nonce, aad, data, tag), so adjacent byte spans
// are inherent to the API rather than a design choice.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
namespace ekicore {
namespace {

enum class direction : std::uint8_t { seal, open };

// OpenSSL's name for a valid selector, or nullptr for an unknown one.
const char* cipher_name(eki_aead_alg alg) noexcept {
  switch (alg) {
  case EKI_AEAD_AES_256_GCM:
    return "AES-256-GCM";
  case EKI_AEAD_CHACHA20_POLY1305:
    return "ChaCha20-Poly1305";
  default:
    return nullptr;
  }
}

// The length checks shared by seal and open, in contract order: key, nonce, input length, then
// the sizes of the outputs, which the C ABI derives from the inputs and so are always right there.
bool lengths_ok(bytes key, bytes nonce, bytes in, std::size_t out_size,
                std::size_t tag_size) noexcept {
  return key.size() == EKI_AEAD_KEY_LEN && nonce.size() == EKI_AEAD_NONCE_LEN &&
         in.size() <= EKI_AEAD_MAX_LEN && out_size == in.size() && tag_size == EKI_AEAD_TAG_LEN;
}

// A context set up for one message: cipher fetched, IV length 12, key and nonce loaded, AAD
// absorbed. Returns nullptr on failure.
ossl::cipher_ctx start(direction dir, const char* name, bytes key, bytes nonce,
                       bytes aad) noexcept {
  const ossl::cipher cipher{EVP_CIPHER_fetch(nullptr, name, nullptr)};
  if (!cipher) {
    return nullptr;
  }
  ossl::cipher_ctx ctx{EVP_CIPHER_CTX_new()};
  if (!ctx) {
    return nullptr;
  }
  const auto init = dir == direction::seal ? &EVP_EncryptInit_ex2 : &EVP_DecryptInit_ex2;
  const auto update = dir == direction::seal ? &EVP_EncryptUpdate : &EVP_DecryptUpdate;

  // Two-step init: pick the cipher, set the IV length, then load key and nonce.
  if (init(ctx.get(), cipher.get(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, EKI_AEAD_NONCE_LEN, nullptr) != 1 ||
      init(ctx.get(), nullptr, key.data(), nonce.data(), nullptr) != 1) {
    return nullptr;
  }

  // AAD goes through update with a null output buffer.
  const bool absorbed = ossl::for_each_chunk(aad.size(), [&](std::size_t offset, std::size_t len) {
    int out_len = 0;
    return update(ctx.get(), nullptr, &out_len, aad.subspan(offset, len).data(),
                  static_cast<int>(len)) == 1;
  });
  if (!absorbed) {
    return nullptr;
  }
  return ctx;
}

// Runs the cipher over in into out (same size). Both modes are stream modes, so each update
// writes exactly as many bytes as it reads; anything else is treated as a backend fault.
bool transform(direction dir, EVP_CIPHER_CTX* ctx, bytes in, mut_bytes out) noexcept {
  const auto update = dir == direction::seal ? &EVP_EncryptUpdate : &EVP_DecryptUpdate;
  return ossl::for_each_chunk(in.size(), [&](std::size_t offset, std::size_t len) {
    int out_len = 0;
    return update(ctx, out.subspan(offset, len).data(), &out_len, in.subspan(offset, len).data(),
                  static_cast<int>(len)) == 1 &&
           std::cmp_equal(out_len, len);
  });
}

eki_status seal_impl(const char* name, bytes key, bytes nonce, bytes aad, bytes pt, mut_bytes ct,
                     mut_bytes tag) noexcept {
  const ossl::cipher_ctx ctx = start(direction::seal, name, key, nonce, aad);
  if (!ctx || !transform(direction::seal, ctx.get(), pt, ct)) {
    return EKI_ERR_BACKEND;
  }
  // Finalising a stream AEAD writes no data, only computes the tag. A scratch buffer keeps the
  // call away from ct, which may be empty.
  std::array<std::uint8_t, EKI_AEAD_TAG_LEN> scratch{};
  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), scratch.data(), &final_len) != 1 || final_len != 0 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, EKI_AEAD_TAG_LEN, tag.data()) != 1) {
    return EKI_ERR_BACKEND;
  }
  return EKI_OK;
}

eki_status open_impl(const char* name, bytes key, bytes nonce, bytes aad, bytes ct, bytes tag,
                     mut_bytes pt) noexcept {
  const ossl::cipher_ctx ctx = start(direction::open, name, key, nonce, aad);
  if (!ctx || !transform(direction::open, ctx.get(), ct, pt)) {
    return EKI_ERR_BACKEND;
  }
  // The ctrl takes a non-const pointer; a local copy avoids casting const away.
  std::array<std::uint8_t, EKI_AEAD_TAG_LEN> expected{};
  std::ranges::copy(tag, expected.begin());
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, EKI_AEAD_TAG_LEN, expected.data()) !=
      1) {
    return EKI_ERR_BACKEND;
  }
  std::array<std::uint8_t, EKI_AEAD_TAG_LEN> scratch{};
  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), scratch.data(), &final_len) != 1) {
    // The tag did not match: an expected outcome, not an error worth keeping on the queue.
    ERR_clear_error();
    return EKI_ERR_AUTH_FAILED;
  }
  return final_len == 0 ? EKI_OK : EKI_ERR_BACKEND;
}

} // namespace

eki_status aead_seal(eki_aead_alg alg, bytes key, bytes nonce, bytes aad, bytes pt, mut_bytes ct,
                     mut_bytes tag16) noexcept {
  const char* name = cipher_name(alg);
  eki_status status = EKI_OK;
  if (name == nullptr || !lengths_ok(key, nonce, pt, ct.size(), tag16.size())) {
    status = EKI_ERR_INVALID_ARGUMENT;
  } else {
    status = seal_impl(name, key, nonce, aad, pt, ct, tag16);
  }
  if (status != EKI_OK) {
    if (ct.size() <= EKI_AEAD_MAX_LEN) {
      ossl::cleanse(ct);
    }
    if (tag16.size() == EKI_AEAD_TAG_LEN) {
      ossl::cleanse(tag16);
    }
  }
  return status;
}

eki_status aead_open(eki_aead_alg alg, bytes key, bytes nonce, bytes aad, bytes ct, bytes tag16,
                     mut_bytes pt) noexcept {
  const char* name = cipher_name(alg);
  eki_status status = EKI_OK;
  if (name == nullptr || !lengths_ok(key, nonce, ct, pt.size(), tag16.size())) {
    status = EKI_ERR_INVALID_ARGUMENT;
  } else {
    status = open_impl(name, key, nonce, aad, ct, tag16, pt);
  }
  // OpenSSL has already written unauthenticated plaintext by the time the tag check fails.
  if (status != EKI_OK && pt.size() <= EKI_AEAD_MAX_LEN) {
    ossl::cleanse(pt);
  }
  return status;
}

} // namespace ekicore
// NOLINTEND(bugprone-easily-swappable-parameters)
