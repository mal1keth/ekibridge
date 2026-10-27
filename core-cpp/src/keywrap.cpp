// RFC 3394 AES Key Wrap with a 256-bit KEK, over OpenSSL's EVP_CIPHER interface
// (EVP_aes_256_wrap).

#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace ekicore {
namespace {

constexpr std::size_t kek_len = 32;
constexpr std::size_t key_len = 32;
static_assert(EKI_WRAPPED_KEY_LEN == key_len + 8, "RFC 3394 adds one 64-bit block");

enum class direction : std::uint8_t { wrap, unwrap };

// A context with the KEK loaded, for wrapping or unwrapping. The default initial value of RFC
// 3394 is used (no IV is passed). Returns nullptr on failure.
ossl::cipher_ctx start(direction dir, bytes kek) noexcept {
  ossl::cipher_ctx ctx{EVP_CIPHER_CTX_new()};
  if (!ctx) {
    return nullptr;
  }
  // OpenSSL 1.x refused a wrap-mode cipher, whose output is longer than its input, on a context
  // without this flag. OpenSSL 3 (3.5 checked) no longer requires it; setting it keeps the call
  // valid under either rule.
  EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  const auto init = dir == direction::wrap ? &EVP_EncryptInit_ex2 : &EVP_DecryptInit_ex2;
  if (init(ctx.get(), EVP_aes_256_wrap(), kek.data(), nullptr, nullptr) != 1) {
    return nullptr;
  }
  return ctx;
}

// Finalises a wrap-mode context. The whole transform happens in the update call, so finalising
// writes nothing; a scratch buffer keeps the call away from the caller's output.
bool finish(direction dir, EVP_CIPHER_CTX* ctx) noexcept {
  std::array<std::uint8_t, EKI_WRAPPED_KEY_LEN> scratch{};
  int final_len = 0;
  const auto final = dir == direction::wrap ? &EVP_EncryptFinal_ex : &EVP_DecryptFinal_ex;
  return final(ctx, scratch.data(), &final_len) == 1 && final_len == 0;
}

eki_status wrap_impl(bytes kek, bytes key, mut_bytes out) noexcept {
  const ossl::cipher_ctx ctx = start(direction::wrap, kek);
  if (!ctx) {
    return EKI_ERR_BACKEND;
  }
  int out_len = 0;
  if (EVP_EncryptUpdate(ctx.get(), out.data(), &out_len, key.data(),
                        static_cast<int>(key.size())) != 1 ||
      std::cmp_not_equal(out_len, out.size()) || !finish(direction::wrap, ctx.get())) {
    return EKI_ERR_BACKEND;
  }
  return EKI_OK;
}

// kek and blob are both byte strings; their order matches the public function.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
eki_status unwrap_impl(bytes kek, bytes blob, mut_bytes key) noexcept {
  const ossl::cipher_ctx ctx = start(direction::unwrap, kek);
  if (!ctx) {
    return EKI_ERR_BACKEND;
  }
  // With a ready context and inputs of the right sizes, the update call fails only when the
  // recovered initial value differs from A6A6A6A6A6A6A6A6, that is, on an integrity failure.
  int out_len = 0;
  if (EVP_DecryptUpdate(ctx.get(), key.data(), &out_len, blob.data(),
                        static_cast<int>(blob.size())) != 1) {
    return EKI_ERR_AUTH_FAILED;
  }
  if (std::cmp_not_equal(out_len, key.size()) || !finish(direction::unwrap, ctx.get())) {
    return EKI_ERR_BACKEND;
  }
  return EKI_OK;
}

} // namespace

eki_status aes_256_key_wrap(bytes kek32, bytes key32, mut_bytes out40) noexcept {
  ossl::error_scope errors;
  const bool out_ok = out40.size() == EKI_WRAPPED_KEY_LEN;
  eki_status status = EKI_OK;
  if (kek32.size() != kek_len || key32.size() != key_len || !out_ok) {
    status = EKI_ERR_INVALID_ARGUMENT;
  } else {
    status = wrap_impl(kek32, key32, out40);
  }
  if (status != EKI_OK && out_ok) {
    ossl::cleanse(out40);
  }
  return errors.settle(status);
}

eki_status aes_256_key_unwrap(bytes kek32, bytes blob40, mut_bytes key32) noexcept {
  ossl::error_scope errors;
  const bool key_ok = key32.size() == key_len;
  eki_status status = EKI_OK;
  if (kek32.size() != kek_len || blob40.size() != EKI_WRAPPED_KEY_LEN || !key_ok) {
    status = EKI_ERR_INVALID_ARGUMENT;
  } else {
    status = unwrap_impl(kek32, blob40, key32);
  }
  // OpenSSL wipes its output on an integrity failure; the wipe here covers every other path too.
  if (status != EKI_OK && key_ok) {
    ossl::cleanse(key32);
  }
  return errors.settle(status);
}

} // namespace ekicore
