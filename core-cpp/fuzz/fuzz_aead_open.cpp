// eki_aead_open on arbitrary algorithm, key, nonce, AAD, ciphertext and tag.
//
// Properties: the status is a defined value, and whenever opening succeeds, sealing the
// recovered plaintext under the same parameters reproduces the ciphertext and the tag exactly.
// Mirrors core-rs/fuzz/fuzz_targets/aead_open.rs.

#include <array>
#include <cstddef>
#include <cstdint>

#include "ekicore.h"
#include "fuzz_input.hpp"

using ekifuzz::Buffer;
using ekifuzz::require;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ekifuzz::Input in(data, size);
  const eki_aead_alg alg = in.i32();
  const Buffer key = in.bytes();
  const Buffer nonce = in.bytes();
  const Buffer aad = in.bytes();
  const Buffer ct = in.bytes();
  const Buffer tag(in.array<EKI_AEAD_TAG_LEN>());

  Buffer pt(ct.size(), 0xA5);
  const auto status = static_cast<int32_t>(
      eki_aead_open(alg, key.data(), key.size(), nonce.data(), nonce.size(), aad.data(), aad.size(),
                    ct.data(), ct.size(), tag.data(), pt.data()));
  ekifuzz::require_status_in_range(status);
  if (status != EKI_OK) {
    return 0;
  }

  Buffer resealed(pt.size(), 0xA5);
  Buffer retag(EKI_AEAD_TAG_LEN, 0xA5);
  const auto reseal = static_cast<int32_t>(
      eki_aead_seal(alg, key.data(), key.size(), nonce.data(), nonce.size(), aad.data(), aad.size(),
                    pt.data(), pt.size(), resealed.data(), retag.data()));
  require(reseal == EKI_OK);
  require(resealed.equals(ct.span()));
  require(retag.equals(tag.span()));
  return 0;
}
