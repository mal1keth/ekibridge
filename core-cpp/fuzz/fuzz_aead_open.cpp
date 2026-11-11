// eki_aead_open and eki_aead_seal on arbitrary algorithm, key, nonce, AAD, ciphertext and tag.
//
// Input: alg (i32), key, nonce, AAD and ciphertext (byte strings), the 16-byte tag.
//
// Properties:
// * opening the input fails or succeeds as the contract allows, and a failure leaves pt_out all
//   zero;
// * when opening succeeds, sealing the recovered plaintext reproduces the ciphertext and tag;
// * sealing the input's ciphertext bytes as a plaintext succeeds exactly when the algorithm, key
//   length and nonce length are valid, and opening the result gives those bytes back, while the
//   same ciphertext with one tag bit flipped is EKI_ERR_AUTH_FAILED with pt_out all zero.
//
// Mirrors core-rs/fuzz/fuzz_targets/aead_open.rs.

#include <array>
#include <cstddef>
#include <cstdint>

#include "ekicore.h"
#include "fuzz_input.hpp"

namespace {

using ekifuzz::Buffer;
using ekifuzz::bytes;
using ekifuzz::Call;
using ekifuzz::OutBuf;
using ekifuzz::require;

using Tag = std::array<uint8_t, EKI_AEAD_TAG_LEN>;

struct Params {
  eki_aead_alg alg;
  Buffer key;
  Buffer nonce;
  Buffer aad;
};

struct Opened {
  int32_t status;
  OutBuf pt;
};

struct Sealed {
  int32_t status;
  OutBuf ct;
  OutBuf tag;
};

Opened open(const Params& p, const Buffer& ct, const Tag& tag) {
  Opened out{0, OutBuf(false, ct.size())};
  out.status = static_cast<int32_t>(eki_aead_open(p.alg, p.key.data(), p.key.size(), p.nonce.data(),
                                                  p.nonce.size(), p.aad.data(), p.aad.size(),
                                                  ct.data(), ct.size(), tag.data(), out.pt.ptr()));
  Call call{"eki_aead_open", out.status};
  call.outputs.push_back(out.pt.seen());
  call.check();
  return out;
}

Sealed seal(const Params& p, const Buffer& pt) {
  Sealed out{0, OutBuf(false, pt.size()), OutBuf(false, EKI_AEAD_TAG_LEN)};
  out.status = static_cast<int32_t>(
      eki_aead_seal(p.alg, p.key.data(), p.key.size(), p.nonce.data(), p.nonce.size(), p.aad.data(),
                    p.aad.size(), pt.data(), pt.size(), out.ct.ptr(), out.tag.ptr()));
  Call call{"eki_aead_seal", out.status};
  call.outputs.push_back(out.ct.seen());
  call.outputs.push_back(out.tag.seen());
  call.check();
  return out;
}

Tag to_tag(bytes b) {
  Tag tag{};
  std::copy(b.begin(), b.end(), tag.begin());
  return tag;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ekifuzz::Input in(data, size);
  Params p{in.i32(), in.bytes(), in.bytes(), in.bytes()};
  const Buffer ct = in.bytes();
  const Tag tag = in.array<EKI_AEAD_TAG_LEN>();
  const bool valid = (p.alg == EKI_AEAD_AES_256_GCM || p.alg == EKI_AEAD_CHACHA20_POLY1305) &&
                     p.key.size() == EKI_AEAD_KEY_LEN && p.nonce.size() == EKI_AEAD_NONCE_LEN;

  const Opened opened = open(p, ct, tag);
  if (valid) {
    require(opened.status == EKI_OK || opened.status == EKI_ERR_AUTH_FAILED, "eki_aead_open");
  } else {
    ekifuzz::expect_status(opened.status, EKI_ERR_INVALID_ARGUMENT, "eki_aead_open");
  }
  if (opened.status == EKI_OK) {
    const Sealed resealed = seal(p, Buffer(opened.pt.span()));
    ekifuzz::expect_status(resealed.status, EKI_OK, "eki_aead_seal of an opened plaintext");
    require(ct.equals(resealed.ct.span()), "seal(open(ct)) changed the ciphertext");
    require(Buffer(resealed.tag.span()).equals(tag), "seal(open(ct)) changed the tag");
  }

  const Sealed sealed = seal(p, ct);
  ekifuzz::expect_status(sealed.status, valid ? EKI_OK : EKI_ERR_INVALID_ARGUMENT, "eki_aead_seal");
  if (sealed.status != EKI_OK) {
    return 0;
  }
  const Buffer ct2(sealed.ct.span());
  Tag tag2 = to_tag(sealed.tag.span());
  const Opened round_trip = open(p, ct2, tag2);
  ekifuzz::expect_status(round_trip.status, EKI_OK, "eki_aead_open of a sealed ciphertext");
  require(ct.equals(round_trip.pt.span()), "open(seal(pt)) changed the plaintext");
  tag2[0] ^= 1U;
  ekifuzz::expect_status(open(p, ct2, tag2).status, EKI_ERR_AUTH_FAILED,
                         "eki_aead_open with a flipped tag bit");
  return 0;
}
