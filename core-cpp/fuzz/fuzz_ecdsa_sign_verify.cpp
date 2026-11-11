// Sign with a stored ECDSA P-256 key, then verify with eki_ecdsa_p256_verify, unchanged and
// tampered.
//
// Input: the message (byte string), one byte modulo 4 choosing what to tamper with (nothing, the
// signature, the message, the public key), and an XOR mask (byte string) applied from the first
// byte; mask bytes past the end of the message are appended to it.
//
// Each run generates a key in a fresh software store, signs the message with eki_ks_sign and
// reads the public key with eki_ks_get_public_key. Properties:
// * signing and reading the public key succeed;
// * the untampered triple verifies;
// * a changed signature or message is EKI_ERR_AUTH_FAILED; a changed public key is
//   EKI_ERR_INVALID_ARGUMENT (not a curve point) or EKI_ERR_AUTH_FAILED.
//
// Mirrors core-rs/fuzz/fuzz_targets/ecdsa_sign_verify.rs.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ekicore.h"
#include "fuzz_input.hpp"

namespace {

using ekifuzz::Buffer;

// XORs mask into b from the first byte; returns whether a byte changed.
bool xor_into(uint8_t* b, size_t len, const Buffer& mask) {
  bool changed = false;
  for (size_t i = 0; i < len && i < mask.size(); ++i) {
    b[i] ^= mask.data()[i];
    changed |= mask.data()[i] != 0;
  }
  return changed;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ekifuzz::Input in(data, size);
  Buffer msg = in.bytes();
  const unsigned tamper = in.u8() % 4U;
  const Buffer mask = in.bytes();

  const ekifuzz::Store store = ekifuzz::Store::software();
  const eki_key_id id = store.generate(EKI_KEY_ECDSA_P256, "fuzz-signer");
  ekifuzz::OutBuf sig_out(false, EKI_P256_SIGNATURE_LEN);
  const auto signed_status =
      static_cast<int32_t>(eki_ks_sign(store.get(), &id, msg.data(), msg.size(), sig_out.ptr()));
  ekifuzz::Call sign{"eki_ks_sign", signed_status};
  sign.outputs.push_back(sig_out.seen());
  sign.check();
  ekifuzz::expect_status(signed_status, EKI_OK, "eki_ks_sign with a fresh key");
  ekifuzz::OutBuf pk_out(false, EKI_P256_PUBLIC_KEY_LEN);
  ekifuzz::expect_status(
      static_cast<int32_t>(eki_ks_get_public_key(store.get(), &id, pk_out.ptr())), EKI_OK,
      "eki_ks_get_public_key of a fresh key");

  Buffer sig(sig_out.span());
  Buffer pk(pk_out.span());
  bool changed = false;
  switch (tamper) {
  case 0:
    break;
  case 1:
    changed = xor_into(sig.data(), sig.size(), mask);
    break;
  case 2:
    changed = xor_into(msg.data(), msg.size(), mask);
    if (mask.size() > msg.size()) {
      std::vector<uint8_t> longer(msg.span().begin(), msg.span().end());
      longer.insert(longer.end(), mask.span().begin() + static_cast<std::ptrdiff_t>(msg.size()),
                    mask.span().end());
      msg = Buffer(longer);
      changed = true;
    }
    break;
  default:
    changed = xor_into(pk.data(), pk.size(), mask);
    break;
  }

  const auto status =
      static_cast<int32_t>(eki_ecdsa_p256_verify(pk.data(), msg.data(), msg.size(), sig.data()));
  ekifuzz::Call{"eki_ecdsa_p256_verify", status}.check();
  if (!changed) {
    ekifuzz::expect_status(status, EKI_OK, "eki_ecdsa_p256_verify of an untampered signature");
  } else if (tamper == 3) {
    ekifuzz::require(status == EKI_ERR_INVALID_ARGUMENT || status == EKI_ERR_AUTH_FAILED,
                     "eki_ecdsa_p256_verify with a changed public key");
  } else {
    ekifuzz::expect_status(status, EKI_ERR_AUTH_FAILED,
                           "eki_ecdsa_p256_verify of a tampered input");
  }
  return 0;
}
