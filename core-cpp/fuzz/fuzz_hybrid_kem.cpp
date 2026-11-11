// The hybrid X25519 + ML-KEM-768 KEM on arbitrary public keys, secret keys and ciphertexts.
//
// Input: one byte modulo 3 choosing the mode, then
// * 0, round trip: an XOR mask for the public key and one for the ciphertext (byte strings,
//   applied from the first byte). A fresh key pair is generated, the masked public key is
//   encapsulated to, the masked ciphertext decapsulated;
// * 1, decapsulation: a secret key and a ciphertext (byte strings, zero-padded or cut to 96 and
//   1120 bytes);
// * 2, encapsulation: a public key (byte string, zero-padded or cut to 1216 bytes).
//
// Properties, in a build with EKI_WITH_PQ:
// * every status is EKI_OK or EKI_ERR_INVALID_ARGUMENT, and every output of a failed call is all
//   zero;
// * key generation succeeds, and so does encapsulation to an unmodified public key;
// * decapsulation fails only when the X25519 part of the ciphertext was modified;
// * without either mask, decapsulation recovers the encapsulated secret; with a mask that changed
//   anything, a successful decapsulation gives a different secret (implicit rejection, and the
//   combiner binds the ciphertext and the public key).
//
// Without EKI_WITH_PQ every call is EKI_ERR_UNSUPPORTED with all outputs zero.
//
// Mirrors core-rs/fuzz/fuzz_targets/hybrid_kem.rs.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <utility>

#include "ekicore.h"
#include "fuzz_input.hpp"

namespace {

using ekifuzz::Buffer;
using ekifuzz::bytes;
using ekifuzz::Call;
using ekifuzz::OutBuf;
using ekifuzz::require;

// X25519 part at the front of a ciphertext.
constexpr size_t kX25519Len = 32;

// Checks a finished call: the contract's rules, then the statuses this target allows.
int32_t finish(const Call& call) {
  call.check();
  if (ekifuzz::kWithPq) {
    require(call.status == EKI_OK || call.status == EKI_ERR_INVALID_ARGUMENT, call.function);
  } else {
    ekifuzz::expect_status(call.status, EKI_ERR_UNSUPPORTED, call.function);
  }
  return call.status;
}

struct KeyPair {
  int32_t status;
  OutBuf pk;
  OutBuf sk;
};

struct Encapsulated {
  int32_t status;
  OutBuf ct;
  OutBuf ss;
};

struct Decapsulated {
  int32_t status;
  OutBuf ss;
};

KeyPair keygen() {
  KeyPair out{0, OutBuf(false, EKI_HYBRID_PK_LEN), OutBuf(false, EKI_HYBRID_SK_LEN)};
  Call call{"eki_hybrid_kem_keygen",
            static_cast<int32_t>(eki_hybrid_kem_keygen(out.pk.ptr(), out.sk.ptr()))};
  call.outputs.push_back(out.pk.seen());
  call.outputs.push_back(out.sk.seen());
  out.status = finish(call);
  return out;
}

Encapsulated encap(const Buffer& pk) {
  require(pk.size() == EKI_HYBRID_PK_LEN, "public key length");
  Encapsulated out{0, OutBuf(false, EKI_HYBRID_CT_LEN), OutBuf(false, EKI_HYBRID_SS_LEN)};
  Call call{"eki_hybrid_kem_encap",
            static_cast<int32_t>(eki_hybrid_kem_encap(pk.data(), out.ct.ptr(), out.ss.ptr()))};
  call.outputs.push_back(out.ct.seen());
  call.outputs.push_back(out.ss.seen());
  out.status = finish(call);
  return out;
}

Decapsulated decap(const Buffer& sk, const Buffer& ct) {
  require(sk.size() == EKI_HYBRID_SK_LEN && ct.size() == EKI_HYBRID_CT_LEN, "key lengths");
  Decapsulated out{0, OutBuf(false, EKI_HYBRID_SS_LEN)};
  Call call{"eki_hybrid_kem_decap",
            static_cast<int32_t>(eki_hybrid_kem_decap(sk.data(), ct.data(), out.ss.ptr()))};
  call.outputs.push_back(out.ss.seen());
  out.status = finish(call);
  return out;
}

// b XORed with mask from the first byte, in an exact allocation; and whether any byte changed.
std::pair<Buffer, bool> masked(bytes b, const Buffer& mask) {
  Buffer out(b);
  bool changed = false;
  for (size_t i = 0; i < std::min(b.size(), mask.size()); ++i) {
    out.data()[i] ^= mask.data()[i];
    changed |= mask.data()[i] != 0;
  }
  return {std::move(out), changed};
}

void round_trip(ekifuzz::Input& in) {
  const Buffer pk_mask = in.bytes();
  const Buffer ct_mask = in.bytes();
  const KeyPair pair = keygen();
  if (pair.status != EKI_OK) {
    return;
  }
  const auto [pk2, pk_changed] = masked(pair.pk.span(), pk_mask);
  const Encapsulated sent = encap(pk2);
  if (!pk_changed) {
    ekifuzz::expect_status(sent.status, EKI_OK, "eki_hybrid_kem_encap to a fresh public key");
  }
  if (sent.status != EKI_OK) {
    return;
  }
  const auto [ct2, ct_changed] = masked(sent.ct.span(), ct_mask);
  const bytes x25519_mask = ct_mask.span().first(std::min(ct_mask.size(), kX25519Len));
  const bool x25519_changed =
      std::any_of(x25519_mask.begin(), x25519_mask.end(), [](uint8_t m) { return m != 0; });
  const Decapsulated received = decap(Buffer(pair.sk.span()), ct2);
  if (!x25519_changed) {
    ekifuzz::expect_status(received.status, EKI_OK, "eki_hybrid_kem_decap");
  }
  if (received.status != EKI_OK) {
    return;
  }
  const bool same = Buffer(received.ss.span()).equals(sent.ss.span());
  if (pk_changed || ct_changed) {
    require(!same, "a modified exchange gave the same secret");
  } else {
    require(same, "decap(encap(pk)) gave another secret");
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ekifuzz::Input in(data, size);
  switch (in.u8() % 3U) {
  case 0:
    round_trip(in);
    break;
  case 1: {
    const Buffer sk = ekifuzz::exact(in.bytes().span(), EKI_HYBRID_SK_LEN, 0);
    const Buffer ct = ekifuzz::exact(in.bytes().span(), EKI_HYBRID_CT_LEN, 0);
    decap(sk, ct);
    break;
  }
  default:
    encap(ekifuzz::exact(in.bytes().span(), EKI_HYBRID_PK_LEN, 0));
    break;
  }
  return 0;
}
