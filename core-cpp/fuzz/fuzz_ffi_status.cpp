// Every stateless function of the ABI with arbitrary buffers and a NULL flag per pointer.
//
// Properties, from the contract (docs/ffi-contract.md):
// * the status is a defined value (0..=12);
// * EKI_ERR_NULL_POINTER is only returned when some pointer argument was NULL;
// * on every failure, each non-NULL output whose length is in its valid range is all zero
//   (outputs are pre-filled with 0xA5, so an untouched output is caught).
//
// EKI_ERR_UNSUPPORTED is exempt from the zero-fill check for now: the stubs return it without
// touching their outputs. Lesson L8 removes the exemption once every module is real.
// The first input byte picks the function, in the order of StatelessCall in
// core-rs/fuzz/src/lib.rs; the fields that follow are read in the same order as there.

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "ekicore.h"
#include "fuzz_input.hpp"

namespace {

using ekifuzz::Buffer;
using ekifuzz::InBuf;
using ekifuzz::Input;
using ekifuzz::require;

constexpr uint8_t kPrefill = 0xA5;
constexpr size_t kOkmLenFuzzMax = 9000; // a little past EKI_HKDF_MAX_OKM_LEN (8160)

// An output buffer pre-filled with 0xA5, passed as NULL when `null` is set. `checked` says
// whether the contract zero-fills it on error at this length.
struct Out {
  bool null;
  bool checked;
  Buffer bytes;

  Out(bool is_null, size_t len, bool zero_filled_on_error)
      : null(is_null), checked(zero_filled_on_error), bytes(len, kPrefill) {}

  uint8_t* ptr() {
    return null ? nullptr : bytes.data();
  }
};

// A fixed-size input array and its NULL flag.
template <size_t N> struct InFixed {
  bool null;
  std::array<uint8_t, N> bytes;

  static InFixed read(Input& in) {
    const bool null = in.boolean();
    return InFixed{null, in.array<N>()};
  }

  [[nodiscard]] const uint8_t* ptr() const {
    return null ? nullptr : bytes.data();
  }
};

struct Result {
  int32_t status;
  bool any_null;
  std::vector<Out> outputs;
};

Result call_hmac(Input& in) {
  const InBuf key = InBuf::read(in);
  const InBuf msg = InBuf::read(in);
  std::vector<Out> outs;
  outs.emplace_back(in.boolean(), EKI_HMAC_SHA256_LEN, true);
  const auto status = static_cast<int32_t>(
      eki_hmac_sha256(key.ptr(), key.len(), msg.ptr(), msg.len(), outs[0].ptr()));
  return {status, key.null || msg.null || outs[0].null, std::move(outs)};
}

Result call_hmac_verify(Input& in) {
  const InBuf key = InBuf::read(in);
  const InBuf msg = InBuf::read(in);
  const InBuf tag = InBuf::read(in);
  const auto status = static_cast<int32_t>(
      eki_hmac_sha256_verify(key.ptr(), key.len(), msg.ptr(), msg.len(), tag.ptr(), tag.len()));
  return {status, key.null || msg.null || tag.null, {}};
}

Result call_hkdf(Input& in) {
  const InBuf ikm = InBuf::read(in);
  const InBuf salt = InBuf::read(in);
  const InBuf info = InBuf::read(in);
  const bool okm_null = in.boolean();
  const size_t okm_len = in.u16() % (kOkmLenFuzzMax + 1);
  const bool in_range = okm_len >= 1 && okm_len <= EKI_HKDF_MAX_OKM_LEN;
  std::vector<Out> outs;
  outs.emplace_back(okm_null, okm_len, in_range);
  const auto status =
      static_cast<int32_t>(eki_hkdf_sha256(ikm.ptr(), ikm.len(), salt.ptr(), salt.len(), info.ptr(),
                                           info.len(), outs[0].ptr(), okm_len));
  return {status, ikm.null || salt.null || info.null || okm_null, std::move(outs)};
}

Result call_aead_seal(Input& in) {
  const eki_aead_alg alg = in.i32();
  const InBuf key = InBuf::read(in);
  const InBuf nonce = InBuf::read(in);
  const InBuf aad = InBuf::read(in);
  const InBuf pt = InBuf::read(in);
  std::vector<Out> outs;
  // pt_len is far below EKI_AEAD_MAX_LEN, so ct_out is always in range.
  outs.emplace_back(in.boolean(), pt.len(), true);
  outs.emplace_back(in.boolean(), EKI_AEAD_TAG_LEN, true);
  const auto status = static_cast<int32_t>(
      eki_aead_seal(alg, key.ptr(), key.len(), nonce.ptr(), nonce.len(), aad.ptr(), aad.len(),
                    pt.ptr(), pt.len(), outs[0].ptr(), outs[1].ptr()));
  const bool any_null =
      key.null || nonce.null || aad.null || pt.null || outs[0].null || outs[1].null;
  return {status, any_null, std::move(outs)};
}

Result call_aead_open(Input& in) {
  const eki_aead_alg alg = in.i32();
  const InBuf key = InBuf::read(in);
  const InBuf nonce = InBuf::read(in);
  const InBuf aad = InBuf::read(in);
  const InBuf ct = InBuf::read(in);
  const auto tag = InFixed<EKI_AEAD_TAG_LEN>::read(in);
  std::vector<Out> outs;
  outs.emplace_back(in.boolean(), ct.len(), true);
  const auto status = static_cast<int32_t>(
      eki_aead_open(alg, key.ptr(), key.len(), nonce.ptr(), nonce.len(), aad.ptr(), aad.len(),
                    ct.ptr(), ct.len(), tag.ptr(), outs[0].ptr()));
  const bool any_null = key.null || nonce.null || aad.null || ct.null || tag.null || outs[0].null;
  return {status, any_null, std::move(outs)};
}

Result call_ecdsa_verify(Input& in) {
  const auto public_key = InFixed<EKI_P256_PUBLIC_KEY_LEN>::read(in);
  const InBuf msg = InBuf::read(in);
  const auto sig = InFixed<EKI_P256_SIGNATURE_LEN>::read(in);
  const auto status = static_cast<int32_t>(
      eki_ecdsa_p256_verify(public_key.ptr(), msg.ptr(), msg.len(), sig.ptr()));
  return {status, public_key.null || msg.null || sig.null, {}};
}

Result run(Input& in) {
  switch (in.u8() % 6U) {
  case 0:
    return call_hmac(in);
  case 1:
    return call_hmac_verify(in);
  case 2:
    return call_hkdf(in);
  case 3:
    return call_aead_seal(in);
  case 4:
    return call_aead_open(in);
  default:
    return call_ecdsa_verify(in);
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Input in(data, size);
  const Result result = run(in);
  ekifuzz::require_status_in_range(result.status);
  if (result.status == EKI_ERR_NULL_POINTER) {
    require(result.any_null);
  }
  // TODO(L8): drop the EKI_ERR_UNSUPPORTED exemption once no function is a stub.
  if (result.status != EKI_OK && result.status != EKI_ERR_UNSUPPORTED) {
    for (const Out& out : result.outputs) {
      if (!out.null && out.checked) {
        require(out.bytes.all(0));
      }
    }
  }
  return 0;
}
