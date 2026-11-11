// eki_hkdf_sha256 on arbitrary inputs and two output lengths from 0 to 9000.
//
// Input: IKM, salt and info (byte strings), then two lengths (u16 each, modulo 9001).
//
// Properties:
// * the call succeeds exactly when ikm_len is 1 to 32768 and okm_len 1 to 8160 (salt and info
//   stay far below their cap); otherwise it is EKI_ERR_INVALID_ARGUMENT;
// * after a failure okm is all zero when its length is in range, and untouched above 8160;
// * prefix stability: of two successful derivations from the same inputs, the shorter output is a
//   prefix of the longer one.
//
// Mirrors core-rs/fuzz/fuzz_targets/hkdf.rs.

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "ekicore.h"
#include "fuzz_input.hpp"

namespace {

using ekifuzz::Buffer;
using ekifuzz::OutBuf;

// Upper bound (inclusive) of the lengths asked for: a little past EKI_HKDF_MAX_OKM_LEN.
constexpr uint16_t kOkmLenFuzzMax = 9000;

struct Derived {
  int32_t status;
  OutBuf okm;
};

Derived derive(const Buffer& ikm, const Buffer& salt, const Buffer& info, size_t okm_len) {
  Derived out{0, ekifuzz::sized_out(false, okm_len, okm_len, EKI_HKDF_MAX_OKM_LEN)};
  out.status =
      static_cast<int32_t>(eki_hkdf_sha256(ikm.data(), ikm.size(), salt.data(), salt.size(),
                                           info.data(), info.size(), out.okm.ptr(), okm_len));
  ekifuzz::Call call{"eki_hkdf_sha256", out.status};
  call.outputs.push_back(out.okm.seen());
  call.check();
  const bool valid = ikm.size() >= 1 && ikm.size() <= EKI_HKDF_MAX_INPUT_LEN &&
                     salt.size() <= EKI_HKDF_MAX_INPUT_LEN &&
                     info.size() <= EKI_HKDF_MAX_INPUT_LEN && okm_len >= 1 &&
                     okm_len <= EKI_HKDF_MAX_OKM_LEN;
  ekifuzz::expect_status(out.status, valid ? EKI_OK : EKI_ERR_INVALID_ARGUMENT, "eki_hkdf_sha256");
  return out;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ekifuzz::Input in(data, size);
  const Buffer ikm = in.bytes();
  const Buffer salt = in.bytes();
  const Buffer info = in.bytes();
  const size_t first = in.u16() % (kOkmLenFuzzMax + 1U);
  const size_t second = in.u16() % (kOkmLenFuzzMax + 1U);

  const Derived one = derive(ikm, salt, info, first);
  const Derived two = derive(ikm, salt, info, second);
  if (one.status == EKI_OK && two.status == EKI_OK) {
    const size_t n = std::min(first, second);
    ekifuzz::require(std::equal(one.okm.span().begin(),
                                one.okm.span().begin() + static_cast<std::ptrdiff_t>(n),
                                two.okm.span().begin()),
                     "HKDF outputs of two lengths differ in their common prefix");
  }
  return 0;
}
