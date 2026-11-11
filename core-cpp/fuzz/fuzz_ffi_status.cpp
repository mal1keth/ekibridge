// Every exported function of the ABI, called in arbitrary sequences with arbitrary buffers,
// lengths within and beyond their caps, NULL flags and selectors, on a software key store.
//
// Input: the session's store (one byte modulo 3: none, eki_ks_open, eki_ks_open_v2; then a Config
// for the last two), then calls until the input ends (at most kMaxCalls): one byte modulo kOps
// picks the function, and its arguments follow in parameter order (see step). A store call gets
// the session's handle, or NULL when its first byte says so or no store is open. Key ids are raw
// bytes or ids the session made (read_key_ref). The run's audit log, the approver keys and their
// signatures, the last wrapped key, KEM key pair and ciphertext and destroy request are carried
// from call to call, so the success paths are reachable.
//
// Properties of every call (Call::check in fuzz_input.hpp):
// * the status is a defined value, never EKI_ERR_INTERNAL;
// * a NULL pointer parameter gives EKI_ERR_NULL_POINTER, and that status has no other cause than
//   a NULL parameter or configuration field;
// * a length above its maximum gives EKI_ERR_INVALID_ARGUMENT;
// * after any failure every non-NULL output is all zero, with no exception for
//   EKI_ERR_UNSUPPORTED, except an output whose length was above its maximum, which is left
//   untouched;
// * EKI_ERR_BACKEND only where the contract allows it here (opening a store or a log, reading a
//   log), and EKI_ERR_UNSUPPORTED only for a feature that is off or a handle without the audit
//   log or approvers the call needs.
//
// Exact oracles where the status is fully determined: opening a store (Config::expected_open),
// generating a key, reading an audit log, the metadata functions. At the end the store is closed;
// if it had the run's audit log, the log verifies and opens again (the lock was released).
//
// Mirrors core-rs/fuzz/fuzz_targets/ffi_status.rs; one seed file drives both.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "ekicore.h"
#include "fuzz_input.hpp"

namespace {

using ekifuzz::Buffer;
using ekifuzz::Call;
using ekifuzz::InBuf;
using ekifuzz::Input;
using ekifuzz::OutBuf;
using ekifuzz::require;
using ekifuzz::Slot;

// Calls made from one input at most.
constexpr size_t kMaxCalls = 24;

// Number of functions step can call.
constexpr unsigned kOps = 29;

// Names of the status values, for eki_status_name.
constexpr std::array<std::string_view, 13> kStatusNames = {
    "EKI_OK",
    "EKI_ERR_NULL_POINTER",
    "EKI_ERR_INVALID_ARGUMENT",
    "EKI_ERR_BUFFER_TOO_SMALL",
    "EKI_ERR_UNSUPPORTED",
    "EKI_ERR_AUTH_FAILED",
    "EKI_ERR_KEY_NOT_FOUND",
    "EKI_ERR_KEY_EXISTS",
    "EKI_ERR_WRONG_KEY_TYPE",
    "EKI_ERR_BACKEND",
    "EKI_ERR_INTERNAL",
    "EKI_ERR_KEY_STATE",
    "EKI_ERR_APPROVAL_REQUIRED",
};

// What a session carries from call to call.
struct Session {
  explicit Session(const ekifuzz::Scratch& run_scratch) : scratch(run_scratch) {}

  const ekifuzz::Scratch& scratch;
  ekifuzz::Approvers approvers;
  std::optional<ekifuzz::Store> store;
  bool dual = false;             // the store has approvers
  bool audited = false;          // the store has the run's audit log
  std::vector<eki_key_id> known; // ids of keys the session made
  std::array<uint8_t, EKI_WRAPPED_KEY_LEN> wrapped{};
  std::optional<std::pair<ekifuzz::Request, eki_key_id>> request;
  ekifuzz::Digest head{};
  std::vector<uint8_t> kem_pk;
  std::vector<uint8_t> kem_sk;
  std::vector<uint8_t> kem_ct;

  // The handle argument of a store call: NULL when the input's byte says so or no store is open.
  eki_ks* ks(Input& in) const {
    const bool null = in.boolean();
    return store && !null ? store->get() : nullptr;
  }

  // Whether eki_ks_open_v2 must find the run's log locked.
  [[nodiscard]] bool log_locked() const {
    return store && audited;
  }
};

// A fixed-size input with its NULL flag: Input::boolean, then N bytes.
template <size_t N> struct Fixed {
  bool null;
  std::array<uint8_t, N> bytes;

  static Fixed read(Input& in) {
    const bool null = in.boolean();
    return {null, in.array<N>()};
  }
  [[nodiscard]] const uint8_t* ptr() const {
    return null ? nullptr : bytes.data();
  }
};

template <size_t N> const uint8_t* ptr_or_null(bool null, const std::array<uint8_t, N>& a) {
  return null ? nullptr : a.data();
}

const uint8_t* ptr_or_null(bool null, const Buffer& b) {
  return null ? nullptr : b.data();
}

int32_t to_int(eki_status status) {
  return static_cast<int32_t>(status);
}

Call open_store(unsigned op, Session& s, Input& in) {
  const bool v2 = op == 12;
  const bool config_null = in.boolean();
  Slot<eki_ks*> out(in.boolean());
  const ekifuzz::Config config = ekifuzz::Config::read(in, s.scratch, s.approvers);
  const eki_ks_config raw1 = config.v1();
  const eki_ks_config_v2 raw2 = config.v2();
  const int32_t status = v2 ? to_int(eki_ks_open_v2(config_null ? nullptr : &raw2, out.ptr()))
                            : to_int(eki_ks_open(config_null ? nullptr : &raw1, out.ptr()));
  Call call{v2 ? "eki_ks_open_v2" : "eki_ks_open", status};
  call.null_param = config_null || out.is_null();
  call.null_field = v2 ? config.null_field_v2() : config.null_field_v1();
  call.outputs.push_back(out.seen());
  if (!call.null_param) {
    ekifuzz::expect_one_of(status, config.expected_open(v2, s.scratch, s.log_locked()),
                           call.function);
  }
  if (status == EKI_OK) {
    // Closed at once: the session keeps its own store.
    const ekifuzz::Store opened(out.get());
  }
  return call;
}

Call audit_verify(Session& s, Input& in) {
  const ekifuzz::Text path = ekifuzz::read_audit_path(in, s.scratch);
  std::optional<ekifuzz::Digest> head;
  switch (in.u8() % 3U) {
  case 0:
    break;
  case 1:
    head = in.array<EKI_AUDIT_HASH_LEN>();
    break;
  default:
    head = s.head;
    break;
  }
  Slot<uint64_t> records(in.boolean());
  const int32_t status =
      to_int(eki_audit_verify(path.ptr(), head ? head->data() : nullptr, records.ptr()));
  Call call{"eki_audit_verify", status};
  call.null_param = path.is_null() || records.is_null();
  call.outputs.push_back(records.seen());
  if (!call.null_param) {
    const ekifuzz::bytes seen = path.seen(EKI_AUDIT_PATH_MAX_LEN + 1).value_or(ekifuzz::bytes{});
    std::vector<int32_t> expected;
    if (seen.empty() || seen.size() > EKI_AUDIT_PATH_MAX_LEN) {
      expected = {EKI_ERR_INVALID_ARGUMENT};
    } else if (!ekifuzz::same(seen, s.scratch.log) || !s.scratch.log_exists()) {
      expected = {EKI_ERR_BACKEND};
    } else if (!head) {
      expected = {EKI_OK};
    } else {
      expected = {EKI_OK, EKI_ERR_AUTH_FAILED};
    }
    ekifuzz::expect_one_of(status, expected, call.function);
  }
  return call;
}

Call metadata(Input& in) {
  const int32_t value = in.i32();
  require(eki_abi_version() == EKI_ABI_VERSION, "eki_abi_version");
  require(std::string_view(eki_version()).starts_with("ekicore-cpp "), "eki_version");
  const std::string_view expected = value >= 0 && static_cast<size_t>(value) < kStatusNames.size()
                                        ? kStatusNames[static_cast<size_t>(value)]
                                        : "EKI_STATUS_UNKNOWN";
  require(std::string_view(eki_status_name(value)) == expected, "eki_status_name");
  return Call{"eki_status_name", EKI_OK};
}

Call last_error(Session& s, Input& in) {
  eki_ks* ks = s.ks(in);
  const bool buf_null = in.boolean();
  const size_t buf_len = in.u16() % 300U;
  OutBuf buf(buf_null, buf_len);
  const size_t n = eki_ks_last_error_message(ks, reinterpret_cast<char*>(buf.ptr()), buf_len);
  if (ks == nullptr) {
    require(n == 0, "eki_ks_last_error_message(NULL) returned a length");
  }
  if (!buf_null && buf_len > 0) {
    const size_t written = std::min(n, buf_len - 1);
    const ekifuzz::bytes b = buf.span();
    require(b[written] == 0, "message not NUL-terminated where its length says");
    require(std::find(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(written), uint8_t{0}) ==
                b.begin() + static_cast<std::ptrdiff_t>(written),
            "message shorter than reported");
  }
  return Call{"eki_ks_last_error_message", EKI_OK};
}

Call destroy_approve(Session& s, Input& in) {
  eki_ks* ks = s.ks(in);
  const auto raw_request = Fixed<EKI_DESTROY_REQUEST_LEN>::read(in);
  const bool from_session = in.boolean();
  ekifuzz::Request request = raw_request.bytes;
  eki_key_id target{};
  if (s.request && from_session) {
    request = s.request->first;
    target = s.request->second;
  }
  const auto raw_pk = Fixed<EKI_P256_PUBLIC_KEY_LEN>::read(in);
  const bool pk_generated = in.boolean();
  const uint8_t pk_pick = in.u8();
  const ekifuzz::PublicKey pk = pk_generated ? s.approvers.public_key(pk_pick) : raw_pk.bytes;
  const auto raw_sig = Fixed<EKI_P256_SIGNATURE_LEN>::read(in);
  const bool sig_generated = in.boolean();
  const uint8_t sig_pick = in.u8();
  const ekifuzz::Signature sig =
      sig_generated ? s.approvers.approve(sig_pick, request, target) : raw_sig.bytes;
  Slot<uint32_t> remaining(in.boolean());
  const int32_t status = to_int(eki_ks_destroy_approve(
      ks, ptr_or_null(raw_request.null, request), ptr_or_null(raw_pk.null, pk),
      ptr_or_null(raw_sig.null, sig), remaining.ptr()));
  Call call{"eki_ks_destroy_approve", status};
  call.null_param =
      ks == nullptr || raw_request.null || raw_pk.null || raw_sig.null || remaining.is_null();
  call.outputs.push_back(remaining.seen());
  if (!call.null_param) {
    require((status == EKI_ERR_UNSUPPORTED) == !s.dual, "destroy_approve and dual control");
  }
  return call;
}

// One call; its arguments are read from in in parameter order.
Call step(unsigned op, Session& s, Input& in) {
  switch (op) {
  case 0: {
    const InBuf key = InBuf::read(in);
    const InBuf msg = InBuf::read(in);
    OutBuf out(in.boolean(), EKI_HMAC_SHA256_LEN);
    Call call{"eki_hmac_sha256",
              to_int(eki_hmac_sha256(key.ptr(), key.len(), msg.ptr(), msg.len(), out.ptr()))};
    call.null_param = key.null_with(key.len()) || msg.null_with(msg.len()) || out.is_null();
    call.outputs.push_back(out.seen());
    return call;
  }
  case 1: {
    const InBuf key = InBuf::read(in);
    const InBuf msg = InBuf::read(in);
    const InBuf tag = InBuf::read(in);
    Call call{"eki_hmac_sha256_verify",
              to_int(eki_hmac_sha256_verify(key.ptr(), key.len(), msg.ptr(), msg.len(), tag.ptr(),
                                            tag.len()))};
    call.null_param =
        key.null_with(key.len()) || msg.null_with(msg.len()) || tag.null_with(tag.len());
    return call;
  }
  case 2: {
    // A length argument above its cap is never used to access the buffer (the contract's
    // exception); otherwise it is the buffer's length.
    const InBuf ikm = InBuf::read(in);
    const size_t ikm_len = ekifuzz::read_capped_len(in, ikm.len(), EKI_HKDF_MAX_INPUT_LEN);
    const InBuf salt = InBuf::read(in);
    const size_t salt_len = ekifuzz::read_capped_len(in, salt.len(), EKI_HKDF_MAX_INPUT_LEN);
    const InBuf info = InBuf::read(in);
    const size_t info_len = ekifuzz::read_capped_len(in, info.len(), EKI_HKDF_MAX_INPUT_LEN);
    const bool okm_null = in.boolean();
    const size_t okm_size = in.u16() % 9001U;
    const size_t okm_len = ekifuzz::read_capped_len(in, okm_size, EKI_HKDF_MAX_OKM_LEN);
    OutBuf okm = ekifuzz::sized_out(okm_null, okm_size, okm_len, EKI_HKDF_MAX_OKM_LEN);
    Call call{"eki_hkdf_sha256", to_int(eki_hkdf_sha256(ikm.ptr(), ikm_len, salt.ptr(), salt_len,
                                                        info.ptr(), info_len, okm.ptr(), okm_len))};
    call.null_param = ikm.null_with(ikm_len) || salt.null_with(salt_len) ||
                      info.null_with(info_len) || (okm_null && okm_len > 0);
    call.over_cap = ikm_len > EKI_HKDF_MAX_INPUT_LEN || salt_len > EKI_HKDF_MAX_INPUT_LEN ||
                    info_len > EKI_HKDF_MAX_INPUT_LEN || okm_len > EKI_HKDF_MAX_OKM_LEN;
    call.outputs.push_back(okm.seen());
    return call;
  }
  case 3: {
    const eki_aead_alg alg = in.i32();
    const InBuf key = InBuf::read(in);
    const InBuf nonce = InBuf::read(in);
    const InBuf aad = InBuf::read(in);
    const InBuf pt = InBuf::read(in);
    constexpr size_t max = EKI_AEAD_MAX_LEN;
    const size_t pt_len = ekifuzz::read_capped_len(in, pt.len(), max);
    OutBuf ct = ekifuzz::sized_out(in.boolean(), pt.len(), pt_len, max);
    OutBuf tag(in.boolean(), EKI_AEAD_TAG_LEN);
    Call call{"eki_aead_seal",
              to_int(eki_aead_seal(alg, key.ptr(), key.len(), nonce.ptr(), nonce.len(), aad.ptr(),
                                   aad.len(), pt.ptr(), pt_len, ct.ptr(), tag.ptr()))};
    call.null_param = key.null_with(key.len()) || nonce.null_with(nonce.len()) ||
                      aad.null_with(aad.len()) || pt.null_with(pt_len) ||
                      (ct.is_null() && pt_len > 0) || tag.is_null();
    call.over_cap = pt_len > max;
    call.outputs.push_back(ct.seen());
    call.outputs.push_back(tag.seen());
    return call;
  }
  case 4: {
    const eki_aead_alg alg = in.i32();
    const InBuf key = InBuf::read(in);
    const InBuf nonce = InBuf::read(in);
    const InBuf aad = InBuf::read(in);
    const InBuf ct = InBuf::read(in);
    constexpr size_t max = EKI_AEAD_MAX_LEN;
    const size_t ct_len = ekifuzz::read_capped_len(in, ct.len(), max);
    const auto tag = Fixed<EKI_AEAD_TAG_LEN>::read(in);
    OutBuf pt = ekifuzz::sized_out(in.boolean(), ct.len(), ct_len, max);
    Call call{"eki_aead_open",
              to_int(eki_aead_open(alg, key.ptr(), key.len(), nonce.ptr(), nonce.len(), aad.ptr(),
                                   aad.len(), ct.ptr(), ct_len, tag.ptr(), pt.ptr()))};
    call.null_param = key.null_with(key.len()) || nonce.null_with(nonce.len()) ||
                      aad.null_with(aad.len()) || ct.null_with(ct_len) || tag.null ||
                      (pt.is_null() && ct_len > 0);
    call.over_cap = ct_len > max;
    call.outputs.push_back(pt.seen());
    return call;
  }
  case 5: {
    const auto pk = Fixed<EKI_P256_PUBLIC_KEY_LEN>::read(in);
    const InBuf msg = InBuf::read(in);
    const auto sig = Fixed<EKI_P256_SIGNATURE_LEN>::read(in);
    Call call{"eki_ecdsa_p256_verify",
              to_int(eki_ecdsa_p256_verify(pk.ptr(), msg.ptr(), msg.len(), sig.ptr()))};
    call.null_param = pk.null || msg.null_with(msg.len()) || sig.null;
    return call;
  }
  case 6: {
    OutBuf pk(in.boolean(), EKI_HYBRID_PK_LEN);
    OutBuf sk(in.boolean(), EKI_HYBRID_SK_LEN);
    Call call{"eki_hybrid_kem_keygen", to_int(eki_hybrid_kem_keygen(pk.ptr(), sk.ptr()))};
    if (call.status == EKI_OK) {
      s.kem_pk.assign(pk.span().begin(), pk.span().end());
      s.kem_sk.assign(sk.span().begin(), sk.span().end());
    }
    call.null_param = pk.is_null() || sk.is_null();
    call.outputs.push_back(pk.seen());
    call.outputs.push_back(sk.seen());
    return call;
  }
  case 7: {
    const bool pk_null = in.boolean();
    const bool from_session = in.boolean();
    const Buffer raw = in.bytes();
    const Buffer pk =
        ekifuzz::exact(from_session ? ekifuzz::bytes(s.kem_pk) : raw.span(), EKI_HYBRID_PK_LEN, 0);
    OutBuf ct(in.boolean(), EKI_HYBRID_CT_LEN);
    OutBuf ss(in.boolean(), EKI_HYBRID_SS_LEN);
    Call call{"eki_hybrid_kem_encap",
              to_int(eki_hybrid_kem_encap(ptr_or_null(pk_null, pk), ct.ptr(), ss.ptr()))};
    if (call.status == EKI_OK) {
      s.kem_ct.assign(ct.span().begin(), ct.span().end());
    }
    call.null_param = pk_null || ct.is_null() || ss.is_null();
    call.outputs.push_back(ct.seen());
    call.outputs.push_back(ss.seen());
    return call;
  }
  case 8: {
    const bool sk_null = in.boolean();
    const bool sk_from_session = in.boolean();
    const Buffer sk_raw = in.bytes();
    const Buffer sk = ekifuzz::exact(sk_from_session ? ekifuzz::bytes(s.kem_sk) : sk_raw.span(),
                                     EKI_HYBRID_SK_LEN, 0);
    const bool ct_null = in.boolean();
    const bool ct_from_session = in.boolean();
    const Buffer ct_raw = in.bytes();
    const Buffer ct = ekifuzz::exact(ct_from_session ? ekifuzz::bytes(s.kem_ct) : ct_raw.span(),
                                     EKI_HYBRID_CT_LEN, 0);
    OutBuf ss(in.boolean(), EKI_HYBRID_SS_LEN);
    Call call{
        "eki_hybrid_kem_decap",
        to_int(eki_hybrid_kem_decap(ptr_or_null(sk_null, sk), ptr_or_null(ct_null, ct), ss.ptr()))};
    call.null_param = sk_null || ct_null || ss.is_null();
    call.outputs.push_back(ss.seen());
    return call;
  }
  case 9:
    return audit_verify(s, in);
  case 10:
    return metadata(in);
  case 11:
  case 12:
    return open_store(op, s, in);
  case 13:
    return last_error(s, in);
  case 14: {
    eki_ks* ks = s.ks(in);
    const eki_key_alg alg = in.i32();
    const ekifuzz::Text label = ekifuzz::read_label(in);
    Slot<eki_key_id> id(in.boolean());
    Call call{"eki_ks_generate", to_int(eki_ks_generate(ks, alg, label.ptr(), id.ptr()))};
    call.null_param = ks == nullptr || label.is_null() || id.is_null();
    call.outputs.push_back(id.seen());
    if (!call.null_param) {
      const bool valid = alg >= EKI_KEY_AES_256 && alg <= EKI_KEY_ECDSA_P256 &&
                         ekifuzz::label_is_valid(*label.seen(EKI_LABEL_MAX_LEN + 1));
      ekifuzz::expect_status(call.status, valid ? EKI_OK : EKI_ERR_INVALID_ARGUMENT, call.function);
    }
    if (call.status == EKI_OK) {
      s.known.push_back(id.get());
    }
    return call;
  }
  case 15: {
    eki_ks* ks = s.ks(in);
    const auto id = ekifuzz::read_key_ref(in, s.known);
    Slot<eki_key_info> info(in.boolean());
    Call call{"eki_ks_get_info", to_int(eki_ks_get_info(ks, ekifuzz::id_ptr(id), info.ptr()))};
    call.null_param = ks == nullptr || !id || info.is_null();
    call.outputs.push_back(info.seen());
    return call;
  }
  case 16: {
    eki_ks* ks = s.ks(in);
    const auto id = ekifuzz::read_key_ref(in, s.known);
    Slot<eki_key_info_v2> info(in.boolean());
    Call call{"eki_ks_get_info_v2",
              to_int(eki_ks_get_info_v2(ks, ekifuzz::id_ptr(id), info.ptr()))};
    call.null_param = ks == nullptr || !id || info.is_null();
    call.outputs.push_back(info.seen());
    return call;
  }
  case 17: {
    eki_ks* ks = s.ks(in);
    const auto id = ekifuzz::read_key_ref(in, s.known);
    OutBuf out(in.boolean(), EKI_P256_PUBLIC_KEY_LEN);
    Call call{"eki_ks_get_public_key",
              to_int(eki_ks_get_public_key(ks, ekifuzz::id_ptr(id), out.ptr()))};
    call.null_param = ks == nullptr || !id || out.is_null();
    call.outputs.push_back(out.seen());
    return call;
  }
  case 18:
  case 19: {
    eki_ks* ks = s.ks(in);
    const auto id = ekifuzz::read_key_ref(in, s.known);
    const InBuf msg = InBuf::read(in);
    OutBuf out(in.boolean(), op == 18 ? EKI_P256_SIGNATURE_LEN : EKI_HMAC_SHA256_LEN);
    Call call = op == 18 ? Call{"eki_ks_sign", to_int(eki_ks_sign(ks, ekifuzz::id_ptr(id),
                                                                  msg.ptr(), msg.len(), out.ptr()))}
                         : Call{"eki_ks_hmac_sha256",
                                to_int(eki_ks_hmac_sha256(ks, ekifuzz::id_ptr(id), msg.ptr(),
                                                          msg.len(), out.ptr()))};
    call.null_param = ks == nullptr || !id || msg.null_with(msg.len()) || out.is_null();
    call.outputs.push_back(out.seen());
    return call;
  }
  case 20: {
    eki_ks* ks = s.ks(in);
    const auto id = ekifuzz::read_key_ref(in, s.known);
    const InBuf msg = InBuf::read(in);
    const InBuf tag = InBuf::read(in);
    Call call{"eki_ks_hmac_sha256_verify",
              to_int(eki_ks_hmac_sha256_verify(ks, ekifuzz::id_ptr(id), msg.ptr(), msg.len(),
                                               tag.ptr(), tag.len()))};
    call.null_param = ks == nullptr || !id || msg.null_with(msg.len()) || tag.null_with(tag.len());
    return call;
  }
  case 21: {
    eki_ks* ks = s.ks(in);
    const auto kek = ekifuzz::read_key_ref(in, s.known);
    const auto key = ekifuzz::read_key_ref(in, s.known);
    OutBuf out(in.boolean(), EKI_WRAPPED_KEY_LEN);
    Call call{"eki_ks_wrap",
              to_int(eki_ks_wrap(ks, ekifuzz::id_ptr(kek), ekifuzz::id_ptr(key), out.ptr()))};
    if (call.status == EKI_OK) {
      std::copy(out.span().begin(), out.span().end(), s.wrapped.begin());
    }
    call.null_param = ks == nullptr || !kek || !key || out.is_null();
    call.outputs.push_back(out.seen());
    return call;
  }
  case 22: {
    eki_ks* ks = s.ks(in);
    const auto kek = ekifuzz::read_key_ref(in, s.known);
    const bool from_session = in.boolean();
    InBuf blob = InBuf::read(in);
    if (from_session) {
      // The last wrapped key, with the input's bytes XORed over it.
      Buffer data(s.wrapped);
      for (size_t i = 0; i < std::min(data.size(), blob.bytes.size()); ++i) {
        data.data()[i] ^= blob.bytes.data()[i];
      }
      blob = InBuf{false, std::move(data)};
    }
    const eki_key_alg alg = in.i32();
    const ekifuzz::Text label = ekifuzz::read_label(in);
    const auto id = ekifuzz::read_key_ref(in, s.known);
    Call call{"eki_ks_unwrap",
              to_int(eki_ks_unwrap(ks, ekifuzz::id_ptr(kek), blob.ptr(), blob.len(), alg,
                                   label.ptr(), ekifuzz::id_ptr(id)))};
    if (call.status == EKI_OK && id) {
      s.known.push_back(*id);
    }
    call.null_param = ks == nullptr || !kek || blob.null_with(blob.len()) || label.is_null() || !id;
    return call;
  }
  case 23:
  case 25: {
    eki_ks* ks = s.ks(in);
    const auto id = ekifuzz::read_key_ref(in, s.known);
    Call call = op == 23 ? Call{"eki_ks_destroy", to_int(eki_ks_destroy(ks, ekifuzz::id_ptr(id)))}
                         : Call{"eki_ks_revoke", to_int(eki_ks_revoke(ks, ekifuzz::id_ptr(id)))};
    call.null_param = ks == nullptr || !id;
    return call;
  }
  case 24: {
    eki_ks* ks = s.ks(in);
    const auto id = ekifuzz::read_key_ref(in, s.known);
    Slot<eki_key_id> new_id(in.boolean());
    Call call{"eki_ks_rotate", to_int(eki_ks_rotate(ks, ekifuzz::id_ptr(id), new_id.ptr()))};
    if (call.status == EKI_OK) {
      s.known.push_back(new_id.get());
    }
    call.null_param = ks == nullptr || !id || new_id.is_null();
    call.outputs.push_back(new_id.seen());
    return call;
  }
  case 26: {
    eki_ks* ks = s.ks(in);
    const auto id = ekifuzz::read_key_ref(in, s.known);
    OutBuf out(in.boolean(), EKI_DESTROY_REQUEST_LEN);
    Call call{"eki_ks_destroy_request",
              to_int(eki_ks_destroy_request(ks, ekifuzz::id_ptr(id), out.ptr()))};
    if (call.status == EKI_OK && id) {
      ekifuzz::Request request{};
      std::copy(out.span().begin(), out.span().end(), request.begin());
      s.request = std::pair{request, *id};
    }
    call.null_param = ks == nullptr || !id || out.is_null();
    call.outputs.push_back(out.seen());
    if (!call.null_param) {
      require((call.status == EKI_ERR_UNSUPPORTED) == !s.dual, "destroy_request and dual control");
    }
    return call;
  }
  case 27:
    return destroy_approve(s, in);
  default: {
    eki_ks* ks = s.ks(in);
    OutBuf hash(in.boolean(), EKI_AUDIT_HASH_LEN);
    Slot<uint64_t> seq(in.boolean());
    Call call{"eki_ks_audit_head", to_int(eki_ks_audit_head(ks, hash.ptr(), seq.ptr()))};
    if (call.status == EKI_OK) {
      std::copy(hash.span().begin(), hash.span().end(), s.head.begin());
    }
    call.null_param = ks == nullptr || hash.is_null() || seq.is_null();
    call.outputs.push_back(hash.seen());
    call.outputs.push_back(seq.seen());
    if (!call.null_param) {
      require((call.status == EKI_ERR_UNSUPPORTED) == !s.audited, "audit_head and the audit log");
    }
    return call;
  }
  }
}

// The statuses that only some functions may return here: EKI_ERR_BACKEND needs a store or a log
// to open or a log to read (a software store and a scratch file never fail otherwise), and
// EKI_ERR_UNSUPPORTED a feature that is off or a handle without the log or approvers.
void check_rare_statuses(unsigned op, const Call& call) {
  if (call.status == EKI_ERR_BACKEND) {
    require(op == 9 || op == 11 || op == 12, call.function);
  }
  if (call.status == EKI_ERR_UNSUPPORTED) {
    const bool allowed = (op >= 6 && op <= 8 && !ekifuzz::kWithPq) ||
                         ((op == 11 || op == 12) && !ekifuzz::kWithPkcs11) ||
                         (op >= 26 && op <= 28);
    require(allowed, call.function);
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Input in(data, size);
  static const ekifuzz::Scratch scratch("ffi_status");
  scratch.reset();
  Session s(scratch);

  const unsigned kind = in.u8() % 3U;
  if (kind != 0) {
    const ekifuzz::Config config = ekifuzz::Config::read(in, s.scratch, s.approvers);
    const bool v2 = kind == 2;
    Slot<eki_ks*> out(false);
    const eki_ks_config raw1 = config.v1();
    const eki_ks_config_v2 raw2 = config.v2();
    const int32_t status =
        v2 ? to_int(eki_ks_open_v2(&raw2, out.ptr())) : to_int(eki_ks_open(&raw1, out.ptr()));
    Call call{"open the session's store", status};
    call.null_field = v2 ? config.null_field_v2() : config.null_field_v1();
    call.outputs.push_back(out.seen());
    call.check();
    ekifuzz::expect_one_of(status, config.expected_open(v2, s.scratch, false), call.function);
    if (status == EKI_OK) {
      s.store.emplace(out.get());
      s.dual = v2 && config.has_approvers();
      s.audited = v2 && config.has_audit_log();
    }
  }

  for (size_t calls = 0; !in.empty() && calls < kMaxCalls; ++calls) {
    const unsigned op = in.u8() % kOps;
    const Call call = step(op, s, in);
    call.check();
    check_rare_statuses(op, call);
  }

  const bool audited = s.store && s.audited;
  s.store.reset();
  if (audited) {
    Slot<uint64_t> records(false);
    ekifuzz::expect_status(to_int(eki_audit_verify(s.scratch.log.c_str(), nullptr, records.ptr())),
                           EKI_OK, "eki_audit_verify of the log of a closed store");
    require(records.get() >= 2, "open and close were not both logged");
    ekifuzz::Config config = ekifuzz::Config::software();
    config.set_audit_log(s.scratch);
    Slot<eki_ks*> out(false);
    const eki_ks_config_v2 raw = config.v2();
    ekifuzz::expect_status(to_int(eki_ks_open_v2(&raw, out.ptr())), EKI_OK,
                           "eki_ks_open_v2 of the log of a closed store");
    const ekifuzz::Store reopened(out.get());
  }
  s.scratch.reset();
  return 0;
}
