// eki_ks_unwrap on arbitrary blobs, algorithms, labels and ids, in a store opened from an
// arbitrary configuration.
//
// Input: a flag (one byte, low bit); when set, a store configuration (ekifuzz::Config) for
// eki_ks_open_v2, otherwise a plain software store from eki_ks_open. Then a flag choosing the
// blob's origin, the blob or XOR mask (byte string), the algorithm (i32), the id (16 bytes) and
// the label (read_label).
//
// Each run generates an AES-256 key to unwrap under. The blob is the input's bytes as they are,
// or a real wrap of a freshly generated HMAC key with the input's bytes XORed over it, so the
// success path is reachable. Properties:
// * opening fails or succeeds as the contract allows; a failed open leaves *out NULL;
// * the unwrap status is exactly the one the contract's validation order gives: a NULL label,
//   then the algorithm, the blob length, ECDSA, the label format, then the integrity check
//   (EKI_OK only for an unmodified real wrap; a raw blob never authenticates);
// * after a successful unwrap, eki_ks_get_info_v2 reports the requested algorithm, the label and
//   the ACTIVE state, and an HMAC key computes the same tag as the key that was wrapped;
// * the store closes, and an audit log it wrote verifies afterwards.
//
// Mirrors core-rs/fuzz/fuzz_targets/unwrap_blob.rs.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "ekicore.h"
#include "fuzz_input.hpp"

namespace {

using ekifuzz::Buffer;
using ekifuzz::require;

std::optional<ekifuzz::Store> open(ekifuzz::Input& in, const ekifuzz::Scratch& scratch,
                                   ekifuzz::Approvers& approvers) {
  if (!in.boolean()) {
    return ekifuzz::Store::software();
  }
  const ekifuzz::Config config = ekifuzz::Config::read(in, scratch, approvers);
  const eki_ks_config_v2 raw = config.v2();
  ekifuzz::Slot<eki_ks*> out(false);
  const auto status = static_cast<int32_t>(eki_ks_open_v2(&raw, out.ptr()));
  ekifuzz::Call call{"eki_ks_open_v2", status};
  call.null_field = config.null_field_v2();
  call.outputs.push_back(out.seen());
  call.check();
  ekifuzz::expect_one_of(status, config.expected_open(true, scratch, false), "eki_ks_open_v2");
  if (status != EKI_OK) {
    return std::nullopt;
  }
  return ekifuzz::Store(out.get());
}

std::array<uint8_t, EKI_HMAC_SHA256_LEN> hmac(const ekifuzz::Store& store, const eki_key_id& id) {
  static constexpr std::array<uint8_t, 9> msg = {'e', 'k', 'i', 'b', 'r', 'i', 'd', 'g', 'e'};
  std::array<uint8_t, EKI_HMAC_SHA256_LEN> tag{};
  ekifuzz::expect_status(static_cast<int32_t>(eki_ks_hmac_sha256(store.get(), &id, msg.data(),
                                                                 msg.size(), tag.data())),
                         EKI_OK, "eki_ks_hmac_sha256 with an active HMAC key");
  return tag;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ekifuzz::Input in(data, size);
  static const ekifuzz::Scratch scratch("unwrap_blob");
  scratch.reset();
  ekifuzz::Approvers approvers;
  std::optional<ekifuzz::Store> store = open(in, scratch, approvers);
  if (!store) {
    return 0;
  }
  const bool from_wrap = in.boolean();
  const Buffer input_blob = in.bytes();
  const eki_key_alg alg = in.i32();
  eki_key_id id{};
  const auto raw_id = in.array<EKI_KEY_ID_LEN>();
  std::copy(raw_id.begin(), raw_id.end(), std::begin(id.bytes));
  const ekifuzz::Text label = ekifuzz::read_label(in);

  const eki_key_id kek = store->generate(EKI_KEY_AES_256, "fuzz-kek");
  std::optional<eki_key_id> wrapped_key;
  bool changed = false;
  Buffer blob(0);
  if (from_wrap) {
    wrapped_key = store->generate(EKI_KEY_HMAC_SHA256, "fuzz-wrapped");
    blob = Buffer(EKI_WRAPPED_KEY_LEN, ekifuzz::kFill);
    ekifuzz::expect_status(
        static_cast<int32_t>(eki_ks_wrap(store->get(), &kek, &*wrapped_key, blob.data())), EKI_OK,
        "eki_ks_wrap of an HMAC key under an AES key");
    for (size_t i = 0; i < std::min(blob.size(), input_blob.size()); ++i) {
      blob.data()[i] ^= input_blob.data()[i];
      changed |= input_blob.data()[i] != 0;
    }
  } else {
    blob = Buffer(input_blob.span());
  }

  const auto status = static_cast<int32_t>(
      eki_ks_unwrap(store->get(), &kek, blob.data(), blob.size(), alg, label.ptr(), &id));
  ekifuzz::Call call{"eki_ks_unwrap", status};
  call.null_param = label.is_null();
  call.check();

  const auto seen = label.seen(EKI_LABEL_MAX_LEN + 1);
  int32_t expected = EKI_ERR_AUTH_FAILED;
  if (label.is_null()) {
    expected = EKI_ERR_NULL_POINTER;
  } else if (alg < EKI_KEY_AES_256 || alg > EKI_KEY_ECDSA_P256 ||
             blob.size() != EKI_WRAPPED_KEY_LEN || alg == EKI_KEY_ECDSA_P256 ||
             !ekifuzz::label_is_valid(*seen)) {
    expected = EKI_ERR_INVALID_ARGUMENT;
  } else if (wrapped_key && !changed) {
    expected = EKI_OK;
  }
  ekifuzz::expect_status(status, expected, "eki_ks_unwrap");

  if (status == EKI_OK) {
    ekifuzz::Slot<eki_key_info_v2> info_slot(false);
    ekifuzz::expect_status(
        static_cast<int32_t>(eki_ks_get_info_v2(store->get(), &id, info_slot.ptr())), EKI_OK,
        "eki_ks_get_info_v2 of an unwrapped key");
    const eki_key_info_v2 info = info_slot.get();
    require(info.alg == alg, "unwrapped key reports another algorithm");
    require(info.state == EKI_KEY_STATE_ACTIVE, "unwrapped key is not ACTIVE");
    const auto* stored = reinterpret_cast<const uint8_t*>(info.label);
    require(std::equal(seen->begin(), seen->end(), stored), "unwrapped key reports another label");
    require(std::all_of(stored + seen->size(), stored + sizeof(info.label),
                        [](uint8_t b) { return b == 0; }),
            "label not NUL-padded");
    if (alg == EKI_KEY_HMAC_SHA256) {
      require(hmac(*store, id) == hmac(*store, *wrapped_key), "unwrap changed the key");
    }
  }

  store.reset();
  if (scratch.log_exists()) {
    ekifuzz::Slot<uint64_t> records(false);
    ekifuzz::expect_status(
        static_cast<int32_t>(eki_audit_verify(scratch.log.c_str(), nullptr, records.ptr())), EKI_OK,
        "eki_audit_verify of the log of a closed store");
  }
  return 0;
}
