// eki_ks_unwrap in a software key store on arbitrary blobs, algorithms, labels and ids.
//
// Each run opens a fresh store and generates an AES-256 key to unwrap under. The blob is either
// taken from the input as it is or, when the input asks for it, a genuine wrap of a freshly
// generated HMAC key with input bytes XORed over it, so the success path is reachable too.
//
// Properties: every status is a defined value, and after a successful unwrap the new key is
// usable under the id it was given (eki_ks_get_info reports the requested algorithm and label,
// and an HMAC key computes a MAC). Mirrors core-rs/fuzz/fuzz_targets/unwrap_blob.rs.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "ekicore.h"
#include "fuzz_input.hpp"

namespace {

using ekifuzz::Buffer;
using ekifuzz::require;

constexpr size_t kLabelFuzzMax = 80; // longer than EKI_LABEL_MAX_LEN (64)

// Closes the store on every path out of the target.
class Store {
public:
  explicit Store(eki_ks* ks) : ks_(ks) {}
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;
  Store(Store&&) = delete;
  Store& operator=(Store&&) = delete;
  ~Store() {
    eki_ks_close(ks_);
  }

  [[nodiscard]] eki_ks* get() const {
    return ks_;
  }

private:
  eki_ks* ks_;
};

eki_key_id generate(const Store& store, eki_key_alg alg, const char* label) {
  eki_key_id id{};
  std::fill(std::begin(id.bytes), std::end(id.bytes), uint8_t{0xA5});
  const auto status = static_cast<int32_t>(eki_ks_generate(store.get(), alg, label, &id));
  require(status == EKI_OK);
  return id;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ekifuzz::Input in(data, size);
  const bool from_wrap = in.boolean();
  const Buffer blob_input = in.bytes();
  const eki_key_alg alg = in.i32();
  const auto id_bytes = in.array<EKI_KEY_ID_LEN>();
  const Buffer label_input = in.bytes();

  eki_ks_config config{};
  config.backend = EKI_KS_SOFTWARE;
  eki_ks* handle = nullptr;
  const auto opened = static_cast<int32_t>(eki_ks_open(&config, &handle));
  ekifuzz::require_status_in_range(opened);
  if (opened != EKI_OK) {
    // The key store is still a stub (EKI_ERR_UNSUPPORTED): nothing more to exercise.
    require(handle == nullptr);
    return 0;
  }
  require(handle != nullptr);
  const Store store(handle);

  const eki_key_id kek = generate(store, EKI_KEY_AES_256, "fuzz-kek");

  Buffer blob(0);
  if (from_wrap) {
    const eki_key_id key = generate(store, EKI_KEY_HMAC_SHA256, "fuzz-wrapped");
    Buffer wrapped(EKI_WRAPPED_KEY_LEN, 0xA5);
    const auto status = static_cast<int32_t>(eki_ks_wrap(store.get(), &kek, &key, wrapped.data()));
    require(status == EKI_OK);
    const size_t n = std::min(wrapped.size(), blob_input.size());
    for (size_t i = 0; i < n; ++i) {
      wrapped.data()[i] ^= blob_input.data()[i];
    }
    blob = std::move(wrapped);
  } else {
    blob = Buffer(blob_input.span());
  }

  // At most kLabelFuzzMax bytes and a NUL, in an exact allocation.
  const size_t label_len = std::min(label_input.size(), kLabelFuzzMax);
  Buffer label(label_len + 1, 0);
  std::copy_n(label_input.data(), label_len, label.data());
  const char* label_str = reinterpret_cast<const char*>(label.data());

  eki_key_id id{};
  std::copy(id_bytes.begin(), id_bytes.end(), std::begin(id.bytes));
  const auto status = static_cast<int32_t>(
      eki_ks_unwrap(store.get(), &kek, blob.data(), blob.size(), alg, label_str, &id));
  ekifuzz::require_status_in_range(status);
  if (status != EKI_OK) {
    return 0;
  }

  eki_key_info info{};
  info.alg = -1;
  std::memset(static_cast<void*>(info.label), 0x55, sizeof info.label);
  require(static_cast<int32_t>(eki_ks_get_info(store.get(), &id, &info)) == EKI_OK);
  require(info.alg == alg);
  const size_t seen = std::strlen(label_str); // the label the library accepted, without NUL
  require(seen < sizeof info.label);
  require(std::memcmp(info.label, label_str, seen) == 0);
  require(std::all_of(info.label + seen, info.label + sizeof info.label,
                      [](char c) { return c == '\0'; }));

  if (alg == EKI_KEY_HMAC_SHA256) {
    static constexpr std::array<uint8_t, 9> kMsg{'e', 'k', 'i', 'b', 'r', 'i', 'd', 'g', 'e'};
    Buffer mac(EKI_HMAC_SHA256_LEN, 0xA5);
    require(static_cast<int32_t>(eki_ks_hmac_sha256(store.get(), &id, kMsg.data(), kMsg.size(),
                                                    mac.data())) == EKI_OK);
  }
  return 0;
}
