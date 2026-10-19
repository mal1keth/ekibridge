// cpp-caller: C++ code that uses the ekicore C ABI without linking either implementation.
//
// The program is compiled once, against include/ekicore.h only, and loads the library named on the
// command line at run time. Pointing it at libekicore (C++, OpenSSL) or at libekicore_rs (Rust,
// RustCrypto) needs no rebuild: that is the runtime-selection switch of the migration plan in
// miniature. Every function pointer type is taken from the header with decltype, so the caller
// cannot drift from the contract.
//
//   cpp-caller <path to libekicore.{so,dylib} or libekicore_rs.{so,dylib}>
//
// It runs a fixed script (version, hkdf, hmac, aead, keystore) and prints one line per step:
// "PASS <step>" or "FAIL <step> (<status name>): <what failed>". Status names come from the loaded
// library's eki_status_name. Exit status: 0 if every step passed, 1 if a step failed, 2 on a usage
// or loading error.

#include "ekicore.h"

#include <dlfcn.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iostream>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

// ---- loading the library ------------------------------------------------------------------------

// Owns a dlopen() handle and closes it on destruction. RTLD_NOW resolves everything up front, so a
// library missing a dependency fails here and not in the middle of the script; RTLD_LOCAL keeps its
// symbols out of the global namespace, so two ekicore libraries could be loaded side by side.
class Library {
public:
  explicit Library(const char* path) : handle_(dlopen(path, RTLD_NOW | RTLD_LOCAL)) {}
  ~Library() {
    if (handle_ != nullptr) {
      dlclose(handle_);
    }
  }
  Library(const Library&) = delete;
  Library& operator=(const Library&) = delete;
  Library(Library&&) = delete;
  Library& operator=(Library&&) = delete;

  [[nodiscard]] void* handle() const {
    return handle_;
  }

private:
  void* handle_;
};

// Looks up `name` in the library and returns it as the function pointer type `Fn`, or nullptr if
// the library does not export it. Callers always pass decltype(&eki_...), the header's own type.
template <typename Fn> Fn load_sym(void* handle, const char* name) {
  return reinterpret_cast<Fn>(dlsym(handle, name));
}

// The functions of the ABI this program uses, resolved from one loaded library.
struct Api {
  decltype(&eki_abi_version) abi_version = nullptr;
  decltype(&eki_version) version = nullptr;
  decltype(&eki_status_name) status_name = nullptr;
  decltype(&eki_hmac_sha256) hmac_sha256 = nullptr;
  decltype(&eki_hmac_sha256_verify) hmac_sha256_verify = nullptr;
  decltype(&eki_hkdf_sha256) hkdf_sha256 = nullptr;
  decltype(&eki_aead_seal) aead_seal = nullptr;
  decltype(&eki_aead_open) aead_open = nullptr;
  decltype(&eki_ecdsa_p256_verify) ecdsa_p256_verify = nullptr;
  decltype(&eki_ks_open) ks_open = nullptr;
  decltype(&eki_ks_close) ks_close = nullptr;
  decltype(&eki_ks_last_error_message) ks_last_error_message = nullptr;
  decltype(&eki_ks_generate) ks_generate = nullptr;
  decltype(&eki_ks_get_info) ks_get_info = nullptr;
  decltype(&eki_ks_get_public_key) ks_get_public_key = nullptr;
  decltype(&eki_ks_sign) ks_sign = nullptr;
  decltype(&eki_ks_hmac_sha256) ks_hmac_sha256 = nullptr;
  decltype(&eki_ks_wrap) ks_wrap = nullptr;
  decltype(&eki_ks_unwrap) ks_unwrap = nullptr;
  decltype(&eki_ks_destroy) ks_destroy = nullptr;

  [[nodiscard]] std::string name(eki_status status) const {
    const char* text = status_name(static_cast<std::int32_t>(status));
    return text != nullptr ? text : "(null)";
  }
};

// Resolves one symbol into `slot`; records the first missing name in `missing`.
template <typename Fn>
void resolve(void* handle, Fn& slot, const char* name, std::string& missing) {
  slot = load_sym<Fn>(handle, name);
  if (slot == nullptr && missing.empty()) {
    missing = name;
  }
}

// Resolves every function of Api; returns the name of the first missing symbol, or "" if none.
std::string load_api(void* handle, Api& api) {
  std::string missing;
  resolve(handle, api.abi_version, "eki_abi_version", missing);
  resolve(handle, api.version, "eki_version", missing);
  resolve(handle, api.status_name, "eki_status_name", missing);
  resolve(handle, api.hmac_sha256, "eki_hmac_sha256", missing);
  resolve(handle, api.hmac_sha256_verify, "eki_hmac_sha256_verify", missing);
  resolve(handle, api.hkdf_sha256, "eki_hkdf_sha256", missing);
  resolve(handle, api.aead_seal, "eki_aead_seal", missing);
  resolve(handle, api.aead_open, "eki_aead_open", missing);
  resolve(handle, api.ecdsa_p256_verify, "eki_ecdsa_p256_verify", missing);
  resolve(handle, api.ks_open, "eki_ks_open", missing);
  resolve(handle, api.ks_close, "eki_ks_close", missing);
  resolve(handle, api.ks_last_error_message, "eki_ks_last_error_message", missing);
  resolve(handle, api.ks_generate, "eki_ks_generate", missing);
  resolve(handle, api.ks_get_info, "eki_ks_get_info", missing);
  resolve(handle, api.ks_get_public_key, "eki_ks_get_public_key", missing);
  resolve(handle, api.ks_sign, "eki_ks_sign", missing);
  resolve(handle, api.ks_hmac_sha256, "eki_ks_hmac_sha256", missing);
  resolve(handle, api.ks_wrap, "eki_ks_wrap", missing);
  resolve(handle, api.ks_unwrap, "eki_ks_unwrap", missing);
  resolve(handle, api.ks_destroy, "eki_ks_destroy", missing);
  return missing;
}

// ---- step results -------------------------------------------------------------------------------

// Why a step failed: the status the library returned (EKI_OK when the call succeeded but its output
// was wrong) and a description of the call or check.
struct Failure {
  eki_status status;
  std::string what;
};

// std::nullopt means the step passed.
using StepResult = std::optional<Failure>;

// A failure unless `got == want`.
StepResult expect(eki_status got, eki_status want, std::string what) {
  if (got == want) {
    return std::nullopt;
  }
  return Failure{.status = got, .what = std::move(what)};
}

// A failure (reported with EKI_OK, the call itself succeeded) unless `ok` holds.
StepResult check(bool ok, std::string what) {
  if (ok) {
    return std::nullopt;
  }
  return Failure{.status = EKI_OK, .what = std::move(what)};
}

// ---- helpers ------------------------------------------------------------------------------------

// Decodes a lower-case hex string literal from a published test vector.
Bytes unhex(std::string_view hex) {
  auto nibble = [](char c) -> unsigned {
    return c <= '9' ? static_cast<unsigned>(c - '0') : static_cast<unsigned>(c - 'a' + 10);
  };
  Bytes out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>((nibble(hex.at(i)) << 4U) | nibble(hex.at(i + 1))));
  }
  return out;
}

Bytes text(std::string_view s) {
  return {s.begin(), s.end()};
}

// Random test inputs. std::random_device is the platform's non-deterministic source; these bytes
// only feed a self-test, the library generates its own keys.
template <typename Container> void fill_random(Container& out) {
  std::random_device rd;
  std::uniform_int_distribution<int> byte(0, 255);
  for (auto& b : out) {
    b = static_cast<std::uint8_t>(byte(rd));
  }
}

Bytes random_bytes(std::size_t n) {
  Bytes out(n);
  fill_random(out);
  return out;
}

bool all_zero(std::span<const std::uint8_t> bytes) {
  return std::ranges::all_of(bytes, [](std::uint8_t b) { return b == 0; });
}

// ---- step: version ------------------------------------------------------------------------------

StepResult step_version(const Api& api) {
  const char* version = api.version();
  const std::uint32_t abi = api.abi_version();
  std::cout << "  library " << (version != nullptr ? version : "(null)") << ", ABI " << abi << '\n';
  if (auto f = check(version != nullptr, "eki_version returned NULL")) {
    return f;
  }
  return check(abi == EKI_ABI_VERSION, "eki_abi_version is not " + std::to_string(EKI_ABI_VERSION));
}

// ---- step: hkdf (RFC 5869 A.1) ------------------------------------------------------------------

StepResult step_hkdf(const Api& api) {
  const Bytes ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  const Bytes salt = unhex("000102030405060708090a0b0c");
  const Bytes info = unhex("f0f1f2f3f4f5f6f7f8f9");
  const Bytes want = unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf3400"
                           "7208d5b887185865");
  Bytes okm(want.size());
  if (auto f = expect(api.hkdf_sha256(ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(),
                                      info.size(), okm.data(), okm.size()),
                      EKI_OK, "eki_hkdf_sha256 on RFC 5869 A.1")) {
    return f;
  }
  return check(okm == want, "OKM differs from RFC 5869 A.1");
}

// ---- step: hmac (RFC 4231 test case 2) ----------------------------------------------------------

StepResult step_hmac(const Api& api) {
  const Bytes key = text("Jefe");
  const Bytes msg = text("what do ya want for nothing?");
  const Bytes want = unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> tag{};
  if (auto f = expect(api.hmac_sha256(key.data(), key.size(), msg.data(), msg.size(), tag.data()),
                      EKI_OK, "eki_hmac_sha256 on RFC 4231 case 2")) {
    return f;
  }
  if (auto f = check(std::ranges::equal(tag, want), "tag differs from RFC 4231 case 2")) {
    return f;
  }
  if (auto f = expect(api.hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(),
                                             tag.data(), tag.size()),
                      EKI_OK, "eki_hmac_sha256_verify on the correct tag")) {
    return f;
  }
  tag.front() ^= 0x01U;
  return expect(api.hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(), tag.data(),
                                       tag.size()),
                EKI_ERR_AUTH_FAILED, "eki_hmac_sha256_verify on a flipped tag");
}

// ---- step: aead ---------------------------------------------------------------------------------

StepResult aead_round_trip(const Api& api, eki_aead_alg alg, std::string_view alg_name) {
  const std::string name(alg_name);
  const Bytes key = random_bytes(EKI_AEAD_KEY_LEN);
  const Bytes nonce = random_bytes(EKI_AEAD_NONCE_LEN);
  const Bytes aad = random_bytes(16);
  const Bytes pt = random_bytes(1024);
  Bytes ct(pt.size());
  std::array<std::uint8_t, EKI_AEAD_TAG_LEN> tag{};

  if (auto f =
          expect(api.aead_seal(alg, key.data(), key.size(), nonce.data(), nonce.size(), aad.data(),
                               aad.size(), pt.data(), pt.size(), ct.data(), tag.data()),
                 EKI_OK, "eki_aead_seal " + name)) {
    return f;
  }

  Bytes opened(ct.size(), 0xA5);
  if (auto f =
          expect(api.aead_open(alg, key.data(), key.size(), nonce.data(), nonce.size(), aad.data(),
                               aad.size(), ct.data(), ct.size(), tag.data(), opened.data()),
                 EKI_OK, "eki_aead_open " + name)) {
    return f;
  }
  if (auto f = check(opened == pt, "eki_aead_open " + name + " returned other plaintext")) {
    return f;
  }

  tag.back() ^= 0x80U;
  std::ranges::fill(opened, 0xA5);
  if (auto f =
          expect(api.aead_open(alg, key.data(), key.size(), nonce.data(), nonce.size(), aad.data(),
                               aad.size(), ct.data(), ct.size(), tag.data(), opened.data()),
                 EKI_ERR_AUTH_FAILED, "eki_aead_open " + name + " with a tampered tag")) {
    return f;
  }
  return check(all_zero(opened), "eki_aead_open " + name + " left plaintext after a failure");
}

StepResult step_aead(const Api& api) {
  if (auto f = aead_round_trip(api, EKI_AEAD_AES_256_GCM, "AES-256-GCM")) {
    return f;
  }
  return aead_round_trip(api, EKI_AEAD_CHACHA20_POLY1305, "ChaCha20-Poly1305");
}

// ---- step: keystore -----------------------------------------------------------------------------

// Owns an eki_ks handle and closes it on destruction, whatever path the step takes.
class Store {
public:
  explicit Store(const Api& api) : api_(api) {}
  ~Store() {
    close();
  }
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;
  Store(Store&&) = delete;
  Store& operator=(Store&&) = delete;

  // Opens an in-memory software store. The PKCS#11 fields are ignored by that backend.
  eki_status open_software() {
    const eki_ks_config config{
        .backend = EKI_KS_SOFTWARE,
        .pkcs11_module_path = nullptr,
        .pkcs11_token_label = nullptr,
        .pkcs11_user_pin = nullptr,
    };
    return api_.ks_open(&config, &ks_);
  }

  [[nodiscard]] eki_ks* get() const {
    return ks_;
  }

  // Wraps a status check and, on failure, appends the store's last error message when it has one.
  [[nodiscard]] StepResult expect(eki_status got, eki_status want, const std::string& what) const {
    auto failure = ::expect(got, want, what);
    if (failure && ks_ != nullptr) {
      std::array<char, 256> buf{};
      if (api_.ks_last_error_message(ks_, buf.data(), buf.size()) > 0) {
        failure->what += std::string(" [") + buf.data() + "]";
      }
    }
    return failure;
  }

  // eki_ks_close is NULL-safe by contract; the check keeps the caller correct even without that.
  void close() {
    if (ks_ != nullptr) {
      api_.ks_close(ks_);
      ks_ = nullptr;
    }
  }

private:
  const Api& api_;
  eki_ks* ks_ = nullptr;
};

struct NamedKey {
  eki_key_alg alg;
  const char* label;
  eki_key_id id;
};

// get_info must report the algorithm and the label, NUL-padded through byte 64.
StepResult check_info(const Api& api, const Store& store, const NamedKey& key) {
  eki_key_info info{};
  if (auto f = store.expect(api.ks_get_info(store.get(), &key.id, &info), EKI_OK,
                            std::string("eki_ks_get_info ") + key.label)) {
    return f;
  }
  const std::string_view label(key.label);
  const std::span<const char> field(info.label);
  const bool label_ok = std::equal(label.begin(), label.end(), field.begin()) &&
                        std::all_of(field.begin() + static_cast<std::ptrdiff_t>(label.size()),
                                    field.end(), [](char c) { return c == '\0'; });
  return check(info.alg == key.alg && label_ok,
               std::string("eki_ks_get_info ") + key.label + " reported other alg or label");
}

StepResult step_keystore(const Api& api) {
  Store store(api);
  if (auto f = store.expect(store.open_software(), EKI_OK, "eki_ks_open software")) {
    return f;
  }

  NamedKey kek{.alg = EKI_KEY_AES_256, .label = "interop-kek", .id = {}};
  NamedKey mac{.alg = EKI_KEY_HMAC_SHA256, .label = "interop-hmac", .id = {}};
  NamedKey signer{.alg = EKI_KEY_ECDSA_P256, .label = "interop-signer", .id = {}};
  for (NamedKey* key : {&kek, &mac, &signer}) {
    if (auto f = store.expect(api.ks_generate(store.get(), key->alg, key->label, &key->id), EKI_OK,
                              std::string("eki_ks_generate ") + key->label)) {
      return f;
    }
  }
  for (const NamedKey* key : {&kek, &mac, &signer}) {
    if (auto f = check_info(api, store, *key)) {
      return f;
    }
  }

  const Bytes msg = text("interop message signed and authenticated by the key store");

  std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> tag{};
  if (auto f =
          store.expect(api.ks_hmac_sha256(store.get(), &mac.id, msg.data(), msg.size(), tag.data()),
                       EKI_OK, "eki_ks_hmac_sha256 interop-hmac")) {
    return f;
  }

  std::array<std::uint8_t, EKI_P256_SIGNATURE_LEN> sig{};
  std::array<std::uint8_t, EKI_P256_PUBLIC_KEY_LEN> pub{};
  if (auto f =
          store.expect(api.ks_sign(store.get(), &signer.id, msg.data(), msg.size(), sig.data()),
                       EKI_OK, "eki_ks_sign interop-signer")) {
    return f;
  }
  if (auto f = store.expect(api.ks_get_public_key(store.get(), &signer.id, pub.data()), EKI_OK,
                            "eki_ks_get_public_key interop-signer")) {
    return f;
  }
  if (auto f = expect(api.ecdsa_p256_verify(pub.data(), msg.data(), msg.size(), sig.data()), EKI_OK,
                      "eki_ecdsa_p256_verify of the store's signature")) {
    return f;
  }

  std::array<std::uint8_t, EKI_WRAPPED_KEY_LEN> blob{};
  if (auto f = store.expect(api.ks_wrap(store.get(), &kek.id, &mac.id, blob.data()), EKI_OK,
                            "eki_ks_wrap interop-hmac under interop-kek")) {
    return f;
  }
  NamedKey copy{.alg = EKI_KEY_HMAC_SHA256, .label = "interop-hmac-unwrapped", .id = {}};
  fill_random(copy.id.bytes);
  if (auto f = store.expect(api.ks_unwrap(store.get(), &kek.id, blob.data(), blob.size(), copy.alg,
                                          copy.label, &copy.id),
                            EKI_OK, "eki_ks_unwrap as interop-hmac-unwrapped")) {
    return f;
  }
  if (auto f = check_info(api, store, copy)) {
    return f;
  }
  std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> tag_copy{};
  if (auto f = store.expect(
          api.ks_hmac_sha256(store.get(), &copy.id, msg.data(), msg.size(), tag_copy.data()),
          EKI_OK, "eki_ks_hmac_sha256 interop-hmac-unwrapped")) {
    return f;
  }
  if (auto f = check(tag_copy == tag, "the unwrapped key computes a different HMAC")) {
    return f;
  }

  for (const NamedKey* key : {&kek, &mac, &signer, &copy}) {
    if (auto f = store.expect(api.ks_destroy(store.get(), &key->id), EKI_OK,
                              std::string("eki_ks_destroy ") + key->label)) {
      return f;
    }
  }
  for (const NamedKey* key : {&kek, &mac, &signer, &copy}) {
    eki_key_info info{};
    if (auto f = store.expect(api.ks_get_info(store.get(), &key->id, &info), EKI_ERR_KEY_NOT_FOUND,
                              std::string("eki_ks_get_info after destroying ") + key->label)) {
      return f;
    }
  }
  store.close();
  return std::nullopt;
}

// ---- driver -------------------------------------------------------------------------------------

struct Step {
  const char* name;
  StepResult (*run)(const Api&);
};

constexpr std::array kSteps{
    Step{.name = "version", .run = step_version},   // stop here on an ABI mismatch
    Step{.name = "hkdf", .run = step_hkdf},         // RFC 5869 A.1
    Step{.name = "hmac", .run = step_hmac},         // RFC 4231 test case 2
    Step{.name = "aead", .run = step_aead},         // both algorithms, random inputs
    Step{.name = "keystore", .run = step_keystore}, // software backend, full key lifecycle
};
int run(const char* path) {
  const Library lib(path);
  if (lib.handle() == nullptr) {
    const char* err = dlerror();
    std::cerr << "cpp-caller: cannot load " << path << ": " << (err != nullptr ? err : "?") << '\n';
    return 2;
  }
  Api api;
  if (const std::string missing = load_api(lib.handle(), api); !missing.empty()) {
    std::cerr << "cpp-caller: " << path << " does not export " << missing << '\n';
    return 2;
  }

  std::cout << "cpp-caller: " << path << '\n';
  int failed = 0;
  for (const Step& step : kSteps) {
    const StepResult result = step.run(api);
    if (!result) {
      std::cout << "PASS " << step.name << '\n';
      continue;
    }
    ++failed;
    std::cout << "FAIL " << step.name << " (" << api.name(result->status) << "): " << result->what
              << '\n';
    // Nothing else can be trusted from a library that implements a different ABI.
    if (std::string_view(step.name) == "version") {
      break;
    }
  }
  std::cout << (failed == 0 ? "cpp-caller: all steps passed"
                            : "cpp-caller: " + std::to_string(failed) + " step(s) failed")
            << '\n';
  return failed == 0 ? 0 : 1;
}

// Used where an exception must not be thrown: inside main's catch handlers.
void print_error(const char* message) noexcept {
  (void)std::fputs(message, stderr);
}

} // namespace

int main(int argc, char** argv) {
  const std::span<char*> args(argv, static_cast<std::size_t>(argc));
  if (args.size() != 2) {
    print_error("usage: cpp-caller <path to libekicore or libekicore_rs>\n");
    return 2;
  }
  try {
    return run(args.back());
  } catch (const std::exception& e) {
    print_error("cpp-caller: unexpected exception: ");
    print_error(e.what());
    print_error("\n");
  } catch (...) {
    print_error("cpp-caller: unexpected exception\n");
  }
  return 2;
}
