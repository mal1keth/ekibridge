// Benchmarks of libekicore through its C ABI.
//
// Every workload calls the exported eki_* functions declared in <ekicore.h>, exactly as any C
// caller would, so the numbers include the boundary and are directly comparable with
// core-rs/benches/primitives.rs, which runs identical workloads against libekicore_rs. Benchmark
// names ("group/function/size") match the criterion ids on the Rust side; scripts/bench.sh merges
// the two result sets.
//
// The returned status is ignored: a benchmark measures whatever the library does with these
// inputs. Inputs are fixed byte patterns and the AEAD nonce is reused across iterations; that is
// fine for timing and must never be copied into real code.

#include <ekicore.h>

#include <benchmark/benchmark.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::array<std::size_t, 2> kHmacSizes{64, 4096};
constexpr std::array<std::size_t, 2> kAeadSizes{1024, std::size_t{64} * 1024};
constexpr std::size_t kHmacKeyLen = 32;
constexpr std::size_t kAadLen = 16;
constexpr std::size_t kHkdfIkmLen = 32;
constexpr std::size_t kHkdfSaltLen = 16;
constexpr std::size_t kHkdfInfoLen = 16;
constexpr std::size_t kHkdfOkmLen = 32;

struct AeadAlg {
  const char* name;
  eki_aead_alg alg;
};

constexpr std::array<AeadAlg, 2> kAeadAlgs{
    AeadAlg{.name = "aes-256-gcm", .alg = EKI_AEAD_AES_256_GCM},
    AeadAlg{.name = "chacha20-poly1305", .alg = EKI_AEAD_CHACHA20_POLY1305},
};

// One AEAD workload: algorithm and plaintext size.
struct AeadCase {
  eki_aead_alg alg;
  std::size_t size;
};

// Distinguishes the inputs of one workload from each other.
enum class Seed : std::uint8_t {};

// A deterministic, non-constant byte pattern. Produces the same bytes as `pattern` in
// core-rs/benches/primitives.rs for the same length and seed.
Bytes pattern(std::size_t len, Seed seed) {
  Bytes bytes(len);
  std::size_t i = 0;
  for (std::uint8_t& byte : bytes) {
    byte = static_cast<std::uint8_t>((i * 31U) + static_cast<std::uint8_t>(seed));
    ++i;
  }
  return bytes;
}

void set_bytes_processed(benchmark::State& state, std::size_t bytes_per_op) {
  state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(bytes_per_op));
}

void bench_hmac(benchmark::State& state, std::size_t size) {
  const Bytes key = pattern(kHmacKeyLen, Seed{1});
  const Bytes msg = pattern(size, Seed{2});
  std::array<std::uint8_t, EKI_HMAC_SHA256_LEN> out{};
  for (auto _ : state) {
    const std::uint8_t* msg_ptr = msg.data();
    benchmark::DoNotOptimize(msg_ptr);
    eki_status status = eki_hmac_sha256(key.data(), key.size(), msg_ptr, msg.size(), out.data());
    benchmark::DoNotOptimize(status);
  }
  set_bytes_processed(state, size);
}

void bench_hkdf(benchmark::State& state) {
  const Bytes ikm = pattern(kHkdfIkmLen, Seed{3});
  const Bytes salt = pattern(kHkdfSaltLen, Seed{4});
  const Bytes info = pattern(kHkdfInfoLen, Seed{5});
  std::array<std::uint8_t, kHkdfOkmLen> okm{};
  for (auto _ : state) {
    const std::uint8_t* ikm_ptr = ikm.data();
    benchmark::DoNotOptimize(ikm_ptr);
    eki_status status = eki_hkdf_sha256(ikm_ptr, ikm.size(), salt.data(), salt.size(), info.data(),
                                        info.size(), okm.data(), okm.size());
    benchmark::DoNotOptimize(status);
  }
  set_bytes_processed(state, kHkdfOkmLen);
}

void bench_aead_seal(benchmark::State& state, AeadCase c) {
  const Bytes key = pattern(EKI_AEAD_KEY_LEN, Seed{6});
  const Bytes nonce = pattern(EKI_AEAD_NONCE_LEN, Seed{7});
  const Bytes aad = pattern(kAadLen, Seed{8});
  const Bytes pt = pattern(c.size, Seed{9});
  Bytes ct(c.size);
  std::array<std::uint8_t, EKI_AEAD_TAG_LEN> tag{};
  for (auto _ : state) {
    const std::uint8_t* pt_ptr = pt.data();
    benchmark::DoNotOptimize(pt_ptr);
    eki_status status =
        eki_aead_seal(c.alg, key.data(), key.size(), nonce.data(), nonce.size(), aad.data(),
                      aad.size(), pt_ptr, pt.size(), ct.data(), tag.data());
    benchmark::DoNotOptimize(status);
  }
  set_bytes_processed(state, c.size);
}

void bench_aead_open(benchmark::State& state, AeadCase c) {
  const Bytes key = pattern(EKI_AEAD_KEY_LEN, Seed{6});
  const Bytes nonce = pattern(EKI_AEAD_NONCE_LEN, Seed{7});
  const Bytes aad = pattern(kAadLen, Seed{8});
  const Bytes pt = pattern(c.size, Seed{9});
  Bytes ct(c.size);
  std::array<std::uint8_t, EKI_AEAD_TAG_LEN> tag{};
  // Seal once so that, with a real implementation, open measures the success path.
  static_cast<void>(eki_aead_seal(c.alg, key.data(), key.size(), nonce.data(), nonce.size(),
                                  aad.data(), aad.size(), pt.data(), pt.size(), ct.data(),
                                  tag.data()));
  Bytes out(c.size);
  for (auto _ : state) {
    const std::uint8_t* ct_ptr = ct.data();
    benchmark::DoNotOptimize(ct_ptr);
    eki_status status =
        eki_aead_open(c.alg, key.data(), key.size(), nonce.data(), nonce.size(), aad.data(),
                      aad.size(), ct_ptr, ct.size(), tag.data(), out.data());
    benchmark::DoNotOptimize(status);
  }
  set_bytes_processed(state, c.size);
}

void register_benchmarks() {
  for (const std::size_t size : kHmacSizes) {
    benchmark::RegisterBenchmark("hmac/sha256/" + std::to_string(size), bench_hmac, size);
  }
  benchmark::RegisterBenchmark("hkdf/sha256/" + std::to_string(kHkdfOkmLen), bench_hkdf);
  for (const AeadAlg& alg : kAeadAlgs) {
    for (const std::size_t size : kAeadSizes) {
      const std::string id = std::string(alg.name) + "/" + std::to_string(size);
      const AeadCase c{.alg = alg.alg, .size = size};
      benchmark::RegisterBenchmark("aead_seal/" + id, bench_aead_seal, c);
      benchmark::RegisterBenchmark("aead_open/" + id, bench_aead_open, c);
    }
  }
}

} // namespace

int main(int argc, char** argv) {
  try {
    register_benchmarks();
    benchmark::AddCustomContext("library", eki_version());
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
      return 1;
    }
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
  } catch (const std::exception& e) {
    static_cast<void>(std::fputs("ekicore_bench: ", stderr));
    static_cast<void>(std::fputs(e.what(), stderr));
    static_cast<void>(std::fputs("\n", stderr));
  } catch (...) {
    static_cast<void>(std::fputs("ekicore_bench: unknown exception\n", stderr));
  }
  return 1;
}
