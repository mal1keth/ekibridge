#!/usr/bin/env bash
# Benchmarks libekicore (C++, Google Benchmark) and libekicore_rs (Rust, criterion) through the C
# ABI with identical workloads, then prints one merged table in the shape of docs/benchmarks.md.
#
#   scripts/bench.sh            full run
#   scripts/bench.sh --quick    short warm-up and measurement times (smoke test, noisy numbers)
#
# Outputs, under bench-results/ at the repository root:
#   cpp.json      raw Google Benchmark results
#   summary.md    the merged table (also printed to stdout)
#
# The C++ side is built in build/bench (Ninja, Release, EKI_BUILD_BENCH=ON, EKI_BUILD_TESTS=OFF).
# On macOS, OPENSSL_ROOT_DIR defaults to $(brew --prefix openssl@3) when it is not already set.
# The Rust side runs `cargo bench -p ekicore-rs --bench primitives`; its estimates are read from
# target/criterion/.

set -euo pipefail

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
}

quick=0
while [ $# -gt 0 ]; do
  case $1 in
    --quick) quick=1 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "bench: unknown argument $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

build_dir="$root/build/bench"
results="$root/bench-results"
mkdir -p "$results"

# ---- C++: libekicore + Google Benchmark ---------------------------------------------------------

cmake_args=(-S "$root" -B "$build_dir" -G Ninja
  -DCMAKE_BUILD_TYPE=Release
  -DEKI_BUILD_BENCH=ON
  -DEKI_BUILD_TESTS=OFF)
if [ "$(uname -s)" = "Darwin" ] && [ -z "${OPENSSL_ROOT_DIR:-}" ] && command -v brew > /dev/null; then
  cmake_args+=("-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)")
fi

echo "==> configuring $build_dir"
cmake "${cmake_args[@]}" > /dev/null
echo "==> building ekicore_bench"
cmake --build "$build_dir" --target ekicore_bench

cpp_args=(--benchmark_format=json "--benchmark_out=$results/cpp.json" --benchmark_out_format=json)
if [ "$quick" -eq 1 ]; then
  cpp_args+=(--benchmark_min_time=0.05s)
fi
echo "==> running ekicore_bench (libekicore)"
# The JSON goes to the file; the console copy is dropped to keep the output readable.
"$build_dir/core-cpp/bench/ekicore_bench" "${cpp_args[@]}" > /dev/null

# ---- Rust: libekicore_rs + criterion ------------------------------------------------------------

rs_args=()
if [ "$quick" -eq 1 ]; then
  rs_args=(-- --warm-up-time 0.2 --measurement-time 0.5)
fi
echo "==> running cargo bench (libekicore_rs)"
cargo bench -p ekicore-rs --bench primitives ${rs_args[@]+"${rs_args[@]}"}

target_dir=$(cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')

# ---- merge ------------------------------------------------------------------------------------

python3 - "$results/cpp.json" "$target_dir/criterion" "$results/summary.md" <<'PY'
import json
import os
import sys

cpp_path, criterion_dir, out_path = sys.argv[1:4]

# (benchmark id shared by both suites, row label of docs/benchmarks.md, bytes per operation)
WORKLOADS = [
    ("hmac/sha256/64", "HMAC-SHA256, 64 B", 64),
    ("hmac/sha256/4096", "HMAC-SHA256, 4 KiB", 4096),
    ("hkdf/sha256/32", "HKDF-SHA256, 32 B output", 32),
    ("aead_seal/aes-256-gcm/1024", "AES-256-GCM seal, 1 KiB", 1024),
    ("aead_seal/aes-256-gcm/65536", "AES-256-GCM seal, 64 KiB", 65536),
    ("aead_open/aes-256-gcm/1024", "AES-256-GCM open, 1 KiB", 1024),
    ("aead_open/aes-256-gcm/65536", "AES-256-GCM open, 64 KiB", 65536),
    ("aead_seal/chacha20-poly1305/1024", "ChaCha20-Poly1305 seal, 1 KiB", 1024),
    ("aead_seal/chacha20-poly1305/65536", "ChaCha20-Poly1305 seal, 64 KiB", 65536),
    ("aead_open/chacha20-poly1305/1024", "ChaCha20-Poly1305 open, 1 KiB", 1024),
    ("aead_open/chacha20-poly1305/65536", "ChaCha20-Poly1305 open, 64 KiB", 65536),
]

NS_PER_UNIT = {"ns": 1.0, "us": 1e3, "ms": 1e6, "s": 1e9}

# Google Benchmark: one "iteration" entry per benchmark when run without repetitions.
with open(cpp_path) as f:
    cpp_doc = json.load(f)
cpp = {}
for b in cpp_doc.get("benchmarks", []):
    if b.get("run_type", "iteration") != "iteration":
        continue
    name = b.get("run_name", b["name"])
    cpp[name] = b["real_time"] * NS_PER_UNIT[b.get("time_unit", "ns")]

# criterion: <group>/<function>/<value>/new/{benchmark.json,estimates.json}; the median is in ns.
rs = {}
for dirpath, _, filenames in os.walk(criterion_dir):
    if os.path.basename(dirpath) != "new" or "benchmark.json" not in filenames:
        continue
    with open(os.path.join(dirpath, "benchmark.json")) as f:
        full_id = json.load(f)["full_id"]
    with open(os.path.join(dirpath, "estimates.json")) as f:
        rs[full_id] = json.load(f)["median"]["point_estimate"]


def fmt_ns(value):
    return "n/a" if value is None else f"{value:,.1f}"


rows = [
    "| Workload | libekicore ns/op | libekicore_rs ns/op | ratio | MiB/s |",
    "|---|---:|---:|---:|---:|",
]
missing = []
for bench_id, label, nbytes in WORKLOADS:
    c, r = cpp.get(bench_id), rs.get(bench_id)
    if c is None or r is None:
        missing.append(bench_id)
    ratio = f"{r / c:.2f}" if c and r is not None else "n/a"
    mibs = f"{nbytes / (r * 1e-9) / (1 << 20):,.0f}" if r else "n/a"
    rows.append(f"| {label} | {fmt_ns(c)} | {fmt_ns(r)} | {ratio} | {mibs} |")

ctx = cpp_doc.get("context", {})
notes = [
    "",
    f"libekicore: `{ctx.get('library', '?')}`, Google Benchmark mean of one run (real time). "
    "libekicore_rs: criterion median.",
    "ratio = libekicore_rs / libekicore (below 1.0: Rust faster). "
    "MiB/s = libekicore_rs throughput over the input size.",
    f"{ctx.get('num_cpus', '?')} CPUs, run {ctx.get('date', '?')}.",
]
if missing:
    notes.append("Missing results: " + ", ".join(missing))

text = "\n".join(rows + notes) + "\n"
with open(out_path, "w") as f:
    f.write(text)
print()
print(text, end="")
sys.exit(1 if missing else 0)
PY
echo
echo "bench: wrote $results/summary.md and $results/cpp.json"
