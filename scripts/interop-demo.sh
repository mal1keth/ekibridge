#!/usr/bin/env bash
# Runs the interop callers across the language boundary:
#
#   cpp-caller  (C++ program) -> libekicore_rs (Rust implementation)
#   rust-caller (Rust program) -> libekicore    (C++ implementation)
#
# Neither caller links an ekicore library; each loads the path it is given at run time, which is
# the runtime-selection switch of docs/migration-plan.md in miniature. Builds what it needs first:
# CMake preset "release" (libekicore and cpp-caller) and cargo --release (libekicore_rs and
# rust-caller). Exits non-zero if either caller reports a failed step.
#
#   scripts/interop-demo.sh

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

# ---- build -------------------------------------------------------------------------------------

echo "==> building libekicore and cpp-caller (cmake preset release)"
if [ ! -f build/release/CMakeCache.txt ]; then
  cmake --preset release >/dev/null
fi
cmake --build --preset release --target ekicore cpp-caller

echo "==> building libekicore_rs and rust-caller (cargo --release)"
cargo build --release -p ekicore-rs -p interop-rust-caller

# ---- locate ------------------------------------------------------------------------------------

# find_file <dir> <name> <suffix>...: prints the first <dir>/<name><suffix> that exists.
find_file() {
  local dir=$1 name=$2 suffix
  shift 2
  for suffix in "$@"; do
    if [ -f "$dir/$name$suffix" ]; then
      printf '%s\n' "$dir/$name$suffix"
      return 0
    fi
  done
  return 1
}

target_dir=${CARGO_TARGET_DIR:-$root/target}
case $target_dir in /*) ;; *) target_dir=$root/$target_dir ;; esac

cpp_lib=$(find_file "$root/build/release/core-cpp" libekicore .dylib .so) || {
  echo "interop-demo: libekicore.{dylib,so} not found under build/release/core-cpp" >&2
  exit 1
}
rs_lib=$(find_file "$target_dir/release" libekicore_rs .dylib .so) || {
  echo "interop-demo: libekicore_rs.{dylib,so} not found under $target_dir/release" >&2
  exit 1
}
cpp_caller=$(find_file "$root/build/release/interop/cpp-caller" cpp-caller "") || {
  echo "interop-demo: cpp-caller not found under build/release/interop/cpp-caller" >&2
  exit 1
}
rust_caller=$(find_file "$target_dir/release" interop-rust-caller "") || {
  echo "interop-demo: interop-rust-caller not found under $target_dir/release" >&2
  exit 1
}

# ---- run ---------------------------------------------------------------------------------------

stub_seen=0

# run_caller <label> <caller binary> <library>: prints the caller's output, sets $result.
run_caller() {
  local label=$1 caller=$2 lib=$3 output status=0
  echo
  echo "==> $label"
  output=$("$caller" "$lib" 2>&1) || status=$?
  printf '%s\n' "$output"
  if [ "$status" -eq 0 ]; then
    result=PASS
  else
    result="FAIL (exit $status)"
  fi
  if grep -q '(EKI_ERR_UNSUPPORTED)' <<<"$output"; then stub_seen=1; fi
}

run_caller "cpp-caller -> $(basename "$rs_lib")" "$cpp_caller" "$rs_lib"
cpp_result=$result
run_caller "rust-caller -> $(basename "$cpp_lib")" "$rust_caller" "$cpp_lib"
rust_result=$result

echo
echo "==> interop summary"
echo "    cpp-caller  (C++)  -> libekicore_rs (Rust): $cpp_result"
echo "    rust-caller (Rust) -> libekicore    (C++):  $rust_result"

if [ "$cpp_result" = PASS ] && [ "$rust_result" = PASS ]; then
  exit 0
fi
if [ "$stub_seen" -eq 1 ]; then
  echo
  echo "note: EKI_ERR_UNSUPPORTED is what the stubs return. Failures with that status are expected"
  echo "      until the implementations land; 'PASS version' already shows that each library loads"
  echo "      and answers through the shared ABI."
fi
exit 1
