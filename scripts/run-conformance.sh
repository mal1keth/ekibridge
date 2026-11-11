#!/usr/bin/env bash
# Builds libekicore (C++, CMake preset "release") and libekicore_rs (cargo --release), then runs
# the conformance test modules against both.
#
#   scripts/run-conformance.sh                  modules listed in conformance/ci-modules.txt
#   scripts/run-conformance.sh --all            every conformance/tests/*.rs module
#   scripts/run-conformance.sh hmac aead        just these modules
#   scripts/run-conformance.sh --with-pkcs11    PKCS#11 token available: the ks_pkcs11* modules run
#                                               when selected (source scripts/softhsm-init.sh first)
#
# Without --with-pkcs11 the EKI_PKCS11_* variables are cleared for the test run, so a selected
# ks_pkcs11* module skips itself; with it they are required. --with-pkcs11 does not add the
# ks_pkcs11* modules to the selection: CI passes it together with ci-modules.txt, which lists
# them, and --all --with-pkcs11 runs everything.
#
# Environment:
#   EKI_PQ=1      build both libraries with the hybrid KEM (cargo feature pq, CMake EKI_WITH_PQ=ON)
#                 and run the pq module
#   EKI_DIFF_N    iterations per function in the differential tests (default 2000)
#   EKI_DIFF_SEED seed of the differential tests (default 0x454B4942)
#
# The ks_pkcs11* modules always run with --test-threads=1. Exits non-zero if any module fails.

set -euo pipefail

usage() {
  sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
}

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

all=0
with_pkcs11=0
modules=()
while [ $# -gt 0 ]; do
  case $1 in
    --all) all=1 ;;
    --with-pkcs11) with_pkcs11=1 ;;
    -h | --help) usage; exit 0 ;;
    -*) echo "run-conformance: unknown option $1" >&2; usage >&2; exit 2 ;;
    *) modules+=("$1") ;;
  esac
  shift
done

if [ "$with_pkcs11" -eq 1 ] && [ -z "${EKI_PKCS11_MODULE:-}" ]; then
  echo "run-conformance: --with-pkcs11 needs EKI_PKCS11_MODULE; source scripts/softhsm-init.sh first" >&2
  exit 1
fi

pq=0
if [ "${EKI_PQ:-}" = "1" ]; then pq=1; fi

# ---- module list -------------------------------------------------------------------------------

if [ "$all" -eq 1 ]; then
  for f in conformance/tests/*.rs; do
    modules+=("$(basename "$f" .rs)")
  done
elif [ "${#modules[@]}" -eq 0 ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%%#*}
    line=$(printf '%s' "$line" | tr -d '[:space:]')
    if [ -n "$line" ]; then modules+=("$line"); fi
  done <conformance/ci-modules.txt
fi
if [ "$pq" -eq 1 ]; then modules+=(pq); fi

# De-duplicate, keeping the first occurrence, and reject names without a test file.
selected=()
for m in "${modules[@]}"; do
  if [ ! -f "conformance/tests/$m.rs" ]; then
    echo "run-conformance: no module '$m' (conformance/tests/$m.rs does not exist)" >&2
    exit 2
  fi
  dup=0
  for s in ${selected[@]+"${selected[@]}"}; do
    if [ "$s" = "$m" ]; then dup=1; fi
  done
  if [ "$dup" -eq 0 ]; then selected+=("$m"); fi
done
if [ "${#selected[@]}" -eq 0 ]; then
  echo "run-conformance: no modules selected" >&2
  exit 2
fi

# ---- build both libraries ----------------------------------------------------------------------

if [ "$pq" -eq 1 ]; then cmake_pq=ON; cargo_features=(--features pq); else cmake_pq=OFF; cargo_features=(); fi

echo "==> building libekicore (cmake preset release, EKI_WITH_PQ=$cmake_pq)"
# Configure when the build directory is new or the PQ setting differs from the cached one.
cache=build/release/CMakeCache.txt
if [ ! -f "$cache" ] || ! grep -q "^EKI_WITH_PQ:BOOL=$cmake_pq\$" "$cache"; then
  cmake --preset release -DEKI_WITH_PQ="$cmake_pq" >/dev/null
fi
cmake --build --preset release --target ekicore

echo "==> building libekicore_rs (cargo --release ${cargo_features[*]-})"
cargo build -p ekicore-rs --release ${cargo_features[@]+"${cargo_features[@]}"}

find_lib() {
  local dir=$1 base=$2 ext
  for ext in dylib so; do
    if [ -f "$dir/$base.$ext" ]; then
      printf '%s\n' "$dir/$base.$ext"
      return 0
    fi
  done
  return 1
}

cpp_lib=$(find_lib "$root/build/release/core-cpp" libekicore) || {
  echo "run-conformance: libekicore.{dylib,so} not found under build/release/core-cpp" >&2
  exit 1
}
target_dir=${CARGO_TARGET_DIR:-$root/target}
case $target_dir in /*) ;; *) target_dir=$root/$target_dir ;; esac
rs_lib=$(find_lib "$target_dir/release" libekicore_rs) || {
  echo "run-conformance: libekicore_rs.{dylib,so} not found under $target_dir/release" >&2
  exit 1
}
export EKI_CPP_LIB=$cpp_lib
export EKI_RS_LIB=$rs_lib
echo "==> EKI_CPP_LIB=$EKI_CPP_LIB"
echo "==> EKI_RS_LIB=$EKI_RS_LIB"

# ---- run ---------------------------------------------------------------------------------------

if [ "$with_pkcs11" -eq 0 ]; then
  for m in "${selected[@]}"; do
    case $m in
      ks_pkcs11*) echo "==> $m is selected without --with-pkcs11: it will skip (EKI_PKCS11_* cleared)" ;;
    esac
  done
  unset EKI_PKCS11_MODULE EKI_PKCS11_TOKEN_LABEL EKI_PKCS11_PIN
fi

# Compile every selected test binary once up front so build errors are not mistaken for failures.
test_args=()
for m in "${selected[@]}"; do test_args+=(--test "$m"); done
cargo test -p ekicore-conformance "${test_args[@]}" --no-run

passed=()
failed=()
for m in "${selected[@]}"; do
  echo
  echo "==> conformance module: $m"
  harness_args=(--nocapture)
  case $m in ks_pkcs11*) harness_args+=(--test-threads=1) ;; esac
  if cargo test -q -p ekicore-conformance --test "$m" -- "${harness_args[@]}"; then
    passed+=("$m")
  else
    failed+=("$m")
  fi
done

echo
echo "==> conformance summary"
echo "    passed: ${passed[*]-(none)}"
echo "    failed: ${failed[*]-(none)}"
if [ "${#failed[@]}" -gt 0 ]; then exit 1; fi
