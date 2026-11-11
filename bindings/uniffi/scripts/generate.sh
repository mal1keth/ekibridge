#!/usr/bin/env bash
# Builds libekicore_uniffi and generates its foreign bindings with the crate's own uniffi-bindgen
# binary, so nothing has to be installed globally.
#
#   bindings/uniffi/scripts/generate.sh [python] [kotlin] [swift]    (no argument: all three)
#
# Output goes to <target dir>/uniffi/<language>/. The library is copied next to the Python
# module, which is where the generated loader looks for it. Kotlin and Swift are generated and
# checked for the expected declarations, not compiled.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$repo_root"

target_dir=${CARGO_TARGET_DIR:-target}
case "$(uname -s)" in
  Darwin) library_file=libekicore_uniffi.dylib ;;
  *) library_file=libekicore_uniffi.so ;;
esac
library="$target_dir/debug/$library_file"

if [ "$#" -eq 0 ]; then
  set -- python kotlin swift
fi

cargo build -p ekicore-uniffi

# Every exported function must appear in each language, under that language's naming rule.
python_names="hmac_sha256 hmac_sha256_verify hkdf_sha256 aead_seal aead_open ecdsa_p256_verify"
foreign_names="hmacSha256 hmacSha256Verify hkdfSha256 aeadSeal aeadOpen ecdsaP256Verify"

expect() {
  local file=$1 pattern=$2
  if ! grep -Eq "$pattern" "$file"; then
    echo "error: $file does not match: $pattern" >&2
    exit 1
  fi
}

for language in "$@"; do
  out="$target_dir/uniffi/$language"
  rm -rf "$out"
  mkdir -p "$out"
  # --no-format: the output does not depend on whether ktlint or swiftformat is installed.
  cargo run --quiet -p ekicore-uniffi --bin uniffi-bindgen -- \
    generate --no-format --language "$language" --out-dir "$out" "$library"
  case "$language" in
    python)
      cp "$library" "$out/"
      for name in $python_names; do
        expect "$out/ekicore_uniffi.py" "^def $name\("
      done
      expect "$out/ekicore_uniffi.py" "^class EkiError"
      ;;
    kotlin)
      file="$out/uniffi/ekicore_uniffi/ekicore_uniffi.kt"
      for name in $foreign_names; do
        expect "$file" "fun \`$name\`\("
      done
      # The Kotlin generator renames an error type ending in Error to ...Exception.
      expect "$file" "^sealed class EkiException"
      expect "$file" "^data class SealedBox"
      ;;
    swift)
      file="$out/ekicore_uniffi.swift"
      for name in $foreign_names; do
        expect "$file" "^public func $name\("
      done
      expect "$file" "^enum EkiError"
      expect "$file" "^public struct SealedBox"
      expect "$out/ekicore_uniffiFFI.h" "ekicore_uniffi_fn_func_hmac_sha256"
      ;;
    *)
      echo "error: unknown language $language (expected python, kotlin or swift)" >&2
      exit 1
      ;;
  esac
  echo "ok: $language bindings in $out"
done
