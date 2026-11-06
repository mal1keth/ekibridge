#!/usr/bin/env bash
# Checks include/ekicore.h three ways:
#   1. it is exactly what cbindgen produces from ekicore-abi and core-rs/src/ffi.rs,
#   2. it still defines every constant of the ABI contract,
#   3. it compiles standalone as C11 and as C++20 with -Wall -Wextra -Wpedantic -Werror.
# CI installs the pinned cbindgen first; locally:
#   cargo install cbindgen --version 0.29.4 --locked
set -euo pipefail

CBINDGEN_VERSION=0.29.4

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

installed=$(cbindgen --version 2>/dev/null || true)
if [ "$installed" != "cbindgen $CBINDGEN_VERSION" ]; then
  echo "error: cbindgen $CBINDGEN_VERSION is required (found: ${installed:-none})" >&2
  echo "install it with: cargo install cbindgen --version $CBINDGEN_VERSION --locked" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# 1. The committed header must match a fresh run.
cbindgen --config core-rs/cbindgen.toml --crate ekicore-rs --output "$tmp/ekicore.h"
if ! diff -u include/ekicore.h "$tmp/ekicore.h"; then
  echo "error: include/ekicore.h is out of date; regenerate it from the repository root with:" >&2
  echo "  cbindgen --config core-rs/cbindgen.toml --crate ekicore-rs --output include/ekicore.h" >&2
  exit 1
fi
echo "ok: include/ekicore.h matches cbindgen $CBINDGEN_VERSION output"

# 2. Every constant of the contract must be present.
required_defines="
EKI_ABI_VERSION
EKI_HMAC_SHA256_LEN
EKI_AEAD_KEY_LEN
EKI_AEAD_NONCE_LEN
EKI_AEAD_TAG_LEN
EKI_AEAD_MAX_LEN
EKI_HKDF_MAX_OKM_LEN
EKI_HKDF_MAX_INPUT_LEN
EKI_KEY_ID_LEN
EKI_LABEL_MAX_LEN
EKI_P256_PUBLIC_KEY_LEN
EKI_P256_SIGNATURE_LEN
EKI_WRAPPED_KEY_LEN
EKI_HYBRID_PK_LEN
EKI_HYBRID_SK_LEN
EKI_HYBRID_CT_LEN
EKI_HYBRID_SS_LEN
EKI_AUDIT_HASH_LEN
EKI_DESTROY_REQUEST_LEN
EKI_APPROVERS_MAX
EKI_AUDIT_PATH_MAX_LEN
EKI_AEAD_AES_256_GCM
EKI_AEAD_CHACHA20_POLY1305
EKI_KEY_AES_256
EKI_KEY_HMAC_SHA256
EKI_KEY_ECDSA_P256
EKI_KS_SOFTWARE
EKI_KS_PKCS11
EKI_KEY_STATE_ACTIVE
EKI_KEY_STATE_RETIRED
EKI_KEY_STATE_REVOKED
"
missing=0
count=0
for name in $required_defines; do
  count=$((count + 1))
  if ! grep -Eq "^#define $name( |\$)" include/ekicore.h; then
    echo "error: include/ekicore.h does not define $name" >&2
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  exit 1
fi
echo "ok: all $count required #defines are present"

# 3. The header must compile on its own, as C and as C++, with the asserts below checking the
#    sizes and values the contract promises.
cat >"$tmp/abi_compile_test.c" <<'EOF_C'
#include <ekicore.h>

_Static_assert(EKI_ABI_VERSION == 2, "ABI version");
_Static_assert(sizeof(eki_status) == 4, "eki_status is 32 bits");
_Static_assert(sizeof(eki_aead_alg) == 4, "selectors are 32 bits");
_Static_assert(sizeof(eki_key_id) == EKI_KEY_ID_LEN, "key id size");
_Static_assert(sizeof(((eki_key_info *)0)->label) == EKI_LABEL_MAX_LEN + 1, "label size");
_Static_assert(EKI_AEAD_MAX_LEN == 68719476704ULL, "AEAD length cap");
_Static_assert(EKI_WRAPPED_KEY_LEN == EKI_AEAD_KEY_LEN + 8, "RFC 3394 adds 8 bytes");
_Static_assert(EKI_ERR_INTERNAL == 10, "status values are append-only");
_Static_assert(EKI_ERR_APPROVAL_REQUIRED == 12, "status values are append-only");
_Static_assert(sizeof(eki_key_state) == 4, "key state is 32 bits");
_Static_assert(sizeof(((eki_key_info_v2 *)0)->label) == EKI_LABEL_MAX_LEN + 1, "label size");

/* Uses the config struct and the opaque handle the way a caller would. */
int main(void) {
  eki_ks *ks = NULL;
  const eki_ks_config config = {EKI_KS_SOFTWARE, NULL, NULL, NULL};
  return (int)eki_ks_open(&config, &ks);
}
EOF_C

cat >"$tmp/abi_compile_test.cpp" <<'EOF_CPP'
#include <ekicore.h>

#include <cstdint>
#include <type_traits>

static_assert(EKI_ABI_VERSION == 2);
static_assert(sizeof(eki_status) == 4);
static_assert(std::is_enum_v<eki_status>);
static_assert(std::is_same_v<std::underlying_type_t<eki_status>, std::int32_t>);
static_assert(sizeof(eki_aead_alg) == 4);
static_assert(sizeof(eki_key_id) == EKI_KEY_ID_LEN);
static_assert(sizeof(eki_key_info::label) == EKI_LABEL_MAX_LEN + 1);
static_assert(EKI_AEAD_MAX_LEN == 68719476704ULL);
static_assert(EKI_WRAPPED_KEY_LEN == EKI_AEAD_KEY_LEN + 8);
static_assert(EKI_ERR_INTERNAL == 10);
static_assert(EKI_ERR_APPROVAL_REQUIRED == 12);
static_assert(sizeof(eki_key_state) == 4);
static_assert(sizeof(eki_key_info_v2::label) == EKI_LABEL_MAX_LEN + 1);

// Uses the config struct and the opaque handle the way a caller would; linkage is checked by
// scripts/check-exports.sh, not here.
int main() {
  eki_ks *ks = nullptr;
  const eki_ks_config config = {EKI_KS_SOFTWARE, nullptr, nullptr, nullptr};
  return static_cast<int>(eki_ks_open(&config, &ks));
}
EOF_CPP

warn_flags="-Wall -Wextra -Wpedantic -Werror -fsyntax-only"
# shellcheck disable=SC2086
"${CC:-cc}" -std=c11 $warn_flags -I include "$tmp/abi_compile_test.c"
echo "ok: header compiles as C11 with ${CC:-cc}"
# shellcheck disable=SC2086
"${CXX:-c++}" -std=c++20 $warn_flags -I include "$tmp/abi_compile_test.cpp"
echo "ok: header compiles as C++20 with ${CXX:-c++}"
