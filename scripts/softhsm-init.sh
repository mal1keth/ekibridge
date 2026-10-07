#!/usr/bin/env bash
# Prepares a throwaway SoftHSM2 token for the PKCS#11 tests and exports what they read:
#
#   source scripts/softhsm-init.sh
#
# TEST ONLY: the user PIN (1234) and SO PIN (12345678) below protect a throwaway token that lives
# in .softhsm/ inside this checkout. They are not secrets; never reuse them for anything real.
#
# Idempotent: the config file is rewritten with the same content, and the token is created only
# when no token labelled "ekibridge" exists yet.
#
# The file is meant to be sourced, so it must not change the caller's shell options: a leaked
# `set -e` would close an interactive shell on the next failing command. Strict mode is therefore
# switched on only when the script is executed instead of sourced.

# Is this file being sourced? Works in bash and in zsh.
if [ -n "${BASH_VERSION:-}" ]; then
  _eki_self=${BASH_SOURCE[0]}
  if (return 0 2>/dev/null); then _eki_sourced=1; else _eki_sourced=0; fi
elif [ -n "${ZSH_VERSION:-}" ]; then
  eval '_eki_self=${(%):-%x}'
  case ${ZSH_EVAL_CONTEXT:-} in
    *:file*) _eki_sourced=1 ;;
    *) _eki_sourced=0 ;;
  esac
else
  _eki_self=$0
  _eki_sourced=0
fi

if [ "$_eki_sourced" -eq 0 ]; then
  set -euo pipefail
  echo "warning: this script is meant to be sourced (source scripts/softhsm-init.sh)." >&2
  echo "warning: run directly it still prepares the token, but the exported variables are lost when it exits." >&2
fi

_eki_softhsm_init() {
  local root state_dir conf prefix state
  local label=ekibridge
  local pin=1234
  local so_pin=12345678

  root=$(cd "$(dirname "$1")/.." && pwd) || return 1
  state_dir="$root/.softhsm"
  conf="$state_dir/softhsm2.conf"

  mkdir -p "$state_dir/tokens" || return 1
  cat >"$conf" <<CONF || return 1
directories.tokendir = $state_dir/tokens
objectstore.backend = file
log.level = INFO
CONF

  export SOFTHSM2_CONF="$conf"

  # The PKCS#11 module: keep a value the caller already set.
  if [ -z "${EKI_PKCS11_MODULE:-}" ]; then
    case "$(uname -s)" in
      Darwin)
        prefix=$(brew --prefix softhsm 2>/dev/null) || prefix=""
        if [ -z "$prefix" ]; then prefix=/opt/homebrew/opt/softhsm; fi
        EKI_PKCS11_MODULE="$prefix/lib/softhsm/libsofthsm2.so"
        ;;
      *)
        EKI_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
        ;;
    esac
  fi
  export EKI_PKCS11_MODULE
  export EKI_PKCS11_TOKEN_LABEL="$label"
  export EKI_PKCS11_PIN="$pin"

  if ! command -v softhsm2-util >/dev/null 2>&1; then
    echo "softhsm-init: softhsm2-util not found; install SoftHSM2 (brew install softhsm opensc, or apt-get install softhsm2 opensc)" >&2
    return 1
  fi

  if softhsm2-util --show-slots 2>/dev/null | grep -Eq "^[[:space:]]*Label:[[:space:]]+${label}[[:space:]]*\$"; then
    state="already initialized"
  else
    softhsm2-util --init-token --free --label "$label" --pin "$pin" --so-pin "$so_pin" >/dev/null || return 1
    state="created"
  fi

  echo "SoftHSM2 module: $EKI_PKCS11_MODULE"
  if [ ! -f "$EKI_PKCS11_MODULE" ]; then
    echo "warning: that module file does not exist; set EKI_PKCS11_MODULE to the right path" >&2
  fi
  echo "SoftHSM2 config: $SOFTHSM2_CONF"
  echo "token '$label': $state"
}

_eki_softhsm_init "$_eki_self"
_eki_rc=$?

unset -f _eki_softhsm_init
unset _eki_self

if [ "$_eki_sourced" -eq 1 ]; then
  unset _eki_sourced
  # shellcheck disable=SC2317
  return "$_eki_rc" 2>/dev/null || exit "$_eki_rc"
fi
exit "$_eki_rc"
