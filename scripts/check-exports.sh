#!/usr/bin/env bash
# Fails if a shared library exports a symbol that is not part of the ekicore ABI, that is, any
# defined global symbol that does not start with "eki_" and is not ordinary runtime noise.
#
#   scripts/check-exports.sh [lib ...]
#
# With no arguments it checks build/default/core-cpp/libekicore.* and target/debug/libekicore_rs.*.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
os=$(uname -s)
nm_bin=${NM:-nm}

if [ "$os" = Darwin ]; then
  ext=dylib
else
  ext=so
fi

if [ "$#" -eq 0 ]; then
  set -- "$repo_root/build/default/core-cpp/libekicore.$ext" \
    "$repo_root/target/debug/libekicore_rs.$ext"
fi

# Symbols every ELF shared object may carry, plus the Rust unwinding personality routine.
allowed=" _init _fini __bss_start _edata _end rust_eh_personality "

# Prints the names of the defined global symbols of $1, one per line.
list_exports() {
  if [ "$os" = Darwin ]; then
    "$nm_bin" -gU -P "$1"
  else
    "$nm_bin" -D --defined-only -P "$1"
  fi | awk '{ print $1 }'
}

status=0
for lib in "$@"; do
  if [ ! -f "$lib" ]; then
    echo "error: $lib does not exist; build it first" >&2
    status=1
    continue
  fi

  symbols=$(list_exports "$lib")
  offending=""
  exported=0
  for sym in $symbols; do
    name=${sym%%@*} # GNU nm may print name@@VERSION
    if [ "$os" = Darwin ]; then
      name=${name#_} # Mach-O prefixes C symbols with an underscore
    fi
    case "$name" in
      eki_*) exported=$((exported + 1)) ;;
      *)
        case "$allowed" in
          *" $sym "* | *" $name "*) ;;
          *) offending="$offending $sym" ;;
        esac
        ;;
    esac
  done

  if [ -n "$offending" ]; then
    echo "FAIL $lib exports symbols outside the eki_ namespace:" >&2
    for sym in $offending; do
      echo "  $sym" >&2
    done
    status=1
  else
    echo "ok: $lib exports $exported eki_* symbols and nothing else"
  fi
done

exit "$status"
