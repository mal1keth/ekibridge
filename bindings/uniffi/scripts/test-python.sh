#!/usr/bin/env bash
# Generates the Python binding, then runs tests/python against it and the library it loads.
#
#   bindings/uniffi/scripts/test-python.sh
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$repo_root"

bindings/uniffi/scripts/generate.sh python
PYTHONPATH="${CARGO_TARGET_DIR:-target}/uniffi/python" \
  python3 -m unittest discover --start-directory bindings/uniffi/tests/python --verbose
