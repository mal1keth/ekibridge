#!/usr/bin/env bash
# Prints a markdown inventory of the unsafe code in the Rust FFI layer, for docs/ffi-contract.md:
#
#   (a) every `unsafe fn` definition (including `unsafe extern "C" fn`) and whether its doc
#       comment has a `# Safety` section;
#   (b) every `unsafe { ... }` block, the function that encloses it, and the text of the
#       `// SAFETY:` comment directly above it, or MISSING;
#   (c) every `unsafe impl`, with its `// SAFETY:` comment, or MISSING.
#
# Comments, string literals and attributes such as #[unsafe(no_mangle)] are not counted.
# Exits 1 if any unsafe block or unsafe impl lacks a SAFETY comment.
#
#   scripts/unsafe-inventory.sh [file.rs]      (default: core-rs/src/ffi.rs)

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
file=${1:-$root/core-rs/src/ffi.rs}
if [ ! -f "$file" ]; then
  echo "unsafe-inventory: $file does not exist" >&2
  exit 2
fi
case $file in "$root"/*) display=${file#"$root"/} ;; *) display=$file ;; esac

exec python3 - "$file" "$display" <<'EOF'
import re
import sys

path, display = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    src = f.read()

IDENT = re.compile(r"[A-Za-z0-9_]")


def mask(text):
    """Blanks comments and the contents of string and char literals, keeping offsets and newlines,
    so the regexes below only ever see code."""
    out = list(text)
    i, n = 0, len(text)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == '"':
            # Raw string? Look back for r, r#, r##... preceded by a non-identifier or a b/c prefix.
            k, hashes = i - 1, 0
            while k >= 0 and text[k] == "#":
                k, hashes = k - 1, hashes + 1
            raw = k >= 0 and text[k] == "r" and (
                k == 0 or not IDENT.match(text[k - 1]) or
                (text[k - 1] in "bc" and (k == 1 or not IDENT.match(text[k - 2]))))
            if raw:
                end = text.find('"' + "#" * hashes, i + 1)
                end = n if end < 0 else end
            else:
                end = i + 1
                while end < n and text[end] != '"':
                    end += 2 if text[end] == "\\" else 1
            blank(i + 1, min(end, n))
            i = end + 1 + (hashes if raw else 0)
        elif c == "'":
            # A char literal ('a', '\n', '\u{..}'), not a lifetime ('a).
            if i + 1 < n and text[i + 1] == "\\":
                end = text.find("'", i + 2)
            elif i + 2 < n and text[i + 2] == "'":
                end = i + 2
            else:
                end = -1
            if end > 0:
                blank(i + 1, end)
                i = end + 1
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


code = mask(src)
lines = src.split("\n")


def line_of(offset):
    return src.count("\n", 0, offset) + 1


def matching_brace(open_at):
    depth = 0
    for k in range(open_at, len(code)):
        if code[k] == "{":
            depth += 1
        elif code[k] == "}":
            depth -= 1
            if depth == 0:
                return k
    return len(code)


# Every named fn with a body, for "enclosing function" lookups.
functions = []  # (name, body_start, body_end)
for m in re.finditer(r"\bfn\s+([A-Za-z_]\w*)", code):
    depth, k = 0, m.end()
    while k < len(code):
        ch = code[k]
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        elif ch == ";" and depth <= 0:
            k = -1
            break
        elif ch == "{" and depth <= 0:
            break
        k += 1
    if 0 <= k < len(code):
        functions.append((m.group(1), k, matching_brace(k)))


def enclosing(offset):
    best = None
    for name, start, end in functions:
        if start < offset < end and (best is None or start > best[1]):
            best = (name, start)
    return best[0] if best else "(module level)"


def comment_above(line_no):
    """The // SAFETY: comment in the run of // lines directly above line `line_no` (1-based),
    joined into one line, or None."""
    k = line_no - 2
    group = []
    while k >= 0 and lines[k].lstrip().startswith("//") and not lines[k].lstrip().startswith("///"):
        group.insert(0, lines[k].strip()[2:].strip())
        k -= 1
    for idx, text in enumerate(group):
        if text.startswith("SAFETY:"):
            return " ".join(t for t in group[idx:] if t)
    return None


def has_safety_doc(line_no):
    k = line_no - 2
    while k >= 0:
        s = lines[k].strip()
        if s.startswith("#[") or s.startswith("#!["):
            k -= 1
            continue
        if s.startswith("///"):
            if re.match(r"///\s*#\s*Safety\b", s):
                return True
            k -= 1
            continue
        break
    return False


def cell(text):
    return text.replace("|", "\\|")


fns = [(line_of(m.start()), m.group(1)) for m in re.finditer(
    r"\bunsafe\s+(?:extern\s*(?:\"[^\"]*\"\s*)?)?fn\s+([A-Za-z_]\w*)", code)]
blocks = [(line_of(m.start()), enclosing(m.start())) for m in re.finditer(r"\bunsafe\s*\{", code)]
impls = [(line_of(m.start()), " ".join(lines[line_of(m.start()) - 1].split()))
         for m in re.finditer(r"\bunsafe\s+impl\b", code)]

print(f"# Unsafe inventory: `{display}`")
print()
print(f"## Unsafe functions ({len(fns)})")
print()
if fns:
    print("| Line | Function | `# Safety` doc section |")
    print("|---:|---|---|")
    for line_no, name in fns:
        print(f"| {line_no} | `{name}` | {'yes' if has_safety_doc(line_no) else 'no'} |")
else:
    print("None.")
if re.search(r"#!\[allow\([^)]*clippy::missing_safety_doc", code):
    print()
    print("The file allows `clippy::missing_safety_doc`: the shared caller contract is stated once,"
          " in the module documentation and in `docs/ffi-contract.md`.")

missing = 0
print()
print(f"## Unsafe blocks ({len(blocks)})")
print()
if blocks:
    print("| Line | Enclosing function | SAFETY comment |")
    print("|---:|---|---|")
    for line_no, fn in blocks:
        comment = comment_above(line_no)
        if comment is None:
            missing += 1
        print(f"| {line_no} | `{fn}` | {cell(comment) if comment else '**MISSING**'} |")
else:
    print("None.")

if impls:
    print()
    print(f"## Unsafe impls ({len(impls)})")
    print()
    print("| Line | Impl | SAFETY comment |")
    print("|---:|---|---|")
    for line_no, text in impls:
        comment = comment_above(line_no)
        if comment is None:
            missing += 1
        print(f"| {line_no} | `{cell(text.rstrip('{} ').strip())}` | "
              f"{cell(comment) if comment else '**MISSING**'} |")

print()
if missing:
    print(f"{missing} unsafe block(s) or impl(s) without a `// SAFETY:` comment.")
    sys.exit(1)
print("Every unsafe block and impl carries a `// SAFETY:` comment.")
EOF
