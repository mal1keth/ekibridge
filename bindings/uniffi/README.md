# ekicore-uniffi

[UniFFI](https://mozilla.github.io/uniffi-rs/) bindings over the safe API of `ekicore-rs`, for
Python, Kotlin and Swift. The interface is declared with proc macros in [`src/lib.rs`](src/lib.rs)
(no UDL file) and wraps the safe modules, never the `extern "C"` layer.

| Rust | Python | Kotlin / Swift |
|---|---|---|
| `hmac_sha256(key, msg) -> Vec<u8>` | `hmac_sha256` | `hmacSha256` |
| `hmac_sha256_verify(key, msg, tag)` | `hmac_sha256_verify` | `hmacSha256Verify` |
| `hkdf_sha256(ikm, salt, info, length) -> Vec<u8>` | `hkdf_sha256` | `hkdfSha256` |
| `aead_seal(algorithm, key, nonce, aad, plaintext) -> SealedBox` | `aead_seal` | `aeadSeal` |
| `aead_open(algorithm, key, nonce, aad, ciphertext, tag) -> Vec<u8>` | `aead_open` | `aeadOpen` |
| `ecdsa_p256_verify(public_key, msg, signature)` | `ecdsa_p256_verify` | `ecdsaP256Verify` |

Byte strings are `bytes` in Python, `ByteArray` in Kotlin and `Data` in Swift. `AeadAlgorithm` is
an enum (`AES256_GCM`, `CHACHA20_POLY1305` in Python), so an unknown algorithm cannot be named.
`aead_seal` returns a `SealedBox` record with `ciphertext` and the detached 16-byte `tag`. Every
failure raises `EkiError` (`EkiException` in Kotlin), with one subclass per variant of
`ekicore_rs::error::Error` (`EkiError.InvalidArgument`, `EkiError.AuthFailed`, ...) and the C
status name, for example `EKI_ERR_AUTH_FAILED`, as its message. Verification functions return
nothing and raise `AuthFailed` on a mismatch.

The PKCS#11 backend (the default feature `pkcs11` of `ekicore-rs`) is turned off: none of these
functions uses a key store.

## Build, generate, test

From the repository root:

```sh
cargo build -p ekicore-uniffi                 # target/debug/libekicore_uniffi.{so,dylib}
bindings/uniffi/scripts/generate.sh           # Python, Kotlin, Swift into target/uniffi/<language>/
bindings/uniffi/scripts/test-python.sh        # generate Python, then run tests/python
```

The generator is the `uniffi-bindgen` binary of this crate (`uniffi-bindgen.rs`), built from the
same pinned uniffi as the scaffolding, so nothing is installed globally and the generated code
always matches the library's checksums. It reads the interface from the metadata embedded in the
built library (library mode):

```sh
cargo run -p ekicore-uniffi --bin uniffi-bindgen -- generate --language python \
    --out-dir out/ target/debug/libekicore_uniffi.so
```

The generated Python module loads the library from its own directory, so `generate.sh` copies the
library next to it.

```python
import ekicore_uniffi as eki

sealed = eki.aead_seal(eki.AeadAlgorithm.CHACHA20_POLY1305, key, nonce, b"aad", b"plaintext")
plaintext = eki.aead_open(eki.AeadAlgorithm.CHACHA20_POLY1305, key, nonce, b"aad",
                          sealed.ciphertext, sealed.tag)
```

## What is tested

- **Python, run.** [`tests/python/test_bindings.py`](tests/python/test_bindings.py) loads the
  generated module with the built library and checks one published vector per primitive (RFC 4231
  test case 2, RFC 5869 A.1, RFC 8439 2.8.2, the GCM specification's test case 16 for AES-256-GCM,
  RFC 6979 A.2.5), a seal/open round trip per AEAD algorithm, and both error classes the functions
  raise: invalid argument (empty key, short tag, HKDF lengths, wrong key, nonce and tag sizes, a
  compressed point) and authentication failure (changed tag, AAD, ciphertext, message).
- **Kotlin and Swift, generated only.** `generate.sh` writes them and checks that each exported
  function, the error type and the record are declared. They are not compiled: no Kotlin or Swift
  toolchain is part of this repository's builds.
- **Rust.** `cargo test -p ekicore-uniffi` checks that every `Error` variant maps to the variant of
  the same name and that its message is the status name.

## Secrets cross as copies

UniFFI copies every argument and result: the foreign side serialises a byte string into a buffer,
and Rust reads it into a `Vec<u8>` of its own; results go the same way back. The binding wipes
the copies it holds of keys, input keying material, plaintext and derived output when they are
dropped. It cannot wipe the serialisation buffers UniFFI frees, nor the foreign objects: a Python
`bytes` is immutable and lives until the garbage collector reclaims it. A caller that needs secrets
to stay out of a managed heap should use the C ABI or the key store, where keys never leave the
library.

## Notes

- The library also exports the `eki_*` functions of `ekicore-rs`: a `#[no_mangle]` function of a
  linked Rust library is exported from a `cdylib`. The generated code does not use them.
- `src/lib.rs` is `#![deny(unsafe_code)]`. The `unsafe` in the scaffolding comes from the uniffi
  macros, which the lint does not attribute to this crate.
- uniffi brings `basic-toml` (through askama, its template engine) into the build, which RustSec
  lists as unmaintained (RUSTSEC-2026-0374); `deny.toml` ignores that advisory with the reason.

## Versions

| Tool | Version |
|---|---|
| uniffi (scaffolding and `uniffi-bindgen`) | 0.32.2 |
| Rust | stable, 1.99.1 when this was written |
| Python | 3.10.5 locally; the runner's `python3` in CI (Ubuntu 24.04, macOS 15) |
