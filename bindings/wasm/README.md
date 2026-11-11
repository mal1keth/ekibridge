# ekicore-wasm

The safe API of `ekicore-rs` compiled to WebAssembly and exported to JavaScript with
[wasm-bindgen](https://wasm-bindgen.github.io/wasm-bindgen/). [`src/lib.rs`](src/lib.rs) wraps the
safe modules, never the `extern "C"` layer.

```ts
export type AeadAlgorithm = "aes-256-gcm" | "chacha20-poly1305";
export interface SealedBox { ciphertext: Uint8Array; tag: Uint8Array; }

export function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array;
export function hmacSha256Verify(key: Uint8Array, msg: Uint8Array, tag: Uint8Array): void;
export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array;
export function aeadSeal(algorithm: AeadAlgorithm, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): SealedBox;
export function aeadOpen(algorithm: AeadAlgorithm, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Uint8Array;
export function ecdsaP256Verify(publicKey: Uint8Array, msg: Uint8Array, signature: Uint8Array): void;
```

That is the TypeScript wasm-bindgen generates. Every failure is a thrown `Error` with `name`
`"EkiError"` and the C status name as both `code` and `message`, for example
`EKI_ERR_AUTH_FAILED`. Verification functions return nothing and throw on a mismatch. The algorithm
is a string; an unknown name such as `"aes-128-gcm"` throws `EKI_ERR_INVALID_ARGUMENT`, as an
unknown selector does in the C ABI. `aeadSeal` returns a plain object rather than a wasm-bindgen
class, so there is no `free()` to call.

## Making ekicore-rs build for wasm32-unknown-unknown

- **PKCS#11.** The backend loads a native module with `dlopen`, which WebAssembly cannot do, so
  this crate depends on `ekicore-rs` with default features off.
- **Random numbers.** `getrandom` has no default source on `wasm32-unknown-unknown`. This crate
  adds `getrandom` with the `wasm_js` feature for wasm32 targets only (`crypto.getRandomValues` of
  the host); feature unification applies it to the copy `ekicore-rs` uses. None of the exported
  functions draws random numbers, but the key store code is compiled in.
- **Audit log.** `core-rs/src/keystore/audit.rs` used `std::os::unix` for the log file's mode
  (0600) and to turn a path's bytes into a path. Those lines are gated with `#[cfg(unix)]`; outside
  Unix the file is created without a mode and a path must be UTF-8. Native builds and the C header
  are unchanged. The audit log is not reachable from JavaScript, and `std::fs` fails at run time on
  this target anyway.

## Build, test, package

From the repository root:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked   # must equal the wasm-bindgen pin

cargo build -p ekicore-wasm --target wasm32-unknown-unknown

# tests/node.rs under Node, through wasm-bindgen-test-runner
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test -p ekicore-wasm --target wasm32-unknown-unknown

# a CommonJS package for Node: ekicore_wasm.js, ekicore_wasm.d.ts and the .wasm module
wasm-bindgen --target nodejs --out-dir target/wasm-pkg \
  target/wasm32-unknown-unknown/debug/ekicore_wasm.wasm
```

`--target web` or `--target bundler` produce the browser variants. The tests in
[`tests/node.rs`](tests/node.rs) pass real `Uint8Array` objects and inspect the thrown errors as
JavaScript sees them. They check one published vector per primitive (RFC 4231 test case 2, RFC
5869 A.1, RFC 8439 2.8.2, the GCM specification's test case 16 for AES-256-GCM, RFC 6979 A.2.5), a
seal/open round trip per AEAD algorithm, invalid arguments (including an unknown algorithm name)
and authentication failures. On a native target the test file compiles to nothing.

## Secrets cross as copies

A WebAssembly module and its JavaScript host share no address space. `Uint8Array.to_vec` copies
each argument into the module's linear memory and `Uint8Array::from` copies each result out into a
new JavaScript buffer. The binding wipes the copies it holds in linear memory once a call is done,
for every input and for derived output and plaintext. The JavaScript objects on either side are
the caller's and are not wiped; they live until the garbage collector reclaims them.

## Notes

- The `.wasm` module also exports the `eki_*` functions of `ekicore-rs` (a `#[no_mangle]` function
  of a linked Rust library is exported from a `cdylib`). The generated JavaScript does not expose
  them.
- `src/lib.rs` is `#![deny(unsafe_code)]`; the `unsafe` glue comes from the `#[wasm_bindgen]`
  macros. `missing_docs` is allowed only in the module that holds `AeadAlgorithm`, because
  wasm-bindgen adds an undocumented hidden variant and function to a string enum.
- On a 32-bit target clippy reports `absurd_extreme_comparisons` in `core-rs/src/aead.rs`, where
  the AEAD length cap saturates at `usize::MAX` by design, so the wasm32 lint runs with `--no-deps`.

## Versions

| Tool | Version |
|---|---|
| wasm-bindgen (crate and CLI) | 0.2.130 |
| wasm-bindgen-test | 0.3.80 |
| js-sys | 0.3.107 |
| Rust | stable, 1.99.1 when this was written, target `wasm32-unknown-unknown` |
| Node | 23.8.0 locally; the runner's Node in CI (Ubuntu 24.04) |
