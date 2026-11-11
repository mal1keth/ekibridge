//! The UniFFI bindings generator, built from the uniffi version this crate pins. It reads the
//! metadata the proc macros embed in the built library and writes the foreign code:
//!
//! ```text
//! cargo run -p ekicore-uniffi --bin uniffi-bindgen -- generate \
//!     --library target/debug/libekicore_uniffi.so --language python --out-dir out/
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
