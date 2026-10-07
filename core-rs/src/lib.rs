//! `ekicore-rs`: the Rust implementation of the ekicore C ABI, built on RustCrypto.
//!
//! The crate builds as `libekicore_rs` (a `cdylib`, a `staticlib` and an `rlib`) and exports
//! exactly the `eki_*` functions declared in `include/ekicore.h`, the same ones the C++
//! library `libekicore` exports. A caller can load either library without recompiling.
//!
//! The safe code lives in the ordinary modules. [`ffi`] is the only module allowed to contain
//! `unsafe`: it turns raw C pointers into slices, calls the safe code, and maps every outcome,
//! including a panic, to an `eki_status`.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod aead;
pub mod ecdsa;
pub mod error;
#[allow(unsafe_code)]
pub mod ffi;
pub mod hkdf;
pub mod hmac;
pub mod keystore;
#[cfg(feature = "pq")]
pub mod pq;
