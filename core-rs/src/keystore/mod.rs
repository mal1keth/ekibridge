//! Key store: the handle behind `eki_ks`, with a software backend (lesson L6) and a PKCS#11
//! backend (lesson L7).

pub mod software;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;
