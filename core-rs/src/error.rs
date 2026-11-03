//! Error type and the mapping from Rust errors to `eki_status`.

use ekicore_abi::eki_status;

/// Failure of a safe-module call.
///
/// Each variant has exactly one C status, fixed by the `From<Error> for eki_status` impl below.
/// `Ok` is not a variant: success is the `Ok` side of the `Result`. The type is `Copy` and
/// carries no text: the message of a key store failure is kept in the store's last-error text,
/// which the handle owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Authentication failed: a tag or signature does not match the data it covers, or a wrapped
    /// key fails the RFC 3394 integrity check.
    AuthFailed,
    /// An argument has an invalid length, range or format, or a selector has an unknown value.
    InvalidArgument,
    /// A required pointer argument was NULL. Detected while C pointers are turned into slices,
    /// before a safe module is called.
    NullPointer,
    /// No object in the key store carries the given id.
    KeyNotFound,
    /// An object in the key store already carries the given id.
    KeyExists,
    /// The key exists but its algorithm does not allow the operation.
    WrongKeyType,
    /// The selector is known but its implementation is not compiled into this library.
    Unsupported,
    /// The key store backend failed for a reason that is not the caller's input; the handle's
    /// last-error text says why.
    Backend,
    /// An internal invariant did not hold.
    Internal,
}

impl From<Error> for eki_status {
    fn from(error: Error) -> Self {
        // No wildcard arm: a variant added later must fail to compile until its status is chosen.
        match error {
            Error::AuthFailed => eki_status::EKI_ERR_AUTH_FAILED,
            Error::InvalidArgument => eki_status::EKI_ERR_INVALID_ARGUMENT,
            Error::NullPointer => eki_status::EKI_ERR_NULL_POINTER,
            Error::KeyNotFound => eki_status::EKI_ERR_KEY_NOT_FOUND,
            Error::KeyExists => eki_status::EKI_ERR_KEY_EXISTS,
            Error::WrongKeyType => eki_status::EKI_ERR_WRONG_KEY_TYPE,
            Error::Unsupported => eki_status::EKI_ERR_UNSUPPORTED,
            Error::Backend => eki_status::EKI_ERR_BACKEND,
            Error::Internal => eki_status::EKI_ERR_INTERNAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_variant_maps_to_its_status() {
        let pairs = [
            (Error::AuthFailed, eki_status::EKI_ERR_AUTH_FAILED),
            (Error::InvalidArgument, eki_status::EKI_ERR_INVALID_ARGUMENT),
            (Error::NullPointer, eki_status::EKI_ERR_NULL_POINTER),
            (Error::KeyNotFound, eki_status::EKI_ERR_KEY_NOT_FOUND),
            (Error::KeyExists, eki_status::EKI_ERR_KEY_EXISTS),
            (Error::WrongKeyType, eki_status::EKI_ERR_WRONG_KEY_TYPE),
            (Error::Unsupported, eki_status::EKI_ERR_UNSUPPORTED),
            (Error::Backend, eki_status::EKI_ERR_BACKEND),
            (Error::Internal, eki_status::EKI_ERR_INTERNAL),
        ];
        for (error, status) in pairs {
            assert_eq!(eki_status::from(error), status, "{error:?}");
        }
    }
}
