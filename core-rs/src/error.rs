//! Error type and the mapping from Rust errors to `eki_status`.

use ekicore_abi::eki_status;

/// Failure of a safe-module call.
///
/// Each variant has exactly one C status, fixed by the `From<Error> for eki_status` impl below.
/// `Ok` is not a variant: success is the `Ok` side of the `Result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Authentication failed: a tag or signature does not match the data it covers.
    AuthFailed,
    /// An argument has an invalid length, range or format.
    InvalidArgument,
    /// A required pointer argument was NULL. Detected while C pointers are turned into slices,
    /// before a safe module is called.
    NullPointer,
}

impl From<Error> for eki_status {
    fn from(error: Error) -> Self {
        // No wildcard arm: a variant added later must fail to compile until its status is chosen.
        match error {
            Error::AuthFailed => eki_status::EKI_ERR_AUTH_FAILED,
            Error::InvalidArgument => eki_status::EKI_ERR_INVALID_ARGUMENT,
            Error::NullPointer => eki_status::EKI_ERR_NULL_POINTER,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_variant_maps_to_its_status() {
        assert_eq!(
            eki_status::from(Error::AuthFailed),
            eki_status::EKI_ERR_AUTH_FAILED
        );
        assert_eq!(
            eki_status::from(Error::InvalidArgument),
            eki_status::EKI_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            eki_status::from(Error::NullPointer),
            eki_status::EKI_ERR_NULL_POINTER
        );
    }
}
